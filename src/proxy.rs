//! The one route: adapt minimally, inject the credential, stream SSE back untouched.

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::Response;
use axum::routing::post;
use serde_json::{Value, json};

use crate::auth::{AccessToken, AccountId, Auth, AuthError};

#[derive(Clone)]
pub struct Gateway {
    pub auth: Arc<Auth>,
    pub http: reqwest::Client,
    pub upstream_url: String,
}

/// Shared cookie jar (Cloudflare, as codex does); connect timeout only — a total
/// timeout would sever long SSE streams.
pub fn client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .cookie_store(true)
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
}

pub fn router(gateway: Gateway) -> Router {
    // Shelley's /anthropic, /xai, /fireworks prefixes fall to 404 (terminal in Shelley).
    Router::new()
        .route("/openai/v1/responses", post(forward))
        .route("/healthz", axum::routing::get(healthz))
        .with_state(gateway)
}

/// Always 200 while serving; login state is informational (a restart can't fix it).
async fn healthz(State(gateway): State<Gateway>) -> Response {
    let auth = match gateway.auth.login_required().await {
        None => "ok",
        Some(_) => "login required",
    };
    let body = json!({ "auth": auth }).to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("healthz response is valid")
}

async fn forward(State(gateway): State<Gateway>, body: Bytes) -> Response {
    let started = Instant::now();
    let request = match adapt_request(&body) {
        Ok(request) => request,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
    };
    let model = request["model"].as_str().unwrap_or("?").to_owned();
    // Shelley's conversation id; doubles as the upstream session id.
    let cache_key = request["prompt_cache_key"].as_str().map(str::to_owned);

    let (token, account_id) = match gateway.auth.credentials().await {
        Ok(credentials) => credentials,
        Err(err) => return auth_error_response(err),
    };
    // Level 3, unconditional — pi's fallback only covers Node runtimes without zstd.
    let body = zstd::encode_all(
        serde_json::to_vec(&request)
            .expect("JSON value serializes")
            .as_slice(),
        3,
    )
    .expect("in-memory zstd compression");

    let mut response = match send_upstream(&gateway, &body, &cache_key, &token, &account_id).await {
        Ok(response) => response,
        Err(err) => return upstream_error_response(err, &model),
    };
    // 401 before streaming starts: the token was invalidated server-side. Recover
    // (reload/refresh) and replay exactly once; a second 401 propagates unchanged.
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        let (token, account_id) = match gateway.auth.recover(&token).await {
            Ok(credentials) => credentials,
            Err(err) => return auth_error_response(err),
        };
        tracing::warn!(
            model,
            "upstream 401; replaying once with recovered credential"
        );
        response = match send_upstream(&gateway, &body, &cache_key, &token, &account_id).await {
            Ok(response) => response,
            Err(err) => return upstream_error_response(err, &model),
        };
    }

    let status = response.status();
    tracing::info!(
        %status,
        model,
        header_ms = started.elapsed().as_millis() as u64,
        "POST /openai/v1/responses"
    );
    let mut relayed = Response::builder().status(status.as_u16());
    for (name, value) in response.headers() {
        if !skip_response_header(name.as_str()) {
            relayed = relayed.header(name.as_str(), value.as_bytes());
        }
    }
    relayed
        .body(Body::from_stream(response.bytes_stream()))
        .expect("relayed response headers are valid")
}

/// Inbound headers (Shelley's `Bearer implicit` included) are never forwarded; this
/// trusted set replaces them.
async fn send_upstream(
    gateway: &Gateway,
    body: &[u8],
    cache_key: &Option<String>,
    token: &AccessToken,
    account_id: &AccountId,
) -> reqwest::Result<reqwest::Response> {
    let mut upstream = gateway
        .http
        .post(&gateway.upstream_url)
        .header(header::AUTHORIZATION, format!("Bearer {}", token.as_str()))
        .header("chatgpt-account-id", account_id.as_str())
        .header("originator", crate::ORIGINATOR)
        .header(header::USER_AGENT, crate::user_agent())
        .header("OpenAI-Beta", "responses=experimental")
        .header(header::ACCEPT, "text/event-stream")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_ENCODING, "zstd");
    if let Some(key) = cache_key {
        upstream = upstream
            .header("session-id", key)
            .header("x-client-request-id", key);
    }
    upstream.body(body.to_vec()).send().await
}

fn auth_error_response(err: AuthError) -> Response {
    match err {
        AuthError::LoginRequired(_) => {
            tracing::error!(%err, "rejecting request");
            error_response(StatusCode::UNAUTHORIZED, &err.to_string())
        }
        AuthError::Transient(_) => error_response(StatusCode::BAD_GATEWAY, &err.to_string()),
    }
}

fn upstream_error_response(err: reqwest::Error, model: &str) -> Response {
    tracing::error!(%err, model, "upstream request failed");
    error_response(
        StatusCode::BAD_GATEWAY,
        &format!("upstream request failed: {err}"),
    )
}

/// Drop `max_output_tokens` (absent from the Codex schema), force `store:false` /
/// `stream:true`; pass the rest (Lark tools, encrypted reasoning) untouched.
fn adapt_request(body: &[u8]) -> Result<Value, &'static str> {
    let mut request: Value =
        serde_json::from_slice(body).map_err(|_| "request body is not valid JSON")?;
    let object = request
        .as_object_mut()
        .ok_or("request body must be a JSON object")?;
    object.remove("max_output_tokens");
    object.insert("store".to_owned(), Value::Bool(false));
    object.insert("stream".to_owned(), Value::Bool(true));
    Ok(request)
}

/// Hop-by-hop headers, plus set-cookie: upstream Cloudflare cookies belong in the
/// gateway's own jar, not broadcast to every caller.
fn skip_response_header(name: &str) -> bool {
    matches!(
        name,
        "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "trailer"
            | "upgrade"
            | "te"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "set-cookie"
    )
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let body = json!({ "error": { "message": message } }).to_string();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("error response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapt_strips_max_output_tokens_and_forces_flags() {
        let body = json!({
            "model": "gpt-5.4",
            "max_output_tokens": 32768,
            "store": false,
            "stream": true,
            "include": ["reasoning.encrypted_content"],
            "tools": [{
                "type": "custom",
                "name": "apply_patch",
                "format": {"type": "grammar", "syntax": "lark", "definition": "start: x"},
            }],
            "input": [{"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "opaque"}],
        });
        let adapted = adapt_request(body.to_string().as_bytes()).expect("adapt request");
        assert!(adapted.get("max_output_tokens").is_none());
        assert_eq!(adapted["store"], json!(false));
        assert_eq!(adapted["stream"], json!(true));
        assert_eq!(adapted["tools"], body["tools"]);
        assert_eq!(adapted["input"], body["input"]);
        assert_eq!(adapted["include"], body["include"]);
    }

    #[test]
    fn adapt_rejects_non_object_bodies() {
        assert!(adapt_request(b"not json").is_err());
        assert!(adapt_request(b"[1,2]").is_err());
    }
}
