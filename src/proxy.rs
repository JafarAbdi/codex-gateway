//! The one route: adapt minimally, inject the credential, stream SSE back untouched.

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::rejection::{BytesRejection, FailedToBufferBody};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::post;
use serde_json::{Value, json};

use crate::auth::{AccessToken, AccountId, Auth, AuthError};
use crate::logging;

/// Room for Shelley's 20 MiB images after base64 encoding plus Responses context.
pub const INBOUND_BODY_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const SHELLEY_REQUEST_ID: &str = "shelley-request-id";

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
        .cookie_provider(Arc::new(Jar::default()))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
}

/// Single-upstream cookie jar: name=value pairs, last write wins. The one upstream
/// host makes domain/path/expiry handling (and the public-suffix list) dead weight.
#[derive(Default)]
struct Jar(std::sync::Mutex<std::collections::HashMap<String, String>>);

impl reqwest::cookie::CookieStore for Jar {
    fn set_cookies(
        &self,
        cookie_headers: &mut dyn Iterator<Item = &axum::http::HeaderValue>,
        _url: &reqwest::Url,
    ) {
        let mut jar = self.0.lock().expect("cookie jar lock");
        for header in cookie_headers {
            let Ok(text) = header.to_str() else { continue };
            let pair = text.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') {
                jar.insert(name.trim().to_owned(), value.trim().to_owned());
            }
        }
    }

    fn cookies(&self, _url: &reqwest::Url) -> Option<axum::http::HeaderValue> {
        let jar = self.0.lock().expect("cookie jar lock");
        if jar.is_empty() {
            return None;
        }
        let joined = jar
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        axum::http::HeaderValue::from_str(&joined).ok()
    }
}

pub fn router(gateway: Gateway) -> Router {
    // Shelley's /anthropic, /xai, /fireworks prefixes fall to 404 (terminal in Shelley).
    Router::new()
        .route(
            "/openai/v1/responses",
            post(forward).layer(DefaultBodyLimit::max(INBOUND_BODY_LIMIT_BYTES)),
        )
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

fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;

    if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

struct InboundRequest {
    value: Value,
    request_id: Option<String>,
    bytes: usize,
}

fn extract_inbound(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<InboundRequest, Box<Response>> {
    let request_id = headers
        .get(SHELLEY_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let body = body.map_err(|error| {
        Box::new(body_rejection_response(
            error,
            content_length,
            request_id.as_deref(),
        ))
    })?;
    let bytes = body.len();
    let readable_bytes = human_bytes(bytes as u64);
    let value = adapt_request(&body).map_err(|message| {
        logging::status(
            StatusCode::BAD_REQUEST.as_u16(),
            format_args!(
                "POST /openai/v1/responses status=400 shelley_request_id={:?} body={readable_bytes} error={message:?}",
                request_id.as_deref().unwrap_or("-")
            ),
        );
        Box::new(error_response(StatusCode::BAD_REQUEST, message))
    })?;
    Ok(InboundRequest {
        value,
        request_id,
        bytes,
    })
}

async fn forward(
    State(gateway): State<Gateway>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let started = Instant::now();
    let InboundRequest {
        value: request,
        request_id,
        bytes: inbound_bytes,
    } = match extract_inbound(&headers, body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let model = request["model"].as_str().unwrap_or("?").to_owned();
    // Shelley's conversation id; doubles as the upstream session id.
    let cache_key = request["prompt_cache_key"].as_str().map(str::to_owned);

    // Level 3, unconditional — pi's fallback only covers Node runtimes without zstd.
    // Bytes so the 401 replay reuses the buffer without copying.
    let upstream_body = Bytes::from(
        zstd::encode_all(
            serde_json::to_vec(&request)
                .expect("JSON value serializes")
                .as_slice(),
            3,
        )
        .expect("in-memory zstd compression"),
    );
    let upstream_zstd_bytes = upstream_body.len();
    let inbound_size = human_bytes(inbound_bytes as u64);
    let upstream_zstd_size = human_bytes(upstream_zstd_bytes as u64);

    let response = match send_with_recovery(&gateway, &upstream_body, &cache_key, &model).await {
        Ok(response) => response,
        Err(response) => return *response,
    };
    let status = response.status();
    logging::status(
        status.as_u16(),
        format_args!(
            "POST /openai/v1/responses {status} model={model} shelley_request_id={:?} body={inbound_size} zstd={upstream_zstd_size} header_latency={} ms",
            request_id.as_deref().unwrap_or("-"),
            started.elapsed().as_millis()
        ),
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

async fn send_with_recovery(
    gateway: &Gateway,
    body: &Bytes,
    cache_key: &Option<String>,
    model: &str,
) -> Result<reqwest::Response, Box<Response>> {
    let (token, account_id) = gateway
        .auth
        .credentials()
        .await
        .map_err(|err| Box::new(auth_error_response(err)))?;
    let mut response = send_upstream(gateway, body, cache_key, &token, &account_id)
        .await
        .map_err(|err| Box::new(upstream_error_response(err, model)))?;
    // 401 before streaming starts: recover and replay exactly once.
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        let (token, account_id) = gateway
            .auth
            .recover(&token)
            .await
            .map_err(|err| Box::new(auth_error_response(err)))?;
        logging::warning(format_args!(
            "upstream 401 for {model}; replaying once with recovered credential"
        ));
        response = send_upstream(gateway, body, cache_key, &token, &account_id)
            .await
            .map_err(|err| Box::new(upstream_error_response(err, model)))?;
    }
    Ok(response)
}

/// Inbound headers (Shelley's `Bearer implicit` included) are never forwarded; this
/// trusted set replaces them.
async fn send_upstream(
    gateway: &Gateway,
    body: &Bytes,
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
    upstream.body(body.clone()).send().await
}

fn body_rejection_response(
    error: BytesRejection,
    content_length: Option<u64>,
    request_id: Option<&str>,
) -> Response {
    match error {
        BytesRejection::FailedToBufferBody(FailedToBufferBody::LengthLimitError(_)) => {
            let content_length_log = content_length
                .map(|bytes| format!(" content_length={}", human_bytes(bytes)))
                .unwrap_or_default();
            let request_id_log = request_id
                .map(|id| format!(" shelley_request_id={id:?}"))
                .unwrap_or_default();
            logging::status(
                StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                format_args!(
                    "POST /openai/v1/responses status=413 limit={}{content_length_log}{request_id_log}",
                    human_bytes(INBOUND_BODY_LIMIT_BYTES as u64)
                ),
            );
            let message = content_length.map_or_else(
                || format!("request body exceeds the 64 MiB limit ({INBOUND_BODY_LIMIT_BYTES} bytes)"),
                |bytes| {
                    format!(
                        "request body exceeds the 64 MiB limit ({INBOUND_BODY_LIMIT_BYTES} bytes); received Content-Length {bytes} bytes"
                    )
                },
            );
            error_response(StatusCode::PAYLOAD_TOO_LARGE, &message)
        }
        BytesRejection::FailedToBufferBody(FailedToBufferBody::UnknownBodyError(error)) => {
            logging::status(
                StatusCode::BAD_REQUEST.as_u16(),
                format_args!(
                    "POST /openai/v1/responses status=400 shelley_request_id={:?} body_buffer_error={error}",
                    request_id.unwrap_or("-")
                ),
            );
            error_response(StatusCode::BAD_REQUEST, "failed to buffer request body")
        }
        error => {
            logging::status(
                StatusCode::BAD_REQUEST.as_u16(),
                format_args!(
                    "POST /openai/v1/responses status=400 shelley_request_id={:?} body_buffer_error={error}",
                    request_id.unwrap_or("-")
                ),
            );
            error_response(StatusCode::BAD_REQUEST, "failed to buffer request body")
        }
    }
}

fn auth_error_response(err: AuthError) -> Response {
    match err {
        AuthError::LoginRequired(_) => {
            logging::error(format_args!("rejecting request: {err}"));
            error_response(StatusCode::UNAUTHORIZED, &err.to_string())
        }
        AuthError::Transient(_) => {
            logging::error(format_args!("authentication failed transiently: {err}"));
            error_response(StatusCode::BAD_GATEWAY, &err.to_string())
        }
    }
}

fn upstream_error_response(err: reqwest::Error, model: &str) -> Response {
    logging::error(format_args!("upstream request failed for {model}: {err}"));
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
    fn formats_byte_counts_for_humans() {
        assert_eq!(human_bytes(8), "8 B");
        assert_eq!(human_bytes(2_124_545), "2.03 MiB");
        assert_eq!(human_bytes(1_250_552), "1.19 MiB");
    }

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

    #[test]
    fn jar_stores_and_replays_cookies_last_write_wins() {
        use reqwest::cookie::CookieStore;
        let jar = Jar::default();
        let url = reqwest::Url::parse("https://chatgpt.com/backend-api/codex/responses")
            .expect("parse url");
        let set = |jar: &Jar, values: &[&str]| {
            let headers: Vec<axum::http::HeaderValue> = values
                .iter()
                .map(|value| axum::http::HeaderValue::from_str(value).expect("header"))
                .collect();
            jar.set_cookies(&mut headers.iter(), &url);
        };
        assert!(jar.cookies(&url).is_none(), "empty jar sends no header");
        set(
            &jar,
            &[
                "__cf_bm=first; Path=/; Secure; HttpOnly",
                "cf_clearance=abc; Path=/",
            ],
        );
        set(&jar, &["__cf_bm=second; Path=/"]);
        let header = jar.cookies(&url).expect("cookie header");
        let sent = header.to_str().expect("ascii");
        assert!(sent.contains("__cf_bm=second"), "last write wins: {sent}");
        assert!(!sent.contains("first"));
        assert!(sent.contains("cf_clearance=abc"));
        assert!(!sent.contains("Path"), "attributes never leak: {sent}");
    }
}
