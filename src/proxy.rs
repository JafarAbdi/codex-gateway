//! The one route: pi's own Codex requests, forwarded untouched with the shared credential.
//! `POST` carries a request body and streams SSE back; `GET` upgrades to a WebSocket that
//! is relayed message for message.

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::rejection::BytesRejection;
use axum::extract::ws::{self, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderName, StatusCode, header};
use axum::response::Response;
use axum::routing::post;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self as ts, http::HeaderValue};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::auth::{AccessToken, AccountId, Auth, AuthError};
use crate::logging;

/// pi's own request headers; its placeholder credentials never pass.
const FORWARDED_HEADERS: [HeaderName; 8] = [
    header::ACCEPT,
    header::CONTENT_TYPE,
    header::CONTENT_ENCODING,
    header::USER_AGENT,
    HeaderName::from_static("originator"),
    HeaderName::from_static("openai-beta"),
    HeaderName::from_static("session-id"),
    HeaderName::from_static("x-client-request-id"),
];
const SESSION_ID: HeaderName = HeaderName::from_static("session-id");

type Upstream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

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
    // No body or message caps of our own: only trusted callers reach the gateway, and
    // the backend enforces its limits.
    Router::new()
        .route(
            "/codex/responses",
            post(forward)
                .get(connect)
                .layer(DefaultBodyLimit::disable()),
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

fn session_id(headers: &HeaderMap) -> &str {
    headers
        .get(SESSION_ID)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
}

fn forwarded(headers: &HeaderMap) -> HeaderMap {
    FORWARDED_HEADERS
        .iter()
        .filter_map(|name| Some((name.clone(), headers.get(name)?.clone())))
        .collect()
}

/// The shared credential, in place of the caller's.
fn credential_headers(token: &AccessToken, account_id: &AccountId) -> [(HeaderName, String); 2] {
    [
        (header::AUTHORIZATION, format!("Bearer {}", token.as_str())),
        (
            HeaderName::from_static("chatgpt-account-id"),
            account_id.as_str().to_owned(),
        ),
    ]
}

async fn forward(
    State(gateway): State<Gateway>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let started = Instant::now();
    let session = session_id(&headers);
    let body = match body {
        Ok(body) => body,
        Err(error) => return body_rejection_response(&error, session),
    };
    let response = match send_with_recovery(&gateway, &headers, &body).await {
        Ok(response) => response,
        Err(response) => return *response,
    };
    let status = response.status();
    logging::status(
        status.as_u16(),
        format_args!(
            "POST /codex/responses {status} session={session} body={} header_latency={} ms",
            human_bytes(body.len() as u64),
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
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<reqwest::Response, Box<Response>> {
    let (token, account_id) = gateway
        .auth
        .credentials()
        .await
        .map_err(|err| Box::new(auth_error_response(err)))?;
    let mut response = send_upstream(gateway, headers, body, &token, &account_id)
        .await
        .map_err(|err| Box::new(upstream_error_response(&err)))?;
    // 401 before streaming starts: recover and replay exactly once.
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        let (token, account_id) = gateway
            .auth
            .recover(&token)
            .await
            .map_err(|err| Box::new(auth_error_response(err)))?;
        logging::warning(format_args!(
            "upstream 401; replaying once with recovered credential"
        ));
        response = send_upstream(gateway, headers, body, &token, &account_id)
            .await
            .map_err(|err| Box::new(upstream_error_response(&err)))?;
    }
    Ok(response)
}

async fn send_upstream(
    gateway: &Gateway,
    headers: &HeaderMap,
    body: &Bytes,
    token: &AccessToken,
    account_id: &AccountId,
) -> reqwest::Result<reqwest::Response> {
    let mut upstream = gateway
        .http
        .post(&gateway.upstream_url)
        .headers(forwarded(headers));
    for (name, value) in credential_headers(token, account_id) {
        upstream = upstream.header(name, value);
    }
    upstream.body(body.clone()).send().await
}

async fn connect(
    State(gateway): State<Gateway>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let started = Instant::now();
    let session = session_id(&headers).to_owned();
    let upstream = match connect_with_recovery(&gateway, &headers).await {
        Ok(upstream) => upstream,
        Err(response) => return *response,
    };
    logging::status(
        StatusCode::SWITCHING_PROTOCOLS.as_u16(),
        format_args!(
            "GET /codex/responses 101 session={session} handshake_latency={} ms",
            started.elapsed().as_millis()
        ),
    );
    upgrade
        .max_message_size(usize::MAX)
        .max_frame_size(usize::MAX)
        .on_upgrade(move |client| relay(client, upstream, session))
}

async fn connect_with_recovery(
    gateway: &Gateway,
    headers: &HeaderMap,
) -> Result<Upstream, Box<Response>> {
    let (token, account_id) = gateway
        .auth
        .credentials()
        .await
        .map_err(|err| Box::new(auth_error_response(err)))?;
    let connected = match connect_upstream(gateway, headers, &token, &account_id).await {
        // 401 on the handshake: recover and connect again exactly once.
        Err(ts::Error::Http(response)) if response.status() == StatusCode::UNAUTHORIZED => {
            let (token, account_id) = gateway
                .auth
                .recover(&token)
                .await
                .map_err(|err| Box::new(auth_error_response(err)))?;
            logging::warning(format_args!(
                "upstream 401; reconnecting once with recovered credential"
            ));
            connect_upstream(gateway, headers, &token, &account_id).await
        }
        connected => connected,
    };
    connected.map_err(|err| Box::new(websocket_error_response(err)))
}

async fn connect_upstream(
    gateway: &Gateway,
    headers: &HeaderMap,
    token: &AccessToken,
    account_id: &AccountId,
) -> Result<Upstream, ts::Error> {
    let mut url = reqwest::Url::parse(&gateway.upstream_url).expect("upstream URL is valid");
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .expect("http(s) and ws(s) are interchangeable schemes");
    let mut request = url.as_str().into_client_request()?;
    request.headers_mut().extend(forwarded(headers));
    for (name, value) in credential_headers(token, account_id) {
        let value = HeaderValue::from_str(&value).map_err(ts::http::Error::from)?;
        request.headers_mut().insert(name, value);
    }
    let config = WebSocketConfig::default()
        .max_message_size(None)
        .max_frame_size(None);
    let (upstream, _) =
        tokio_tungstenite::connect_async_with_config(request, Some(config), true).await?;
    Ok(upstream)
}

/// Each side answers its own pings; everything else crosses unchanged until either
/// side closes.
async fn relay(client: WebSocket, upstream: Upstream, session: String) {
    let started = Instant::now();
    let (mut client_tx, mut client_rx) = client.split();
    let (mut upstream_tx, mut upstream_rx) = upstream.split();
    let to_upstream = async {
        while let Some(message) = client_rx.next().await {
            if let Some(message) = to_upstream_message(message?) {
                upstream_tx.send(message).await?;
            }
        }
        anyhow::Ok(())
    };
    let to_client = async {
        while let Some(message) = upstream_rx.next().await {
            if let Some(message) = to_client_message(message?) {
                client_tx.send(message).await?;
            }
        }
        anyhow::Ok(())
    };
    let result = tokio::select! {
        result = to_upstream => result,
        result = to_client => result,
    };
    let seconds = started.elapsed().as_secs();
    match result {
        Ok(()) => logging::success(format_args!(
            "websocket session={session} closed after {seconds} s"
        )),
        Err(error) => logging::error(format_args!(
            "websocket session={session} failed after {seconds} s: {error:#}"
        )),
    }
}

fn to_upstream_text(text: ws::Utf8Bytes) -> ts::Utf8Bytes {
    ts::Utf8Bytes::try_from(Bytes::from(text)).expect("axum text is UTF-8")
}

fn to_client_text(text: ts::Utf8Bytes) -> ws::Utf8Bytes {
    ws::Utf8Bytes::try_from(Bytes::from(text)).expect("tungstenite text is UTF-8")
}

fn to_upstream_message(message: ws::Message) -> Option<ts::Message> {
    match message {
        ws::Message::Text(text) => Some(ts::Message::Text(to_upstream_text(text))),
        ws::Message::Binary(bytes) => Some(ts::Message::Binary(bytes)),
        ws::Message::Close(frame) => Some(ts::Message::Close(frame.map(|frame| {
            ts::protocol::CloseFrame {
                code: frame.code.into(),
                reason: to_upstream_text(frame.reason),
            }
        }))),
        ws::Message::Ping(_) | ws::Message::Pong(_) => None,
    }
}

fn to_client_message(message: ts::Message) -> Option<ws::Message> {
    match message {
        ts::Message::Text(text) => Some(ws::Message::Text(to_client_text(text))),
        ts::Message::Binary(bytes) => Some(ws::Message::Binary(bytes)),
        ts::Message::Close(frame) => Some(ws::Message::Close(frame.map(|frame| ws::CloseFrame {
            code: frame.code.into(),
            reason: to_client_text(frame.reason),
        }))),
        ts::Message::Ping(_) | ts::Message::Pong(_) | ts::Message::Frame(_) => None,
    }
}

fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut chain = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        let message = error.to_string();
        if !chain.ends_with(&message) {
            chain.push_str(": ");
            chain.push_str(&message);
        }
        source = error.source();
    }
    chain
}

fn body_rejection_response(error: &BytesRejection, session: &str) -> Response {
    let error = error_chain(error);
    logging::status(
        StatusCode::BAD_REQUEST.as_u16(),
        format_args!(
            "POST /codex/responses status=400 session={session} body_buffer_error={error:?}"
        ),
    );
    error_response(StatusCode::BAD_REQUEST, "failed to buffer request body")
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

fn upstream_error_response(err: &reqwest::Error) -> Response {
    let err = error_chain(err);
    logging::error(format_args!("upstream request failed: {err}"));
    error_response(
        StatusCode::BAD_GATEWAY,
        &format!("upstream request failed: {err}"),
    )
}

/// A refused handshake is relayed with the backend's own status and body; anything
/// else is a 502.
fn websocket_error_response(err: ts::Error) -> Response {
    let ts::Error::Http(response) = err else {
        let err = error_chain(&err);
        logging::error(format_args!("upstream websocket failed: {err}"));
        return error_response(
            StatusCode::BAD_GATEWAY,
            &format!("upstream websocket failed: {err}"),
        );
    };
    let status = response.status();
    logging::status(
        status.as_u16(),
        format_args!("GET /codex/responses {status}: upstream refused the websocket"),
    );
    let (parts, body) = response.into_parts();
    let mut relayed = Response::builder().status(parts.status);
    for (name, value) in &parts.headers {
        if !skip_response_header(name.as_str()) {
            relayed = relayed.header(name, value);
        }
    }
    relayed
        .body(Body::from(body.unwrap_or_default()))
        .expect("relayed response headers are valid")
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
    fn forwards_only_request_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer caller".parse().expect("header"),
        );
        headers.insert("chatgpt-account-id", "caller".parse().expect("header"));
        headers.insert(header::CONTENT_ENCODING, "zstd".parse().expect("header"));
        headers.insert("session-id", "session-1".parse().expect("header"));
        let forwarded = forwarded(&headers);
        assert_eq!(forwarded.len(), 2);
        assert_eq!(forwarded[header::CONTENT_ENCODING], "zstd");
        assert_eq!(forwarded["session-id"], "session-1");
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
