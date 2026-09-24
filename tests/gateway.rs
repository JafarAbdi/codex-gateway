//! End-to-end tests: real gateway router, mock ChatGPT backend and auth server.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::ws::WebSocketUpgrade;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::post;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codex_gateway::auth::Auth;
use codex_gateway::proxy::{Gateway, client, router};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

const SSE_BODY: &str =
    "data: {\"type\":\"response.completed\",\"response\":{}}\n\ndata: [DONE]\n\n";

fn fake_jwt(exp: i64, account_id: &str) -> String {
    let encode =
        |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).expect("serialize claims"));
    let claims = json!({
        "exp": exp,
        "https://api.openai.com/auth": { "chatgpt_account_id": account_id },
    });
    format!(
        "{}.{}.sig",
        encode(&json!({"alg": "none"})),
        encode(&claims)
    )
}

fn far_future() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64
        + 3600
}

fn write_auth_file(path: &Path, access_token: &str) {
    std::fs::write(
        path,
        json!({
            "tokens": {
                "access_token": access_token,
                "refresh_token": "refresh-1",
                "account_id": "acct-file",
            }
        })
        .to_string(),
    )
    .expect("write auth file");
}

async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock listener");
    let addr = listener.local_addr().expect("listener addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("mock server") });
    addr
}

#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<(HeaderMap, Bytes)>>>);

async fn upstream_handler(
    State(captured): State<Captured>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    captured
        .0
        .lock()
        .expect("lock captured requests")
        .push((headers, body));
    ([("content-type", "text/event-stream")], SSE_BODY)
}

async fn start_gateway(auth_path: &Path, issuer: String, upstream_url: String) -> SocketAddr {
    let auth = Auth::load(auth_path.to_owned(), issuer).expect("load auth");
    let gateway = Gateway {
        auth: Arc::new(auth),
        http: client().expect("build client"),
        upstream_url,
    };
    serve(router(gateway)).await
}

#[tokio::test]
async fn forwards_the_body_untouched_and_replaces_credentials() {
    let captured = Captured::default();
    let upstream = serve(
        Router::new()
            .route("/responses", post(upstream_handler))
            .with_state(captured.clone()),
    )
    .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let auth_path = dir.path().join("auth.json");
    let token = fake_jwt(far_future(), "acct-jwt");
    write_auth_file(&auth_path, &token);
    let gateway = start_gateway(
        &auth_path,
        "http://unused.invalid".into(),
        format!("http://{upstream}/responses"),
    )
    .await;

    // pi's own request: its placeholder credential, a zstd body the gateway never reads.
    let body = b"\x28\xb5\x2f\xfd opaque zstd frame".to_vec();
    let response = reqwest::Client::new()
        .post(format!("http://{gateway}/codex/responses"))
        .header("authorization", "Bearer placeholder")
        .header("chatgpt-account-id", "placeholder")
        .header("originator", "pi")
        .header("content-type", "application/json")
        .header("content-encoding", "zstd")
        .header("openai-beta", "responses=experimental")
        .header("session-id", "session-1")
        .header("x-unrelated", "dropped")
        .body(body.clone())
        .send()
        .await
        .expect("request to gateway");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"]
            .to_str()
            .expect("ascii header"),
        "text/event-stream"
    );
    assert_eq!(response.text().await.expect("read response body"), SSE_BODY);

    let requests = captured.0.lock().expect("lock captured requests");
    let (headers, received) = &requests[0];
    assert_eq!(received.as_ref(), body.as_slice());
    let header = |name: &str| headers[name].to_str().expect("ascii header").to_owned();
    assert_eq!(header("authorization"), format!("Bearer {token}"));
    assert_eq!(header("chatgpt-account-id"), "acct-file");
    assert_eq!(header("originator"), "pi");
    assert_eq!(header("content-encoding"), "zstd");
    assert_eq!(header("openai-beta"), "responses=experimental");
    assert_eq!(header("session-id"), "session-1");
    assert!(!headers.contains_key("x-unrelated"));
}

#[tokio::test]
async fn request_larger_than_axum_default_limit_reaches_upstream() {
    let captured = Captured::default();
    let upstream = serve(
        Router::new()
            .route("/responses", post(upstream_handler))
            .layer(axum::extract::DefaultBodyLimit::disable())
            .with_state(captured.clone()),
    )
    .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let auth_path = dir.path().join("auth.json");
    write_auth_file(&auth_path, &fake_jwt(far_future(), "acct"));
    let gateway = start_gateway(
        &auth_path,
        "http://unused.invalid".into(),
        format!("http://{upstream}/responses"),
    )
    .await;

    let payload = vec![b'x'; 3 * 1024 * 1024];
    let response = reqwest::Client::new()
        .post(format!("http://{gateway}/codex/responses"))
        .body(payload.clone())
        .send()
        .await
        .expect("large request to gateway");
    assert_eq!(response.status(), 200);

    let requests = captured.0.lock().expect("lock captured requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.as_ref(), payload.as_slice());
}

#[tokio::test]
async fn expired_token_refreshes_exactly_once_across_concurrent_requests() {
    let captured = Captured::default();
    let upstream = serve(
        Router::new()
            .route("/responses", post(upstream_handler))
            .with_state(captured.clone()),
    )
    .await;

    let refreshes = Arc::new(AtomicUsize::new(0));
    let issuer = {
        let refreshes = refreshes.clone();
        serve(Router::new().route(
            "/oauth/token",
            post(move |body: Bytes| {
                let refreshes = refreshes.clone();
                async move {
                    let request: Value =
                        serde_json::from_slice(&body).expect("json refresh request");
                    assert_eq!(request["grant_type"], json!("refresh_token"));
                    refreshes.fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!({
                        "access_token": fake_jwt(far_future(), "acct-new"),
                        "refresh_token": "refresh-2",
                    }))
                }
            }),
        ))
        .await
    };

    let dir = tempfile::tempdir().expect("create tempdir");
    let auth_path = dir.path().join("auth.json");
    write_auth_file(&auth_path, &fake_jwt(0, "acct-old"));
    let gateway = start_gateway(
        &auth_path,
        format!("http://{issuer}"),
        format!("http://{upstream}/responses"),
    )
    .await;

    let post_once = || async {
        reqwest::Client::new()
            .post(format!("http://{gateway}/codex/responses"))
            .json(&json!({"model": "gpt-5.4", "input": []}))
            .send()
            .await
            .expect("request to gateway")
            .status()
    };
    let (first, second) = tokio::join!(post_once(), post_once());
    assert_eq!((first.as_u16(), second.as_u16()), (200, 200));
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);

    // The rotated credential was persisted.
    let saved: Value = serde_json::from_slice(&std::fs::read(&auth_path).expect("read auth file"))
        .expect("parse auth file");
    assert_eq!(saved["tokens"]["refresh_token"], json!("refresh-2"));
    assert_eq!(saved["tokens"]["account_id"], json!("acct-new"));
}

fn refresh_issuer(refreshes: Arc<AtomicUsize>, response: Value) -> Router {
    Router::new().route(
        "/oauth/token",
        post(move |_body: Bytes| {
            refreshes.fetch_add(1, Ordering::SeqCst);
            let response = response.clone();
            async move { axum::Json(response) }
        }),
    )
}

/// Upstream that 401s any bearer except `accept`, counting hits.
fn picky_upstream(accept: String, hits: Arc<AtomicUsize>) -> Router {
    Router::new().route(
        "/responses",
        post(move |headers: HeaderMap, _body: Bytes| {
            hits.fetch_add(1, Ordering::SeqCst);
            let ok = headers["authorization"].to_str().expect("ascii header")
                == format!("Bearer {accept}");
            async move {
                if ok {
                    ([("content-type", "text/event-stream")], SSE_BODY).into_response()
                } else {
                    axum::http::StatusCode::UNAUTHORIZED.into_response()
                }
            }
        }),
    )
}

#[tokio::test]
async fn upstream_401_recovers_and_replays_once() {
    // Access token is far from expiry, so only 401-triggered recovery can fix this.
    let new_token = fake_jwt(far_future(), "acct-new");
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = serve(picky_upstream(new_token.clone(), hits.clone())).await;
    let refreshes = Arc::new(AtomicUsize::new(0));
    let issuer = serve(refresh_issuer(
        refreshes.clone(),
        json!({"access_token": new_token, "refresh_token": "refresh-2"}),
    ))
    .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let auth_path = dir.path().join("auth.json");
    write_auth_file(&auth_path, &fake_jwt(far_future(), "acct-revoked"));
    let gateway = start_gateway(
        &auth_path,
        format!("http://{issuer}"),
        format!("http://{upstream}/responses"),
    )
    .await;

    let response = reqwest::Client::new()
        .post(format!("http://{gateway}/codex/responses"))
        .json(&json!({"model": "gpt-5.4", "input": []}))
        .send()
        .await
        .expect("request to gateway");
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.expect("read response body"), SSE_BODY);
    assert_eq!(hits.load(Ordering::SeqCst), 2, "original + one replay");
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn second_401_propagates_without_looping() {
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = serve(picky_upstream("never-matches".into(), hits.clone())).await;
    let issuer = serve(refresh_issuer(
        Arc::new(AtomicUsize::new(0)),
        json!({"access_token": fake_jwt(far_future(), "acct-new")}),
    ))
    .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let auth_path = dir.path().join("auth.json");
    write_auth_file(&auth_path, &fake_jwt(far_future(), "acct-old"));
    let gateway = start_gateway(
        &auth_path,
        format!("http://{issuer}"),
        format!("http://{upstream}/responses"),
    )
    .await;

    let status = reqwest::Client::new()
        .post(format!("http://{gateway}/codex/responses"))
        .json(&json!({"model": "gpt-5.4", "input": []}))
        .send()
        .await
        .expect("request to gateway")
        .status();
    assert_eq!(status, 401);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "exactly one replay, no loop"
    );
}

#[tokio::test]
async fn refresh_omitting_fields_preserves_refresh_token() {
    let new_token = fake_jwt(far_future(), "acct-new");
    let upstream = serve(picky_upstream(
        new_token.clone(),
        Arc::new(AtomicUsize::new(0)),
    ))
    .await;
    // Refresh response carries only a new access token.
    let issuer = serve(refresh_issuer(
        Arc::new(AtomicUsize::new(0)),
        json!({"access_token": new_token}),
    ))
    .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let auth_path = dir.path().join("auth.json");
    write_auth_file(&auth_path, &fake_jwt(0, "acct-old"));
    let gateway = start_gateway(
        &auth_path,
        format!("http://{issuer}"),
        format!("http://{upstream}/responses"),
    )
    .await;

    let status = reqwest::Client::new()
        .post(format!("http://{gateway}/codex/responses"))
        .json(&json!({"model": "gpt-5.4", "input": []}))
        .send()
        .await
        .expect("request to gateway")
        .status();
    assert_eq!(status, 200);
    let saved: Value = serde_json::from_slice(&std::fs::read(&auth_path).expect("read auth file"))
        .expect("parse auth file");
    assert_eq!(
        saved["tokens"]["refresh_token"],
        json!("refresh-1"),
        "kept when omitted"
    );
    assert_eq!(saved["tokens"]["account_id"], json!("acct-new"));
}

#[tokio::test]
async fn relogin_recovers_without_restart() {
    let fresh_token = fake_jwt(far_future(), "acct-fresh");
    let upstream = serve(picky_upstream(
        fresh_token.clone(),
        Arc::new(AtomicUsize::new(0)),
    ))
    .await;
    // Refresh always terminally rejected → NeedsLogin.
    let issuer = serve(Router::new().route(
        "/oauth/token",
        post(|| async {
            (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": {"code": "invalid_grant"}})),
            )
        }),
    ))
    .await;

    let dir = tempfile::tempdir().expect("create tempdir");
    let auth_path = dir.path().join("auth.json");
    write_auth_file(&auth_path, &fake_jwt(far_future(), "acct-revoked"));
    let gateway = start_gateway(
        &auth_path,
        format!("http://{issuer}"),
        format!("http://{upstream}/responses"),
    )
    .await;

    let post_once = || async {
        reqwest::Client::new()
            .post(format!("http://{gateway}/codex/responses"))
            .json(&json!({"model": "gpt-5.4", "input": []}))
            .send()
            .await
            .expect("request to gateway")
            .status()
    };
    // Upstream 401 → recovery refresh terminally fails → login required.
    assert_eq!(post_once().await, 401);
    assert_eq!(
        post_once().await,
        401,
        "stays login-required, auth server not hammered"
    );
    // Operator re-runs `login` (simulated: file rewritten); no serve restart.
    write_auth_file(&auth_path, &fresh_token);
    assert_eq!(post_once().await, 200);
}

type Client =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Echoes every message; captures the handshake headers. Upgrades only for `accept`.
fn websocket_upstream(accept: String, hits: Arc<AtomicUsize>, captured: Captured) -> Router {
    Router::new().route(
        "/responses",
        axum::routing::get(move |headers: HeaderMap, upgrade: WebSocketUpgrade| {
            hits.fetch_add(1, Ordering::SeqCst);
            let ok = headers["authorization"].to_str().expect("ascii header")
                == format!("Bearer {accept}");
            captured
                .0
                .lock()
                .expect("lock captured requests")
                .push((headers, Bytes::new()));
            async move {
                if !ok {
                    return axum::http::StatusCode::UNAUTHORIZED.into_response();
                }
                upgrade
                    .max_message_size(usize::MAX)
                    .max_frame_size(usize::MAX)
                    .on_upgrade(|mut socket| async move {
                        while let Some(Ok(message)) = socket.recv().await {
                            if socket.send(message).await.is_err() {
                                break;
                            }
                        }
                    })
            }
        }),
    )
}

async fn connect_client(gateway: SocketAddr) -> Client {
    let mut request = format!("ws://{gateway}/codex/responses")
        .into_client_request()
        .expect("client request");
    let headers = request.headers_mut();
    headers.insert(
        "authorization",
        "Bearer placeholder".parse().expect("header"),
    );
    headers.insert("originator", "pi".parse().expect("header"));
    headers.insert(
        "openai-beta",
        "responses_websockets".parse().expect("header"),
    );
    headers.insert("session-id", "session-1".parse().expect("header"));
    headers.insert("x-unrelated", "dropped".parse().expect("header"));
    let config = WebSocketConfig::default()
        .max_message_size(None)
        .max_frame_size(None);
    let (client, _) = tokio_tungstenite::connect_async_with_config(request, Some(config), true)
        .await
        .expect("websocket through the gateway");
    client
}

async fn echo(client: &mut Client, text: String) -> String {
    client
        .send(Message::text(text))
        .await
        .expect("send to gateway");
    match client.next().await.expect("reply").expect("reply frame") {
        Message::Text(text) => text.to_string(),
        other => panic!("expected text, got {other:?}"),
    }
}

#[tokio::test]
async fn websocket_relays_messages_and_replaces_credentials() {
    let token = fake_jwt(far_future(), "acct-jwt");
    let captured = Captured::default();
    let upstream = serve(websocket_upstream(
        token.clone(),
        Arc::new(AtomicUsize::new(0)),
        captured.clone(),
    ))
    .await;
    let dir = tempfile::tempdir().expect("create tempdir");
    let auth_path = dir.path().join("auth.json");
    write_auth_file(&auth_path, &token);
    let gateway = start_gateway(
        &auth_path,
        "http://unused.invalid".into(),
        format!("http://{upstream}/responses"),
    )
    .await;

    let mut client = connect_client(gateway).await;
    assert_eq!(echo(&mut client, "hello".into()).await, "hello");
    // Above tungstenite's default 16 MiB frame cap: the gateway adds no limit of its own.
    let large = "x".repeat(17 * 1024 * 1024);
    assert_eq!(echo(&mut client, large.clone()).await.len(), large.len());
    client.close(None).await.expect("close");

    let requests = captured.0.lock().expect("lock captured requests");
    let headers = &requests[0].0;
    let header = |name: &str| headers[name].to_str().expect("ascii header").to_owned();
    assert_eq!(header("authorization"), format!("Bearer {token}"));
    assert_eq!(header("chatgpt-account-id"), "acct-file");
    assert_eq!(header("originator"), "pi");
    assert_eq!(header("openai-beta"), "responses_websockets");
    assert_eq!(header("session-id"), "session-1");
    assert!(!headers.contains_key("x-unrelated"));
}

#[tokio::test]
async fn websocket_handshake_401_recovers_and_reconnects_once() {
    let new_token = fake_jwt(far_future(), "acct-new");
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = serve(websocket_upstream(
        new_token.clone(),
        hits.clone(),
        Captured::default(),
    ))
    .await;
    let refreshes = Arc::new(AtomicUsize::new(0));
    let issuer = serve(refresh_issuer(
        refreshes.clone(),
        json!({"access_token": new_token, "refresh_token": "refresh-2"}),
    ))
    .await;
    let dir = tempfile::tempdir().expect("create tempdir");
    let auth_path = dir.path().join("auth.json");
    write_auth_file(&auth_path, &fake_jwt(far_future(), "acct-revoked"));
    let gateway = start_gateway(
        &auth_path,
        format!("http://{issuer}"),
        format!("http://{upstream}/responses"),
    )
    .await;

    let mut client = connect_client(gateway).await;
    assert_eq!(echo(&mut client, "hello".into()).await, "hello");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "original + one reconnect");
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}
