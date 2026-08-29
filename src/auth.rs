//! auth.json persistence, token refresh, device-code login.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{CLIENT_ID, logging};

/// JWT claim object holding the ChatGPT account id.
const AUTH_CLAIM: &str = "https://api.openai.com/auth";
/// Refresh this long before `exp` (codex and pi both use 5 min).
const REFRESH_MARGIN: Duration = Duration::from_secs(300);
const DEVICE_LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Credential revoked/expired beyond refresh; serve 401 until a human re-logs-in.
    #[error("login required ({0}); run `codex-gateway login` on the gateway host")]
    LoginRequired(String),
    /// May pass on its own (network, 5xx).
    #[error("token refresh failed: {0}")]
    Transient(String),
}

#[derive(Clone)]
pub struct AccessToken(String);

impl AccessToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone)]
pub struct AccountId(String);

impl AccountId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Subset of codex CLI's `auth.json`, so a `codex login` file can be dropped in.
#[derive(Serialize, Deserialize)]
struct AuthFile {
    tokens: Tokens,
}

#[derive(Serialize, Deserialize)]
struct Tokens {
    access_token: String,
    refresh_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
}

pub struct Auth {
    path: PathBuf,
    issuer: String,
    http: reqwest::Client,
    state: tokio::sync::Mutex<State>,
}

struct State {
    file: AuthFile,
    /// Terminal refresh failure; stops us hammering the auth server.
    login_required: Option<String>,
}

impl Auth {
    pub fn load(path: PathBuf, issuer: String) -> anyhow::Result<Self> {
        let raw = std::fs::read(&path).with_context(|| {
            format!(
                "cannot read credentials at {}; run `codex-gateway login`",
                path.display()
            )
        })?;
        let file: AuthFile = serde_json::from_slice(&raw)
            .with_context(|| format!("malformed credential file {}", path.display()))?;
        Ok(Self {
            path,
            issuer,
            http: auth_http()?,
            state: tokio::sync::Mutex::new(State {
                file,
                login_required: None,
            }),
        })
    }

    /// Bearer token + account id, refreshing first if `exp` is within [`REFRESH_MARGIN`].
    pub async fn credentials(&self) -> Result<(AccessToken, AccountId), AuthError> {
        let mut state = self.state.lock().await;
        // A re-login rewrites the file; adopting it here means no serve restart.
        if state.login_required.is_some() && !self.reload_if_changed(&mut state) {
            let reason = state.login_required.clone().expect("checked above");
            return Err(AuthError::LoginRequired(reason));
        }
        let expires_soon = jwt_exp(&state.file.tokens.access_token)
            .is_none_or(|exp| exp <= now_unix() + REFRESH_MARGIN.as_secs() as i64);
        if expires_soon && let Err(err) = self.refresh(&mut state).await {
            if let AuthError::LoginRequired(reason) = &err {
                state.login_required = Some(reason.clone());
            }
            return Err(err);
        }
        current(&state)
    }

    /// After an upstream 401: adopt a peer's newer credential (memory, then disk), else
    /// force one refresh — codex's Reload → RefreshToken recovery. The caller replays once.
    pub async fn recover(
        &self,
        stale: &AccessToken,
    ) -> Result<(AccessToken, AccountId), AuthError> {
        let mut state = self.state.lock().await;
        let already_rotated =
            state.file.tokens.access_token != stale.0 || self.reload_if_changed(&mut state);
        if !already_rotated && let Err(err) = self.refresh(&mut state).await {
            if let AuthError::LoginRequired(reason) = &err {
                state.login_required = Some(reason.clone());
            }
            return Err(err);
        }
        current(&state)
    }

    /// Why serving is blocked, if it is; for /healthz.
    pub async fn login_required(&self) -> Option<String> {
        self.state.lock().await.login_required.clone()
    }

    /// Adopt the credential file if another process rewrote it; true when adopted.
    fn reload_if_changed(&self, state: &mut State) -> bool {
        let Ok(raw) = std::fs::read(&self.path) else {
            return false;
        };
        let Ok(file) = serde_json::from_slice::<AuthFile>(&raw) else {
            return false;
        };
        if file.tokens.access_token == state.file.tokens.access_token
            && file.tokens.refresh_token == state.file.tokens.refresh_token
        {
            return false;
        }
        state.file = file;
        state.login_required = None;
        true
    }

    async fn refresh(&self, state: &mut State) -> Result<(), AuthError> {
        let resp = self
            .http
            .post(format!("{}/oauth/token", self.issuer))
            .json(&json!({
                "client_id": CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": state.file.tokens.refresh_token,
            }))
            .send()
            .await
            .map_err(|err| AuthError::Transient(err.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            let code = error_code(&body).unwrap_or("unknown error");
            let terminal = status == reqwest::StatusCode::UNAUTHORIZED
                || (status == reqwest::StatusCode::BAD_REQUEST && code == "invalid_grant")
                || matches!(
                    code,
                    "refresh_token_expired" | "refresh_token_reused" | "refresh_token_invalidated"
                );
            let message = format!("refresh rejected with {status}: {code}");
            return Err(if terminal {
                AuthError::LoginRequired(message)
            } else {
                AuthError::Transient(message)
            });
        }
        // All fields optional; overwrite only what came back (rotation-safe).
        #[derive(Deserialize)]
        struct Refreshed {
            access_token: Option<String>,
            refresh_token: Option<String>,
        }
        let refreshed: Refreshed = resp
            .json()
            .await
            .map_err(|err| AuthError::Transient(err.to_string()))?;
        if let Some(access) = refreshed.access_token {
            state.file.tokens.access_token = access;
        }
        if let Some(refresh) = refreshed.refresh_token {
            state.file.tokens.refresh_token = refresh;
        }
        if let Some(id) = jwt_account_id(&state.file.tokens.access_token) {
            state.file.tokens.account_id = Some(id);
        }
        save(&self.path, &state.file)
            .map_err(|err| AuthError::Transient(format!("persisting credentials: {err}")))?;
        logging::success(format_args!("refreshed ChatGPT access token"));
        Ok(())
    }
}

fn current(state: &State) -> Result<(AccessToken, AccountId), AuthError> {
    let account = state
        .file
        .tokens
        .account_id
        .clone()
        .or_else(|| jwt_account_id(&state.file.tokens.access_token))
        .ok_or_else(|| AuthError::LoginRequired("token carries no ChatGPT account id".into()))?;
    Ok((
        AccessToken(state.file.tokens.access_token.clone()),
        AccountId(account),
    ))
}

/// A hung auth call must never hold the credential mutex open-ended (pi caps at 15 s).
fn auth_http() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .build()
}

fn print_plan(access_token: &str) {
    if let Some(plan) = jwt_payload(access_token).and_then(|claims| {
        claims[AUTH_CLAIM]["chatgpt_plan_type"]
            .as_str()
            .map(str::to_owned)
    }) {
        println!("Logged in to a ChatGPT {plan} account.");
    }
}

fn device_poll_interval(value: Option<&Value>) -> Duration {
    let seconds = value
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
        .unwrap_or(5)
        .max(1);
    Duration::from_secs(seconds)
}

/// Device-code login; polling is the protocol (server-paced interval).
pub async fn login(path: &Path, issuer: &str) -> anyhow::Result<()> {
    let http = auth_http()?;
    let resp = http
        .post(format!("{issuer}/api/accounts/deviceauth/usercode"))
        .json(&json!({ "client_id": CLIENT_ID }))
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        bail!(
            "device-code login is not enabled for this ChatGPT account; \
             enable it under ChatGPT security settings (or workspace permissions), then retry"
        );
    }
    #[derive(Deserialize)]
    struct UserCode {
        device_auth_id: String,
        #[serde(alias = "usercode")]
        user_code: String,
        interval: Option<Value>,
    }
    let user_code: UserCode = resp.error_for_status()?.json().await?;
    // Arrives as a number or a numeric string.
    let mut interval = device_poll_interval(user_code.interval.as_ref());

    println!(
        "Visit {issuer}/codex/device and enter code: {}",
        user_code.user_code
    );
    let deadline = tokio::time::Instant::now() + DEVICE_LOGIN_TIMEOUT;
    loop {
        tokio::time::sleep(interval).await;
        if tokio::time::Instant::now() >= deadline {
            bail!("device login not approved within 15 minutes");
        }
        let resp = http
            .post(format!("{issuer}/api/accounts/deviceauth/token"))
            .json(&json!({
                "device_auth_id": user_code.device_auth_id,
                "user_code": user_code.user_code,
            }))
            .send()
            .await?;
        let status = resp.status();
        // On this endpoint 403/404 mean "not approved yet".
        if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::NOT_FOUND {
            continue;
        }
        let body: Value = resp.json().await?;
        if !status.is_success() {
            match error_code(&body) {
                Some("deviceauth_authorization_pending") => continue,
                Some("slow_down") => {
                    interval += Duration::from_secs(5);
                    continue;
                }
                code => bail!(
                    "device authorization failed with {status}: {}",
                    code.unwrap_or("unknown error")
                ),
            }
        }
        // Approved; the server supplies the PKCE verifier.
        let code = body["authorization_code"]
            .as_str()
            .context("device approval response lacks authorization_code")?;
        let verifier = body["code_verifier"]
            .as_str()
            .context("device approval response lacks code_verifier")?;
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: String,
        }
        let tokens: TokenResponse = http
            .post(format!("{issuer}/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", CLIENT_ID),
                ("code_verifier", verifier),
                ("redirect_uri", &format!("{issuer}/deviceauth/callback")),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let account_id = jwt_account_id(&tokens.access_token);
        print_plan(&tokens.access_token);
        let file = AuthFile {
            tokens: Tokens {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                account_id,
            },
        };
        if let Some(dir) = path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        save(path, &file)?;
        println!("Credentials saved to {}", path.display());
        return Ok(());
    }
}

/// Atomic 0600 write: tmp in the same dir, rename over.
fn save(path: &Path, file: &AuthFile) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("json.tmp");
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    out.write_all(&serde_json::to_vec_pretty(file).expect("auth file serializes"))?;
    out.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64
}

fn jwt_payload(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

fn jwt_exp(token: &str) -> Option<i64> {
    jwt_payload(token)?.get("exp")?.as_i64()
}

fn jwt_account_id(token: &str) -> Option<String> {
    jwt_payload(token)?[AUTH_CLAIM]["chatgpt_account_id"]
        .as_str()
        .map(str::to_owned)
}

/// Error code from `{"error":"code"}` or `{"error":{"code":"code"}}`.
fn error_code(body: &Value) -> Option<&str> {
    match body.get("error")? {
        Value::String(code) => Some(code),
        Value::Object(err) => err.get("code")?.as_str(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn fake_jwt(claims: &Value) -> String {
        let encode =
            |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).expect("serialize claims"));
        format!("{}.{}.sig", encode(&json!({"alg": "none"})), encode(claims))
    }

    #[test]
    fn extracts_exp_and_account_id() {
        let token = fake_jwt(&json!({
            "exp": 1234,
            AUTH_CLAIM: { "chatgpt_account_id": "acct-1" },
        }));
        assert_eq!(jwt_exp(&token), Some(1234));
        assert_eq!(jwt_account_id(&token), Some("acct-1".to_owned()));
        assert_eq!(jwt_exp("not-a-jwt"), None);
    }

    #[test]
    fn error_code_handles_both_shapes() {
        assert_eq!(
            error_code(&json!({"error": "slow_down"})),
            Some("slow_down")
        );
        assert_eq!(
            error_code(&json!({"error": {"code": "invalid_grant"}})),
            Some("invalid_grant")
        );
        assert_eq!(error_code(&json!({"message": "nope"})), None);
    }

    #[test]
    fn save_is_0600_and_round_trips() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("auth.json");
        let file = AuthFile {
            tokens: Tokens {
                access_token: "a".into(),
                refresh_token: "r".into(),
                account_id: Some("acct".into()),
            },
        };
        save(&path, &file).expect("save auth file");
        let mode = std::fs::metadata(&path)
            .expect("stat auth file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let loaded: AuthFile =
            serde_json::from_slice(&std::fs::read(&path).expect("read auth file"))
                .expect("parse auth file");
        assert_eq!(loaded.tokens.access_token, "a");
        assert_eq!(loaded.tokens.account_id.as_deref(), Some("acct"));
    }
}
