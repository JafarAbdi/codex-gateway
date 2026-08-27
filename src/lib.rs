//! Many Shelley instances, one ChatGPT Codex login: adapt `POST /openai/v1/responses`
//! minimally, inject the shared credential, stream SSE back; everything else 404.
//! All wire behavior is ported — see PROVENANCE.md before changing constants.

pub mod auth;
pub mod proxy;

/// Codex CLI's OAuth client id (pi uses it too).
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const ISSUER: &str = "https://auth.openai.com";
pub const UPSTREAM_URL: &str = "https://chatgpt.com/backend-api/codex/responses";
/// Custom values are accepted (pi ships `pi`); fall back to `codex_cli_rs` if rejected.
pub const ORIGINATOR: &str = "codex_gateway";

pub fn user_agent() -> String {
    format!(
        "codex-gateway/{} ({} {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}
