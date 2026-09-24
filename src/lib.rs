//! Many pi instances, one ChatGPT Codex login: forward pi's own `/codex/responses`
//! requests (SSE and WebSocket) with the shared credential; everything else 404.
//! All wire behavior is ported — see PROVENANCE.md before changing constants.

pub mod auth;
mod logging;
pub mod proxy;

/// Codex CLI's OAuth client id (pi uses it too).
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const ISSUER: &str = "https://auth.openai.com";
pub const UPSTREAM_URL: &str = "https://chatgpt.com/backend-api/codex/responses";
