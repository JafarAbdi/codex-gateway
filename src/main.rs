//! Thin CLI over the library: `codex-gateway login` and `codex-gateway serve`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use codex_gateway::{ISSUER, UPSTREAM_URL, auth, proxy};

#[derive(Parser)]
#[command(
    name = "codex-gateway",
    version,
    about = "Shared ChatGPT Codex OAuth gateway for Shelley"
)]
struct Cli {
    /// Credential file (codex-compatible auth.json subset) [default: ~/.codex-gateway/auth.json].
    #[arg(long, global = true, env = "CODEX_GATEWAY_AUTH")]
    auth_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in to ChatGPT with the device-code flow and save credentials.
    Login,
    /// Serve the gateway.
    Serve {
        /// Address to listen on. The gateway has no caller auth — bind loopback or a
        /// private (e.g. tailscale) address only.
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
    },
    /// Probe a running gateway's /healthz; exits non-zero when unreachable.
    Check {
        /// Address the gateway listens on.
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
    },
}

/// Lazy so a HOME-less environment works when --auth-file/CODEX_GATEWAY_AUTH is given.
fn default_auth_file() -> Result<PathBuf> {
    let home = std::env::home_dir()
        .context("cannot determine home directory; pass --auth-file or set CODEX_GATEWAY_AUTH")?;
    Ok(home.join(".codex-gateway/auth.json"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Login => {
            let auth_file = cli.auth_file.map_or_else(default_auth_file, Ok)?;
            auth::login(&auth_file, ISSUER).await
        }
        Command::Check { listen } => {
            let response = reqwest::get(format!("http://{listen}/healthz")).await?;
            let status = response.status();
            println!("{status} {}", response.text().await.unwrap_or_default());
            anyhow::ensure!(status.is_success(), "health check failed");
            Ok(())
        }
        Command::Serve { listen } => {
            let auth_file = cli.auth_file.map_or_else(default_auth_file, Ok)?;
            let auth = auth::Auth::load(auth_file, ISSUER.to_owned())?;
            let gateway = proxy::Gateway {
                auth: Arc::new(auth),
                http: proxy::client().context("building upstream HTTP client")?,
                upstream_url: UPSTREAM_URL.to_owned(),
            };
            let listener = tokio::net::TcpListener::bind(listen).await?;
            // As container PID 1 the default SIGTERM action is ignored; exit explicitly
            // (stateless proxy — nothing worth draining).
            tokio::spawn(async {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("install SIGTERM handler");
                term.recv().await;
                tracing::info!("SIGTERM received; exiting");
                std::process::exit(0);
            });
            tracing::info!(%listen, upstream = UPSTREAM_URL, "codex-gateway serving");
            axum::serve(listener, proxy::router(gateway)).await?;
            Ok(())
        }
    }
}
