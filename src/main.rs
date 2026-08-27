//! Thin CLI over the library: `codex-gateway login | serve | check`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use codex_gateway::{ISSUER, UPSTREAM_URL, auth, proxy};

const USAGE: &str = "\
Shared ChatGPT Codex OAuth gateway for Shelley

Usage: codex-gateway [--auth-file PATH] <COMMAND> [--listen ADDR]

Commands:
  login   Log in to ChatGPT with the device-code flow and save credentials
  serve   Serve the gateway. No caller auth: bind only loopback or a private
          (e.g. tailscale) address [--listen default: 127.0.0.1:8787]
  check   Probe a running gateway's /healthz; exits non-zero when unreachable
          [--listen default: 127.0.0.1:8787]

Options:
  --auth-file PATH  Credential file (codex-compatible auth.json subset)
                    [env: CODEX_GATEWAY_AUTH] [default: ~/.codex-gateway/auth.json]
  --listen ADDR     Address to serve on / probe (serve and check only)
  -h, --help        Print help
  -V, --version     Print version
";

enum Command {
    Login,
    Serve,
    Check,
}

struct Cli {
    auth_file: Option<PathBuf>,
    command: Command,
    listen: SocketAddr,
}

fn parse_args() -> Result<Cli> {
    let mut auth_file = std::env::var_os("CODEX_GATEWAY_AUTH").map(PathBuf::from);
    let mut command = None;
    let mut listen = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("codex-gateway {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--auth-file" => {
                auth_file = Some(args.next().context("--auth-file needs a value")?.into());
            }
            "--listen" => {
                let value = args.next().context("--listen needs a value")?;
                listen = Some(value.parse().context("--listen: invalid address")?);
            }
            "login" if command.is_none() => command = Some(Command::Login),
            "serve" if command.is_none() => command = Some(Command::Serve),
            "check" if command.is_none() => command = Some(Command::Check),
            other => bail!("unexpected argument {other:?}\n\n{USAGE}"),
        }
    }
    let Some(command) = command else {
        bail!("missing command\n\n{USAGE}");
    };
    if listen.is_some() && matches!(command, Command::Login) {
        bail!("--listen does not apply to login\n\n{USAGE}");
    }
    let listen = listen.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8787)));
    Ok(Cli {
        auth_file,
        command,
        listen,
    })
}

/// TCP_NODELAY on every accepted connection: Nagle would batch small SSE frames.
struct NoDelay(tokio::net::TcpListener);

impl axum::serve::Listener for NoDelay {
    type Io = tokio::net::TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok((stream, addr)) => {
                    let _ = stream.set_nodelay(true);
                    return (stream, addr);
                }
                Err(err) => eprintln!("accept failed: {err}"),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

/// Lazy so a HOME-less environment works when --auth-file/CODEX_GATEWAY_AUTH is given.
fn default_auth_file() -> Result<PathBuf> {
    let home = std::env::home_dir()
        .context("cannot determine home directory; pass --auth-file or set CODEX_GATEWAY_AUTH")?;
    Ok(home.join(".codex-gateway/auth.json"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = parse_args()?;
    match cli.command {
        Command::Login => {
            let auth_file = cli.auth_file.map_or_else(default_auth_file, Ok)?;
            auth::login(&auth_file, ISSUER).await
        }
        Command::Check => {
            let response = reqwest::get(format!("http://{}/healthz", cli.listen)).await?;
            let status = response.status();
            println!("{status} {}", response.text().await.unwrap_or_default());
            anyhow::ensure!(status.is_success(), "health check failed");
            Ok(())
        }
        Command::Serve => {
            let auth_file = cli.auth_file.map_or_else(default_auth_file, Ok)?;
            let auth = auth::Auth::load(auth_file, ISSUER.to_owned())?;
            let gateway = proxy::Gateway {
                auth: Arc::new(auth),
                http: proxy::client().context("building upstream HTTP client")?,
                upstream_url: UPSTREAM_URL.to_owned(),
            };
            let listener = NoDelay(tokio::net::TcpListener::bind(cli.listen).await?);
            // As container PID 1 the default SIGTERM action is ignored; exit explicitly
            // (stateless proxy — nothing worth draining).
            tokio::spawn(async {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("install SIGTERM handler");
                term.recv().await;
                eprintln!("SIGTERM received; exiting");
                std::process::exit(0);
            });
            eprintln!("codex-gateway serving on {} -> {UPSTREAM_URL}", cli.listen);
            axum::serve(listener, proxy::router(gateway)).await?;
            Ok(())
        }
    }
}
