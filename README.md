# codex-gateway

Share one ChatGPT Plus/Pro Codex subscription across many [pi] instances.

The gateway owns the OAuth credential and forwards pi's own Codex requests to
`https://chatgpt.com/backend-api/codex/responses` untouched, replacing only the caller's
credentials with the shared bearer token and account-id headers:

- `POST /codex/responses` forwards the (zstd) body byte for byte and streams SSE back.
- `GET /codex/responses` upgrades to a WebSocket and relays messages both ways, so pi sends
  only each turn's new input. pi falls back to SSE when a WebSocket fails, so both stay.

Every other path is 404.

[pi]: https://github.com/earendil-works/pi

Run it on a private network (tailscale). Whoever can reach it can spend the
subscription; nobody can read the credential.

## Use

    cargo build --release
    ./target/release/codex-gateway login
    ./target/release/codex-gateway serve --listen <tailscale-ip>:8787

`login` is the device-code flow — enable "device code authorization" in your ChatGPT
security settings first. Credentials land in `~/.codex-gateway/auth.json` (0600;
override with `--auth-file` or `CODEX_GATEWAY_AUTH`). `serve` defaults to
`127.0.0.1:8787`; there is no caller auth, so bind only loopback or a private address.

Point pi's `openai-codex` provider at it in `~/.pi/agent/models.json`. pi reads the
account id out of its token before sending, so `apiKey` is a placeholder JWT whose
payload is `{"https://api.openai.com/auth": {"chatgpt_account_id": "gateway"}}`; the
gateway replaces it:

    { "providers": { "openai-codex": {
        "baseUrl": "http://<tailnet-host>:8787",
        "apiKey": "e30.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiZ2F0ZXdheSJ9fQ.gateway"
    } } }

## Credentials

- Refresh is automatic, 5 minutes before the access token expires.
- An upstream 401 triggers one reload → refresh → replay; a second 401 passes through.
- A dead refresh token means 401 "login required" until you run `login` again. No
  restart needed — the running gateway picks up the new file.
- A `CODEX_HOME=… codex login` file works via `--auth-file`. Never share a live file
  with a running codex CLI: token rotation breaks the other side.

## Operating

- The gateway never retries or masks upstream errors; pi retries 429/5xx itself. A
  refused WebSocket handshake is relayed with the backend's status and body.
- `GET /healthz` reports `{"auth":"ok"}` or `{"auth":"login required"}`.
- `codex-gateway check` probes /healthz and exits non-zero when unreachable — a
  container health check with no shell or curl. rustls bundles its CA roots and a musl
  build is fully static, so `scratch` images work.
- No body or message size caps of its own; the backend enforces its limits.
- Colored stderr logs include status, session id, body size, latency and WebSocket
  lifetimes; never bodies, messages or credentials. `NO_COLOR=1` disables color.

Every wire detail is ported from openai/codex or earendil-works/pi;
[PROVENANCE.md](PROVENANCE.md) maps each to its source at a pinned commit.

## License

MIT or Apache-2.0, at your option.
