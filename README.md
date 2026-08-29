# codex-gateway

Share one ChatGPT Plus/Pro Codex subscription across many Shelley instances.

The gateway owns the OAuth credential and forwards `POST /openai/v1/responses` to
`https://chatgpt.com/backend-api/codex/responses`, streaming the SSE response back
untouched. Every other path is 404. On the way through it strips `max_output_tokens`,
forces `store:false`/`stream:true`, zstd-compresses the body, and replaces caller auth
with the shared bearer token and account-id headers.

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

Point each Shelley at it:

    { "llm_gateway": "http://<tailnet-host>:8787" }

## Credentials

- Refresh is automatic, 5 minutes before the access token expires.
- An upstream 401 triggers one reload → refresh → replay; a second 401 passes through.
- A dead refresh token means 401 "login required" until you run `login` again. No
  restart needed — the running gateway picks up the new file.
- A `CODEX_HOME=… codex login` file works via `--auth-file`. Never share a live file
  with a running codex CLI: token rotation breaks the other side.

## Operating

- Only OpenAI models work; Shelley's Anthropic/xAI/Fireworks entries get a clean 404.
- The gateway never retries or masks upstream errors; Shelley retries 429/5xx itself.
- `GET /healthz` reports `{"auth":"ok"}` or `{"auth":"login required"}`.
- `codex-gateway check` probes /healthz and exits non-zero when unreachable — a
  container health check with no shell or curl. rustls bundles its CA roots and a musl
  build is fully static, so `scratch` images work.
- Request bodies are capped at 64 MiB and zstd-compressed upstream.
- Colored stderr logs include status, model, request ID, body sizes, and latency;
  never bodies or credentials. `NO_COLOR=1` disables color.
- Don't export `OPENAI_API_KEY` in Shelley's env; it relabels the UI model source.

Every wire detail is ported from openai/codex, earendil-works/pi, or
boldsoftware/shelley; [PROVENANCE.md](PROVENANCE.md) maps each to its source at a
pinned commit.

## License

MIT or Apache-2.0, at your option.
