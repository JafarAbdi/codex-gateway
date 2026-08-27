# Provenance & acknowledgments

Nothing here is invented; every wire behavior is ported and cross-checked. When something
breaks, diff the referenced file at `main` against its pinned commit.

Thanks to: **[openai/codex]** (official Rust CLI — auth, refresh, request shape),
**[earendil-works/pi]** (independent cross-check; proof custom `originator` works),
**[boldsoftware/shelley]** (the downstream contract), **[exe.dev]** (the trust-boundary
architecture: credential injected at the edge, reachability as capability).

| Upstream | Pinned commit |
|---|---|
| openai/codex | `2c4a95736bea64256a50f7b8506bd33c181cc85a` |
| earendil-works/pi | `e86823096c5bad39e1ca282ec24bc5eb9bec745b` |
| boldsoftware/shelley | `4a930abee1d66c11c565decc51e32ddafd50f0ec` |

## Sources

| This code | Ported from |
|---|---|
| `CLIENT_ID`, issuer, `/oauth/token` | codex [manager.rs] + pi [openai-codex.ts] (identical) |
| Upstream URL `chatgpt.com/backend-api/codex/responses` | codex [model-provider-info][mpi] (`CHATGPT_CODEX_BASE_URL`); pi [providers][pi-prov] |
| JWT claim `https://api.openai.com/auth` → `chatgpt_account_id`; unverified base64url decode | codex [token_data.rs] |
| `originator: codex_gateway` | ours — codex sends `codex_cli_rs` ([default_client.rs]), pi sends `pi`; custom values accepted |
| Device flow: endpoints; `{issuer}/codex/device`; **403/404 = pending**; `interval` may be a numeric string; `usercode` alias; 404 on usercode = feature disabled; server-supplied PKCE verifier; `redirect_uri={issuer}/deviceauth/callback` | codex [device_code_auth.rs]; cross-checked in pi [openai-codex.ts] |
| Refresh: JSON body, optional response fields, overwrite only what returns | codex [manager.rs] (`request_chatgpt_token_refresh`, `persist_tokens`) |
| 5-min margin, single-lock refresh | codex [manager.rs]; pi [resolve.ts] (independently identical) |
| 15 s auth-call timeout | pi [resolve.ts] (`DEFAULT_OAUTH_REFRESH_TIMEOUT_MS = 15_000`) |
| Upstream 401 → reload auth file → one refresh → one replay | codex [manager.rs] (`Reload → RefreshToken` recovery steps) |
| Terminal: `refresh_token_expired\|reused\|invalidated`, 400+`invalid_grant`, any 401 | codex [manager.rs] (`classify_refresh_token_failure`) |
| `auth.json` shape, mode 0600 | codex [storage.rs]; atomic tmp+rename is ours (codex truncates in place) |
| Upstream header set | codex [bearer_auth_provider.rs]; pi [openai-codex-responses.ts] |
| `OpenAI-Beta: responses=experimental` on SSE | pi only (codex omits on HTTP) — drop first if the backend objects |
| `session-id`/`x-client-request-id` = `prompt_cache_key` | pi [openai-codex-responses.ts] |
| No `max_output_tokens`; always `store:false, stream:true` | codex [common.rs] (`ResponsesApiRequest` lacks the field); pi identical |
| Cookie jar + no client timeout | codex [responses-api-proxy][rap] (the 275-line official proxy this is modeled on) |
| zstd request body, level 3, `content-encoding: zstd` | codex [http-client/src/request.rs][hc-req] (`enable_request_compression` on by default for the ChatGPT backend); pi [openai-codex-responses.ts]. pi's plain-JSON fallback covers Node runtimes without zstd — moot in Rust, so none here |
| Shelley path `<gw>/openai/v1/responses`, `Bearer implicit` | shelley [modelsources.go], [models.go] |
| Shelley always sends `max_output_tokens:32768`; SSE requires `response.completed`; 429/5xx retried, other 4xx terminal → dead credential must be 401, never 502 | shelley [oai_responses.go] |
| Shelley 3-min **idle** stream timeout; `Shelley-*` headers | shelley [llmhttp.go] |

Architecture: [http-proxy-secrets], [integrations-llm] (their ChatGPT integration also
uses device-code login), [integrations-http-proxy].

**Deliberately not ported:** WebSocket, continuation caching (pi); keyring,
API-key exchange, `x-codex-*` turn headers, app-server (codex); provider/attachment
machinery (exe.dev).

[openai/codex]: https://github.com/openai/codex
[earendil-works/pi]: https://github.com/earendil-works/pi
[boldsoftware/shelley]: https://github.com/boldsoftware/shelley
[exe.dev]: https://exe.dev
[manager.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/login/src/auth/manager.rs
[device_code_auth.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/login/src/device_code_auth.rs
[storage.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/login/src/auth/storage.rs
[token_data.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/login/src/token_data.rs
[default_client.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/login/src/auth/default_client.rs
[bearer_auth_provider.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/model-provider/src/bearer_auth_provider.rs
[mpi]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/model-provider-info/src/lib.rs
[common.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/codex-api/src/common.rs
[rap]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/responses-api-proxy/src/lib.rs
[hc-req]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/http-client/src/request.rs
[openai-codex.ts]: https://github.com/earendil-works/pi/blob/e86823096c5bad39e1ca282ec24bc5eb9bec745b/packages/ai/src/auth/oauth/openai-codex.ts
[resolve.ts]: https://github.com/earendil-works/pi/blob/e86823096c5bad39e1ca282ec24bc5eb9bec745b/packages/ai/src/auth/resolve.ts
[openai-codex-responses.ts]: https://github.com/earendil-works/pi/blob/e86823096c5bad39e1ca282ec24bc5eb9bec745b/packages/ai/src/api/openai-codex-responses.ts
[pi-prov]: https://github.com/earendil-works/pi/blob/e86823096c5bad39e1ca282ec24bc5eb9bec745b/packages/ai/src/providers/openai-codex.ts
[modelsources.go]: https://github.com/boldsoftware/shelley/blob/4a930abee1d66c11c565decc51e32ddafd50f0ec/modelsources/modelsources.go
[models.go]: https://github.com/boldsoftware/shelley/blob/4a930abee1d66c11c565decc51e32ddafd50f0ec/models/models.go
[oai_responses.go]: https://github.com/boldsoftware/shelley/blob/4a930abee1d66c11c565decc51e32ddafd50f0ec/llm/oai/oai_responses.go
[llmhttp.go]: https://github.com/boldsoftware/shelley/blob/4a930abee1d66c11c565decc51e32ddafd50f0ec/llm/llmhttp/llmhttp.go
[http-proxy-secrets]: https://blog.exe.dev/http-proxy-secrets
[integrations-llm]: https://exe.dev/docs/integrations-llm
[integrations-http-proxy]: https://exe.dev/docs/integrations-http-proxy
