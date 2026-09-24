# Provenance & acknowledgments

Nothing here is invented; every wire behavior is ported and cross-checked. When something
breaks, diff the referenced file at `main` against its pinned commit.

Thanks to: **[openai/codex]** (official Rust CLI — login, refresh, upstream headers) and
**[earendil-works/pi]** (the caller: its Codex requests, SSE and WebSocket, pass through
untouched).

| Upstream | Pinned commit |
|---|---|
| openai/codex | `2c4a95736bea64256a50f7b8506bd33c181cc85a` |
| earendil-works/pi | `13cbf77df2396303013a41646bcfa77b4271ae56` (v0.86.1) |

## Sources

| This code | Ported from |
|---|---|
| `CLIENT_ID`, issuer, `/oauth/token` | codex [manager.rs] + pi [openai-codex.ts] (identical) |
| Upstream URL `chatgpt.com/backend-api/codex/responses` | codex [model-provider-info][mpi] (`CHATGPT_CODEX_BASE_URL`); pi [providers][pi-prov] |
| JWT claim `https://api.openai.com/auth` → `chatgpt_account_id`; unverified base64url decode | codex [token_data.rs] |
| Device flow: endpoints; `{issuer}/codex/device`; **403/404 = pending**; `interval` may be a numeric string; `usercode` alias; 404 on usercode = feature disabled; server-supplied PKCE verifier; `redirect_uri={issuer}/deviceauth/callback` | codex [device_code_auth.rs]; cross-checked in pi [openai-codex.ts] |
| Refresh: JSON body, optional response fields, overwrite only what returns | codex [manager.rs] (`request_chatgpt_token_refresh`, `persist_tokens`) |
| 5-min margin, single-lock refresh | codex [manager.rs]; pi [resolve.ts] (independently identical) |
| 15 s auth-call timeout | pi [resolve.ts] (`DEFAULT_OAUTH_REFRESH_TIMEOUT_MS = 15_000`) |
| Upstream 401 (response or WebSocket handshake) → reload auth file → one refresh → one replay | codex [manager.rs] (`Reload → RefreshToken` recovery steps) |
| Terminal: `refresh_token_expired\|reused\|invalidated`, 400+`invalid_grant`, any 401 | codex [manager.rs] (`classify_refresh_token_failure`) |
| `auth.json` shape, mode 0600 | codex [storage.rs]; atomic tmp+rename is ours (codex truncates in place) |
| Credential headers the gateway sets: `Authorization`, `chatgpt-account-id` | codex [bearer_auth_provider.rs]; pi [openai-codex-responses.ts] (`buildBaseCodexHeaders`) |
| Caller headers passed through: `accept`, `content-type`, `content-encoding`, `User-Agent`, `originator` (`pi`), `OpenAI-Beta`, `session-id`, `x-client-request-id` | pi [openai-codex-responses.ts] (`buildSSEHeaders`, `buildWebSocketHeaders`) |
| pi path `<baseUrl>/codex/responses`; WebSocket at the same path over `wss` | pi [openai-codex-responses.ts] (`resolveCodexUrl`, `resolveCodexWebSocketUrl`) |
| Body untouched: pi already sends `store:false`, `stream:true`, no `max_output_tokens`, zstd | pi [openai-codex-responses.ts] (`compressRequestBodyZstd`) |
| Both transports: a WebSocket failure before the reply falls back to SSE for the session | pi [openai-codex-responses.ts] (`recordWebSocketSseFallback`) |
| Cookie jar + no client timeout | codex [responses-api-proxy][rap] (the 275-line official proxy this is modeled on) |

**Deliberately not ported:** keyring, API-key exchange, `x-codex-*` turn headers,
app-server (codex).

[openai/codex]: https://github.com/openai/codex
[earendil-works/pi]: https://github.com/earendil-works/pi
[manager.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/login/src/auth/manager.rs
[device_code_auth.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/login/src/device_code_auth.rs
[storage.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/login/src/auth/storage.rs
[token_data.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/login/src/token_data.rs
[bearer_auth_provider.rs]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/model-provider/src/bearer_auth_provider.rs
[mpi]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/model-provider-info/src/lib.rs
[rap]: https://github.com/openai/codex/blob/2c4a95736bea64256a50f7b8506bd33c181cc85a/codex-rs/responses-api-proxy/src/lib.rs
[openai-codex.ts]: https://github.com/earendil-works/pi/blob/13cbf77df2396303013a41646bcfa77b4271ae56/packages/ai/src/auth/oauth/openai-codex.ts
[resolve.ts]: https://github.com/earendil-works/pi/blob/13cbf77df2396303013a41646bcfa77b4271ae56/packages/ai/src/auth/resolve.ts
[openai-codex-responses.ts]: https://github.com/earendil-works/pi/blob/13cbf77df2396303013a41646bcfa77b4271ae56/packages/ai/src/api/openai-codex-responses.ts
[pi-prov]: https://github.com/earendil-works/pi/blob/13cbf77df2396303013a41646bcfa77b4271ae56/packages/ai/src/providers/openai-codex.ts
