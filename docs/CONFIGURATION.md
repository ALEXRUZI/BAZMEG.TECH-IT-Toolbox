# Environment configuration

These are the application variables read by [the backend](../backend/src/server.mjs), [Vite](../frontend/vite.config.ts), and [the Pages Function](../frontend/functions/api/[[path]].ts). Test-runner variables such as `CI` are not deployment settings.

| Component / variable | Required and actual default | Purpose and security significance | Configure in | Browser exposure |
| --- | --- | --- | --- | --- |
| Backend `PORT` | Optional; unset/empty → `3001` | Listening port, converted with `Number`; bind address remains `127.0.0.1`. Supply a valid port. | Launching process environment | Not injected |
| Backend `BACKEND_SECRET` | Required for protected API access; no default | Exact shared credential compared to `X-Toolbox-Backend-Secret`. Missing/empty configuration makes protected routes return 401, not a startup failure. | Launching process environment / operator secret storage | **Never** |
| Backend `TRUST_TOOLBOX_PROXY_HEADERS` | Optional; disabled unless exactly `true` | Enables validated `X-Toolbox-Client-IP`, then Fastify `request.ip` fallback. Default identity is socket peer. Enable only with verified, controlled ingress; Fastify has broad `trustProxy: true`. | Launching process environment | Not injected |
| Vite development `BACKEND_ORIGIN` | Optional; unset/empty → `http://127.0.0.1:3001` | Upstream HTTP(S) origin, without credentials/path/query/fragment. HTTP only for loopback IP literals; other hosts require verified HTTPS. No production fallback. | Frontend shell environment or ignored `frontend/.env.local` | Not injected; browser uses relative `/api` |
| Vite development `BACKEND_SECRET` | Required for API proxy access; no default | Matching backend credential injected server-side. Missing/whitespace-only → 503. Invalid header value fails configuration. | Frontend shell environment or ignored `frontend/.env.local` | **Never; do not use `VITE_*`** |
| Vite development `ALLOW_LAN_API_PROXY` | Optional; unset/empty → disabled; nonempty value must be `true` or `false` | `true` authorizes non-loopback clients to use the development proxy's credential. `dev:lan` alone does not enable it. | Frontend shell environment or ignored `frontend/.env.local` | Not injected |
| Pages `BACKEND_ORIGIN` | Required; no default | Absolute HTTP(S) URL without credentials. Prefer an HTTPS origin only; incoming path/query replace configured path/query and fragment is discarded. Pages still accepts HTTP: transport safety is an operator obligation. | Server-side Pages environment binding, separately for each applicable deployment environment | Not injected |
| Pages `BACKEND_SECRET` | Required; no default | Matching backend credential; empty/whitespace-only, surrounding whitespace, controls, or invalid HTTP header values fail closed with 503. | Server-side Pages binding / platform secret configuration, separately for each applicable environment | **Never** |

## Loading and safe handling

- [Local setup](../README.md#local-development) uses shell environment variables on Windows and Linux. Vite loads local environment files; existing shell values take precedence. Restart after configuration changes.
- [Backend example](../backend/.env.example) is a reference, not an automatically loaded file: `npm start` is `node src/server.mjs`, without an env-file loader. Use shell variables or the deployment's process manager. Backend secret changes require restarting the process.
- [Frontend example](../frontend/.env.example) configures **development Vite**, not production Pages. Cloudflare does not automatically supply these bindings. The operator must configure them without committing credentials.
- Use a strong unique production secret outside the repository; keep development/preview/production credentials separate. Ensure both sides match exactly. Never put secrets in URLs, client assets, logs, issue reports, or `VITE_*` variables.
- `.env`/`.env.*` (except examples), private-key formats, logs, and local infrastructure notes are ignored by [`.gitignore`](../.gitignore). Ignore rules are not secret storage or a substitute for reviewing staged content.
- Static preview has no API proxy. E2E explicitly disables development API proxying. Neither needs production bindings.

See [Pages trust details](../frontend/functions/README.md), [API errors](API.md), and [production configuration checks](OPERATIONS.md). Deployment-specific values must be supplied by the operator.
