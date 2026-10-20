# Pages proxy validation and trust boundary

Run from `frontend/` on Node 22:

```sh
npm run typecheck:pages
npm run test:pages
```

CI runs both explicitly on `dev`/`main` pushes and pull requests. The dedicated
strict, no-emit `functions/tsconfig.json` checks the actual handler against pinned
`@cloudflare/workers-types` 5.20261010.1, using only ES2022 plus Workers globals
(not DOM or Node globals). This type-only dependency avoids adding Wrangler or
requiring Cloudflare credentials/configuration generation. Application typechecks
are unchanged and are not a substitute for this check.

## Configuration and authentication

`BACKEND_ORIGIN` and `BACKEND_SECRET` are server-side bindings, never `VITE_*`
variables. A missing/empty/whitespace-only secret, surrounding whitespace,
control characters or a value rejected by HTTP Headers fails closed with a
non-sensitive 503 `PAGES_PROXY_CONFIGURATION` response before fetching. The
secret is not trimmed into a different credential. Backend 401s remain 401s.

The destination must be a configured absolute HTTP(S) URL without credentials.
As before, the incoming path and query **replace**, not append to, any configured
path/query. Both incoming and configured fragments are discarded. Prefer an
HTTPS origin without a path/query/fragment in deployment. HTTP remains supported
for compatibility; this phase does not change the deployment's origin transport
policy. Do not send credentials over an untrusted HTTP connection.

## Identity and forwarding

The handler removes incoming toolbox authentication/identity values, `Forwarded`,
the entire `X-Forwarded-*` family case-insensitively (including Port, Prefix, SSL,
Scheme, Server and unknown future members), `X-Real-IP`, `True-Client-IP`, and
`CF-Connecting-IP`. Only `X-Forwarded-Host` is reconstructed within that family.
It reconstructs the backend secret and `X-Forwarded-Host`
from configuration and the incoming URL. Only an edge-provided `CF-Connecting-IP`
is copied into `X-Toolbox-Client-IP`; without it, no client IP is invented.
Hop-by-hop headers, including valid names nominated by `Connection`, are removed
before protected headers are reconstructed. Other application headers are retained.

**Deployment assumption:** Cloudflare must control `CF-Connecting-IP` on the
actual Pages ingress, and all ingress to a backend trusting toolbox proxy headers
must be verified and protected. Mocked CF headers prove forwarding behavior,
not Cloudflare authenticity. Worker subrequests and alternate ingress may have
different identity semantics and must be reviewed for that deployment. The proxy
does not independently authenticate header provenance. Backend
`TRUST_TOOLBOX_PROXY_HEADERS` and Fastify's broad `trustProxy: true` are unchanged.
When toolbox trust is enabled, removing `X-Forwarded-For` closes the spoofed
`request.ip` fallback when a valid toolbox IP is absent; this does not establish
the safety of every other ingress or downstream reverse proxy.

Methods, unread request streams, status codes, response streams and application
headers pass through. Fetch uses `redirect: 'manual'`, so the credential is not
automatically sent to a redirect destination. Original redirect responses and
Location headers are returned; this is not a redirect-following feature.

The incoming AbortSignal is passed to fetch. Pre-aborted requests do not fetch;
an observed cancellation returns a non-success 499 `PAGES_PROXY_CANCELLED` when
a response can still be delivered. Other fetch failures produce safe 502
`PAGES_PROXY_UNAVAILABLE` responses. No raw exception, retry, logging or fallback
is added. Proxy-generated errors use `Cache-Control: no-store`.

## Coverage and limits

`tests/pages-proxy.test.mjs` directly imports the production handler. Node 22 Web
APIs and a stubbed fetch test request/response bytes, unconsumed stream identity,
headers, redirect mode, failures and controlled cancellation without network
traffic. JavaScript tests isolate Node test globals from the Workers-only TS
environment. The suite is also part of `test:unit`. A temporary, cleaned-up
Functions type-error probe proves that the dedicated check fails, while both
application configs omit Functions. An in-memory browser build checks that the
synthetic server secret and proxy implementation are absent from artifacts.
Credential assertions use booleans, no snapshots or credential-bearing call dumps.

No Workers emulator is needed for these Web API/forwarding-contract checks:
tests pass the original stream to mocked fetch and do not construct a Node fetch
request (which would require Node-specific `duplex`). Workers typings validate
the actual fetch signature. These are not workerd/deployment integration tests:
they do not prove runtime disconnect notification, fetch cancellation timing,
edge header provenance, or production connectivity. Fetch rejection handling
applies before a response is returned; subsequent response-stream failures and
disconnect cleanup remain owned by the runtime. An arbitrary backend that
echoes or logs authentication headers is outside this proxy's guarantee; backend
responses intentionally are not buffered or rewritten to redact secrets.
