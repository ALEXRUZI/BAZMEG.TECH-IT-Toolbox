# IT Toolbox | Bazmeg.Tech

A browser-based workbench for everyday sysadmin, Linux, network, certificate, and developer tasks. Generate commands and secrets, convert data, or inspect public DNS, HTTP, and TLS endpoints.

> This is an AI-assisted project. Code, structure, and documentation are built with help from AI, but the project is manually reviewed, tested, and maintained.

Project target URL: <https://toolbox.bazmeg.tech>. Live availability is not verified by this documentation.

## Tools and processing

The [tool registry](frontend/src/app/toolRegistry.ts) is the status source of truth. “Working” means implemented, not a guarantee of production availability or suitability for every environment.

| Working browser-only tools | Working backend-backed tools |
| --- | --- |
| Password / Secret Generator | DNS checker |
| Hash Calculator | RDAP / WHOIS Lookup |
| Firewalld generator | HTTP Header Checker |
| UFW generator | TLS cert checker |
| nftables generator | |
| chmod calculator | |
| Cron generator | |
| Epoch & Unix timestamp | |
| Data Transfer Calculator | |
| Units of information calculator | |
| CSR Generator | |
| Base64 / URL encode | |
| JSON/YAML formatter | |

Browser-only tools process entered/generated material locally, without sending it to the application backend. Firewall tools generate commands; they do not apply rules. nftables currently supports IPv4 only. YAML-lite formatting is not a full YAML parser or validator.

**Hash Calculator:** one file (picker or drop) or exact UTF-8 text; SHA-256 by default,
plus SHA-384, SHA-512, BLAKE3-256, unkeyed BLAKE2b-256, CRC32 (IEEE), xxHash32
(seed 0), SHA-1 and MD5. CRC32/xxHash32 are non-cryptographic corruption checks.
Incremental hashing runs in a local
Web Worker, sharing each file chunk across selected algorithms. Includes progress,
cancel/restart, per-digest copy and hexadecimal checksum verification. MD5/SHA-1
are broken for collision resistance and require transient per-algorithm risk
acknowledgment before calculation, with a one-click switch to SHA-256. The permanent
amber warning remains visible. Ambiguous 8/64-hex checksums require an explicit
algorithm choice; a matching checksum is not proof of source
authenticity. No uploads, runtime CDN, input telemetry or input persistence.
See [implementation, dependency and test notes](frontend/src/tools/hash-calculator/README.md).

**RDAP / WHOIS Lookup:** on-demand domain (including IDN), individual IPv4/IPv6
and AS-prefixed ASN registration data with structured/raw views and explicit exports.
Auto prefers IANA-discovered RDAP and falls back only for unsupported HTTPS discovery
or query HTTP 405/501; forced modes never switch. WHOIS uses plaintext TCP/43.
No monitoring, purchase-availability guarantees, verified geolocation or live DNSSEC
validation. See [contracts, resource limits and unsupported cases](backend/REGISTRATION_LOOKUP.md).

**Planned only:** MAC Address Lookup; SMTP Banner Checker; Subnet Calculator; Docker Run to Docker Compose Converter; Text to ASCII Art; rsync Command Builder; SCP / SFTP Command Builder; OpenSSL Certificate Command Builder; systemd Service / Timer Generator; ssh_config Generator; NGINX Reverse Proxy Config Generator; Text A vs Text B Compare. These are placeholders, with no committed release dates.

### Privacy and sensitive data

- CSR key generation and signing use browser Web Crypto. Private keys and CSR inputs are not sent to the application backend. See the [CSR regression contract](frontend/tests/csr/README.md) for algorithms and export limitations.
- Passwords, passphrases, PINs, API keys, tokens, and recovery codes are generated locally using secure randomness. The application does not persist these generated secrets in browser storage.
- Copy/export follows user action. Copied material leaves application control; clipboard monitors, extensions, malware, screenshots, and compromised devices remain risks. Browser processing does not guarantee secure memory erasure.
- DNS/HTTP/TLS tools send the requested query or target to the backend, which contacts resolvers or destinations. DNS/HTTP results may be cached in process memory; request/failure logs may contain target and client information. Do not use sensitive internal names or credentials as diagnostic input.
- Registration lookup sends identifiers to the backend and registration services. Results can include public contacts and are shared in a bounded, process-local 60-second cache; WHOIS has no transport confidentiality or authentication. Do not submit sensitive identifiers.

See [security guidance](SECURITY.md) for trust boundaries and diagnostic limitations.

## Architecture and stack

```text
Browser → Cloudflare Pages frontend → Pages Function /api proxy → separate backend API
Browser-only utilities stay in the browser
Local development: browser → Vite /api proxy → loopback backend
```

- [Frontend](frontend/package.json): React 19, strict TypeScript, Vite 8, Tailwind CSS 4; Vitest/Testing Library and Playwright tests.
- [App structure](frontend/src/app/): layout, registry, typed tool IDs, and component dispatch. Tool implementations live in [frontend/src/tools/](frontend/src/tools/); shared UI in [frontend/src/components/](frontend/src/components/).
- [Backend](backend/src/server.mjs): Node.js 22, Fastify 5, ESM modules, native DNS/HTTP/TLS APIs, and the Node test runner. Route modules own cancellation/error mapping; tool modules own validation, diagnostics, and resource limits.
- [Pages Function](frontend/functions/api/[[path]].ts): server-side authentication and streaming proxy. See its [validation and trust notes](frontend/functions/README.md).

## Local development

### Prerequisites

Use a current patched **Node.js 22** release (CI selects 22), npm, Git, and a modern browser. Use a secure browser context (HTTPS or localhost/loopback) for Web Crypto and clipboard features; plain HTTP LAN access may not provide them. Backend certificate regression tests require local OpenSSL on `PATH`; the TLS policy fallback also uses OpenSSL when needed and degrades to unavailable policy evidence if it cannot run.

There is no root npm package. Run commands in `backend/` or `frontend/` and use their committed lockfiles with `npm ci`. Chromium browser tests also require Playwright's browser/system dependencies.

Use two terminals starting at the repository root. The secret below is **disposable local example data**, not a production credential. Neither workflow defaults to a production backend.

### Windows PowerShell

Backend terminal:

```powershell
cd backend
npm ci
$env:PORT = "3001"
$env:BACKEND_SECRET = "disposable-local-example"
$env:TRUST_TOOLBOX_PROXY_HEADERS = "false"
npm start
```

Frontend terminal:

```powershell
cd frontend
npm ci
$env:BACKEND_ORIGIN = "http://127.0.0.1:3001"
$env:BACKEND_SECRET = "disposable-local-example"
$env:ALLOW_LAN_API_PROXY = "false"
npm run dev
```

In a third terminal, check only local health/authentication (no outbound diagnostic work):

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:3001/healthz"
Invoke-RestMethod -Uri "http://127.0.0.1:3001/api/ping" -Headers @{ "X-Toolbox-Backend-Secret" = "disposable-local-example" }
Invoke-RestMethod -Uri "http://localhost:5173/api/ping"
```

### Linux shell (including Ubuntu)

Backend terminal:

```sh
cd backend
npm ci
export PORT=3001
export BACKEND_SECRET=disposable-local-example
export TRUST_TOOLBOX_PROXY_HEADERS=false
npm start
```

Frontend terminal:

```sh
cd frontend
npm ci
export BACKEND_ORIGIN=http://127.0.0.1:3001
export BACKEND_SECRET=disposable-local-example
export ALLOW_LAN_API_PROXY=false
npm run dev
```

In a third terminal:

```sh
curl --fail http://127.0.0.1:3001/healthz
curl --fail -H 'X-Toolbox-Backend-Secret: disposable-local-example' http://127.0.0.1:3001/api/ping
curl --fail http://localhost:5173/api/ping
```

Health returns `{"status":"ok","service":"toolbox-api"}`; ping returns `{"ok":true,"message":"toolbox API reachable"}`. The backend binds to **127.0.0.1**, default port **3001**. Protected calls fail closed without a matching secret.

Open the URL printed by Vite (normally `http://localhost:5173`; it may select another port if occupied). Vite injects the secret server-side for relative `/api/...` calls; the browser needs no secret. Missing development secret → 503; mismatched secret → backend 401; unreachable backend → 502. There is no production fallback. Browser-only utilities remain usable.

### Configuration, LAN, and static preview

- Vite defaults `BACKEND_ORIGIN` to `http://127.0.0.1:3001`. Optional settings can go in ignored `frontend/.env.local`, copied from [frontend/.env.example](frontend/.env.example); shell values take precedence. Restart Vite after changes.
- The backend reads process environment only: copying [backend/.env.example](backend/.env.example) to `.env` does **not** load it with `npm start`. Set values in the launching shell or operator-managed environment.
- Development origins must have no path, query, fragment, or URL credentials. HTTP requires a loopback IP literal (`127.0.0.0/8` or `[::1]`); even `localhost` as an upstream hostname requires HTTPS. Non-loopback origins require verified HTTPS and deliberate configuration.
- `npm run dev:lan` exposes the UI on `0.0.0.0`. Non-loopback API clients are blocked with 403 unless `ALLOW_LAN_API_PROXY=true`. Enable only on a trusted development network: allowed clients use Vite's backend credential. Browser-supplied authentication/identity headers are removed.
- From `frontend/`, `npm run build` produces `dist/`; `npm run preview` serves that static build. `npm run preview:lan` allows LAN preview. **Neither preview command runs the API proxy or Pages Function**, so this is not a full deployment test.
- Never put `BACKEND_SECRET` in browser code or `VITE_*` variables. Production Pages bindings are configured separately, not automatically populated from local files. See [environment configuration](docs/CONFIGURATION.md).

## Testing and CI

From `frontend/`, after `npm ci`:

```sh
npm run typecheck
npm run typecheck:pages
npm run test:pages
npm run build
npm run test:unit
npx playwright install chromium
npm run test:e2e
```

On Ubuntu, `npx playwright install --with-deps chromium` installs the browser plus system dependencies (may require administrator permission). Optional frontend scripts: `test:unit:watch`, `test:e2e:headed`, and `test:e2e:report`.

From `backend/`, after `npm ci`:

```sh
npm test
npm run check
```

[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) is **CI**. Private CI runs on `dev`/`main` and PRs; the curated public CI runs on `main` and PRs and is callable by the production workflow. Ubuntu 24.04 / Node 22 jobs run frontend, Pages, Chromium, backend and offline deployment regressions. Only allowlisted, sanitized browser failure metadata is uploaded for seven days; never raw reports, traces or secret-bearing fixtures.

Unit/component tests cover validation, calculations, rendering, accessible controls, clipboard behavior, API contracts, and both proxies. Backend tests exercise offline network/security/resource boundaries, with local loopback servers where needed. [CSR verification](frontend/tests/csr/README.md) independently checks ASN.1 and actual signatures/private-key interoperability.

Playwright runs a local test-only Vite server on `127.0.0.1:4173` (keep it free), disables the API proxy, mocks network-tool responses, and blocks unexpected API/external requests. No deployed backend or credentials are needed. Clipboard tests run with one worker. Coverage is **Chromium**, not every browser/device; offline mocks do not prove production connectivity or Cloudflare edge identity authenticity. Automated accessibility checks do not establish full screen-reader compatibility.

For documentation-only changes, verify links, source claims, scripts, and the diff rather than rerunning every application suite. See [contribution guidance](CONTRIBUTING.md) for change-specific checks.

## Deployment and project decisions

Cloudflare Pages serves the frontend and its `/api` Function from public production `main`. Owner-triggered public deployment verifies the backend first, then uploads the same commit's assets and precompiled Function to the existing Pages project. Automatic production Git deployments must be disabled. The Function supplies `BACKEND_SECRET` server-side and uses manual redirects. Loopback binding requires controlled ingress. Automation remains disabled until the owner configures approvals, credentials, server migration and Pages settings; source does not establish live readiness.

Development is private (`ALEXRUZI/BAZMEG.TECH-IT-Toolbox-dev`, `dev`); production is public (`ALEXRUZI/BAZMEG.TECH-IT-Toolbox`, `main`). Publication opens a public PR containing only the tested allowlisted snapshot, never private Git history. The owner reviews/merges after CI; main requires a PR and zero approving reviews. The public production environment requires only the owner, with self-review allowed. See [production architecture, ordering, verification and rollback](docs/PRODUCTION.md).

- [Operations, release, rollback, and recovery](docs/OPERATIONS.md)
- [Production release and Cloudflare Pages settings](docs/PRODUCTION.md)
- [Environment configuration](docs/CONFIGURATION.md)
- [Backend API reference](docs/API.md)
- [Pages proxy implementation/trust boundary](frontend/functions/README.md)
- [Security and vulnerability disclosure](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

**Licensing:** no tracked top-level `LICENSE` establishes a repository-wide license grant. [backend/package.json](backend/package.json) declares ISC for that package; this is not a verified project-wide licensing decision. The owner must decide repository-wide licensing and ownership before the whole project is presented as open source or reuse rights are assumed.

**Disclosure:** no dedicated private vulnerability-reporting channel is verified. Selecting and publishing one is a maintainer decision; do not publish sensitive unpatched vulnerabilities in ordinary issues. See [SECURITY.md](SECURITY.md).
