# Operations, release, rollback, and recovery

This is an environment-neutral runbook, grounded in tracked source. It does **not** certify a live deployment or supply infrastructure commands. **Deployment-specific value must be supplied by the operator.** Do not treat example local addresses as production destinations.

The [production architecture](PRODUCTION.md) and public-safe backend runbook
(published as `deploy/PRODUCTION-BACKEND.md`) define the protected public-repository
pipeline. Private operator inventory is excluded from releases. Initial systemd
migration, Pages settings and ingress trust require separately authorized operator
configuration; none is established by offline tests.

## Components and verified boundaries

```text
Browser → Cloudflare Pages frontend → Pages Function /api/* → separately operated backend
                                                             ↓
                                                  public DNS / HTTP / TLS targets
```

| Component | Responsibility / verified fact |
| --- | --- |
| Frontend | `frontend/` builds with `npm run build` to `frontend/dist/`; browser-only tools need no diagnostic backend. |
| Pages Function | [Tracked handler](../frontend/functions/api/[[path]].ts) forwards `/api/*`, supplies server-side authentication, strips/reconstructs identity headers, streams responses, and uses manual redirects. A deployment must include this Function, not just static assets. |
| Backend | [Fastify entry point](../backend/src/server.mjs) reads process environment and binds **127.0.0.1**, default port 3001. It validates targets and owns network diagnostics/rate/cache/resource state. |
| Backend ingress | External reachability requires operator-controlled ingress to that loopback listener. The prepared systemd deployment procedure does not establish reverse-proxy configuration or live ingress trust. |
| GitHub Actions | [deploy.yml](../.github/workflows/deploy.yml) runs **CI only**. Its filename does not imply deployment, secret provisioning, or rollback automation. |

See [Pages trust/forwarding details](../frontend/functions/README.md), [configuration reference](CONFIGURATION.md), and [API reference](API.md); those documents own the detailed contracts.

## Required production configuration and prerequisites

1. Identify the deployment operator, approved commit for each component, Pages project/environment, backend host/ingress, runtime/service controls, and last known-good versions. The prepared backend procedure supplies proposed paths, not evidence that production has been migrated or the workflow enabled.
2. Supply Pages server-side `BACKEND_ORIGIN` and `BACKEND_SECRET` in every applicable environment. Supply matching backend `BACKEND_SECRET`, optional `PORT`, and an explicitly reviewed `TRUST_TOOLBOX_PROXY_HEADERS` value in its process environment. Cloudflare does not automatically configure these values. Do not use `VITE_*` secrets or commit env files.
3. Provide current patched Node 22 for the backend. Install backend dependencies using its lockfile with `npm ci`; its launch script is `npm start`. Actual service lifecycle/install location is deployment-specific. Local OpenSSL enables the optional certificate-policy fallback; missing fallback evidence must not be mistaken for a verified certificate type.
4. Ensure Pages can reach an operator-approved backend origin through controlled ingress. Keep the application's loopback bind; do not assume it listens publicly. Prefer verified **HTTPS** to ingress and HTTPS for browser access. Pages accepts HTTP upstream configuration, so HTTPS is not enforced by that handler; never carry the shared credential over an untrusted HTTP connection. Vite's stricter development-origin rules are not a production transport policy.
5. Leave toolbox proxy-header trust disabled unless **all** relevant backend ingress paths are verified and control forwarded identity. When enabled, the backend accepts valid toolbox IPs and otherwise uses Fastify `request.ip`; Fastify's `trustProxy: true` is broad. Verify Cloudflare's control of `CF-Connecting-IP` at actual Pages ingress and review alternate ingress/subrequests/downstream proxies. Unit mocks cannot authenticate edge provenance. Without trust, clients behind ingress may share the socket-peer rate bucket.
6. Confirm outbound policy supports fixed resolver UDP/53 destinations for DNS and allowed public TCP ports for HTTP/TLS. HTTP/TLS also require hostname resolution. Do not broaden network/trust policy to conceal a failed check; record and review the actual requirement.
7. Define restricted-access logging, retention, alerting, and recovery ownership. No repository-backed production alerting service, backup location, or retention policy is specified.

### Logging and data precautions

Fastify logging is enabled. HTTP failure logs include bounded hostname/URL, destination address, and error information. Do not claim diagnostics are anonymous or unlogged. Review ingress/platform/request logging before release: redact authentication headers, do not log credentials or request bodies unnecessarily, and restrict log access/retention. Never add CSR/private-key/password/token material to logs, reports, screenshots, or telemetry.

DNS/HTTP caches and rate histories are process-memory state, not a durable database; TLS has no result cache. A restart loses cache/rate history and interrupts active requests; it is not a routine rate-limit bypass. Budgets are per process and do not become distributed protections when replicas are added. See [resource/state documentation](API.md#errors-admission-and-cancellation).

## Configuration validation and health

Perform these checks only in an approved environment with its operator; this documentation phase makes no production calls:

- Check values are supplied in the correct process/Pages environment, with the secret exactly matching. Validate the upstream destination and transport without printing credentials. Restart/reload via the operator's approved process after changes.
- `GET /healthz` on the backend's controlled health path should return `status: "ok"`, `service: "toolbox-api"`. Use the exact URL without a query. It is exempt from authentication and proves only process reachability, not backend outbound connectivity.
- An authenticated `GET /api/ping` through Pages should succeed without a secret in the browser. A direct protected backend request without the header must return 401. Do not include secrets in browser requests, URLs, reports, or shell history; use operator-approved secret handling for any direct authenticated check.
- Confirm the Function is deployed and correctly bound: static preview does not run it. Confirm browser assets contain no server secret and network requests remain relative `/api/...`.
- Inspect negative responses: configuration → proxy 503; fetch/unavailable → proxy 502; mismatched secret → backend 401. Do not interpret health success alone as readiness.

## Release checklist

### Before release

- [ ] Confirm repository, target branch, and approved commit(s); record frontend/backend versions and review `git status --short` for clean source. Keep local secrets/infrastructure outside tracked content.
- [ ] Verify GitHub CI is green **for those commits**, not merely a prior branch build. CI runs on `main`/`dev` pushes and pull requests; it does not deploy.
- [ ] Confirm frontend app typecheck/build/unit tests, dedicated Pages `typecheck:pages` and `test:pages`, Chromium E2E, and backend `npm test` / `npm run check`. See [exact commands](../README.md#testing-and-ci).
- [ ] Review changes touching secrets, proxy identity/authentication, SSRF validation, redirects, crypto, response contracts, and resource limits. Verify frontend/backend payload compatibility.
- [ ] Confirm secrets are supplied outside the repository and isolated by environment. Verify HTTPS, ingress access, and trusted identity assumptions without exposing credential values.
- [ ] Identify the deployment operator, rollback target for **each** component, and configuration required by both old/new versions.
- [ ] Confirm recovery prerequisites: retrievable last known-good artifacts/source, secure recovery of bindings/service configuration, necessary operator access, and any deployment-specific backups. Repository code establishes no durable application data store; infrastructure/configuration recovery still needs an operator plan. Never store secrets in the release record.

### Release

1. Record approved frontend/backend commits and artifact identifiers with non-secret configuration/version notes.
2. Follow [the owner-approved publication and deployment procedure](PRODUCTION.md). Review/merge the public snapshot PR after CI, then manually dispatch the exact public main SHA. Keep automatic Pages production deployment disabled: the workflow first verifies the backward-compatible backend, then deploys that commit's immutable frontend **and Function** to the existing Pages project.
3. Use expand/contract releases for API changes. Keep old/new clients compatible during rollout and rollback; incompatible changes require a separately approved maintenance plan. Coordinate any secret change across both sides; mismatched versions/configuration can break every API tool.
4. Keep the previous known-good frontend, Function, backend, and configuration references available until verification completes. Do not guess SSH/SFTP/systemd/Cloudflare commands from this general runbook; use only separately reviewed, approved environment-specific procedures.

### Post-release (operator-approved verification)

- [ ] Frontend loads over HTTPS; navigation/search, keyboard focus, labels/errors, and narrow-screen layout are usable. Full screen-reader evaluation remains separate from automated checks.
- [ ] Browser-only calculations/formatting and secret/CSR generation work using disposable inputs; inspect traffic to confirm no secret/key material leaves the browser. Avoid screenshots/recordings of secrets and clear any test clipboard material.
- [ ] Pages authenticated ping works; missing direct backend authentication fails closed. Review backend health independently of Pages `/api` routing.
- [ ] With explicit approval, run a small DNS/HTTP/TLS diagnostic against **operator-owned or authorized public test destinations**. Confirm expected fields, duplicate HTTP headers, certificate trust/hostname distinctions, and safe error/retry behavior. This is outbound traffic; CI mocks do not prove it works live.
- [ ] Review unexpected external traffic, backend errors, capacity/rate/timeouts, ingress identity, latency, and regression reports using deployment-specific monitoring. Do not stress public services or provoke saturation on production to “test limits.”
- [ ] Record verification outcomes and retain the rollback target; do not claim readiness from health/CI alone.

## Rollback and recovery

1. Decide which component regressed: frontend assets, Pages Function/bindings, backend, ingress/configuration, or an external dependency. Frontend and backend need **not** always roll back together.
2. Select the recorded last known-good version of the affected component. Check request/response, authentication, environment, and security compatibility with components that will remain deployed; a coupled contract change may require coordinated rollback.
3. Use the operator's validated platform rollback/service procedure. Exact Pages release selection, backend artifact/service commands, paths, accounts, and permissions are not established here: **deployment-specific value must be supplied by the operator**. Do not use destructive Git resets as a production recovery procedure.
4. Restore compatible non-secret settings and securely supplied bindings. Coordinate credential changes; never restore a known-compromised secret merely because an old release used it. Backend restart discards in-memory cache/rate state and active diagnostics, and there is no cache restoration requirement.
5. Repeat health, proxy/authentication, frontend, and approved diagnostic verification. Review monitoring and record rolled-back versions, cause, and remaining limitations. If rollback fails, stop repeated retries and escalate to the designated operator with sanitized evidence.

For suspected credential exposure, restrict affected ingress through the operator, rotate the shared credential on both sides using approved secret storage, review accessible logs/artifacts, and verify authentication again. No repository-provided key-rotation, backup restore, or incident-response automation is established.

## Troubleshooting

| Symptom | Safe investigation |
| --- | --- |
| UI works; API tools fail in static preview | Preview has no API proxy/Function. Use local Vite+backend or the approved Pages environment. |
| Proxy 503 | Check Pages binding validity or development secret configuration; do not print the secret. |
| Backend 401 | Check exact matching process/proxy secrets and that updated backend configuration was restarted. |
| Proxy 502 with backend health locally OK | Check operator-controlled ingress, upstream origin/HTTPS certificate, reachability, and Function deployment. Loopback backend is not directly reachable from Pages. |
| Development LAN 403 | Default guard; only deliberately enable `ALLOW_LAN_API_PROXY=true` on trusted networks. |
| Tool 400 | Inspect validated input/address policy and safe code; parser errors differ from tool errors. Do not disable SSRF checks. |
| 429 / capacity 503 / deadline 504 | Stop rapid retries, review per-process resource use and identity. HTTP/TLS system DNS may remain outstanding after cancellation; limits do not aggregate across replicas. |
| DNS `ok: false` at HTTP 200 | Inspect provider status/truncation/enrichment warnings; UDP-only diagnostics may be incomplete, not an API outage. |
| TLS inspection succeeds but warnings fail | `ok` is completion, not certificate validity. Review authorization, hostname, exact expiration and unknown chain provenance separately. |

## Operator decisions still required

The prepared backend procedure supplies a proposed host/service/release layout and rollback mechanism. Operators must still verify that inventory and supply approval governance, Pages project/account and deployment details, ingress trust, operator ownership, secure backup/recovery locations, log retention and monitoring/alerting. Supply sensitive details in restricted operator documentation; do not expose local infrastructure files or credentials to fill documentation gaps. Licensing and private disclosure decisions are tracked in [README](../README.md#deployment-and-project-decisions) and [SECURITY.md](../SECURITY.md).
