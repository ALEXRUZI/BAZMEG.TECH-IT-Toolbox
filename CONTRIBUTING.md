# Contributing

This is a small AI-assisted project. These are practical review guidelines, not a claim about enforced branch protection, required review counts, or an established public contribution policy. Repository-wide licensing remains undecided; see [README](README.md#deployment-and-project-decisions). Confirm contribution/reuse terms with the owner where needed.

## Get oriented

1. Read [README](README.md) for Node 22 prerequisites, Windows/Linux setup, architecture and tools, and [production boundaries](docs/PRODUCTION.md). Private development instructions are not part of public releases.
2. Inspect branch/HEAD and `git status` before editing; preserve existing work. Work in a dedicated branch for the scoped change, without resetting/reverting someone else's edits.
3. There is no root npm package. Use `npm ci` in the affected `frontend/` and/or `backend/` package. Follow [configuration guidance](docs/CONFIGURATION.md) with disposable local secrets, never a production backend by default.

## Make focused changes

- Match React/strict TypeScript/Tailwind conventions in the frontend and ESM `.mjs` conventions in the backend. Extend established modules, shared controls and tool registry/dispatch; do not invent parallel systems or mark placeholders working.
- Inspect implementation, callers, tests and executable configuration before editing. Preserve typed/runtime API contracts, duplicate headers, stable error messages/codes, accessibility, long-output wrapping and narrow-screen usability.
- Preserve browser-only secret/CSR processing, secure randomness, SSRF/redirect controls, authentication, proxy identity, resource budgets and cleanup. Document material security/behavior changes; add regression tests for defects, boundaries, failure and recovery.
- Avoid unrelated refactors, dependency upgrades, lockfile churn or deployment/CI/trust changes. New dependencies need justification and the correct package lockfile.
- Keep secrets out of code, env examples, logs, browser variables, test artifacts, URLs and reports. Use disposable test keys/passwords and non-revealing assertions; preserve secret-test confidentiality protections and E2E networking guards.
- Update relevant documentation if contracts, source paths, commands or limitations change. Source/tests/configuration take precedence over older prose. Files use LF by default under [`.gitattributes`](.gitattributes); Windows script exceptions are explicit.

## Validate the change

Exact commands are in [README](README.md#testing-and-ci). Deployment changes also require `python3 -B -m unittest discover -s deploy/tests -v` from the root. All deployment tests are offline and unprivileged.

| Area | Checks from the package directory |
| --- | --- |
| Backend | `npm test`, `npm run check`; local OpenSSL is needed for certificate regression tests. |
| Frontend | `npm run typecheck`, `npm run build`, `npm run test:unit`, relevant Playwright specs. |
| Shared UI/layout/registry or cross-boundary changes | Full `npm run test:e2e` in addition to frontend checks; backend checks for API/architecture changes. |
| Pages Function | `npm run typecheck:pages`, `npm run test:pages`; full frontend/backend suites for boundary changes. App typecheck/build is not a Functions check. |
| Documentation only | Verify links/source paths, commands, env/API/CI/tool claims, and `git diff --check`; application suites need not be rerun unless relevant facts require checking. |

Install Chromium with `npx playwright install chromium` (`--with-deps chromium` on Ubuntu/CI when needed). E2E uses a local test-only server on port 4173, mocks API responses, blocks unexpected traffic, and serializes clipboard use. Do not bypass guards or test against production/public destinations without authorization. Tests cover Chromium, not all browsers or full screen-reader compatibility. [CSR tests](frontend/tests/csr/README.md) include independent signature/key verification.

## Submit for review

Review the complete diff and final status for unintended files, secrets and generated artifacts. Describe scope/rationale, changed behavior, tests actually run/results, checks not run with reasons, and material limitations. Keep unrelated defects separate. Submit changes for maintainer review using the repository's available review process; do not infer merge/deploy permission, review-count rules, or licensing approval from these guidelines. Agents must not commit, push, merge or deploy without explicit authorization.

For sensitive vulnerabilities, follow [SECURITY.md](SECURITY.md), not an ordinary public issue.
