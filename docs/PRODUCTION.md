# Production: one owner, two repositories

Prepared source only. No live settings, credentials, publication or deployment have
been changed or verified. **ALEXRUZI is the sole approver**, including their own
triggered deployments. There is no second-person or private-plan approval dependency.

- Private development: `ALEXRUZI/BAZMEG.TECH-IT-Toolbox-dev`, `dev`.
- Public production: `ALEXRUZI/BAZMEG.TECH-IT-Toolbox`, `main`.
- Private manual publication tests/scans a strict immutable-blob allowlist and opens
  a public snapshot PR with public-only history; it never writes main or deploys.
- The owner reviews/merges after required CI; the owner separately dispatches
  **Production deployment** on public main with its exact `approved_sha`.
- No push automatically deploys production. Backend is verified first, then the
  same public SHA's prebuilt assets **and Pages Function** are uploaded to the
  existing Cloudflare Pages project, on GitHub-hosted runners.

Backend delivery is **pull-only**: GitHub publishes an owner-approved Ed25519-signed
authorization; the backend checks outbound every **60 seconds**, independently verifies
root-provisioned trust and activates locally. No GitHub SSH/SCP/SFTP connection,
deployment webhook or backend Actions runner. The installed activation helper remains
unchanged. Full protocol, host preparation, pin bootstrap, timer installation (disabled
by default), check-only qualification and recovery: [pull runbook](../deploy/PULL-DEPLOYMENT.md).

## Required manual GitHub configuration

Do not enable `TOOLBOX_PRODUCTION_ENABLED=true` in the public repository until all
items below are verified. Never put production signing/Cloudflare secrets in private
development, ordinary repository/organization secrets, PR jobs or preview runners.

### Public main protection: PR and CI, zero approving reviews

Require a PR, current/up-to-date CI (`frontend`, `backend`, `deployment-regressions`,
using exact names reported by actual PR runs), resolution of review conversations,
and block force-push/deletion. Set **required approving reviews to 0**, not 1.
Do not require code-owner approval, last-push approval or independent review.
Do not enable auto-merge. The owner reviews their own release PR manually, then uses
the merge button after CI. The App needs no main-write/bypass exception.

Owner configuration example for the classic branch protection model (reference
only; NOT executed here):

```json
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["frontend", "backend", "deployment-regressions"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "require_code_owner_reviews": false,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
```

Install/verify via repository settings or the branch-protection API under owner
authority. An equivalent ruleset must require PR/CI with zero reviews and no bypass
actors. Verify the App cannot update main directly. GITHUB_TOKEN has deliberately
limited read permissions and does not administer/read all protection details;
the workflow checks main is protected, while the owner audits the exact rules
and required-check provenance separately. A protected flag alone is not proof of
the full policy. Do not weaken permissions by adding an administrator token to CI.

### Public production environments: owner can approve their own run

Create **production** (backend) and **production-pages** (frontend) in the public
repository. Apply the following identical protections to **both**:

1. Required reviewers: **User ALEXRUZI only** (no team/additional user).
2. **Prevent self-review: disabled**. The triggering owner must be able to approve
   the environment prompt. Do not configure other protection rules that require
   another person. Disable administrator bypass where available; the owner uses
   the normal review prompt, not a bypass. REST does not expose every bypass setting.
3. Selected deployment branches/tags: exactly one **branch** named `main`, not a
   wildcard, tag or all protected branches. Public default branch must expose the
   reviewed manual workflow. Keep workflow/environment administration owner-controlled.
4. Verify settings before the first dispatch with read-only API calls to
   `repos/ALEXRUZI/BAZMEG.TECH-IT-Toolbox/environments/production` and its
   `/deployment-branch-policies` endpoint, and the corresponding `production-pages`
   endpoints. Confirm sole reviewer login/type and
   `prevent_self_review: false`; confirm the logged-in/triggering account is ALEXRUZI.
   An unprivileged workflow preflight repeats those checks **before requesting an
   environment review**, then each deployment job rechecks them (including original/
   rerun actor, exact input SHA, run SHA and current main tip). Missing metadata
   or self-review prevention fails closed, rather than requesting a second approver.

Each stage uses a different environment on a fresh hosted runner. This prevents
backend approval or credentials from authorizing Pages. The same owner gives
**one approval per stage**, with no additional approver. The Pages job is not eligible
until backend verification succeeds. Each credentialed step also verifies GitHub's
read-only review history for one explicit owner approval of its exact environment
ID in this run. Missing/rejected/ambiguous approval fails closed. Environment
administration remains trusted; this does not replace GitHub's credential barrier.

**Production reruns are refused**, including failed-job reruns. Review history is
run-scoped rather than attempt-scoped; use a fresh owner dispatch for retries, new
artifacts and fresh approvals. Cancelled/completed runs fail the live-run check.
Do not enable custom protection rules requiring another person. Admin bypass must
still be disabled manually; API metadata does not prove every protection setting.
Do not merge another release while a coordinated rollout is in progress; stale
queued runs fail, but main cannot be locked atomically across external services.

### Production-only credentials and variables

Only public **production** environment secret (backend authorization):

- `PRODUCTION_RELEASE_SIGNING_KEY`: dedicated independently generated Ed25519 private
  PEM; no application/build/test execution with this key. Only the approved publishing
  job gets it and `contents: write`. Environment variable `PRODUCTION_RELEASE_KEY_ID`
  identifies the independently provisioned root-owned public verification pin.
- Remove/revoke obsolete production deployment SSH secrets/authorized keys and the
  toolboxdeploy sudo activation grant under an explicit cutover decision. New delivery
  needs no SSH credential or sudo grant. Development SSH infrastructure is unchanged.

Only public **production-pages** environment secrets (Pages):

- `PRODUCTION_CLOUDFLARE_API_TOKEN`: new production-only Cloudflare Pages edit token,
  scoped to the production account and existing project as narrowly as supported.
  Pages tokens may be account-scoped rather than project-scoped: review this residual
  privilege, expiration/rotation and operator access. Never reuse preview/builder tokens.
- `PRODUCTION_CLOUDFLARE_ACCOUNT_ID`: existing account identifier.

Public `production-pages` variable: `PRODUCTION_PAGES_PROJECT` (existing project name).
Set `PRODUCTION_PAGES_URL` (verified HTTPS UI origin, no path/query/credentials) as a
repository variable for the credential-free backend waiter and in the Pages environment.
Pages preflight checks this origin against the exact project's
custom domains/subdomain and does not follow API redirects with credentials. Pages
Deploy Hook inventory/removal requires manual dashboard verification; the documented
Pages API does not expose a stable hook-list contract used by this workflow.
Public repository variable: `TOOLBOX_PRODUCTION_ENABLED=true` only after readiness.
The signing key is referenced only in the approved publishing step; Cloudflare token only
in the frontend upload step. Build/test jobs have neither. No BACKEND_SECRET is
given to GitHub jobs. Public CI remains unprivileged even for fork PRs.

Inventory/revoke old development-controlled production-capable keys/tokens during
the separately authorized cutover; new names do not revoke existing access. Keep
development preview/builder workflows, files, runners and credentials unchanged.

## Backend outbound connectivity and local activation

Use the existing root-owned versioned-release/rollback helper and new fixed-path
pull orchestrator, described in `deploy/PULL-DEPLOYMENT.md`. Preserve loopback,
verified HTTPS ingress, SELinux, secret environment, bounded archive checks,
unprivileged dependency installation, immutable releases, atomic switch, locks,
health checks and transaction recovery. There is no host migration/helper update.
Network retrieval is toolboxdeploy-only; root reauthenticates frozen bytes before
durable sequence reservation and activation. Unknown keys, expired approvals,
conflicts/replays and pending transactions fail closed. No TOFU key is permitted.

Minute-aligned systemd polling is non-overlapping, no backlog, disabled by default.
Authenticated read-only polling is optional and recommended for shared egress;
unauthenticated 60/hour limits leave little headroom. ETags, bounded HTTPS redirects,
timeouts/sizes and persisted rate/backoff avoid continuous retries. GitHub outage
does not interrupt active service. Host preparation/pin provisioning/OL10.2 SELinux
qualification remain mandatory manual checks, not a reason to open inbound deployment.

## Existing Cloudflare Pages project: controlled exact-SHA upload

Keep the existing Git-integrated public project and custom domains; do not create
a new project, change DNS or switch integration types. Manually verify/configure:

| Setting | Required state |
| --- | --- |
| Git integration | Public `ALEXRUZI/BAZMEG.TECH-IT-Toolbox`, production branch `main`. |
| Automatic production builds | **Disabled** (`production_deployments_enabled=false`). No Deploy Hook. |
| Automatic preview builds on this project | Disabled (`preview_deployment_setting=none`); private preview/builder stays separate and unchanged. |
| Dashboard configuration | Production `BACKEND_ORIGIN` = verified HTTPS backend; `BACKEND_SECRET` = matching **secret_text** binding. Neither is a browser/VITE value. Preserve compatibility settings and other bindings. |
| Existing Git build settings | Root `frontend`, output `dist`, Node 22 and lockfile build if retained for recovery; automatic builds remain disabled. |
| Access | Owner approval, HTTPS domains, rollback permissions and no production-bound PR execution. |

The dedicated `deploy/pages/` package pins Wrangler and its dependency lockfile.
This dependency is needed to compile Pages routing and upload the supported Worker
bundle format; no application or preview dependencies were changed. Production
builds run without secrets and precompile the actual `frontend/functions/` tree:

```sh
deploy/pages/node_modules/.bin/wrangler pages functions build frontend/functions \
  --outdir frontend/dist/_worker.js --output-routes-path frontend/dist/_routes.json
```

Wrangler's `--outfile` format is multipart upload data, **not** plain JavaScript;
do not substitute it. The `_worker.js/index.js` directory is Pages advanced mode.
An offline regression executes that compiled Worker with disposable runtime
bindings, checks `/api/*` routing, authenticated proxy header replacement, missing
binding failure and static fallback. Full proxy security tests still run too.

The complete dist payload, compiled Worker and routes are sealed with path/content
hashes and public SHA, then stored as an immutable v4 Actions artifact (30 days).
Downloads use the producer job's exact artifact ID, not a mutable name/latest run.
Artifact names include run/attempt IDs; no artifact is overwritten. Production
reruns are refused rather than reusing an earlier attempt's approvals or backend.
After backend acceptance, a separate owner-approved job verifies all bytes and
rejects source/config/dotenv/symlinks. From a clean directory outside the checkout:

```sh
wrangler pages deploy . --project-name "$PRODUCTION_PAGES_PROJECT" \
  --branch main --commit-hash "$GITHUB_SHA" --commit-dirty=false \
  --commit-message "Approved production release" --no-bundle
```

No npm/application build or runtime Function execution occurs with Cloudflare
credentials. No Wrangler config is supplied/discovered, so existing dashboard
production bindings/settings remain authoritative; do not add an empty `vars`
config that replaces them. Read-only API preflight verifies project identity,
disabled Git builds, HTTPS backend binding and secret binding metadata. Postflight
requires unchanged production settings, the exact Wrangler deployment ID, production
environment, matching commit metadata, successful deploy stage and canonical release
ID. The subsequent real HTTPS `/api/ping` check verifies runtime proxy authentication;
offline tests alone cannot prove live binding values/provenance or configuration.

`--commit-hash` is a label, not a source checkout: exact bytes come from the checked-out
run SHA, full CI, publication receipt and same-run sealed immutable artifact. No
branch-tip Deploy Hook or mutable frontend rebuild is used. Review the Actions
artifact digest and per-file manifest alongside the backend archive SHA-256.

References checked 2026-10-17: [Pages direct upload and Functions](https://developers.cloudflare.com/pages/get-started/direct-upload/),
[Wrangler Pages commands](https://developers.cloudflare.com/workers/wrangler/commands/pages/),
[binding configuration/source of truth](https://developers.cloudflare.com/pages/functions/wrangler-configuration/),
[branch build controls](https://developers.cloudflare.com/pages/configuration/branch-build-controls/),
[GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

## Release acceptance and failures

1. Owner records compatibility plan, known-good public SHA, backend archive/digest,
   Pages deployment ID and secure configuration recovery references.
2. Manually publish the sanitized snapshot PR; review/merge after full required CI.
   Source publication does not deploy. Private dispatch bootstrap is documented in
   the private operator procedure; it must exist on the private default branch first.
3. Dispatch public **Production deployment** on main with the exact resulting main
   `approved_sha`. Full frontend/backend/deployment CI runs again. Build jobs verify
   the committed receipt; backend archive uses committed objects and commit-time
   timestamps, never npm-mutated files or wall-clock archive times. Same-SHA retries
   reproduce the backend digest and can reuse its immutable installed release.
4. Owner approves backend in **production**. The isolated signing job publishes archive,
   canonical manifest and detached signature under a unique SHA/run/sequence identity.
   The backend independently discovers/verifies/activates it; root helper rolls back on
   activation failure. A credential-free job waits up to 25 minutes (30-minute job bound)
   for authenticated acceptance via the
   still-live Pages Function. The authenticated `/api/release` response must report
   this public SHA, the tested archive SHA-256, `toolbox-api-v1`, and the **exact
   current signed release, sequence, canonical manifest SHA-256 and signing key ID**.
   Commit/archive are loaded once from the executing immutable release directory
   and `.archive-sha256`; accepted authorization is read per request from a separate
   root-owned read-only projection published only after durable successful acceptance.
   Expectations come from actual signed manifest outputs, never mutable Release
   metadata. Same SHA/archive under an earlier approval cannot satisfy a new run.
   No identity comes from a request/env/branch label. Local, preview and legacy runs
   report unknown identity and cannot satisfy production acceptance.
   Bounded `{}` POST probes require the expected validation errors from all four
   tool endpoints, without triggering diagnostic network work. A missing endpoint,
   incompatible error envelope, stale backend or failed health check blocks Pages.
5. Owner approves frontend in **production-pages** after backend success. Verify artifact/deployment IDs,
   live UI and `/api/ping`, direct backend rejection without authentication and old/new
   API compatibility. Use disposable secret-tool inputs, no secret-bearing recordings.
   Any live diagnostics require separate authorization and bounded approved targets.
   Immediately before upload, recheck the same signed authorization after Cloudflare
   project preflight. A waiter timeout never makes Pages eligible later.
   Automatic postflight repeats signed backend identity/compatibility and compares live
   HTML SHA-256 against the exact uploaded artifact. Cloudflare's canonical deployment
   ID/commit and successful deploy stage are checked separately. This is not a
   cryptographic attestation of server execution or a full functional API proof.

Use additive expand/contract API changes, removing old contracts only after the
rollback window. Backend health alone is not compatibility. Avoid combining breaking
changes with secret rotation. No cross-platform atomic transaction is claimed.

On a frontend upload/verification failure the run fails; the new backend may remain
active and Pages may already have changed. Stop releases, inspect exact deployment
IDs, and have the same owner restore the known-good Pages deployment **including its
Function** first, then the compatible retained backend archive if needed. Do not
automatically roll backend back behind a potentially active new frontend. Bindings
and project settings may need separate recovery; never restore compromised secrets.
If backend regresses before frontend changed, restore it while retaining old Pages.
The root script automatically attempts rollback on activation/health failure and
still reports failure; ingress-only failure after successful activation needs owner
recovery. Interrupted/failed rollback uses its existing transaction/journal procedure.
Retain secure recovery artifacts beyond Actions expiry. Never force-push, reset main
or merge private history to roll back. Record safe outcomes and remaining defects.

## Recovery matrix (owner action, not automatic cross-service rollback)

| Failure/partial state | Safe response |
| --- | --- |
| Plan/tests/digest fail before public branch | No public update. Correct/review and replan; never waive a gate. |
| Public branch pushed but PR creation cancelled/fails | Inspect retained candidate branch; manually open the exact PR or separately authorize branch cleanup. Main is unchanged. |
| Public main merged, backend not yet accepted | Source is public but hosting must not auto-deploy. Inspect current services before a fresh exact-main dispatch. |
| Backend activation/health fails | Root script attempts rollback and fails the workflow. Confirm old service/transaction state; Pages is not eligible. |
| Backend accepted but Pages approval absent/rejected/cancelled | Compatible new backend remains with old frontend. Do not infer rollback from cancellation. Inspect live state before fresh dispatch. |
| Pages upload fails, succeeds without postflight, or postflight fails | Pages may already be active. Stop releases; inspect canonical ID and restore known-good Pages **and Function**, then backend only if compatible. |
| Approval waits while main advances | Recheck refuses stale SHA. Replan/review the new public base; do not redeploy stale inputs. |
| Repeat same release | Fresh dispatch + CI/artifacts + both approvals. Reproducible backend archive permits immutable-release reuse; Pages may create a new deployment ID. |
| Wait timeout/cancellation during pull/activation | A published signature remains eligible until expiry/root revocation; backend may activate later. Pages stays blocked. Inspect backend transaction/high-water/journal and canonical Pages state, then fresh dispatch/CI/both approvals; never replay old approval or delete intent markers. |

No workflow can atomically lock GitHub main, the host and Cloudflare. A final
read-only check narrows but cannot remove the external-operation race. Freeze owner
merges/settings/manual deployments throughout rollout. Reconcile public changes
through a new fast-forward PR; never roll Git history backward.

## Deployment readiness checklist

**Implemented and offline-tested**: explicit SHA/digest selection, public-only
snapshot ancestry, immutable producer artifact IDs, approval-history/first-attempt
gates, backend-first dependency, revision/API probes, canonical Pages and HTML checks,
root-script failure recovery, secret-free application tests. Release-related Actions
are pinned to reviewed commit IDs; Wrangler and transitives use the committed lockfile.
The credentialed Pages runner installs tools with lifecycle scripts disabled.

**Requires manual configuration/owner verification (not performed)**:

- [ ] Install the private dispatch workflow on the actual default branch through
  the narrowly scoped bootstrap procedure, and the reviewed controller on dev.
- [ ] Protect private workflow/manifest administration; provision the public-only
  publication App without main bypass. Confirm App installation permissions and
  public PR CI triggering; keep publication disabled until ready.
- [ ] Public default branch is main and exposes the reviewed dispatch workflow.
  Protect main with PR/strict trusted CI, zero required approving reviews, no
  auto-merge/force push/deletion/admin bypass. Restrict merge and settings authority.
- [ ] Both public environments have sole reviewer ALEXRUZI, self-review allowed,
  no bypass/additional custodian, exact main **branch** policy and separate secrets.
  Confirm GITHUB_TOKEN can read environment/run/review metadata; leave disabled if
  metadata is unavailable, rather than granting CI an administrator credential.
- [ ] Provision independent production signing key/root public pin and Cloudflare credentials;
  inventory/revoke previous production-capable development credentials separately.
- [ ] Verify outbound API/CDN access, installed checksum-pinned root helper and pull code,
  root-owned key/policy/high-water state, removal of deploy sudo/SSH grants, accounts,
  systemd/SELinux, loopback/HTTPS ingress; check-only then separately authorize timer.
- [ ] Verify existing Pages account/project/domains, disabled automatic production
  and preview Git builds, no Deploy Hooks, HTTPS BACKEND_ORIGIN and secret binding.
- [ ] Record old/new API compatibility and rollback window; retain compatible backend
  archives/digests, Pages IDs **including Functions**, configuration backup references
  and authorized operator recovery access beyond artifact expiry.
- [ ] Resolve or explicitly accept the documented node-forge risk before release.
  A green bundle guard is not a security-exception approval.

**Requires a separately authorized real first deployment**: owner self-approval UX
at both checkpoints, actual Actions metadata permissions, signed-release/CDN interoperability,
service revision/ingress, Cloudflare upload/settings/binding preservation, domain
propagation and rollback rehearsal. No live environment or setting is certified by
these offline tests; the owner has not authorized any production release.
