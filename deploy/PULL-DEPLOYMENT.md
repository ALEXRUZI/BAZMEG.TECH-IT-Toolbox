# Pull-only production backend: installation and operations

**Repository implementation only. Nothing has been installed, enabled or deployed.**
The timer must remain disabled until the owner completes this checklist. This
runbook is public-safe; do not put host inventories, credentials or backups here.

## Architecture and authorization

The private curated snapshot → public PR → protected main process is unchanged.
Public main requires `frontend`, `backend`, `deployment-regressions`, PRs, zero
required approving reviews, owner manual merge, no force push/deletion/bypass.
Only ALEXRUZI can dispatch Production deployment with exact current main SHA.
First-attempt/live-run, environment identity, sole owner approval, main-only policy,
protected-branch, receipt and complete CI checks remain mandatory.

Unprivileged jobs test committed source and create deterministic `git archive`
with commit-time metadata and `gzip -n` (16 MiB maximum). Immutable Actions artifact
IDs identify the exact producer. A **fresh** hosted `production` job rechecks owner
approval and signs, then creates a unique draft GitHub Release with exactly three
assets and publishes it only after upload. Only this job has `contents: write`.
Before the signing step exposes its key, this job independently verifies the committed
receipt, reconstructs the archive from a fresh checkout's immutable Git objects and
compares both archive and snapshot digests with the producer. No npm/application code
runs here; build/test output alone cannot choose the signed artifact bytes.
No root key, SSH identity or backend application secret goes to build/test jobs.
No GitHub job delivers artifacts to the backend or invokes a host command.

The backend initiates outbound HTTPS. Root orchestrates one serialized operation;
`runuser` executes discovery/download in an empty environment as `toolboxdeploy`.
The child authenticates the candidate **before downloading the archive**. Root
independently freezes bounded regular-file bytes into memory, verifies signature,
archive size/hash and sequence policy, then durably reserves the authorization.
Root stages through an opened `O_NOFOLLOW` directory descriptor. The existing
checksum-pinned helper independently freezes/hashes again, validates/extracts bounded
archives, installs dependencies as toolboxdeploy, publishes root-owned immutable
releases, switches current atomically, restarts and verifies/rolls back.
A staging substitution can cause refusal, never acceptance of different bytes.
Root, the independently provisioned key/policy, trusted workflow administration,
OpenSSL/OS and reviewed dependencies remain trust boundaries.

GitHub Releases/tags/assets/API/ETags are untrusted distribution hints, **not approval**.
The signing key is the authorization authority. Possession of that key could forge
owner evidence; GitHub environment protection is what confines its legitimate use.
Protect owner account, workflow code and environment administration accordingly.

## Canonical signed protocol (schema 1)

`release_protocol.py` is shared by signer and both verifiers. Manifest is ASCII JSON,
sorted keys, no spaces, ASCII escapes, exactly one final LF. Duplicate keys, extra
fields, alternate whitespace/encoding and unsupported schema/algorithm fail exact
byte comparison **before** OpenSSL verifies those same bytes. Integers are positive,
non-boolean, less than 2^63. Detached signature is exactly 64 raw Ed25519 bytes:

```sh
openssl pkeyutl -sign -rawin -inkey PRIVATE -in manifest.json -out manifest.sig
openssl pkeyutl -verify -pubin -rawin -inkey PINNED_PUBLIC -in manifest.json -sigfile manifest.sig
```

Fields: `schema=1`, `algorithm=Ed25519`, exact `repository`, public `commit`,
publication receipt's SHA-256 `snapshot`, `sequence` (workflow `run_number`), `run`
(`run_id`), `attempt=1`, fixed `workflow`, `owner=ALEXRUZI`, `environment=production`,
`key`, archive `size`, `sha256`, `archive=backend-<commit>.tar.gz`,
`release=production-<sequence>-<run>-<commit>`, Unix `issued` and `expires`.
Authorizations expire after 24 hours; future issue time permits only 60 seconds of
clock skew. Accurate synchronized host/runner clocks are prerequisites. Expiry is
checked again by root immediately before acceptance. Expiry never stops an already
accepted service. A new dispatch/approval is required after expiry.

Sequence orders approvals, **not commit SHAs or GitHub timestamps**. Never reset
the workflow run-number lineage or local high-water state. Old/out-of-order approvals
cannot supersede higher accepted/reserved sequences. Duplicate active authorizations
are skipped without archive download/restart. Same-sequence competing identities
fail closed. Highest valid visible sequence is selected; listing is bounded to the
10 most recent releases. Flooding/hiding/deleting releases can deny discovery but
cannot authorize installation. Stale API/cache results cannot lower the high-water;
an unseen newer authorization cannot be inferred offline. Freeze merges/releases
during coordinated rollout. Transport does not prove completeness/freshness.

## Durable acceptance evidence and read-only API boundary

Root-private `/var/lib/toolbox-pull/state.json` remains root:root 0600 in a 0700
directory. New records additionally retain an `authorization` object derived solely
from the root-verified frozen manifest: release, decimal-text sequence, commit,
archive SHA-256, canonical manifest SHA-256 and signing key ID. Legacy high-water
records remain valid, but cannot be promoted into evidence without a fresh approval.

The separate `/var/lib/toolbox-release/accepted.json` projection is root:root 0644
in a root:root 0755 real directory with root-controlled, non-writable ancestors.
It contains only `schema:1` and that authorization object's fields, no secrets,
paths, policy or token. Local users may read this non-sensitive metadata; neither
toolboxapi nor toolboxdeploy can write/replace it or its parents. Never expose or
relax the private state directory to the application. Audit ACLs/supplemental groups
and labels as well as modes; application code must remain immutable/root-owned.

Ordering is deliberately fail-closed:

1. Root verifies signature/expiry, archive bytes, eligibility and helper checksum.
2. Root atomically replaces evidence with JSON `null` and fsyncs file/directory,
   **before** durable pending/high-water reservation and helper activation.
3. The unchanged checksum-pinned helper verifies local health, or rolls back and
   returns failure. Same-commit activation checks health without restarting Node.
4. Root rechecks manifest expiry, durably commits `pending:false` with the exact
   authorization, then publishes the read-only projection using a fresh inode,
   fsync, rename and directory fsync. SELinux restorecon labels the temporary inode
   **before** rename; approved fcontext rules must cover all directory entries.

Failure/interruption after invalidation and before step 4 leaves no success proof.
Refusal before invalidation may retain only the previously accepted authorization,
which cannot satisfy a different run. A projection lost after durable acceptance
leaves unknown; unattended polling never rebuilds evidence
from state, GitHub metadata or files left by the download account. Inspect storage
and request a fresh higher-sequence authorization. No two-file transaction or
hardware durability beyond filesystem fsync guarantees is claimed. Never manually
copy state into evidence or use pending recovery to certify successful acceptance.
If interruption occurs after the final projection rename, readers may see that
completed record: activation, health and durable acceptance have already finished.
It is never evidence of a pending/failed activation. A final directory-fsync error
requires operator inspection even if that valid accepted record is visible.

Authenticated `/api/release` keeps startup-loaded revision/archive/contract and
adds `authorization` (see [API contract](../docs/API.md)). It reopens evidence on
every request, so newly accepted same-commit authorizations are immediately visible
without restart. The reader rejects unsafe ancestors, symlinks, nonregular/multiply
linked files, non-root ownership, write permissions, oversized/malformed records,
wrong commit/archive/current target and unresolved helper transactions. It reads
one opened inode with O_NOFOLLOW/O_NONBLOCK and fstat, not stat-then-read-by-path.
Missing/inaccessible evidence (including SELinux denial) reports null, never cached
old success. The API is trusted operational evidence, not remote attestation against
compromised root, application runtime, ingress or workflow administration.

## Signing-key provisioning (owner operation, not performed)

1. Keep `TOOLBOX_PRODUCTION_ENABLED` unset/false until full readiness. Provision
   public `production` and `production-pages`, main **branch** only, sole required
   reviewer User ALEXRUZI, Prevent self-review disabled, administrator bypass disabled.
   Verify run/approval APIs are readable with the workflow token; never add admin PATs.
2. Generate a dedicated production Ed25519 key on a trusted offline/admin machine:

   ```sh
   umask 077
   openssl genpkey -algorithm Ed25519 -out production-signing-private.pem
   openssl pkey -in production-signing-private.pem -pubout -out production-signing-public.pem
   openssl pkey -pubin -in production-signing-public.pem -outform DER | sha256sum
   ```

   Store the **private** PEM only in public `production` environment secret
   `PRODUCTION_RELEASE_SIGNING_KEY` (and restricted off-repository recovery storage).
   Set environment variable `PRODUCTION_RELEASE_KEY_ID=production-2026`. Never upload
   private files to artifacts/releases or put these in private dev/preview secrets.
   GitHub runner temp private key is mode 0600 and removed in `finally`; this is not
   guaranteed memory/disk erasure. Ephemeral runner/secret administration is trusted.
3. Deliver only the public PEM through an independently authenticated operator path.
   Compare its DER SHA-256 fingerprint on the backend with the independently recorded
   value. Do **not** bootstrap trust from a release download or unauthenticated message.
4. Delete/revoke obsolete public production SSH environment secrets and host deployment
   authorized keys under separate cutover authorization. Remove the old toolboxdeploy
   sudoers activation grant using `visudo`; confirm `sudo -l -U toolboxdeploy` grants
   no activation/admin commands. Do not change development SSH workflows/identities.
   The new agent needs **no sudo grant**. Restrict interactive deployment login using
   existing operator policy without impairing root recovery access.

`PRODUCTION_PAGES_URL` must be a **repository variable** too, because credential-free
acceptance has no environment. Pages environment retains its origin/project variables,
Cloudflare token/account secrets and separate approval. No job gets `BACKEND_SECRET`.
Do not change Pages project, DNS, domains, integration, disabled Git automatic/preview
builds, deploy-hook controls, Function authentication or pinned Wrangler toolchain.

## Read-only Oracle Linux 10.2 preflight

Use approved operator access, not a GitHub runner. Do not print env files/tokens.

```sh
getenforce
id toolboxdeploy
id toolboxapi
systemctl is-active toolbox-api.service
systemctl show toolbox-api.service -p User -p Group -p WorkingDirectory -p ExecStart -p EnvironmentFiles
readlink -f /opt/toolbox-api/current
stat -c '%U:%G %a %n' /opt/toolbox-api /opt/toolbox-api/releases /usr/local/sbin/toolbox-backend-deploy
sha256sum /usr/local/sbin/toolbox-backend-deploy
command -v python3 openssl node npm runuser timeout flock restorecon curl logger
python3 --version
openssl version
timedatectl status
ls -ldZ /var/lib/toolbox-deploy /var/lib/toolbox-deploy/incoming /opt/toolbox-api/releases
findmnt -T /opt/toolbox-api
sudo -l -U toolboxdeploy
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:3001/healthz
```

Require Python 3.9+ (Oracle Linux platform Python), OpenSSL 3 Ed25519 support, Node 22
at `/usr/bin/node`, existing helper dependencies and sufficient space for separate
node_modules per release. Preserve existing toolbox-api unit/drop-ins, loopback/HTTPS
ingress and `/etc/toolbox-api.env` verbatim. No migration/restart of the healthy
legacy release is needed. Expected helper SHA-256:
`e5f973abdc73e886f00f07ea2bed449214f384d8897e13566fe99d9488fe23ac`.
`sha256sum deploy/toolbox-backend-deploy.sh` must match too. **No helper update is
required or performed**. A mismatch blocks activation: investigate, don't overwrite
or update the pin blindly. Helper schema/limits/tests remain the compatibility gate.

Verify root owns immutable release parents with no group/world write; toolboxdeploy
and toolboxapi cannot modify agent, policy, pins, state or releases. Audit supplemental
groups, ACLs and writable ancestors as well as Unix modes. Root path checks do not
substitute for an ACL/SELinux audit. Check expected labels with `matchpathcon` and
`restorecon -nRv`; do not disable SELinux or grant broad allow rules to pass preparation.
Review AVCs and local policy with the host administrator if service execution is denied.

## Non-destructive installation (root, approved preparation only)

Start in a separately verified public checkout copied through the operator channel.
Verify its publication receipt/committed source and independently approved patch hashes.
No remote install pipe, automated host write, application secret change or restart.
Abort on **any** existing destination (including dangling links); inspect existing
installations rather than replacing them. These commands prepare only new files:

```bash
set -Eeuo pipefail
for p in /usr/local/libexec/toolbox-pull /etc/toolbox-pull /var/lib/toolbox-pull /var/lib/toolbox-release \
  /etc/systemd/system/toolbox-pull.service /etc/systemd/system/toolbox-pull.timer; do
  if [[ -e "$p" || -L "$p" ]]; then echo 'STOP: destination already exists'; exit 1; fi
done
install -d -o root -g root -m 0755 /usr/local/libexec/toolbox-pull /etc/toolbox-pull
install -d -o root -g root -m 0700 /var/lib/toolbox-pull
install -d -o root -g root -m 0755 /var/lib/toolbox-release
install -o root -g root -m 0644 deploy/release_protocol.py deploy/toolbox-pull.py /usr/local/libexec/toolbox-pull/
install -o root -g root -m 0644 deploy/pull-policy.example.json /etc/toolbox-pull/policy.json
# production-signing-public.pem is the independently delivered/fingerprint-verified PUBLIC key.
install -o root -g root -m 0644 production-signing-public.pem /etc/toolbox-pull/production-2026.pem
install -o root -g root -m 0644 deploy/toolbox-pull.service deploy/toolbox-pull.timer /etc/systemd/system/
# Exclusive creation: never reset an existing high-water record.
python3 -I - <<'PY'
import json, os
path = '/var/lib/toolbox-pull/state.json'
with open(path, 'x') as output:
    os.chmod(path, 0o600)
    json.dump({'sequence': 0, 'pending': False}, output)
    output.write('\n')
    output.flush()
    os.fsync(output.fileno())
PY
restorecon -Rv /usr/local/libexec/toolbox-pull /etc/toolbox-pull /var/lib/toolbox-pull /var/lib/toolbox-release
restorecon -v /etc/systemd/system/toolbox-pull.service /etc/systemd/system/toolbox-pull.timer
systemd-analyze verify /etc/systemd/system/toolbox-pull.service /etc/systemd/system/toolbox-pull.timer
systemctl daemon-reload
systemctl is-enabled toolbox-pull.timer || true
systemctl is-active toolbox-pull.timer || true
```

The last two commands must show disabled/inactive. **Do not enable/start either
unit during preparation.** Agent mode is fixed-path root orchestration, no caller
destination/helper/key argument. Network operations run as toolboxdeploy; no root
network listener exists. Root does not inherit an application EnvironmentFile.
`ProtectSystem=full`, private tmp, protected home, empty child environment and
NoNewPrivileges preserve legitimate helper writes/systemctl/runuser operation.
The wrapper is not a root sandbox: `/opt` and `/var` writes are necessary. Verify
systemd/runuser/PAM/SELinux on the actual OL10.2 host before authorization.

Before first activation, the host administrator must verify `matchpathcon` and
`ls -ldZ` for the evidence directory and a disposable root-created `.pull-*` inode.
If existing policy cannot permit the pull service's root writer/rename and the
toolbox-api domain's read/search, install a narrowly reviewed persistent fcontext
mapping for `/var/lib/toolbox-release(/.*)?` and, only if necessary, minimal local
policy. The type is host-policy-specific; do not blindly choose a type, disable
SELinux or broaden application write access. Run restorecon, verify toolboxapi can
read but cannot create/write/rename there, and inspect AVCs. Do not give toolboxapi
read/search access to `/var/lib/toolbox-pull`. New evidence is absent until genuine
acceptance; preparation must not synthesize a successful record.

Policy must explicitly bound key sequence ranges and revoke obsolete keys. Bootstrap
`sequence:0` is allowed **only** after independently verifying no earlier signed
production history exists. Otherwise provision the known high-water floor (no
`release` at that floor means an equal candidate is refused). Never reconstruct a
lower floor from stale GitHub listings or delete state on reinstall/restore.

For upgrades: disable the timer, wait for the oneshot/helper and locks to clear,
record active/high-water/pending state, backup only root code/units/policy to restricted
storage, compare independently approved SHA-256s, install into a new root-owned
versioned libexec directory, verify, then separately approve switching unit ExecStart.
Do not overwrite the helper, keys, state, units, app data or secrets automatically.
Keep rollback copies and timer disabled until check-only qualification is repeated.

## Polling, ETags and optional read credential

`OnCalendar=*-*-* *:*:00`, `AccuracySec=1s`, plus `OnBootSec=60s` schedules minute
boundaries and a boot check. Persistent=false means no missed-event backlog. systemd
never starts a second copy of an active oneshot. Events during installation are
coalesced, not queued; discovery resumes at a later minute boundary. Root nonblocking
flock covers the whole operation; the unchanged helper retains its separate lock.
Normal discovery latency is approximately 0–61 seconds, excluding outage/backoff,
system load, verification and installation. No unconditional five-minute polling.

One conditional Releases API request per check, at most ten visible candidates;
accepted/older identities skip asset downloads. Validated ETag is reused for 304
responses with cached bounded release listings. Metadata is reauthenticated before
any install. The serialized hint cache caps at 2 MiB; Unicode expansion beyond that
discards only listing/ETag hints, preserving rate backoff and root acceptance state.
Redirects are manually limited to three transitions; HTTPS 443 only, no credentials,
API repository path restricted, GitHub repository download paths
restricted and only `release-assets.githubusercontent.com` as the CDN. Default TLS
certificate/hostname verification remains enabled. Proxies from environment are
disabled. Optional token is sent only to api.github.com, never CDN redirects.
Each socket operation has a 20-second timeout; the whole retrieval child is bounded
by GNU timeout (230 seconds plus 5 seconds kill grace). Archive is at most 16 MiB;
manifest 8192 bytes, signature 64 bytes, listing 1 MiB. Root checks frozen bytes
again. The helper enforces 66 MiB decoded tar, 64 MiB file data, 512 entries, required
files, no links/sparse/devices/traversal/duplicates/unexpected paths.

Unauthenticated public API typically permits only **60 requests/hour per egress IP**;
one-minute checks consume the entire budget and shared egress can exhaust it sooner.
Conditional requests are not a reliable unauthenticated rate-limit exemption.
For reliable minute polling, provision an optional fine-grained token restricted to
the public repository, contents **read only**, metadata read, no other write/admin
permissions. A token is not deployment authority. Confirm current GitHub public-resource
token semantics and remaining budget on the host. Use expiry/rotation; do not grant
classic broad `repo` scope. Have the operator securely create
`/var/lib/toolbox-deploy/github-read-token` as toolboxdeploy:toolboxdeploy 0600 (never
echo token into shell history, logs, code or commands). Do not put it in app secrets.
No token is required for basic public discovery/download.

403/429 and 503 Retry-After honor integer/date delay and primary reset, conservatively
clamped to 24 hours (bad headers default one hour). A successful response reporting
remaining=0 delays further polls to reset. Other failures exponentially back off
120 seconds to one hour. No immediate retries or unlimited loops. Subsequent timer
events may perform a local backoff check rather than HTTP. Cache/backoff is untrusted
account-owned `/var/lib/toolbox-deploy/pull-cache.json`; its manipulation can deny
service but cannot bypass root authorization. Root acceptance state is separate.
After an outage, the next successful eligible poll resumes discovery; active service
is never stopped because GitHub is unavailable. Releases older than 24 hours require
fresh owner dispatch/approval, not an expiry override.

## Check-only and controlled first activation

1. Finish publication/CI, owner GitHub protections, key pin/fingerprint, host ACL/SELinux,
   legacy health, sudo/SSH cutover, backup/rollback and Pages compatibility reviews.
   Set GitHub enablement only after these checks. Keep timer disabled initially.
2. Explicitly authorize a **test discovery window**: owner dispatch exact public main,
   approve `production`. Signing publishes the first installable release. This does
   not install it while the host timer is disabled. The waiting job may time out.
3. As root, manually validate without activation:

   ```sh
   /usr/bin/python3 -I /usr/local/libexec/toolbox-pull/toolbox-pull.py --check
   ```

   Require `authenticated candidate; check-only` (not merely `no new ...`). It verifies
   live discovery, signature, root pin, exact archive bytes and sequence without state
   reservation, helper invocation or restart. Cache/download scratch may be written;
   scratch is cleaned, acceptance state is untouched. An offline/no-release check is
   **not** proof of authentication. Check-only is available only to root operators.
4. Obtain the owner's separate final host activation decision, verify authorization
   still unexpired and the existing service healthy, then and only then:

   ```sh
   systemctl enable --now toolbox-pull.timer
   systemctl list-timers toolbox-pull.timer
   journalctl -u toolbox-pull.service --since '-15 minutes' --no-pager
   ```

   This enables automatic activation of future correctly signed eligible approvals;
   it does not authorize arbitrary public-main commits. Do not directly enable the
   service (it has no Install section). First pull must log accepted identity; inspect
    root state `pending:false`, exact authorization/manifest digest in read-only evidence,
    current exact public SHA, `.archive-sha256`, active
   toolbox-api and exact local health, then authenticated external `/api/release`.
   Verify legacy release is retained, secrets/service identity/labels unchanged.
5. Wait for GitHub's bounded exact acceptance; approve `production-pages` separately.
   Verify canonical Cloudflare deployment ID, exact HTML and authenticated Function.
   Record release/run/sequence, archive/snapshot digests, pin fingerprint and Pages ID.
   Test direct unauthenticated backend rejection only under separately authorized live
   checks. Never place sensitive response bodies/screenshots in issue or CI artifacts.

## Acceptance, monitoring and failure recovery

`accept-backend` polls the existing public Pages Function at roughly 50-second waits,
maximum 30 attempts/25 minutes, independent Actions 30-minute timeout. Each probe is
bounded and verifies authenticated ping, exact `/api/release` commit/digest/contract
**and the current signed release/sequence/canonical manifest digest/signing key ID**,
four invalid-input compatibility envelopes and frontend availability. It gets no
application BACKEND_SECRET and never connects to a private backend address.
`production-pages` is eligible only after exact acceptance; it rechecks live owner
approval/current main, sealed artifact bytes, the same signed identity and compatibility **immediately
before** Wrangler upload, unchanged Cloudflare settings and postflight identity/HTML.
Use additive compatible APIs across the entire rollout/rollback window.

If GitHub times out/cancels but backend installs later, **Pages does not resume**.
Inspect backend and Pages, then fresh owner dispatch of current main, full CI,
fresh production approval/signature and separate Pages approval. Same SHA has the
same deterministic archive, so helper reuses the healthy immutable release without
restart. The old authorization still fails the new run's gate until root actually
verifies and durably accepts the new signed bytes. Workflow expectations come from
the actual signed manifest outputs, not tags or mutable Release metadata. Consumers
validate outputs, decimal sequence/current workflow run and exact SHA before probing.
A newly signed authorization is not a bypass of either review.
Cancellation cannot revoke a previously published signature; root revocation or
expiry prevents future acceptance, not rollback of an already running service.

Diagnostics: `systemctl status toolbox-pull.service toolbox-pull.timer`,
`journalctl -u toolbox-pull.service`, root-read `/var/lib/toolbox-pull/state.json`,
`readlink -f /opt/toolbox-api/current`, root-read active `.archive-sha256`, and
`journalctl -t toolbox-backend-deploy`. Logs report bounded fixed messages and safe
release IDs, not response bodies, signed CDN URLs, tokens or exceptions. Exit failure
is intentionally conservative: inspect clock, pins, policy, API/rate status and pending
state locally. Do not paste token/cache contents or application unit secrets into CI.
Each run reports last authorization sequence/identity and active release basename.
The wrapper's lock is root-only `operation.lock` beside the acceptance state. Before
using the unchanged helper it safely creates/checks the helper's root-owned fixed
lock, refusing symlinks or unsafe lock directories (writable directories must be
root-owned and sticky). This prevents local precreation attacks after reboot.
Multiply linked lock files are refused too, rather than trusting file ownership alone.
Raw helper/npm output is suppressed; the helper's fixed local logger diagnostics
remain available. On deadline the wrapper terminates the whole activation process
group with a 240-second rollback grace before force termination; pending state stays
set. This exceeds the helper's 130-second restart bound plus 60-second health loop.
systemd also terminates the control group with a four-minute stop grace.

Root uses fsync + atomic replace + directory fsync for high-water/pending records.
Before activation it writes `pending:true`; success alone clears pending. On failure,
reboot, partial write or unresolved helper transaction, unattended work stops. **Never
delete transaction/state markers to retry blindly.** Disable timer, wait for processes
and both locks, inspect helper journal and `.deployment-transaction`, active/previous
root-owned releases and exact health. Under explicit owner maintenance approval,
invoke the existing root helper with the reserved commit/digest to exercise its
interrupted-transaction recovery (first recovery invocation deliberately fails).
Before **any direct manual helper invocation**, including rollback, first create/check
its fixed lock using the installed agent's `secure_lock(Path('/run/lock/toolbox-backend-deploy.lock'))`
in a root Python context as shown for the operation lock below. Close that descriptor
before invoking the helper, which acquires its own flock. Refuse unsafe parents,
symlinks or non-root lock files; investigate rather than unlinking them blindly.
The automatic wrapper already performs this check. Keep timer stopped and permit
only one root maintenance operator while recovering.
Verify rollback succeeded; if not, use recorded restricted operator recovery paths.
Only after reconciliation, root may atomically clear `pending` while retaining the
reserved sequence, release and digest. Use a reviewed root Python operation equivalent
to this block, **only after explicit owner recovery authorization**, replacing the
placeholder with the recorded reserved release identity:

```sh
python3 -I - <<'PY'
import fcntl, importlib.util, json
from pathlib import Path
expected = 'REPLACE-WITH-RECORDED-PENDING-RELEASE'
spec = importlib.util.spec_from_file_location('pull', '/usr/local/libexec/toolbox-pull/toolbox-pull.py')
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
agent.trusted(agent.STATE)
with agent.secure_lock(agent.STATE.parent / 'operation.lock') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state = agent.validate_state(json.loads(agent.safe_read(agent.STATE, 8192, root=True)))
    assert state['pending'] is True and state['release'] == expected
    agent.evidence(None)  # recovery is not successful authorization acceptance
    state['pending'] = False
    agent.atomic(agent.STATE, state)
PY
```

This is fsynced, same-directory, mode 0600, with no sequence decrement. Next automated
attempt requires a **new higher-sequence owner dispatch/approval**, not replay.
Disk/fsync errors or restored stale backups require operator investigation, not a
state reset. Crash durability ultimately depends on filesystem/hardware guarantees.

## Manual rollback, key rotation and emergency revocation

Manual rollback is a distinct **root operator + owner maintenance authorization**,
not an automatic old-signature exception. Disable timer, wait for all work/locks,
record approval and high-water, select independently retained verified archive/digest
and compatible Pages version. Under the operation lock, call the installed agent's
`evidence(None)` **before any manual helper/symlink/service rollback or recovery**;
keep evidence null throughout maintenance and never reconstruct it from private
state. A root manual rollback is not acceptance of a signed release. Then invoke
the unchanged root helper as root with
that exact SHA/digest. It can reuse a retained immutable release. Keep anti-replay
high-water unchanged; never re-enable timer with a lowered state. Verify local health,
external revision/API compatibility and Pages/Function identity. For legacy recovery,
use recorded symlink/service maintenance recovery, never invent a public commit.
Root is already ultimate authority; toolboxdeploy has no way to request this override.
Prefer a new reviewed public revert commit plus fresh signed production approval for
normal rollback. Roll back Pages and its Function separately under owner authority;
do not automatically undo backend behind a potentially active new frontend.

For rotation: disable timer, independently deliver/fingerprint new public key,
add root policy with nonoverlapping `first`/`last` sequence ranges, bound old key's
last sequence to the cutover floor, and switch production secret/key-ID only after
host provisioning. Test both ranges offline/check-only, then authorize enablement.
Never allow a release to add its own key. Emergency: disable/stop the timer, **stop the
oneshot service too** and wait for helper recovery and both locks to clear; a timer
stop alone cannot cancel an in-flight authorization. Reconcile any pending transaction.
Then mark the compromised key revoked in root policy (or remove it), remove environment secret, revoke read token
if needed, inspect all approvals/active code, provision new independent key/ranges.
Keep high-water intact. Already accepted malicious code needs incident recovery,
not merely signature revocation. Restore trusted root state from independently
retained high-water evidence; if uncertain, leave disabled rather than bootstrap low.

Offline tests do not establish live owner-review UX/API permission, OL10.2 PAM/SELinux,
GitHub CDN behavior, real token quotas, storage durability, nginx/TLS ingress, Cloudflare
bindings, rollback timing or dependency supply-chain integrity. These are mandatory
manual acceptance checks, not claims of production readiness.
