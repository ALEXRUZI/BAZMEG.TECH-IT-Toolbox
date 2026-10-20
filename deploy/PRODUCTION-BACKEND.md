# Versioned production backend (operator runbook)

Prepared only: provisioning and activation require separate operator authorization.
See [production release coordination](../docs/PRODUCTION.md). No hostnames, keys,
environment files or private infrastructure configuration belong in this repository.

## Trust and prerequisites

The owner manually dispatches the public workflow on the exact approved main SHA.
It runs the full CI suite, verifies the publication
receipt, tests the backend, and archives only committed `backend/package.json`,
`package-lock.json` and `src/`. A separate ephemeral hosted deployment job receives
that immutable artifact only after approval of the `production` environment.
It never checks out or executes application code with SSH credentials available.
Queued deployments are rejected if their commit is no longer the public main tip.

Keep `TOOLBOX_PRODUCTION_ENABLED` unset until the owner verifies all protections.
Protect main, workflows and environments. Restrict the production
environment to main, require **ALEXRUZI as sole reviewer**, disable Prevent self-review
so the triggering owner can approve, and disable administrator bypass where available.
Require public PR/passing CI with zero approving reviews and owner manual merge.
No push deploys production. Variables and the receipt are not approval.
Use no PR/workflow_run/pull_request_target deployment entrypoint. Public PR CI is
unprivileged and uses only ephemeral hosted runners.

Provision **new, production-only** Ed25519 SSH credentials, unrelated to any old
development deployment identity. Store these only in the public repository's
`production` environment:

- `PRODUCTION_BACKEND_SSH_HOST`: verified hostname or IPv4 literal, no options/URL.
- `PRODUCTION_BACKEND_SSH_USER`: `toolboxdeploy`.
- `PRODUCTION_BACKEND_SSH_KEY`: new dedicated private key.
- `PRODUCTION_BACKEND_SSH_KNOWN_HOSTS`: independently verified host key lines.

No SSH credential or application `BACKEND_SECRET` goes into repository secrets
available to ordinary CI. Never use development/PR runners for production. The
operator must inventory and revoke any old development-controlled production key
under separate cutover approval; renaming GitHub secrets is not revocation. The
host must accept an approved secure hosted-runner network path; this is not yet
verified. If unavailable, record the connectivity blocker and leave disabled, without
weakening SSH/firewall restrictions or requiring an externally controlled runner.
Do not attach a persistent self-hosted runner to a public repository.

## Server preparation (not performed by Actions)

Independently inspect systemd, account permissions, expected SELinux contexts,
storage, ingress, health and secure backups. Node 22 must be at `/usr/bin/node`;
require npm, Python 3.8+, Bash, GNU utilities, `flock`, `curl`, `restorecon`,
`runuser`, `timeout` and `logger`. Keep SELinux enforcing. The application remains
bound to loopback; verified HTTPS ingress is an operator responsibility.

The fixed, reviewed server design is:

- `/opt/toolbox-api/releases/<public-commit>`: root-owned immutable releases.
- `/opt/toolbox-api/current`: root-controlled relative symlink into releases.
- `/etc/toolbox-api.env`: existing root-only secret environment; never uploaded,
  overwritten or made readable by the deployment account.
- `toolbox-api.service`: runs as `toolboxapi:toolboxapi`; preserve all existing
  hardening, restart policy and environment declarations.
- `/var/lib/toolbox-deploy/incoming`: writable only by the dedicated SSH account.
- `/usr/local/sbin/toolbox-backend-deploy`: reviewed copy of
  `deploy/toolbox-backend-deploy.sh`, root-owned 0755, immutable by deploy/runtime users.

Use a maintenance window and secured off-repository backups for first migration.
Copy the old source, manifests and dependencies to a fresh `legacy-<UTC timestamp>`
release **without moving/deleting the live files**. Normalize ownership, permissions
and expected SELinux labels on the copy. Before creating the initial link:

```bash
# APP=/opt/toolbox-api; LEGACY is the fresh, verified copied release identifier.
if [[ -e "$APP/current" || -L "$APP/current" ]]; then
  printf 'STOP: current exists; inspect without overwriting.\n' >&2
  exit 1
fi
ln -sT "releases/$LEGACY" "$APP/current"
```

Verify root controls both parent directories, with no group/world write. After
inspecting the entire existing service, add a new, previously absent systemd drop-in
changing **only** WorkingDirectory to `/opt/toolbox-api/current` and clearing/resetting
ExecStart to `/usr/bin/node /opt/toolbox-api/current/src/server.mjs`. Do not replace
the unit. Reload, verify, restart and require exact health JSON
`{"status":"ok","service":"toolbox-api"}`. If migration fails, restore the original
service paths by removing only the newly created drop-in, reload/restart/verify;
retain all copied releases/backups. Do not proceed while unhealthy.

Provision `toolboxdeploy` without Docker, runtime or admin group membership. It
must not modify release parents, current, the root script or the secret env file.
Install its new public key with restrictive SSH permissions and no forwarding,
agent forwarding, X11 or PTY (`restrict` authorized_keys option); constrain network
access where possible. Verify SFTP/SCP and only this root-owned sudo entry:

```sudoers
toolboxdeploy ALL=(root) NOPASSWD: /usr/local/sbin/toolbox-backend-deploy
```

Use root-owned sudoers mode 0440, env_reset and no SETENV; validate with visudo.
The script validates fixed paths/arguments and rejects unsafe/bounded archives.
Application code execution as `toolboxapi` is still a powerful deployment privilege.

## Activation, verification and rollback

The existing root script freezes and hashes uploaded bytes, validates bounded tar
contents, installs lockfile dependencies in a separate unprivileged directory with
an empty environment, then relinquishes ownership to root. The archive has no
secrets/tests/node_modules. It labels the final path, journals intent, atomically
switches current, restarts systemd and checks exact health JSON under a deployment
lock. Dependency installation requires approved npm registry access and lifecycle
script review. No application secret is passed to npm or Actions.

After a failed/interrupted activation it attempts restoration and verification of
the previous release, retaining both releases and failing the run. SIGKILL/crash
recovery is deferred to the next invocation via `.deployment-transaction`; this
is not a power-loss durability or unattended recovery guarantee. A failed rollback
requires restricted-journal/operator inspection; never delete the transaction to
bypass recovery. Releases are not automatically pruned.

For deliberate rollback, select the retained public-commit archive and digest from
the approved run (artifacts expire after 30 days; retain secure recovery copies).
With the same owner's maintenance approval, an operator may invoke the same installed
root script with that public SHA/digest after checking frontend/API compatibility.
Legacy release recovery requires the operator's recorded pre-migration procedure,
not an invented commit ID. Verify health, authenticated Pages ping and approved
diagnostics afterward. Do not force-push/reset Git or blindly retry deployments.

This is not zero downtime: restarts interrupt work and drop process-local caches
and rate history. Health alone does not prove authenticated ingress, outbound
diagnostics or compatibility. Follow [coordinated verification and rollback](../docs/PRODUCTION.md).
Authenticated `/api/release` must identify the executing release SHA/archive digest,
and bounded invalid-input probes must confirm the expected tool API contracts.
Only after successful backend/ingress verification does the owner approve frontend
upload of the same public SHA's immutable Pages assets and precompiled Function.
Pages has a distinct `production-pages` environment and Cloudflare credentials, never
the backend SSH environment. Both stages require one owner self-approval. Production
reruns are refused; recover by inspecting live state and freshly dispatching/approving.

## Offline checks

`python3 -B -m unittest discover -s deploy/tests -v` from the repository root, or
`npm test` in `backend/`, runs the offline deployment regression suite. It uses
temporary copies and command doubles, not production/systemd/root/network access.
`bash -n deploy/toolbox-backend-deploy.sh` checks shell syntax. A passing test is
not evidence that server migration or environment protection has been configured.
