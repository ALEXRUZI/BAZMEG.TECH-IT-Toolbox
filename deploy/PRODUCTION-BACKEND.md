# Versioned production backend: pull-only deployment

Prepared repository source only; no server installation or activation is implied.
Follow [PULL-DEPLOYMENT.md](PULL-DEPLOYMENT.md) for the complete Oracle Linux 10.2
read-only preflight, independent key fingerprint bootstrap, disabled-by-default
systemd installation, **60-second** discovery, manual check-only validation,
explicit enablement decision, diagnostics, key rotation/revocation and recovery.
See [production coordination](../docs/PRODUCTION.md) for GitHub and Pages approval.

GitHub signs/publishes only after ALEXRUZI's explicit production environment review.
The backend retrieves outbound as toolboxdeploy; root independently verifies pinned
Ed25519 authorization, exact archive bytes and durable monotonic acceptance state,
then invokes the unchanged root-owned versioned-release helper. GitHub never initiates
SSH/SCP/SFTP, and the host has no deployment listener or self-hosted Actions runner.
Do not grant toolboxdeploy sudo activation privileges. Preserve existing healthy
legacy installation, service identity/hardening, secrets, SELinux and rollback paths.

Pages remains separately owner-approved and blocked until exact backend revision,
archive digest, signed release/sequence/canonical manifest digest/signing key ID and
API compatibility pass through the existing authenticated Function. Root publishes
read-only acceptance evidence only after durable verified activation, and invalidates
it before new work. The API reads it per request; same-commit reauthorization needs
actual independent acceptance, not a restart. Pages rechecks immediately before upload.
No application BACKEND_SECRET is provided to GitHub. Source merges, tags, API metadata,
ETags and successful CI alone never authorize backend activation.

## Historical migration safeguard

The prepared host already has a healthy current link; do not repeat migration.
If a separately authorized operator ever recovers a pre-versioned installation,
copy/verify a root-controlled legacy release first and refuse every existing link:

```bash
# APP=/opt/toolbox-api; LEGACY is a separately copied, verified release basename.
if [[ -e "$APP/current" || -L "$APP/current" ]]; then
  printf 'STOP: current exists; inspect without overwriting.\n' >&2
  exit 1
fi
ln -sT "releases/$LEGACY" "$APP/current"
```

This is a guard reference, not an instruction or authorization to change a live host.
