#!/bin/bash
# Install as /usr/local/sbin/toolbox-backend-deploy, owned by root, mode 0755.
# sudo may delegate this specific script to the dedicated toolboxdeploy account.
set -Eeuo pipefail
umask 022
# These are trusted installation paths, not caller-configurable test hooks.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME

app_root=/opt/toolbox-api
releases="$app_root/releases"
current="$app_root/current"
incoming=/var/lib/toolbox-deploy/incoming
service=toolbox-api.service
health=http://127.0.0.1:3001/healthz
staging=''
nextlink=''
private_archive=''
npm_build=''
previous=''
new_release=''
activation_pending=0
verified=0
transaction="$app_root/.deployment-transaction"
transaction_tmp=''

diagnostic() {
  printf '%s\n' "$*" >&2 || :
  # Fixed local journal/syslog metadata survives loss of the SSH output channel.
  # Never log EnvironmentFile contents, npm environment or raw systemd properties.
  if command -v logger >/dev/null; then
    logger --tag toolbox-backend-deploy -- "$*" 2>/dev/null || :
  fi
}
fail() { diagnostic "ERROR: $*"; exit 1; }
cleanup() {
  if [[ -n "$nextlink" && -L "$nextlink" ]]; then rm -f -- "$nextlink"; fi
  if [[ -n "$staging" && -d "$staging" ]]; then rm -rf -- "$staging"; fi
  if [[ -n "$npm_build" && -d "$npm_build" ]]; then rm -rf -- "$npm_build"; fi
  if [[ -n "$private_archive" && -f "$private_archive" ]]; then rm -f -- "$private_archive"; fi
  if [[ -n "$transaction_tmp" && -f "$transaction_tmp" ]]; then rm -f -- "$transaction_tmp"; fi
}

health_ok() {
  systemctl is-active --quiet "$service" || return 1
  curl --disable --noproxy '*' --fail --silent --show-error --max-time 3 "$health" \
    | /usr/bin/node -e 'let b="";process.stdin.on("data",x=>{b+=x;if(b.length>4096)process.exit(1)});process.stdin.on("end",()=>{try{const j=JSON.parse(b);process.exit(j.status==="ok"&&j.service==="toolbox-api"?0:1)}catch{process.exit(1)}})' \
    >/dev/null
}

verify_after_restart() {
  local attempt
  for ((attempt=1; attempt<=12; attempt++)); do
    if health_ok; then return 0; fi
    sleep 2
  done
  return 1
}

restart_and_verify() {
  timeout --kill-after=10s 120s systemctl restart "$service" && verify_after_restart
}

rollback() {
  local active
  active="$(readlink -f -- "$current")" || return 1
  # Never overwrite an unexpected operator change. The lock serializes this script.
  [[ "$active" == "$previous" || "$active" == "$new_release" ]] || return 1
  if [[ "$active" != "$previous" ]]; then
    nextlink="$app_root/.current-rollback-$$"
    ln -s "${previous#"$app_root/"}" "$nextlink" || return 1
    mv -Tf -- "$nextlink" "$current" || return 1
    nextlink=''
  fi
  restart_and_verify || return 1
  rm -f -- "$transaction" || return 1
  diagnostic "ROLLBACK SUCCEEDED: restored $previous"
  return 0
}

finish() {
  local status="$1"
  # EXIT owns all recovery/cleanup. Ignore further catchable signals during recovery;
  # do not recurse into traps or let a second disconnect interrupt rollback.
  trap - EXIT
  trap '' TERM HUP INT
  set +e
  if ((activation_pending && !verified)); then
    ((status != 0)) || status=1
    diagnostic "ERROR: Activation failed/interrupted (exit $status); restoring $previous."
    if ! rollback; then
      diagnostic 'CRITICAL: Rollback failed. Transaction and both releases retained; operator recovery required.'
    fi
  fi
  if ((status != 0)); then
    diagnostic "Deployment failed (exit $status); candidate=$new_release previous=$previous. Inspect restricted journalctl -u $service; no release was deleted."
  fi
  cleanup
  exit "$status"
}
trap 'finish "$?"' EXIT
# A disconnected SSH channel can close stderr/stdout too. Logging failure must
# not kill the recovery shell or turn a successful rollback into a failed one.
trap '' PIPE
trap 'printf "ERROR: Received TERM.\n" >&2 || :; exit 143' TERM
trap 'printf "ERROR: Received HUP.\n" >&2 || :; exit 129' HUP
trap 'printf "ERROR: Received INT.\n" >&2 || :; exit 130' INT

[[ "$EUID" -eq 0 ]] || fail 'Run through the restricted sudo rule as root.'
[[ "$#" -eq 2 ]] || fail 'Usage: toolbox-backend-deploy <40-hex-commit> <64-hex-archive-sha256>'
sha="$1"
expected_digest="$2"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail 'Invalid commit SHA.'
[[ "$expected_digest" =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid SHA-256 digest.'
for command_name in flock python3 runuser npm node systemctl curl sha256sum cp find timeout restorecon logger; do
  command -v "$command_name" >/dev/null || fail "Missing dependency: $command_name"
done

# A second deployment must not race the active symlink or service restart.
exec 9>/run/lock/toolbox-backend-deploy.lock
flock -n 9 || fail 'Another deployment is running.'

[[ -d "$app_root" && ! -L "$app_root" ]] || fail 'Application root must be a real directory.'
[[ -d "$releases" && ! -L "$releases" ]] || fail 'Missing root-controlled releases directory.'
[[ -L "$current" ]] || fail 'First-time systemd/symlink migration has not been completed.'
[[ "$(stat -c '%U' "$app_root")" == root ]] || fail 'Application root must be root-owned.'
[[ "$(stat -c '%U' "$releases")" == root ]] || fail 'Releases directory must be root-owned.'
writable_parents="$(find "$app_root" "$releases" -maxdepth 0 -perm /022 -print -quit)" || fail 'Cannot inspect release parent permissions.'
[[ -z "$writable_parents" ]] || fail 'Release parents must not be group/world writable.'
[[ "$(systemctl show -p User --value "$service")" == toolboxapi ]] || fail 'Unexpected systemd service account.'
[[ "$(systemctl show -p Group --value "$service")" == toolboxapi ]] || fail 'Unexpected systemd service group.'
[[ "$(systemctl show -p WorkingDirectory --value "$service")" == "$current" ]] || fail 'Service WorkingDirectory must point to current.'
exec_start="$(systemctl show -p ExecStart --value "$service")"
[[ "$exec_start" == *"$current/src/server.mjs"* ]] || fail 'Service ExecStart does not use current.'
[[ -f /etc/toolbox-api.env ]] || fail 'Existing production EnvironmentFile is unavailable.'
[[ "$(systemctl show -p EnvironmentFiles --value "$service")" == *"/etc/toolbox-api.env"* ]] || fail 'Service no longer declares expected EnvironmentFile.'
[[ -x /usr/bin/node ]] || fail 'Node executable missing at /usr/bin/node.'

previous="$(readlink -f -- "$current")" || fail 'Current release is invalid.'
valid_release_links() {
  # npm legitimately creates internal .bin links; none may escape the immutable
  # release into deploy-account-controlled paths, even if the link is root-owned.
  python3 -I - "$1" <<'PY'
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1]).resolve()
for directory, directories, files in os.walk(root, followlinks=False):
    for name in directories + files:
        path = pathlib.Path(directory, name)
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            try:
                path.resolve(strict=True).relative_to(root)
            except (ValueError, RuntimeError, OSError):
                raise SystemExit('Release contains an escaping, dangling or cyclic symlink')
        elif not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise SystemExit('Release contains an unsupported filesystem type')
PY
}
valid_release() {
  local found
  [[ "$1" == "$releases/"* && "${1#"$releases/"}" =~ ^([0-9a-f]{40}|legacy-[0-9]{8}T[0-9]{6}Z)$ && -d "$1" && ! -L "$1" ]] || return 1
  [[ "$(stat -c '%U' "$1")" == root ]] || return 1
  found="$(find "$1" -type d -perm /022 -print -quit)" || return 1
  [[ -z "$found" ]] || return 1
  found="$(find "$1" -type f -perm /022 -print -quit)" || return 1
  [[ -z "$found" ]] || return 1
  found="$(find "$1" ! -user root -print -quit)" || return 1
  [[ -z "$found" ]] || return 1
  valid_release_links "$1" || return 1
}
valid_release "$previous" || fail 'Current target is not a root-controlled direct release.'
# A durable intent record covers SIGKILL/power loss, which no shell trap can catch.
# Recover on the next invocation and fail that invocation; a fresh approval/retry
# is required. Never continue deploying over an unresolved transaction.
if [[ -e "$transaction" || -L "$transaction" ]]; then
  [[ -f "$transaction" && ! -L "$transaction" && "$(stat -c '%U' "$transaction")" == root ]] || fail 'Unsafe transaction record.'
  mapfile -t saved < "$transaction"
  [[ "${#saved[@]}" -eq 2 ]] || fail 'Malformed transaction record; operator recovery required.'
  previous="${saved[0]}"
  new_release="${saved[1]}"
  valid_release "$previous" && valid_release "$new_release" || fail 'Invalid interrupted transaction releases.'
  activation_pending=1
  fail 'Recovering an interrupted activation; redispatch only after recovery is verified.'
fi
incoming_archive="$incoming/backend-${sha}.tar.gz"
[[ -f "$incoming_archive" && ! -L "$incoming_archive" ]] || fail 'Release archive missing or is a symlink.'
# Freeze the uploaded bytes into a root-owned copy BEFORE verifying their hash.
# The SSH/deploy account must not be able to alter the verified archive.
private_archive="$(mktemp "$releases/.archive-${sha:0:12}.XXXXXXXX")"
chmod 600 "$private_archive"
python3 -I - "$incoming_archive" "$private_archive" <<'PY'
import os, stat, sys
with os.fdopen(os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as src:
    info = os.fstat(src.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
        raise SystemExit('Compressed archive is too large or not a regular file')
    with open(sys.argv[2], 'wb') as dst:
        total = 0
        while chunk := src.read(1024 * 1024):
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise SystemExit('Compressed archive is too large')
            dst.write(chunk)
PY
actual_digest="$(sha256sum -- "$private_archive" | cut -d' ' -f1)"
[[ "$actual_digest" == "$expected_digest" ]] || fail 'Release SHA-256 mismatch.'

new_release="$releases/$sha"
if [[ -e "$new_release" || -L "$new_release" ]]; then
  [[ -d "$new_release" && ! -L "$new_release" ]] || fail 'Release path is not a directory.'
  valid_release "$new_release" || fail 'Existing release is not root-controlled.'
  [[ -f "$new_release/.archive-sha256" && ! -L "$new_release/.archive-sha256" ]] || fail 'Existing release has no regular hash marker.'
  [[ "$(cat "$new_release/.archive-sha256")" == "$expected_digest" ]] || fail 'Existing release hash differs.'
  echo 'Reusing previously staged immutable release.'
else
  staging="$(mktemp -d "$releases/.staging-${sha:0:12}.XXXXXXXX")"
  # Untrusted tar input is parsed and extracted as regular files/directories only.
  # Never allow symlinks, hardlinks, absolute paths, traversal, or extra top-level files.
  python3 -I - "$private_archive" "$staging" <<'PY'
import gzip
import pathlib
import sys
import tarfile

archive, destination = sys.argv[1:]
seen = set()
files = set()
total_bytes = 0
# Bound the entire decoded tar, including PAX/extension headers and padding,
# before tarfile can allocate metadata from an attacker-controlled size field.
expanded_bytes = 0
with gzip.open(archive, 'rb') as decoded:
    while chunk := decoded.read(1024 * 1024):
        expanded_bytes += len(chunk)
        if expanded_bytes > 66 * 1024 * 1024:
            raise SystemExit('Expanded tar stream is too large')
with tarfile.open(archive, mode='r:gz') as src:
    for count, member in enumerate(src, start=1):
        if count > 512:
            raise SystemExit('Too many files in release archive')
        name = member.name.rstrip('/') if member.isdir() else member.name
        parts = name.split('/')
        if (not name or any(p in ('', '.', '..') for p in parts)
                or name.startswith('/')
                or '\\' in name or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or not (name in ('package.json', 'package-lock.json', 'src')
                        or name.startswith('src/'))):
            raise SystemExit('Unexpected archive path')
        if name in seen:
            raise SystemExit('Duplicate archive member')
        seen.add(name)
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            raise SystemExit('Unsupported archive member type')
        if (member.sparse is not None or any(k.startswith('GNU.sparse') for k in member.pax_headers)):
            raise SystemExit('Sparse archive members are not supported')
        if (name in ('package.json', 'package-lock.json') and not member.isfile()
                or name == 'src' and not member.isdir()):
            raise SystemExit('Unexpected archive member shape')
        target = pathlib.Path(destination).joinpath(*parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(0o755)
            continue
        total_bytes += member.size
        if total_bytes > 64 * 1024 * 1024 or member.size < 0:
            raise SystemExit('Archive is too large')
        target.parent.mkdir(parents=True, exist_ok=True)
        stream = src.extractfile(member)
        if stream is None:
            raise SystemExit('Missing file contents')
        with target.open('xb') as output:
            remaining = member.size
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise SystemExit('Truncated file contents')
                output.write(chunk)
                remaining -= len(chunk)
        target.chmod(0o644)
        files.add(name)
if not {'package.json', 'package-lock.json', 'src/server.mjs'} <= files:
    raise SystemExit('Required backend files missing')
PY
  # Install dependencies separately as toolboxdeploy so npm lifecycle scripts
  # cannot change the verified application source or package manifests.
  npm_build="$(mktemp -d "$releases/.npm-${sha:0:12}.XXXXXXXX")"
  cp -- "$staging/package.json" "$staging/package-lock.json" "$npm_build/"
  chown -R toolboxdeploy:toolboxdeploy "$npm_build"
  # Drop all inherited environment (including any accidental application secret).
  # Close the lock descriptor in dependency processes; only this root shell owns it.
  runuser -u toolboxdeploy -- env -i PATH="$PATH" HOME="$npm_build" \
    sh -c 'cd "$1" && npm ci --omit=dev --no-audit --no-fund && npm ls --omit=dev --depth=0' sh "$npm_build" 9>&-
  [[ -d "$npm_build/node_modules" ]] || fail 'Dependency installation produced no node_modules.'
  [[ ! -L "$npm_build/node_modules" ]] || fail 'Dependency root must not be a symlink.'
  cp -a -- "$npm_build/node_modules" "$staging/node_modules"
  rm -rf -- "$npm_build"
  npm_build=''
  /usr/bin/node --check "$staging/src/server.mjs"
  printf '%s\n' "$expected_digest" > "$staging/.archive-sha256"
  # npm ran as toolboxdeploy and cp -a retains that ownership. Relinquish
  # ALL dependency-tree ownership before publishing the release, otherwise
  # the SSH deployment identity can modify the code the service executes.
  chown -hR root:root "$staging"
  # mktemp starts the staging root at 0700. Set traversable/readable modes
  # for the unprivileged toolboxapi service; retain executable mode on bins.
  find "$staging" -type d -exec chmod 0755 {} +
  find "$staging" -type f -exec chmod go-w,a+r {} +
  valid_release_links "$staging" || fail 'Dependency tree is not self-contained.'
  mv -T -- "$staging" "$new_release"
  staging=''
fi
# Label the FINAL path: local SELinux fcontext rules may differ for staging.
restorecon -R "$new_release"

if [[ "$previous" == "$new_release" ]]; then
  health_ok || fail 'Already active release is unhealthy.'
  echo "Already deployed $sha. No restart necessary."
  exit 0
fi

# Record activation intent BEFORE the atomic switch. A signal between mv and the
# next shell statement still causes rollback; completed releases are never cleanup targets.
transaction_tmp="$(mktemp "$app_root/.transaction.XXXXXXXX")"
chmod 600 "$transaction_tmp"
printf '%s\n%s\n' "$previous" "$new_release" > "$transaction_tmp"
activation_pending=1
mv -T -- "$transaction_tmp" "$transaction"
transaction_tmp=''
# Atomic symlink replacement; the previous version remains untouched.
nextlink="$app_root/.current-next-$$"
ln -s "releases/$sha" "$nextlink"
mv -Tf -- "$nextlink" "$current"
nextlink=''

[[ "$(readlink -f -- "$current")" == "$new_release" ]] || fail 'Active link changed unexpectedly.'
if restart_and_verify; then
  [[ "$(readlink -f -- "$current")" == "$new_release" ]] || fail 'Active link changed during verification.'
  # Only verified releases can escape rollback. If removal is interrupted, the
  # retained intent causes conservative recovery on the next invocation.
  verified=1
  rm -f -- "$transaction"
  echo "DEPLOYED: $sha (archive SHA-256: $expected_digest)"
  exit 0
fi

fail 'New release failed restart or health verification.'
