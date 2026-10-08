#!/usr/bin/env bash
set -euo pipefail

# Deployment hardening for installations where kernel isolation is unavailable.
# Run as root; this creates a dedicated non-login OS account and a root-owned
# read-only virtualenv. Workspace data must live elsewhere and be writable only
# by the dedicated service account.
if [[ ${EUID} -ne 0 ]]; then echo "run as root" >&2; exit 2; fi
PREFIX=${PREFIX:-/opt/localagent}
USER_NAME=${USER_NAME:-localagent}
GROUP_NAME=${GROUP_NAME:-localagent}
PYTHON=${PYTHON:-python3}

getent group "$GROUP_NAME" >/dev/null || groupadd --system "$GROUP_NAME"
if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --gid "$GROUP_NAME" --home-dir "$PREFIX" --shell /usr/sbin/nologin "$USER_NAME"
fi
install -d -o root -g root -m 0755 "$PREFIX"
$PYTHON -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/python" -m pip install --no-cache-dir .
# Freeze the deployment environment only after installation has completed.
chown -R root:root "$PREFIX/venv"
chmod -R a-w "$PREFIX/venv"
install -d -o "$USER_NAME" -g "$GROUP_NAME" -m 0700 "${WORKSPACE:-/var/lib/localagent/workspace}"
cat <<EOF
Installed localagent in $PREFIX/venv.
OS account: $USER_NAME (non-login)
The virtualenv is root-owned/read-only.
Run agents only as $USER_NAME and keep secrets outside its workspace.
EOF
