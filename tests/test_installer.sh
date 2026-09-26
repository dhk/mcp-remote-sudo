#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="$ROOT/install/install.sh"

bash -n "$INSTALL"
UNINSTALL="$ROOT/install/uninstall.sh"
bash -n "$UNINSTALL"

# Normal uninstall preserves audit/config state and its owning service identity;
# destructive account/log/config removal belongs only to --purge.
grep -q 'if \$PURGE; then' "$UNINSTALL"
purge_block="$(sed -n '/if \$PURGE; then/,/^else$/p' "$UNINSTALL")"
grep -q 'rm -rf /etc/mcp-remote-sudo /var/log/mcp-remote-sudo' <<<"$purge_block"
grep -q 'userdel mcp-remote-sudo' <<<"$purge_block"
normal_block="$(sed -n '/^else$/,/^fi$/p' "$UNINSTALL")"
! grep -q 'userdel mcp-remote-sudo' <<<"$normal_block"
grep -q 'preserved: /etc/mcp-remote-sudo /var/log/mcp-remote-sudo and service user' "$UNINSTALL"

out="$(bash "$INSTALL" --plan || true)"
grep -q '^BOOTSTRAP_PLAN$' <<<"$out"
grep -q 'LISTEN: 127.0.0.1:' <<<"$out"
grep -q 'RUNTIME_PRIVILEGED_MUTATION: disabled' <<<"$out"

# Authority constraints must use the canonical fail-closed rule field.
grep -q '^    args:$' "$INSTALL"
! grep -q '^    arguments:$' "$INSTALL"

# Installed lifecycle scripts must support direct execution.
grep -Fq 'chmod 0755 "$PREFIX/src/install/bootstrap.sh" "$PREFIX/src/install/install.sh" "$PREFIX/src/install/uninstall.sh"' "$INSTALL"

# Source-level safety assertions for the bootstrap script.
! grep -Eq '0\.0\.0\.0|NOPASSWD: *ALL|chmod +777|shell=True' "$INSTALL"
grep -q 'NoNewPrivileges=true' "$INSTALL"
grep -q 'ProtectSystem=strict' "$INSTALL"

# The server currently uses the MCP SDK 1.x FastMCP API; do not allow a fresh
# install to resolve the incompatible 2.x SDK.
grep -Eq '"mcp>=1\.0,<2"' "$ROOT/pyproject.toml"

# Reinstall must activate newly installed code/config rather than leave a stale process.
grep -Fq 'systemctl enable "$SERVICE.service"' "$INSTALL"
grep -Fq 'systemctl restart "$SERVICE.service"' "$INSTALL"
! grep -Fq 'systemctl enable --now "$SERVICE.service"' "$INSTALL"

# Ready must require sustained health and reject a restart during verification.
grep -q 'NRestarts' "$INSTALL"
grep -q 'service_restarted_during_verification' "$INSTALL"

# The selected loopback port must be validated, collision-checked, and passed to the server.
grep -q 'MCP_REMOTE_SUDO_PORT:-8765' "$INSTALL"
grep -q 'port_in_use' "$INSTALL"
grep -q -- '--port $PORT' "$INSTALL"
grep -Fq 'p.add_argument("--port",type=int,default=8765)' "$ROOT/src/mcp_remote_sudo/server.py"
! grep -Fq 'FastMCP("mcp-remote-sudo",host="127.0.0.1",port=8765)' "$ROOT/src/mcp_remote_sudo/server.py"

echo "installer contract tests passed"
