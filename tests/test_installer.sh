#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="$ROOT/install/install.sh"

bash -n "$INSTALL"
bash -n "$ROOT/install/uninstall.sh"

out="$(bash "$INSTALL" --plan || true)"
grep -q '^BOOTSTRAP_PLAN$' <<<"$out"
grep -q 'LISTEN: 127.0.0.1:' <<<"$out"
grep -q 'RUNTIME_PRIVILEGED_MUTATION: disabled' <<<"$out"

# Source-level safety assertions for the bootstrap script.
! grep -Eq '0\.0\.0\.0|NOPASSWD: *ALL|chmod +777|shell=True' "$INSTALL"
grep -q 'NoNewPrivileges=true' "$INSTALL"
grep -q 'ProtectSystem=strict' "$INSTALL"

# The server currently uses the MCP SDK 1.x FastMCP API; do not allow a fresh
# install to resolve the incompatible 2.x SDK.
grep -Eq '"mcp>=1\.0,<2"' "$ROOT/pyproject.toml"

# Ready must require sustained health and reject a restart during verification.
grep -q 'NRestarts' "$INSTALL"
grep -q 'service_restarted_during_verification' "$INSTALL"

# The selected loopback port must be validated, collision-checked, and passed to the server.
grep -q 'MCP_REMOTE_SUDO_PORT:-8765' "$INSTALL"
grep -q 'port_in_use' "$INSTALL"
grep -q -- '--port $PORT' "$INSTALL"
grep -q 'p.add_argument("--port",type=int,default=8765)' "$ROOT/src/mcp_remote_sudo/server.py"
! grep -q 'FastMCP("mcp-remote-sudo",host="127.0.0.1",port=8765)' "$ROOT/src/mcp_remote_sudo/server.py"

echo "installer contract tests passed"
