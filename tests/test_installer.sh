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
grep -q 'DEFAULT_PORT=8765' "$INSTALL"
grep -q 'MCP_REMOTE_SUDO_PORT' "$INSTALL"
grep -q 'port_in_use' "$INSTALL"
grep -q -- '--port $PORT' "$INSTALL"
grep -Fq 'p.add_argument("--port",type=int,default=8765)' "$ROOT/src/mcp_remote_sudo/server.py"
! grep -Fq 'FastMCP("mcp-remote-sudo",host="127.0.0.1",port=8765)' "$ROOT/src/mcp_remote_sudo/server.py"

# ICMP support must never be granted through capabilities.
# (Explicit if/exit: a bare `! cmd` does not trip `set -e`.)
if grep -Eq '^(AmbientCapabilities|CapabilityBoundingSet)=.*CAP_NET_RAW|^AmbientCapabilities=|setcap ' "$INSTALL"; then echo "installer must not grant CAP_NET_RAW"; exit 1; fi
grep -q 'removed ICMP grant' "$UNINSTALL"

# ---------------------------------------------------------------------------
# Behavioral tests of installer helpers (sourced with MCP_REMOTE_SUDO_LIB_ONLY=1
# against stub ss/sysctl and a fake /proc; nothing touches the host).
# ---------------------------------------------------------------------------
# Explicit assertion helper: `[[ ]]` failures do not trip `set -e` on bash < 4.1.
expect_eq(){ [[ "$1" == "$2" ]] || { echo "FAIL: expected '$2', got '$1'"; exit 1; }; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/proc/111" "$WORK/proc/222" "$WORK/etc"
cat >"$WORK/bin/ss" <<'EOF'
#!/usr/bin/env bash
# Stub: one listener when FAKE_SS_PID is set; PIDs only with -p.
[[ -n "${FAKE_SS_PID:-}" ]] || exit 0
if [[ "$1" == *p* ]]; then
  echo "LISTEN 0 2048 127.0.0.1:8766 0.0.0.0:* users:((\"python3\",pid=$FAKE_SS_PID,fd=6))"
else
  echo "LISTEN 0 2048 127.0.0.1:8766 0.0.0.0:*"
fi
EOF
cat >"$WORK/bin/sysctl" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == "-n" ]] && { printf '%s\n' "$FAKE_PING_RANGE"; exit 0; }
exit 0
EOF
chmod +x "$WORK/bin/ss" "$WORK/bin/sysctl"
echo "0::/system.slice/mcp-remote-sudo.service" >"$WORK/proc/111/cgroup"
echo "0::/system.slice/lobster-mcp.service" >"$WORK/proc/222/cgroup"

lib(){
  # Run "$@" with the installer helpers loaded and paths redirected to $WORK.
  ( export PATH="$WORK/bin:$PATH" MCP_REMOTE_SUDO_LIB_ONLY=1
    unset MCP_REMOTE_SUDO_PORT
    # shellcheck disable=SC1090
    source "$INSTALL"
    UNIT="$WORK/etc/unit"; MANIFEST="$WORK/etc/authority.yaml"
    SYSCTL_DROPIN="$WORK/etc/60-ping.conf"; PROC_ROOT="$WORK/proc"
    "$@" )
}

# Reinstall keeps the existing unit's port; env overrides; default otherwise.
printf '[Service]\nExecStart=/opt/x/mcp-remote-sudo --manifest m --port 8766\n' >"$WORK/etc/unit"
expect_eq "$(lib eval 'resolve_port; echo "$PORT $PORT_SOURCE"')" "8766 existing_unit"
expect_eq "$(lib eval 'MCP_REMOTE_SUDO_PORT=9001; resolve_port; echo "$PORT $PORT_SOURCE"')" "9001 env"
rm "$WORK/etc/unit"
expect_eq "$(lib eval 'resolve_port; echo "$PORT $PORT_SOURCE"')" "8765 default"

# Listener classification: free, ours (service cgroup), foreign (another unit),
# unknown (PIDs not visible).
expect_eq "$(lib classify_port_listener 8766)" free
expect_eq "$(FAKE_SS_PID=111 lib classify_port_listener 8766)" ours
expect_eq "$(FAKE_SS_PID=222 lib classify_port_listener 8766)" foreign
expect_eq "$(FAKE_SS_PID=333 lib classify_port_listener 8766)" foreign  # no cgroup file

# Manifest backup: none when absent; byte-identical copy when present.
expect_eq "$(lib backup_manifest)" ""
echo "apiVersion: mcp-remote-sudo/v1 # original" >"$WORK/etc/authority.yaml"
backup="$(lib backup_manifest)"
expect_eq "$backup" "$WORK/etc/authority.yaml.bak-"*
cmp -s "$backup" "$WORK/etc/authority.yaml"

# ICMP decision: only replaces the disabled kernel default or our own range;
# never narrows an administrator's range; opt-out honored.
expect_eq "$(FAKE_PING_RANGE='1	0' lib icmp_decision 987)" enabled
expect_eq "$(FAKE_PING_RANGE='987	987' lib icmp_decision 987)" enabled
expect_eq "$(FAKE_PING_RANGE='0	2147483647' lib icmp_decision 987)" already_permitted
expect_eq "$(FAKE_PING_RANGE='100	200' lib icmp_decision 987)" skipped_conflicting_range
expect_eq "$(FAKE_PING_RANGE='1	0' MCP_REMOTE_SUDO_ICMP=0 lib icmp_decision 987)" disabled

# The drop-in grants exactly the service group.
lib write_ping_dropin 987
grep -qx 'net.ipv4.ping_group_range = 987 987' "$WORK/etc/60-ping.conf"
expect_eq "$(grep -c '^net\.' "$WORK/etc/60-ping.conf")" 1

echo "installer contract tests passed"
