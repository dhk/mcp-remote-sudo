#!/usr/bin/env bash
set -euo pipefail

SERVICE="mcp-remote-sudo"
SERVICE_USER="mcp-remote-sudo"
PREFIX="/opt/mcp-remote-sudo"
CONFIG_DIR="/etc/mcp-remote-sudo"
STATE_DIR="/var/lib/mcp-remote-sudo"
LOG_DIR="/var/log/mcp-remote-sudo"
MANIFEST="$CONFIG_DIR/authority.yaml"
RECEIPTS="$LOG_DIR/receipts.jsonl"
UNIT="/etc/systemd/system/$SERVICE.service"
SYSCTL_DROPIN="/etc/sysctl.d/60-mcp-remote-sudo-ping.conf"
PROC_ROOT="/proc"
DEFAULT_PORT=8765
TTL_HOURS="${MCP_REMOTE_SUDO_TTL_HOURS:-24}"
ICMP="${MCP_REMOTE_SUDO_ICMP:-1}"
WIFI_RESCAN="${MCP_REMOTE_SUDO_WIFI_RESCAN:-}"
POLKIT_RULE="/etc/polkit-1/rules.d/60-mcp-remote-sudo-wifi-scan.rules"
MODE="${1:-install}"

say(){ printf '%s\n' "$*"; }
fail(){
  printf 'MCP_REMOTE_SUDO_INSTALL\nschema: 1\nstatus: failed\nreason: %s\n' "$1"
  exit 1
}
have(){ command -v "$1" >/dev/null 2>&1; }

# Validate opt-ins before anything is planned or changed (no half-installed state on a typo).
case "$WIFI_RESCAN" in ""|0|1) ;; *) fail "invalid_MCP_REMOTE_SUDO_WIFI_RESCAN" ;; esac

# Port selection precedence: explicit MCP_REMOTE_SUDO_PORT, then the port the
# existing unit already uses (a reinstall must not silently move the service),
# then the default.
existing_unit_port(){
  [[ -f "$UNIT" ]] || return 0
  sed -n 's/^ExecStart=.*--port \([0-9][0-9]*\).*$/\1/p' "$UNIT" | head -n 1
}
resolve_port(){
  local existing
  if [[ -n "${MCP_REMOTE_SUDO_PORT:-}" ]]; then
    PORT="$MCP_REMOTE_SUDO_PORT"; PORT_SOURCE=env
  elif existing="$(existing_unit_port)" && [[ -n "$existing" ]]; then
    PORT="$existing"; PORT_SOURCE=existing_unit
  else
    PORT="$DEFAULT_PORT"; PORT_SOURCE=default
  fi
}

# PIDs listening on TCP port $1 (empty when not visible, e.g. without root).
listener_pids(){
  have ss || return 0
  ss -ltnpH "sport = :$1" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
}
port_has_listener(){
  have ss && ss -ltnH "sport = :$1" 2>/dev/null | grep -q .
}
# Classify the listener on port $1: free | ours | foreign | unknown.
# "ours" requires every listening PID to belong to this service's cgroup, so
# another daemon on the same port is a collision even while this service runs.
classify_port_listener(){
  local port="$1" pids p
  port_has_listener "$port" || { echo free; return; }
  pids="$(listener_pids "$port")"
  [[ -n "$pids" ]] || { echo unknown; return; }
  for p in $pids; do
    grep -qs "/$SERVICE\.service\$" "$PROC_ROOT/$p/cgroup" || { echo foreign; return; }
  done
  echo ours
}

# Back up an existing authority manifest before it is replaced. Prints the
# backup path (nothing when there was no manifest). Receipts are never touched.
backup_manifest(){
  [[ -f "$MANIFEST" ]] || return 0
  local backup
  backup="$MANIFEST.bak-$(date -u +%Y%m%dT%H%M%SZ)"
  # Never overwrite an earlier backup (e.g. two runs within one second).
  [[ ! -e "$backup" ]] || backup="$backup.$$"
  [[ ! -e "$backup" ]] || return 1
  # Explicit failure handling: errexit is disabled inside command substitution.
  cp -p "$MANIFEST" "$backup" || return 1
  cmp -s "$MANIFEST" "$backup" || return 1
  printf '%s\n' "$backup"
}

# ICMP probes (network.probe) under NoNewPrivileges=true: ping's cap_net_raw
# file capability cannot be gained, so permit unprivileged ICMP echo
# (datagram) sockets for the service group only. Never grants CAP_NET_RAW.
# Prints: enabled | already_permitted | disabled | skipped_conflicting_range
ping_range_current(){ sysctl -n net.ipv4.ping_group_range 2>/dev/null | tr -s ' \t' ' '; }
icmp_decision(){
  local gid="$1" current lo hi
  [[ "$ICMP" != "0" ]] || { echo disabled; return; }
  current="$(ping_range_current)"
  read -r lo hi <<<"$current"
  # Our own range (e.g. set by a previous install or by hand): (re)write the
  # drop-in so it persists across reboots.
  [[ "$current" == "$gid $gid" ]] && { echo enabled; return; }
  if [[ "$lo" =~ ^[0-9]+$ && "$hi" =~ ^[0-9]+$ ]] && (( lo <= gid && gid <= hi )); then
    echo already_permitted; return
  fi
  # Only replace the kernel default (disabled, lo > hi). Never narrow or
  # replace a range another administrator configured.
  if [[ "$lo" =~ ^[0-9]+$ && "$hi" =~ ^[0-9]+$ ]] && (( lo > hi )); then
    echo enabled; return
  fi
  echo skipped_conflicting_range
}
write_ping_dropin(){
  local gid="$1"
  cat >"$SYSCTL_DROPIN" <<EOF
# Installed by mcp-remote-sudo. Allows ICMP echo (datagram) sockets for the
# mcp-remote-sudo service group only, so network.probe works under
# NoNewPrivileges=true without CAP_NET_RAW. Removed by uninstall.sh.
net.ipv4.ping_group_range = $gid $gid
EOF
  chmod 0644 "$SYSCTL_DROPIN"
}

# Remove a previously installed drop-in (opt-out on reinstall). Resets the live
# value only while it is still exactly the range we installed, then re-applies
# any administrator-configured value from sysctl.d.
remove_ping_dropin(){
  local gid="$1"
  [[ -f "$SYSCTL_DROPIN" ]] || return 0
  rm -f "$SYSCTL_DROPIN"
  if [[ "$(ping_range_current)" == "$gid $gid" ]]; then
    sysctl -w net.ipv4.ping_group_range="1 0" >/dev/null || return 1
    sysctl --system >/dev/null 2>&1 || true
  fi
}

resolve_port
# Allow the test suite to source the helpers above without running anything.
if [[ "${MCP_REMOTE_SUDO_LIB_ONLY:-0}" == "1" ]]; then return 0 2>/dev/null || exit 0; fi

preflight(){
  local missing=()
  [[ "$(uname -s)" == "Linux" ]] || missing+=("linux")
  [[ -d /run/systemd/system ]] || missing+=("systemd")
  for c in python3 ip systemctl journalctl; do have "$c" || missing+=("$c"); done
  if have python3; then
    python3 - <<'PY' >/dev/null 2>&1 || missing+=("python>=3.11")
import sys
raise SystemExit(0 if sys.version_info >= (3,11) else 1)
PY
  fi
  if (("${#missing[@]}")); then
    say "preflight: incompatible"
    say "missing: ${missing[*]}"
    return 2
  fi
  if ! have nmcli; then
    say "preflight: compatible_with_reduced_capabilities"
    say "unavailable: wifi_status wifi_scan wifi_link"
  else
    say "preflight: compatible"
  fi
  [[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || { say "preflight: incompatible"; say "invalid_port: $PORT"; return 2; }
  # A healthy existing installation may legitimately own its configured port
  # during an idempotent reinstall. Any other listener is a collision.
  PORT_OWNER="$(classify_port_listener "$PORT")"
  case "$PORT_OWNER" in
    foreign)
      PORT_COLLISION=1; say "preflight: incompatible"; say "port_in_use: 127.0.0.1:$PORT"; return 4 ;;
    unknown)
      # Listener PIDs are not visible (typically: preflight without root).
      if [[ "${EUID}" -eq 0 ]] || ! systemctl is-active --quiet "$SERVICE.service" 2>/dev/null; then
        PORT_COLLISION=1; say "preflight: incompatible"; say "port_in_use: 127.0.0.1:$PORT"; return 4
      fi
      say "port_owner: unverified (rerun as root to confirm)" ;;
  esac
  say "hostname: $(hostname)"
  say "python: $(python3 --version 2>&1)"
  say "port: $PORT"
  say "port_source: $PORT_SOURCE"
}

plan(){
  cat <<EOF
BOOTSTRAP_PLAN
CREATE system user: $SERVICE_USER (if absent)
CREATE $CONFIG_DIR $STATE_DIR $LOG_DIR $PREFIX
INSTALL pinned working tree into $PREFIX/src
CREATE virtualenv: $PREFIX/venv
INSTALL systemd unit: $UNIT
BACKUP existing $MANIFEST to $MANIFEST.bak-<timestamp> (if present)
INSTALL baseline authority: $MANIFEST
GRANT journal read via systemd-journal group when present
INSTALL operator command: /usr/local/sbin/mcp-remote-sudo-admin (isolated python -I)
INSTALL privileged helper: $SERVICE-helper.socket (0660 root:$SERVICE_USER, typed operations only, CAP_SYS_MODULE only)
ENABLE and START: $SERVICE.service
CONFIGURE ICMP echo sockets for group $SERVICE_USER only: $SYSCTL_DROPIN (skip with MCP_REMOTE_SUDO_ICMP=0)
GRANT polkit org.freedesktop.NetworkManager.wifi.scan to $SERVICE_USER only: $POLKIT_RULE (only with MCP_REMOTE_SUDO_WIFI_RESCAN=1; =0 removes; unset unchanged)
LISTEN: 127.0.0.1:$PORT only (port source: $PORT_SOURCE)
RUNTIME_PRIVILEGED_MUTATION: disabled
EOF
}

if [[ "$MODE" == "--preflight" ]]; then preflight; exit $?; fi
if [[ "$MODE" == "--plan" ]]; then preflight || true; plan; exit 0; fi
[[ "$MODE" == "install" ]] || fail "unknown_mode"

if ! preflight; then
  rc=$?
  # Preserve a specific machine-readable reason for a listener collision.
  if [[ "${PORT_COLLISION:-0}" == 1 ]]; then fail "port_in_use"; fi
  fail "preflight_failed"
fi
plan

if [[ "${EUID}" -ne 0 ]]; then
  printf 'MCP_REMOTE_SUDO_INSTALL\nschema: 1\nstatus: needs_authorization\nreason: bootstrap_requires_root\n'
  exit 3
fi

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_COMMIT="$(git -C "$SOURCE_ROOT" rev-parse HEAD 2>/dev/null || printf unknown)"
HOST="$(hostname)"

if ! getent passwd "$SERVICE_USER" >/dev/null; then
  useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
if getent group systemd-journal >/dev/null; then
  usermod -aG systemd-journal "$SERVICE_USER"
fi

install -d -o root -g root -m 0755 "$PREFIX" "$CONFIG_DIR"
# External Task Packs: one root-owned pip --target tree per distribution (installed only by mcp-remote-sudo-admin).
install -d -o root -g root -m 0755 "$PREFIX/packs"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_DIR" "$LOG_DIR"

rm -rf "$PREFIX/src.new"
mkdir -p "$PREFIX/src.new"
cp -a "$SOURCE_ROOT/." "$PREFIX/src.new/"
rm -rf "$PREFIX/src"
mv "$PREFIX/src.new" "$PREFIX/src"
# The installed source tree is also the lifecycle administration surface.
# Ensure its entry-point scripts support direct execution regardless of
# repository/archive mode preservation.
chmod 0755 "$PREFIX/src/install/bootstrap.sh" "$PREFIX/src/install/install.sh" "$PREFIX/src/install/uninstall.sh"

python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --disable-pip-version-check "$PREFIX/src"

NOT_AFTER="$("$PREFIX/venv/bin/python" - "$TTL_HOURS" <<'PY'
from datetime import datetime, timedelta, timezone
import sys
print((datetime.now(timezone.utc)+timedelta(hours=int(sys.argv[1]))).isoformat())
PY
)"

MANIFEST_BACKUP="$(backup_manifest)" || fail "manifest_backup_failed"
cat >"$MANIFEST" <<EOF
apiVersion: mcp-remote-sudo/v1
kind: TaskAuthority
metadata:
  id: baseline-read-only
  version: 1
binding:
  agent: mcp-remote-sudo
  session: baseline
  host: "$HOST"
lifetime:
  notAfter: "$NOT_AFTER"
  renewable: false
  expansion: prohibited
allow:
  - tool: authority.propose
  - tool: system.info
  - tool: network.status
  - tool: wifi.status
  - tool: wifi.scan
  - tool: systemd.status
  - tool: journal.query
    args:
      lines:
        minimum: 1
        maximum: 500
deny: []
EOF
chmod 0644 "$MANIFEST"

cat >"$UNIT" <<EOF
[Unit]
Description=mcp-remote-sudo task-scoped MCP authority
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
SupplementaryGroups=systemd-journal
# No --session: the session comes from the active manifest and each admin grant mints a new one (#39).
ExecStart=$PREFIX/venv/bin/mcp-remote-sudo --manifest $MANIFEST --agent mcp-remote-sudo --host $HOST --receipts $RECEIPTS --port $PORT --packs-dir $PREFIX/packs
Restart=on-failure
# SIGHUP means "reload"; if one lands before Python installs its handler, restart rather than stay down.
RestartForceExitStatus=SIGHUP
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=$LOG_DIR $STATE_DIR

[Install]
WantedBy=multi-user.target
EOF

# Some distributions do not provide systemd-journal; remove the directive there.
if ! getent group systemd-journal >/dev/null; then
  sed -i '/^SupplementaryGroups=systemd-journal$/d' "$UNIT"
fi

SERVICE_GID="$(getent group "$SERVICE_USER" | cut -d: -f3)"
ICMP_STATUS="$(icmp_decision "$SERVICE_GID")"
if [[ "$ICMP_STATUS" == enabled ]]; then
  write_ping_dropin "$SERVICE_GID"
  sysctl -p "$SYSCTL_DROPIN" >/dev/null || fail "icmp_sysctl_failed"
elif [[ "$ICMP_STATUS" == disabled ]]; then
  remove_ping_dropin "$SERVICE_GID" || fail "icmp_sysctl_failed"
fi

# Forced Wi-Fi rescans (#59, opt-in): NetworkManager's wifi.scan polkit action is auth_admin for sessionless callers.
# MCP_REMOTE_SUDO_WIFI_RESCAN=1 grants exactly that one action to exactly the service user; =0 removes our rule;
# unset leaves the current state. The grant still has to allow wifi.scan with an explicit rescan constraint.
WIFI_RESCAN_STATUS=unchanged
polkit_present(){ [[ -x /usr/lib/polkit-1/polkitd || -x /usr/libexec/polkitd ]] || have pkaction; }
case "$WIFI_RESCAN" in
  1)
    if ! polkit_present; then
      WIFI_RESCAN_STATUS=unavailable   # nothing would enforce the rule; don't claim it's enabled
    else
      # Don't touch an existing rules.d (distros ship it polkitd-owned 0700); create it only if missing.
      [[ -d /etc/polkit-1/rules.d ]] || install -d -o root -g root -m 0755 /etc/polkit-1/rules.d
      cat >"$POLKIT_RULE.tmp" <<EOF
// Installed by mcp-remote-sudo (MCP_REMOTE_SUDO_WIFI_RESCAN=1): lets the service user force a Wi-Fi rescan, nothing else.
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.NetworkManager.wifi.scan" && subject.user == "$SERVICE_USER") {
        return polkit.Result.YES;
    }
});
EOF
      chown root:root "$POLKIT_RULE.tmp"; chmod 0644 "$POLKIT_RULE.tmp"; mv -f "$POLKIT_RULE.tmp" "$POLKIT_RULE"
      WIFI_RESCAN_STATUS=enabled
    fi ;;
  0)
    rm -f "$POLKIT_RULE"; WIFI_RESCAN_STATUS=disabled ;;
esac

# Operator entry point (#56): runs the admin in isolated mode (-I: no PYTHONPATH, no user site), so it never sees the
# packs directory and never imports pack code as root.
ADMIN_WRAPPER="/usr/local/sbin/mcp-remote-sudo-admin"
install -d -o root -g root -m 0755 /usr/local/sbin
cat >"$ADMIN_WRAPPER.tmp" <<EOF
#!/bin/sh
exec $PREFIX/venv/bin/python -I -m mcp_remote_sudo.admin "\$@"
EOF
chown root:root "$ADMIN_WRAPPER.tmp"; chmod 0755 "$ADMIN_WRAPPER.tmp"; mv -f "$ADMIN_WRAPPER.tmp" "$ADMIN_WRAPPER"

# Root-owned privileged helper (#41): socket-activated, reachable only by the service group (0660) and
# accepted only from the service uid (SO_PEERCRED). It executes typed operations from its own compiled-in
# table after re-checking the active authority; it holds no capabilities until a mutation pack needs them.
HELPER_LOG_DIR="/var/log/mcp-remote-sudo-helper"
APPROVALS_DIR="/var/lib/mcp-remote-sudo-approvals"   # root-only: single-use operator approvals (#42)
install -d -o root -g root -m 0750 "$HELPER_LOG_DIR"
install -d -o root -g root -m 0700 "$APPROVALS_DIR"
cat >"/etc/systemd/system/$SERVICE-helper.socket" <<EOF
[Unit]
Description=mcp-remote-sudo privileged helper socket

[Socket]
ListenStream=/run/mcp-remote-sudo/helper.sock
SocketUser=root
SocketGroup=$SERVICE_USER
SocketMode=0660
DirectoryMode=0755
Accept=no

[Install]
WantedBy=sockets.target
EOF
cat >"/etc/systemd/system/$SERVICE-helper.service" <<EOF
[Unit]
Description=mcp-remote-sudo privileged helper (typed operations only)
Requires=$SERVICE-helper.socket

[Service]
Type=simple
User=root
ExecStart=$PREFIX/venv/bin/python -I -m mcp_remote_sudo.helper --manifest $MANIFEST --receipts $HELPER_LOG_DIR/receipts.jsonl --service-user $SERVICE_USER --approvals-dir $APPROVALS_DIR
NoNewPrivileges=true
# CAP_SYS_MODULE only, for kernel.module.reload (#43, allowlisted names enumerated by the grant). systemctl and
# nmcli act over D-Bus as uid 0 and need no capability. ProtectKernelModules must be off for modprobe to work.
CapabilityBoundingSet=CAP_SYS_MODULE
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=false
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
ReadWritePaths=$HELPER_LOG_DIR $APPROVALS_DIR
EOF

systemctl daemon-reload
systemctl enable "$SERVICE.service"
systemctl enable --now "$SERVICE-helper.socket"
systemctl restart "$SERVICE.service"

# Require the service to remain healthy through a short stabilization window.
# A one-shot is-active check can race a crash/restart loop and report a false ready.
for _ in 1 2 3 4 5; do
  sleep 1
  systemctl is-active --quiet "$SERVICE.service" || fail "service_not_active"
  [[ "$(systemctl show -p NRestarts --value "$SERVICE.service")" == "0" ]] || fail "service_restarted_during_verification"
done

LISTEN_OK=unknown
if have ss; then
  if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)127\.0\.0\.1:$PORT$"; then LISTEN_OK=true; else LISTEN_OK=false; fi
fi
[[ "$LISTEN_OK" != "false" ]] || fail "loopback_listener_not_verified"

MANIFEST_HASH="$("$PREFIX/venv/bin/python" - "$MANIFEST" <<'PY'
from mcp_remote_sudo.authority import Authority
import sys
print(Authority.load(sys.argv[1]).manifest_hash)
PY
)"

cat <<EOF
MCP_REMOTE_SUDO_INSTALL
schema: 1
status: ready
version: 0.1.0
source_commit: $SOURCE_COMMIT
endpoint: http://127.0.0.1:$PORT/mcp
service: $SERVICE.service
service_user: $SERVICE_USER
manifest: $MANIFEST
manifest_hash: $MANIFEST_HASH
manifest_not_after: $NOT_AFTER
manifest_backup: ${MANIFEST_BACKUP:-none}
port_source: $PORT_SOURCE
icmp_probe: $ICMP_STATUS
wifi_rescan: $WIFI_RESCAN_STATUS
receipts: $RECEIPTS
transport: loopback-only
privileged_mutation: disabled
verification: service-and-listener
EOF
