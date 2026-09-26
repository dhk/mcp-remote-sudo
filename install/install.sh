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
PORT="${MCP_REMOTE_SUDO_PORT:-8765}"
TTL_HOURS="${MCP_REMOTE_SUDO_TTL_HOURS:-24}"
MODE="${1:-install}"

say(){ printf '%s\n' "$*"; }
fail(){
  printf 'MCP_REMOTE_SUDO_INSTALL\nschema: 1\nstatus: failed\nreason: %s\n' "$1"
  exit 1
}
have(){ command -v "$1" >/dev/null 2>&1; }

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
    say "unavailable: wifi_status wifi_scan"
  else
    say "preflight: compatible"
  fi
  say "hostname: $(hostname)"
  say "python: $(python3 --version 2>&1)"
  say "port: $PORT"
}

plan(){
  cat <<EOF
BOOTSTRAP_PLAN
CREATE system user: $SERVICE_USER (if absent)
CREATE $CONFIG_DIR $STATE_DIR $LOG_DIR $PREFIX
INSTALL pinned working tree into $PREFIX/src
CREATE virtualenv: $PREFIX/venv
INSTALL systemd unit: $UNIT
INSTALL baseline authority: $MANIFEST
GRANT journal read via systemd-journal group when present
ENABLE and START: $SERVICE.service
LISTEN: 127.0.0.1:$PORT only
RUNTIME_PRIVILEGED_MUTATION: disabled
EOF
}

if [[ "$MODE" == "--preflight" ]]; then preflight; exit $?; fi
if [[ "$MODE" == "--plan" ]]; then preflight || true; plan; exit 0; fi
[[ "$MODE" == "install" ]] || fail "unknown_mode"

preflight || fail "preflight_failed"
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
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_DIR" "$LOG_DIR"

rm -rf "$PREFIX/src.new"
mkdir -p "$PREFIX/src.new"
cp -a "$SOURCE_ROOT/." "$PREFIX/src.new/"
rm -rf "$PREFIX/src"
mv "$PREFIX/src.new" "$PREFIX/src"

python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --disable-pip-version-check "$PREFIX/src"

NOT_AFTER="$("$PREFIX/venv/bin/python" - "$TTL_HOURS" <<'PY'
from datetime import datetime, timedelta, timezone
import sys
print((datetime.now(timezone.utc)+timedelta(hours=int(sys.argv[1]))).isoformat())
PY
)"

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
  - tool: system.info
  - tool: network.status
  - tool: wifi.status
  - tool: wifi.scan
  - tool: systemd.status
  - tool: journal.query
    arguments:
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
ExecStart=$PREFIX/venv/bin/mcp-remote-sudo --manifest $MANIFEST --agent mcp-remote-sudo --session baseline --host $HOST --receipts $RECEIPTS
Restart=on-failure
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

systemctl daemon-reload
systemctl enable --now "$SERVICE.service"
sleep 1
systemctl is-active --quiet "$SERVICE.service" || fail "service_not_active"

LISTEN_OK=unknown
if have ss; then
  if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)127\.0\.0\.1:$PORT$"; then LISTEN_OK=true; else LISTEN_OK=false; fi
fi
[[ "$LISTEN_OK" != "false" ]] || fail "loopback_listener_not_verified"

MANIFEST_HASH="$("$PREFIX/venv/bin/python" - "$MANIFEST" <<'PY'
from mcp_remote_sudo.authority import Authority
import sys
print(Authority.from_path(sys.argv[1]).manifest_hash)
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
receipts: $RECEIPTS
transport: loopback-only
privileged_mutation: disabled
verification: service-and-listener
EOF
