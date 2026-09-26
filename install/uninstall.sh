#!/usr/bin/env bash
set -euo pipefail
PURGE=false
[[ "${1:-}" == "--purge" ]] && PURGE=true
[[ "${EUID}" -eq 0 ]] || { echo "uninstall requires root"; exit 3; }

systemctl disable --now mcp-remote-sudo.service 2>/dev/null || true
rm -f /etc/systemd/system/mcp-remote-sudo.service
systemctl daemon-reload
rm -rf /opt/mcp-remote-sudo
if getent passwd mcp-remote-sudo >/dev/null; then userdel mcp-remote-sudo || true; fi
rm -rf /var/lib/mcp-remote-sudo

if $PURGE; then
  rm -rf /etc/mcp-remote-sudo /var/log/mcp-remote-sudo
  echo "purged configuration and receipts"
else
  echo "preserved: /etc/mcp-remote-sudo /var/log/mcp-remote-sudo"
fi
echo "mcp-remote-sudo uninstalled"
