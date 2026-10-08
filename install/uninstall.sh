#!/usr/bin/env bash
set -euo pipefail
PURGE=false
[[ "${1:-}" == "--purge" ]] && PURGE=true
[[ "${EUID}" -eq 0 ]] || { echo "uninstall requires root"; exit 3; }

SYSCTL_DROPIN="/etc/sysctl.d/60-mcp-remote-sudo-ping.conf"
SERVICE_GID="$(getent group mcp-remote-sudo | cut -d: -f3 || true)"

systemctl disable --now mcp-remote-sudo.service 2>/dev/null || true
systemctl disable --now mcp-remote-sudo-helper.socket mcp-remote-sudo-helper.service 2>/dev/null || true
rm -f /usr/local/sbin/mcp-remote-sudo-admin /etc/polkit-1/rules.d/60-mcp-remote-sudo-wifi-scan.rules
rm -f /etc/systemd/system/mcp-remote-sudo.service \
      /etc/systemd/system/mcp-remote-sudo-helper.socket /etc/systemd/system/mcp-remote-sudo-helper.service
systemctl daemon-reload
rm -rf /opt/mcp-remote-sudo
rm -rf /var/lib/mcp-remote-sudo

# Remove the ICMP grant (runtime permission) installed for network.probe.
# Only reset the live value if it is still exactly the range we installed,
# then re-apply any administrator-configured value from sysctl.d.
if [[ -f "$SYSCTL_DROPIN" ]]; then
  current="$(sysctl -n net.ipv4.ping_group_range 2>/dev/null | tr -s ' \t' ' ' || true)"
  if [[ -n "$SERVICE_GID" && "$current" == "$SERVICE_GID $SERVICE_GID" ]]; then
    # Reset the live grant first; if that fails, keep the drop-in and stop so
    # the remaining grant is visible rather than reported as removed.
    if ! sysctl -w net.ipv4.ping_group_range="1 0" >/dev/null; then
      echo "uninstall failed: could not reset net.ipv4.ping_group_range; group $SERVICE_GID remains permitted ($SYSCTL_DROPIN kept)"
      exit 1
    fi
  fi
  rm -f "$SYSCTL_DROPIN"
  sysctl --system >/dev/null 2>&1 || true
  echo "removed ICMP grant: $SYSCTL_DROPIN"
fi

if $PURGE; then
  rm -rf /etc/mcp-remote-sudo /var/log/mcp-remote-sudo /var/log/mcp-remote-sudo-helper
  if getent passwd mcp-remote-sudo >/dev/null; then userdel mcp-remote-sudo || true; fi
  echo "purged configuration, receipts, and service user"
else
  echo "preserved: /etc/mcp-remote-sudo /var/log/mcp-remote-sudo /var/log/mcp-remote-sudo-helper and service user"
fi
echo "mcp-remote-sudo uninstalled"
