# Operating authority: `mcp-remote-sudo-admin`

The operator, not the agent, changes authority. Run these commands on the host, with sudo:

```bash
A=/opt/mcp-remote-sudo/venv/bin/mcp-remote-sudo-admin
sudo $A status                       # active authority, what the service has loaded, service state
sudo $A validate wifi-diag.yaml      # schema, expiry, operations
sudo $A diff wifi-diag.yaml          # unified diff against the active authority, plus operations added and removed
sudo $A grant wifi-diag.yaml         # back up, install atomically, reload (no restart), confirm; asks for confirmation
sudo $A revoke                       # install an expired deny-all authority (no tools exposed)
sudo $A receipts verify              # recompute the receipt hash chain
sudo $A pack list                    # built-in packs and which operations are exposed
```

## How `grant` works

1. **Validate** the manifest. It must not already be expired, and its binding (agent, session, host) must match the
   running service.
2. **Show** the diff and the operations added and removed, then ask for confirmation. `--yes` skips the prompt.
3. **Back up** the current authority to `authority.yaml.bak-<UTC timestamp>`, then install the new one atomically
   (temporary file, fsync, rename).
4. **Reload** by sending SIGHUP to the service (`systemctl kill --kill-whom=main --signal=HUP`). The service reloads
   in place: there's no restart, and connected clients keep their sessions.
5. **Confirm** by reading `/var/lib/mcp-remote-sudo/authority-status.json` until the service reports the new manifest
   hash.

If the service rejects the new authority, it keeps the previous one. That happens on a validation error, a binding
mismatch, or an operation that no installed pack provides. `grant` then restores the backup, reloads again and exits
non-zero. Every reload, whether accepted or rejected, writes an `authority.reload` receipt.

## Safety notes

- The admin command runs as root, so it **never imports external pack code**. It only knows the built-in packs.
  Operations from external packs are checked by the unprivileged service at reload, and a failed check means
  automatic rollback.
- `revoke` keeps the binding and sets `notAfter` to now. The service then exposes no tools, and any invocation that
  was already in flight is denied as `manifest_expired`.
