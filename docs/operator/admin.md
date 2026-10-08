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
   active manifest's binding. The service also enforces the binding at reload.
2. **Show** the diff and the operations added and removed, then ask for confirmation. `--yes` skips the prompt.
3. **Back up** the current authority to `authority.yaml.bak-<UTC timestamp>`, then install the new one atomically
   (temporary file, fsync, rename).
4. **Reload** by sending SIGHUP to the service (`systemctl kill --kill-whom=main --signal=HUP`). The service reloads
   in place: there's no restart, and connected clients keep their sessions. Clients must list tools again, or
   reconnect, to *see* newly granted tools, because no `tools/list_changed` notification is sent. Removed tools are
   denied immediately either way: every call is checked against the active authority.
5. **Confirm** by reading `/var/lib/mcp-remote-sudo/authority-status.json` until the service reports the new manifest
   hash.

What happens next depends on the service's answer:

- **It rejects the new authority.** That happens on a validation error, a binding mismatch, or an operation that no
  installed pack provides. The service keeps its previous authority, and `grant` restores the backup and exits
  non-zero. If that backup isn't what the service was running, it's restored but **not** reloaded.
- **It doesn't confirm in time.** By default the wait is 45s, longer than any tool's own timeout. Tool calls run on the
  service's event loop, so a reload waits for the call that's running.
- **The signal can't be delivered**, for example because the service is stopped.

In the last two cases the new file **stays installed**. The command exits non-zero and says so, and the authority
applies when the service processes the reload or next starts. **A `revoke` is never rolled back.**

Only one admin operation runs at a time (`grant` and `revoke` take a lock). Every reload, accepted or rejected,
writes an `authority.reload` receipt.

## Safety notes

- The admin command runs as root, so it **never imports external pack code**. It only knows the built-in packs.
  Operations from external packs are checked by the unprivileged service at reload, and a failed check means
  automatic rollback.
- `revoke` keeps the binding and sets `notAfter` to now. A call that's already running finishes under the previous
  authority. After the reload the service exposes no tools, so new calls fail as unknown tools.
