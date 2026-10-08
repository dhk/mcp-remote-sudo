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

1. **Validate** the manifest. It must not already be expired. Its binding must match the active manifest's binding:
   agent and host always, and the session too in fixed-session mode. The service also enforces the binding at
   reload.
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

## Sessions

The installer starts the service **without** `--session`, so it takes its session from the active manifest, and each
`grant` mints a fresh `sess-<timestamp>-<random>` ID. `binding.session` is still required in the manifest you write;
any placeholder works, and the diff shows the minted value that replaces it. Every investigation then has its own session in the receipts, and each
`authority.reload` receipt records the previous session. Agent and host must still match the service.

A service started with a fixed `--session` (the legacy behaviour) keeps it. Grants must then carry the same session,
and none is minted. `status` shows which mode is active. If the service's status file is unavailable, `grant` refuses
rather than guess; pass `--session-mode manifest|fixed`. Re-run the installer to move an older unit to manifest mode.

## External Task Packs

```bash
sudo $A pack install --requirements disk-pack.lock   # wheel-only, hash-pinned; restarts the service
sudo $A pack remove example-pack                     # refused while the active authority uses its operations
sudo $A pack list                                    # built-in + external (metadata only) + what the service loaded
```

The lockfile pins every distribution, dependencies included, as `name==version --hash=sha256:<digest>`. Each
distribution gets its own directory, `/opt/mcp-remote-sudo/packs/<name>/`. The service appends each one to `sys.path`
at lowest priority (`--packs-dir`, set on the unit by the installer). Installation:

1. Runs `pip -I install --only-binary :all: --require-hashes --no-deps --no-compile --target <staging>/<name>` for each
   pin. Only wheels are accepted, so no build hooks run as root, and nothing gets resolved beyond what the lockfile
   pins.
2. Refuses any distribution that would replace mcp-remote-sudo or one of its runtime dependencies.
3. Checks the files **actually staged**, not what the wheel's metadata claims. Every top-level entry must be a plain
   module name, a `.py` file, or a compiled extension module. It must not shadow the standard library, resolve in the
   core environment, or belong to another installed pack. auditwheel `<name>.libs/` directories are allowed if unique.
   Wheels with other top-level files (for example a shared `tests/` directory) are refused.
4. Swaps the new directories in by rename, keeping the previous versions.
5. Restarts the service and confirms it loaded every newly installed pack. If anything fails, the previous versions are
   restored and the service is restarted again. A restart, rather than a reload, gives a clean import state.

Pack operations take the same admin lock as `grant` and `revoke`, then a lock on the packs directory, so only
one authority-changing operation runs at a time. If an earlier pack operation was interrupted after swapping, before
the service confirmed the new packs, the next one first undoes it: it restores the previous versions, removes any packs
that were new in that run, and restarts the service. `pack remove` deletes exactly `/opt/mcp-remote-sudo/packs/<name>`; it never uses a path taken from wheel metadata. It's
refused while the active authority uses the pack's operations, or while another installed pack lists it in
`Requires-Dist`.

The admin never imports pack code. Installing a pack grants nothing: its operations become available, and a later
`grant` decides what is exposed.
