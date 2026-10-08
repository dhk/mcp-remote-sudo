# Privileged helper

Status: implemented by #41 (held for operator review). Roadmap §4, "Controlled mutation".

## Why a helper

The MCP service runs as an unprivileged user with `NoNewPrivileges=true`, so it can't escalate, not even through
`sudo`. Mutating operations (#43) and self-update (#16) need root. That root lives in a separate, root-owned helper,
which can only do what its own code allows.

## Boundary

```text
mcp-remote-sudo (uid mcp-remote-sudo)  ──JSON over /run/mcp-remote-sudo/helper.sock──►  mcp-remote-sudo-helper (root)
```

| Control | Enforced by |
|---|---|
| Who can connect | Socket file `0660 root:mcp-remote-sudo`, plus an `SO_PEERCRED` check that the uid is the service user |
| What can run | The helper's compiled-in `OPERATIONS` table. The request names an operation; it never supplies code, argv or paths. |
| Argument shape | Exact parameter set and types per operation. Booleans are never accepted as ints. |
| Whether the operator allowed it | The helper loads `/etc/mcp-remote-sudo/authority.yaml` itself and evaluates the request, so it doesn't trust the service's decision |
| Size and time | 64 KiB request limit, 10 s connection timeout, one request per connection |
| Evidence | Its own hash-chained receipts in `/var/log/mcp-remote-sudo-helper/`, a root-owned `0750` directory. They're kept out of the service's directory so the service user can't unlink or replace them. |
| OS ceiling | `CapabilityBoundingSet=` (empty until a pack needs a specific capability), `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, `ProtectSystem=strict`, `NoNewPrivileges=true` |

#41 ships only `helper.ping`, so no host state can change yet. Each operation added later (#43) must be reviewed
together with any capability it adds to the unit.

## What this does not defend against

Code running as the service user can connect to the socket directly, skipping the service's own checks and MCP
elicitation. Against that threat, the boundary is this table plus the manifest re-check. Per-action human approval
that holds even then is `confirmation: operator` (#42): a single-use, root-owned approval record that the helper
consumes before it dispatches.
