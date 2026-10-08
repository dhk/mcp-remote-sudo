# Privileged helper

Status: implemented by #41; per-action confirmation by #42; first operations by #43 (all held for operator review). Roadmap §4, "Controlled mutation".

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
| Per-action approval (`confirmation: operator`, the default for host-changing operations) | The helper atomically consumes a root-only, single-use, 10-minute approval record in `/var/lib/mcp-remote-sudo-approvals/` (`0700`). The record binds the request ID, operation, arguments and manifest hash. A mismatched attempt is refused and also uses up the record. |
| Size and time | 64 KiB request limit, 10 s connection timeout, one request per connection |
| Evidence | Its own hash-chained receipts in `/var/log/mcp-remote-sudo-helper/`, a root-owned `0750` directory. They're kept out of the service's directory so the service user can't unlink or replace them. |
| OS ceiling | `CapabilityBoundingSet=` (empty until a pack needs a specific capability), `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, `ProtectSystem=strict`, `NoNewPrivileges=true` |

## Operations (#43, `wifi-remediate`)

These are the recovery steps for a wedged `wl` driver, from least to most invasive:

| Operation | Runs | Grant must enumerate | Inverse recorded | Capability |
|---|---|---|---|---|
| `wifi.radio.set(state)` | `nmcli radio wifi on\|off` | `state` | the opposite state | none (D-Bus as uid 0) |
| `service.restart(unit)` | `systemctl restart -- <unit>`, for `.service` units only | `unit` | none | none (D-Bus as uid 0) |
| `kernel.module.reload(name)` | `modprobe -r <name>`, then `modprobe <name>` | `name` | none | `CAP_SYS_MODULE` |

**Resource arguments must be pinned.** If the matching grant rule doesn't constrain a resource argument with an
`enum` (or an exact value), the helper refuses. A grant can't say "restart any service".

**The unit is still narrow.** The helper unit's capability set is exactly `CAP_SYS_MODULE`, with
`ProtectKernelModules=false` so `modprobe` works. The installer test fails if the set grows. Every other restriction
stays in place, including `NoNewPrivileges`, `ProtectSystem=strict`, `RestrictAddressFamilies=AF_UNIX` and
`IPAddressDeny=any`. Any new operation must be reviewed together with whatever capability it adds.

## What this does not defend against

Code running as the service user can connect to the socket directly, skipping the service's own checks and MCP
elicitation. Against that threat, the boundary is this table plus the manifest re-check. Per-action human approval
that holds even then is `confirmation: operator` (#42): a single-use, root-owned approval record that the helper
consumes before it dispatches.
