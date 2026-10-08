# Authoring a Task Pack

A Task Pack is the unit of capability mcp-remote-sudo ships (roadmap §4, #32). A pack declares typed operations.
**Installing a pack makes its operations available. Only the active TaskAuthority makes them exposed and callable.**

## Shape

```python
from mcp_remote_sudo.packs import Operation, Param, TaskPack

def disk_usage(mount: str) -> dict:
    # Fixed argv only: never shell=True, never a caller-supplied command fragment.
    ...

PACK = TaskPack(
    name="disk",
    version="1",
    description="Read-only disk diagnostics.",
    operations=(
        Operation(
            name="disk.usage",          # authority name, used in manifest allow/deny rules
            tool="disk_usage",          # MCP tool name
            adapter=disk_usage,
            params=(Param("mount", str),),   # Param(name, type, default) — no default means required
            description="Usage for one mount point.",
            mutating=False,             # mutating operations will require per-action confirmation (#42)
            privileges=(),              # host privileges the adapter needs, e.g. "journal-read", "icmp"
        ),
    ),
)
```

## Rules

- **Adapters validate their own inputs** defensively, such as identifier regexes and numeric bounds. The manifest's
  `enum`, `minimum` and `maximum` constraints are the authority boundary, and adapter checks are a second layer.
- **Arguments are normalized** before authority evaluation and receipting: defaults are filled in and unknown keys are
  dropped. That means receipts always show the full argument set that was executed.
- **Names must be unique.** Operation names and MCP tool names must be unique across every installed pack, or the
  server refuses to start.
- **Unknown operations fail closed.** If the active authority allows an operation that no installed pack provides, the
  server refuses to start.

## Registering an external pack

Expose the `TaskPack`, or a zero-argument callable that returns one, under the `mcp_remote_sudo.packs` entry-point
group:

```toml
[project.entry-points."mcp_remote_sudo.packs"]
disk = "mcp_remote_disk.pack:PACK"
```

The operator installs the distribution into the service's virtualenv. This becomes
`mcp-remote-sudo-admin pack install` in #38. A grant then authorizes the specific operations.

The built-in packs are `core` (`system.info`, `network.status`, `systemd.status`, `journal.query`, `journal.boots`) and `wifi`
(`wifi.status`, `wifi.scan`, `wifi.link`, `wifi.driver.status`, `kernel.wifi.log`, `network.probe`).
