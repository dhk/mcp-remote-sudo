# mcp-remote-sudo

Give an MCP client narrowly controlled authority to inspect and operate a remote Linux machine **without giving the agent an unrestricted remote shell**.

`mcp-remote-sudo` is an enforcement-first MCP utility for task-scoped remote operations. A reviewed manifest defines what a particular agent/session may do, to which resources, with which arguments, and for how long. The server exposes only those typed operations and records a receipt for every attempted action.

## Install

On a supported Linux host, the default installation is one command:

```bash
curl -fsSL https://raw.githubusercontent.com/dhk/mcp-remote-sudo/main/install/bootstrap.sh | sudo bash
```

The bootstrap downloads `mcp-remote-sudo`, hands off to the canonical installer, creates a dedicated service account, installs the read-only baseline authority, and binds the MCP service to `127.0.0.1:8765`. It does **not** leave the runtime service with general sudo or a privileged shell.

That command deliberately optimizes for getting started. If you prefer to inspect the installer before running it, pin a commit/release, or verify exactly what will change before elevation, see the [installation guide](docs/installation/zero-shot.md).

After installation, connect remotely through an SSH tunnel:

```bash
ssh -N -L 8765:127.0.0.1:8765 <user>@<host>
```

Your MCP endpoint is then `http://127.0.0.1:8765/mcp`.

## Why

SSH answers: **who may open a remote shell?**

`sudo` answers: **which privileged commands may this identity run?**

`mcp-remote-sudo` asks a narrower agentic question:

> **What authority does this agent need for this bounded task, and no more?**

The goal is not a new IAM system. It is a small orchestration layer over mature controls such as dedicated service accounts, sudoers, polkit, systemd, short-lived credentials, and OS sandboxing.

## Model

```text
Human review
    │
    ▼
Task authority manifest
    │
    ├── agent/session binding
    ├── host/resource scope
    ├── typed tool allowlist
    ├── argument constraints
    ├── explicit lifetime
    └── deny rules
    │
    ▼
mcp-remote-sudo
    │
    ├── validates every invocation
    ├── invokes narrow host adapters
    └── writes action receipts
    │
    ▼
Existing OS / IAM enforcement
```

The manifest is **static by default**. Authority may expire, be revoked, or be narrowed. It does not expand implicitly because an agent discovers that it would like another permission.

## Initial use case

The first wedge is remote Linux diagnostics and controlled remediation.

A Wi-Fi debugging task, for example, might allow system/network status, Wi-Fi scanning, selected systemd status, bounded journal queries, loading/unloading explicitly named kernel modules, toggling Wi-Fi, and activating explicitly allowlisted pre-existing NetworkManager connections.

It should not imply arbitrary shell execution, package installation, unrestricted filesystem writes, system reboot, or general `sudo`/root.

## Example

```yaml
apiVersion: mcp-remote-sudo/v1
kind: TaskAuthority
metadata:
  id: wifi-debug-001
  purpose: Diagnose Wi-Fi driver behavior
binding:
  agent: agent:network-debugger
  session: sess_01
  host: lab-host-01
lifetime:
  notAfter: "2099-01-01T00:00:00Z"
  renewable: false
  expansion: prohibited
allow:
  - tool: network.status
  - tool: wifi.scan
  - tool: systemd.status
    args:
      unit:
        enum: [NetworkManager.service]
  - tool: wifi.driver.status
    args:
      module:
        enum: [b43, wl]
deny:
  - tool: shell.exec
  - tool: package.install
  - tool: system.reboot
  - tool: filesystem.write
receipts:
  required: true
```

### Wi-Fi diagnostic task pack

For a bounded Wi-Fi investigation, a TaskAuthority can combine the existing read-only tools with three additional typed diagnostics:

- `wifi.driver.status` — reports the running kernel, the requested module's loaded state, and `modinfo` for an explicitly allowlisted module such as `wl`.
- `kernel.wifi.log` — kernel journal lines filtered to Wi-Fi/driver terms (firewall drops excluded), at most `lines` (≤500) matches from a bounded window, with `matched`/`returned` counts. By default it reads the current boot only; `boot` (previous boots), `since_minutes` and `include_firewall` widen what it reads and are allowed **only if the grant constrains them explicitly** (the same applies to `journal.query`'s `boot`/`since_minutes`).
- `network.probe` — runs a bounded ICMP probe to an explicitly allowlisted hostname or IP address, with 1–10 packets.

For example:

```yaml
allow:
  - tool: wifi.driver.status
    args:
      module:
        enum: [wl, b43]
  - tool: kernel.wifi.log
    args:
      lines:
        minimum: 1
        maximum: 200
      boot:            # optional: allow looking back up to 3 boots
        minimum: -3
        maximum: 0
  - tool: network.probe
    args:
      target:
        enum: [192.168.7.1, 1.1.1.1]
      count:
        minimum: 1
        maximum: 4
```

These tools do not accept shell strings. The manifest remains the authority boundary: a client cannot probe an unlisted target or inspect an unlisted kernel module through these operations.

## Receipts

Every attempted operation should leave enough evidence to identify the agent/session, manifest and version, typed operation, normalized arguments, authorization decision, enforcement path, result, and affected resources. Denials and failures are evidence too.

## Security stance

Authorization, tool exposure, sandboxing, credential delegation, and audit are separate controls. `mcp-remote-sudo` coordinates them; it does not pretend one replaces the others.

The agent should never receive a raw privileged shell in the initial design. Privilege remains behind narrow, typed adapters whose real OS authority is no broader than the manifest they enforce.

## Status

Early design/prototype. See [Issue #1](https://github.com/dhk/mcp-remote-sudo/issues/1) for the first implementation slice.
