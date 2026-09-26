# mcp-remote-sudo

Give an MCP client narrowly controlled authority to inspect and operate a remote Linux machine **without giving the agent an unrestricted remote shell**.

`mcp-remote-sudo` is an enforcement-first MCP utility for task-scoped remote operations. A reviewed manifest defines what a particular agent/session may do, to which resources, with which arguments, and for how long. The server exposes only those typed operations and records a receipt for every attempted action.

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
  ttl: 30m
  renewable: false
  expansion: prohibited
allow:
  - tool: network.status
  - tool: wifi.scan
  - tool: systemd.status
    args:
      unit:
        enum: [NetworkManager.service]
  - tool: kernel.module.set
    args:
      name:
        enum: [b43, wl]
      state:
        enum: [loaded, unloaded]
deny:
  - tool: shell.exec
  - tool: package.install
  - tool: system.reboot
  - tool: filesystem.write
receipts:
  required: true
```

## Receipts

Every attempted operation should leave enough evidence to identify the agent/session, manifest and version, typed operation, normalized arguments, authorization decision, enforcement path, result, and affected resources. Denials and failures are evidence too.

## Security stance

Authorization, tool exposure, sandboxing, credential delegation, and audit are separate controls. `mcp-remote-sudo` coordinates them; it does not pretend one replaces the others.

The agent should never receive a raw privileged shell in the initial design. Privilege remains behind narrow, typed adapters whose real OS authority is no broader than the manifest they enforce.

## Status

Early design/prototype. See [Issue #1](https://github.com/dhk/mcp-remote-sudo/issues/1) for the first implementation slice.
