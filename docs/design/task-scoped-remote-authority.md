# Design: task-scoped remote authority

Status: proposed  
Issue: #3  
Research basis: `docs/research/task-scoped-authority-research-{brief,report}.md`

## 1. Purpose

`mcp-remote-sudo` gives an MCP client a bounded set of typed remote-Linux operations without handing the agent a general shell or general sudo/root authority.

The design deliberately composes existing security mechanisms. It does not replace sudoers, polkit, systemd, IAM, credential brokers, or sandboxing.

The central artifact is an immutable **TaskAuthority manifest**. It answers:

> For this task, which agent/session may invoke which typed operations against which target resources, with which arguments, until when?

Every invocation is evaluated against that manifest and produces an append-only receipt.

## 2. Security invariants

1. **No arbitrary shell.** Tool implementations use fixed argv construction and never `shell=True`.
2. **Deny by default.** An operation absent from the active manifest is unavailable/denied.
3. **Static authority.** An approved manifest may expire, be revoked, or be replaced by a narrower manifest. It never gains authority implicitly.
4. **Manifest authority cannot exceed host authority.** The service account/helper permissions form the hard ceiling.
5. **Typed arguments.** Resources are selected through validated identifiers and explicit enums/bounds, not caller-supplied command fragments.
6. **Revalidate at invocation.** Mutable names are resolved to stable identifiers where possible; live constraints are checked immediately before execution.
7. **Receipts for every attempt.** Allowed, denied, failed, and successful invocations are recorded.
8. **The agent does not hold privileged credentials.** Privileged operations execute behind narrow adapters/helpers.
9. **Unknown semantics fail closed.** Unsupported manifest fields, tools, or constraints are rejected rather than approximated.
10. **Read authority is still authority.** Journal/system reads are bounded and may require redaction/output limits.

## 3. Architecture

```text
MCP client / agent
       |
       | MCP
       v
+-------------------------+
| mcp-remote-sudo server  |
|                         |
| session binding         |
| tool exposure           |
+-----------+-------------+
            |
            v
+-------------------------+
| authority evaluator     |
|                         |
| manifest schema         |
| deny-first evaluation   |
| argument predicates     |
| expiry / revocation     |
+-----------+-------------+
            |
       allow|deny
            |
       +----+------------------+
       |                       |
       v                       v
+--------------+        +---------------+
| typed adapter|        | receipt writer|
+------+-------+        +---------------+
       |
       v
narrow OS enforcement
(systemd / sudoers /
 polkit / service user)
       |
       v
remote Linux host
```

For the first version the MCP server and host adapter may run on the target host and bind only to loopback. Remote access is through an SSH port forward. SSH remains the transport/security boundary; MCP does not expose a network-wide privileged listener.

## 4. Components

### Manifest loader

Loads one YAML manifest at process/session start. It validates the complete document before any MCP tools become available and computes a canonical manifest hash.

Required fields:

- API version and kind
- manifest ID/version/purpose
- agent/session/host binding
- absolute expiry or bounded TTL
- explicit allow rules
- optional explicit deny rules
- receipt policy

The first version has no manifest merging, inheritance, remote includes, templates, or implicit renewal.

### Authority evaluator

Pure policy code with no subprocess execution. Input:

```text
active manifest
session binding
tool name
normalized arguments
current time
target identity
```

Output:

```text
allow | deny
reason code
matched rule
normalized arguments
```

Deny rules are evaluated first. No matching allow rule means deny.

### MCP surface

Only tools supported by the server and allowed by the active manifest are exposed to the session. Exposure is a usability and attack-surface reduction; invocation-time evaluation remains mandatory and is the authorization boundary.

### Typed adapters

Adapters translate a validated operation into fixed operating-system calls. They contain no policy decisions beyond defensive input validation.

Initial read-only adapters:

- `system.info`
- `network.status`
- `wifi.status`
- `wifi.scan`
- `systemd.status(unit)`
- `journal.query(unit, lines)`

Controlled mutation adapters follow only after the read-only path is tested:

- `kernel.module.set(name, state)`
- `network.radio.set(wifi)`
- `network.connection.activate(uuid)`

### Receipt writer

Writes newline-delimited JSON to an append-only location not writable by the agent.

Each receipt includes:

- receipt ID and parent receipt/hash
- timestamp
- manifest ID/version/hash
- agent/session/host binding
- requested tool
- normalized arguments
- authorization decision and reason
- adapter name
- start/end/result
- affected resource identifiers
- previous receipt hash and current receipt hash

Secret material is never written to receipts.

## 5. Manifest v1

```yaml
apiVersion: mcp-remote-sudo/v1
kind: TaskAuthority

metadata:
  id: wifi-diagnostics-001
  version: 1
  purpose: Diagnose Wi-Fi connectivity

binding:
  agent: agent:claude-code
  session: session-123
  host: lobster

lifetime:
  notAfter: 2026-09-26T04:00:00Z
  renewable: false
  expansion: prohibited

allow:
  - tool: system.info
  - tool: network.status
  - tool: wifi.status
  - tool: wifi.scan
  - tool: systemd.status
    args:
      unit:
        enum:
          - NetworkManager.service
  - tool: journal.query
    args:
      unit:
        enum:
          - NetworkManager.service
      lines:
        maximum: 500

deny:
  - tool: shell.exec
  - tool: filesystem.write
  - tool: package.install
  - tool: system.reboot

receipts:
  required: true
```

Argument constraints supported in v1 are intentionally small:

- exact value
- `enum`
- numeric `minimum` / `maximum`

Regexes, arbitrary expressions, globs, and executable policy snippets are out of scope for v1.

## 6. First vertical slice

The first implementation is intentionally read-only. This proves the manifest/evaluator/receipt path before privileged mutation is introduced.

### Slice

1. Start the server with a manifest path and explicit session/agent identity.
2. Validate the manifest and refuse startup on invalid/expired configuration.
3. Expose only the allowed subset of:
   - `system.info`
   - `network.status`
   - `wifi.status`
   - `wifi.scan`
   - `systemd.status`
   - `journal.query`
4. Re-evaluate every invocation against the active manifest.
5. Execute fixed-argv read-only adapters.
6. Emit a receipt for every allowed/denied/failed/successful request.
7. Bind Streamable HTTP to `127.0.0.1` only.

### Acceptance tests

- An unlisted tool is denied.
- A listed tool with an unlisted enum argument is denied.
- `journal.query(lines=501)` is denied when maximum is 500.
- An expired manifest prevents execution.
- A session/agent/host binding mismatch prevents execution.
- Malformed and unknown manifest fields fail closed.
- No adapter accepts shell fragments.
- Every decision produces a receipt with the manifest hash.
- The receipt chain detects modification/reordering.
- The MCP listener is loopback-only by default.

## 7. Privileged follow-on slice

After the read-only slice is validated, add mutation through separate narrow helpers rather than broadening the MCP service account.

Candidate operations:

- load/unload only named kernel modules
- toggle only Wi-Fi radio state
- activate only pre-existing connection UUIDs named in the manifest

Each operation needs its own OS enforcement design and tests showing that bypassing the MCP evaluator still does not yield broader host authority.

## 8. Explicit non-goals for v1

- arbitrary remote shell
- general sudo
- package management
- arbitrary filesystem writes
- reboot/shutdown
- cloud/SaaS credential brokering
- manifest composition
- automatic authority expansion
- multi-host orchestration
- cryptographic signing infrastructure
- OPA/Rego dependency
- replacing SSH as the remote transport

## 9. Provenance

The receipt model is part of the product, not auxiliary logging. The motivating failure mode is operational: diagnostic agents can alter system state and later observers may misinterpret those interventions as endogenous machine behavior. Receipts make prior agent action first-class evidence.

## 10. Decision

Build the read-only vertical slice first. Keep the policy engine small and deterministic. Use the operating system as the privilege ceiling. Add each mutating adapter only when its host-level enforcement can be made narrower than a shell and independently tested.
