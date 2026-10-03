# Research Brief: Task-Scoped Capability Bundles for Safe Agentic Remote Operations

## Core question

Is there a useful new abstraction in **batching the permissions, tools, constraints, and audit requirements needed for a specific remote task into a temporary capability bundle** that can be loaded for an AI agent or MCP session, used for a bounded period, and then revoked?

The motivating idea is to make remote agent execution **mindfully executable**: explicitly scoped, ephemeral, auditable, and tied to a concrete task rather than granting a standing shell, role, or broad set of machine permissions.

## Motivating example

A remote Linux machine needs Wi-Fi debugging.

The agent initially needs only:

- system information
- NetworkManager status
- Wi-Fi scans
- kernel/module information
- selected systemd status
- selected journal access

Later, a more privileged experiment may require:

- loading/unloading `wl` and `b43`
- toggling Wi-Fi
- activating a NetworkManager connection
- observing resulting state

It should **not** automatically receive:

- arbitrary shell execution
- package installation
- unrestricted filesystem writes
- reboot privileges
- general sudo/root access

Today these permissions tend to be assembled ad hoc from Unix groups, sudoers, polkit, MCP tool exposure, service configuration, OAuth-like scopes, and application logic.

The proposed abstraction would package them into something like:

```yaml
bundle:
  name: wifi-driver-experiment
  version: 1

  capabilities:
    read:
      - network.interfaces
      - kernel.modules
      - journal.kernel
      - journal.NetworkManager

    execute:
      - kernel.module.load: [b43, wl]
      - kernel.module.unload: [b43, wl]
      - network.radio: [on, off]
      - network.connection.activate

  deny:
    - arbitrary_shell
    - package.install
    - system.reboot

  lifetime:
    ttl: 30m

  audit:
    receipts: required
```

A bundle would be:

**defined → loaded → bound to an agent/session → exercised → audited → expired/revoked**

## Hypothesis to test

There may be a missing layer between:

```text
Machine permissions
        ↓
MCP / tool definitions
        ↓
Agent
```

where the missing layer is:

```text
Task-specific capability bundle
```

The distinction is:

- **MCP/tool schema:** what actions exist
- **OS/IAM policy:** what this service/account could theoretically do
- **Capability bundle:** what this particular agent/session may do for this particular task
- **Receipt log:** what it actually did

The research should determine whether this is truly a distinct and useful abstraction or simply a repackaging of existing capability-security, IAM, sandbox, or policy technologies.

## Questions to investigate

### 1. Prior art

Find close analogues in:

- capability-based security
- Unix/Linux capabilities
- sudoers
- polkit
- SELinux/AppArmor
- seccomp
- RBAC and ABAC
- OAuth scopes
- macaroons
- capability URLs/tokens
- SPIFFE/SPIRE
- short-lived credentials
- AWS STS / assumed roles
- Kubernetes RBAC and service accounts
- HashiCorp Vault dynamic credentials
- just-in-time privileged access
- privileged access management
- zero-trust infrastructure access
- sandbox permission manifests
- browser extension permissions
- mobile app entitlements
- CI/CD job permissions
- GitHub Actions permissions
- infrastructure-as-code policy systems
- OPA/Rego
- agent permission systems
- MCP authorization/security proposals
- Claude Code / Codex / agent sandboxing and tool permissions

For each, explain **what is similar and what is materially different**.

### 2. MCP-specific prior art

Research whether MCP or adjacent agent frameworks already support:

- per-session tool exposure
- dynamically loaded capability sets
- tool scopes
- temporary elevation
- runtime constraints on tool arguments
- policy manifests
- task-specific authorization
- expiry/revocation
- human approval gates
- audit receipts
- provenance of actions
- delegation chains

Search MCP specifications, security guidance, GitHub discussions, issue trackers, SDKs, and third-party gateways/proxies.

### 3. Agent frameworks

Examine how current systems handle remote execution permissions:

- Claude Code
- OpenAI Codex / ChatGPT agent tooling
- Cursor
- GitHub Copilot coding agent
- OpenHands
- Cline / Roo Code
- Goose
- Aider
- SWE-agent
- Devin or similar systems where public documentation exists

Do they primarily use:

- standing user permissions
- command-by-command confirmation
- sandboxing
- allow/deny lists
- project-level policy
- task-level policy
- temporary credentials?

Identify gaps.

### 4. Is “batching” itself valuable?

Evaluate whether defining the permission envelope **once at task start** is materially better than repeated per-command approvals.

Potential advantages to test:

- lower approval fatigue
- clearer mental model
- reproducibility
- safer delegation
- easier remote/unattended operation
- deterministic boundaries
- portability between agents
- reviewability before execution
- easier compliance/auditing
- fewer accidental privilege escalations

Also investigate disadvantages:

- over-broad bundles
- stale permissions
- policy complexity
- confused-deputy attacks
- prompt injection exploiting allowed capabilities
- composition problems between bundles
- TOCTOU issues
- hidden privilege inherited from OS/service accounts

### 5. Receipts and provenance

Investigate whether **action receipts** should be part of the abstraction.

A receipt could include:

```text
session
agent
bundle + version
tool
arguments
timestamp
authorization basis
result
affected resources
```

Research comparable concepts in:

- cloud audit logs
- provenance systems
- CI/CD logs
- signed attestations
- in-toto
- SLSA
- event sourcing
- command accounting
- privileged-session recording

Ask whether this closes an important loop for agents: preventing later agents from mistaking previous agent interventions for unexplained system behavior.

## Key conceptual test

Determine whether the following statement describes a genuine architectural gap:

> Existing security systems are mostly organized around identities, applications, resources, and individual operations. Agentic work introduces a useful additional unit of authorization: the **bounded task**. A task may require a coherent temporary bundle of heterogeneous capabilities that is safer to approve as a reviewed whole than either granting a broad standing role or approving commands one by one.

Find evidence **for and against** this claim.

## Desired output

Produce a research report with:

1. **Executive conclusion**
   - Is this a distinct/useful abstraction?
   - Is it novel, partially novel, or established under another name?

2. **Prior-art matrix**
   - system/project
   - unit of authorization
   - ephemeral?
   - task-scoped?
   - heterogeneous capabilities?
   - constraints on arguments/resources?
   - human approval?
   - revocable?
   - audit/provenance?
   - applicability to AI agents

3. **Closest analogues**
   - identify the 5–10 systems most similar to the idea
   - explain exactly where they overlap and diverge

4. **Agent/MCP landscape**
   - what existing agent platforms currently do
   - what appears missing

5. **Security analysis**
   - threats introduced or mitigated by capability bundles

6. **Design implications**
   - smallest useful implementation
   - what should be delegated to OS/IAM rather than reinvented

7. **Novelty assessment**
   - avoid marketing language
   - distinguish:
     - old security primitives
     - new composition
     - genuinely new agent-specific requirements

8. **Recommended terminology**
   Evaluate names such as:
   - capability bundle
   - task capability manifest
   - execution envelope
   - session capability profile
   - ephemeral permission bundle
   - task-scoped authority
   - agent execution manifest

9. **References**
   Prioritize specifications, academic work, official documentation, repositories, and security research over secondary commentary.

## Research standard

Be skeptical of novelty claims.

The strongest useful result may be:

> “The primitives are established, but agentic remote execution creates a new reason to package them around a temporary task boundary.”

If that is the evidence-supported conclusion, say so.

Also distinguish **authorization**, **sandboxing**, **tool exposure**, **credential delegation**, and **audit/provenance** rather than treating them as interchangeable.
