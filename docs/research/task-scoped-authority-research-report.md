# Task-Scoped Authority for Agentic Remote Operations

## Concise product and design assessment

**Decision:** Build a narrow, enforcement-first version. Do not position it as a novel authorization primitive or attempt to replace IAM, OS controls, credential systems, or policy engines.

The worthwhile product is a task-scoped authority layer for agents: a reviewed, versioned, short-lived manifest that binds a particular agent/session to a bounded set of tools, constrained arguments and resources, delegated credentials, approval rules, and action receipts.

The core claim should be restrained:

> The underlying security primitives are established. Agentic remote execution creates a useful new operational reason to compose them around a temporary, reviewable task boundary—and to preserve machine-readable evidence of what the agent actually did.

This is best understood as an authorization-and-evidence orchestration layer, not as a new access-control model.

---

## 1. Is it worth building?

### Yes, with a narrow wedge

There is a real gap between the components available today and the experience needed for safe unattended or semi-attended agent work.

Existing controls commonly work at one of these levels:

- An identity or role may do certain things.
- A client may expose certain tools.
- A sandbox may constrain a process.
- A user may approve a particular action.
- A temporary credential may narrow and time-limit cloud access.
- An audit log may show what happened afterward.

An agent task often crosses all of those levels. For example, diagnosing a remote Linux Wi-Fi failure may require read-only system inspection, selected journal access, NetworkManager operations, and a narrowly constrained kernel-module experiment. A secure implementation must simultaneously constrain tool exposure, exact arguments, host-level authority, time, credential delegation, user approval, and logging.

Most systems make an operator assemble these controls ad hoc. The proposed product makes the assembly itself explicit, reviewable, enforceable, temporary, and repeatable.

### What is genuinely differentiated

The differentiation is not a new primitive such as least privilege, expiry, delegation, policy-as-code, or provenance. Those are well-established.

The differentiation is a coherent **task object** with all of the following properties:

1. It is approved as a bounded whole before the agent starts.
2. It compiles into constraints across heterogeneous enforcement points.
3. It is bound to one agent/session and expires automatically.
4. It validates the actual tool and argument invocation, rather than merely granting a broad role.
5. It records a receipt chain that ties every operation to the approved authority.
6. It is portable across agents, while adapters implement platform-specific enforcement.

That composition is compelling for agents because their execution is adaptive, their inputs may be untrusted, and their authority otherwise tends to inherit broadly from the human or service account that launched them.

### What not to build

Do not build:

- A replacement Linux authorization system.
- A universal IAM product.
- A new credential store.
- A generic agent runtime.
- A claim that task-level authorization is newly invented.
- A system that treats policy evaluation as sufficient enforcement.

Instead, integrate with existing controls and make their joint application legible at an agent-task boundary.

---

## 2. Prior art and closest analogues

| System / concept | Unit of authorization | Ephemeral / revocable | Task-scoped | Argument or resource constraints | Approval / audit | Relationship to this proposal |
|---|---|---:|---:|---:|---:|---|
| Capability-based security | Possession of a capability | Sometimes | Not inherently | Can be narrow by object/right | Depends on implementation | Foundational concept: authority should be explicit and attenuable. Does not supply an agent-task lifecycle or cross-system packaging by itself. |
| Linux capabilities, sudoers, polkit | Process privilege, user-command policy, privileged action | Usually standing; sometimes session-mediated | Rarely | sudoers can constrain commands; polkit authorizes actions | Logging varies | Essential enforcement substrate for host actions. Too host-specific and fragmented to serve as the top-level task object. |
| SELinux/AppArmor/seccomp | Process policy and syscall/resource boundary | Policy-dependent | No | Strong resource, executable, syscall constraints | Audit support varies | Strong containment controls. They restrict execution after launch but do not express a human-reviewed multi-tool task plan. |
| RBAC, ABAC, ReBAC / Zanzibar-style systems | Roles, attributes, relationships | Policy-dependent | Usually no | Strong contextual decisions possible | Audit implementation-dependent | Useful decision and entitlement foundations. Typically identify who may access what, rather than defining a temporary agent work package. |
| OAuth scopes and resource indicators | Bearer token scope and audience/resource | Yes, through expiry/revocation | Sometimes | Scope/resource-level; varies by server | Token/audit logs | Useful for downstream APIs; insufficient alone for host actions, tool schemas, and receipt-level provenance. |
| Macaroons | Delegated token with attenuating caveats | Yes | Potentially | Excellent caveat model for time, resource, and contextual limits | Depends on issuer/verifier | One of the closest conceptual mechanisms. Could inspire the signed, attenuating bundle/token representation. |
| AWS STS session policies | Assumed-role session | Yes | Often job/session-like | Session policy can only narrow role permissions | CloudTrail and IAM audit | Strong cloud analogue: short-lived credentials plus a narrower policy ceiling. It does not span arbitrary local tools or provide a task manifest UX. |
| Vault dynamic secrets / leases | Credential lease | Yes | Indirectly | Backend role policy controls credential | Lease lifecycle and audit | Strong credential component. It does not define the agent’s allowable workflow or tool arguments. |
| SPIFFE/SPIRE | Workload identity and short-lived SVID | Yes | Workload-oriented, not task-oriented | Identity/authentication more than action policy | Depends on ecosystem | Correct identity substrate for the agent/gateway/workload, not the task authority layer. |
| JIT/PAM | Temporary privileged identity/role activation | Yes | Frequently ticket/request-related | Usually role or target centric | Strong approval/session audit in mature products | Closest enterprise operational analogue. The extension here is agent-specific tool/argument constraints and receipts. |
| Kubernetes RBAC/service accounts | API subject, role, resource/verb | Token lifetime varies | Usually workload / namespace scoped | Resource, verb, namespace constraints | Kubernetes audit logs | Relevant substrate for container/Kubernetes execution, but not a general temporary task object. |
| GitHub Actions permissions plus OIDC | Workflow/job token and cloud identity | Yes | Yes: workflow/job | Permission keys, repository context, cloud trust conditions | Workflow logs, attestations | Probably the closest production pattern: a declared unit of work receives narrow, short-lived authority. Agent tasks are more adaptive and require runtime argument constraints. |
| OPA / policy-as-code | A policy decision over structured input | No, by itself | Can evaluate task context | Strong, if input includes arguments/resources | Depends on caller/logging | Ideal decision component for a gateway. It is not the bundle lifecycle, credential issuer, or receipt system. |
| in-toto / SLSA attestations | Signed claims about software supply-chain steps | N/A | Step/build oriented | Statement schema-dependent | Strong provenance verification | Best provenance analogue. Receipts should borrow its signed, structured, verifiable approach where feasible. |
| MCP authorization | Client access token for an MCP server/resource | Yes, via OAuth token lifetime/revocation | Not specified as a first-class object | Protocol/server-specific | Protocol does not create universal action receipts | Necessary transport/server authorization; lacks a portable task-manifest and cross-enforcement lifecycle. |
| Current coding-agent permissions | Session/project tool permissions, sandbox, confirmation | Session-dependent | Usually weak | Tool, path, domain, command patterns vary | UI logs vary | Demonstrates market need, but current designs generally emphasize per-action prompts and workspace/session policy rather than durable task authorities. |

### Closest analogues

1. **GitHub Actions workflow/job permissions plus OIDC** — A declared unit of work receives narrow permissions and exchanges identity for short-lived cloud credentials. The important divergence is that an agent task is adaptive: it needs runtime tool and argument validation, not only declarative job permissions.

2. **AWS STS assumed roles with session policies** — A temporary session can be narrower than its parent role. This strongly supports the design rule that an agent bundle must only attenuate, never amplify, underlying authority.

3. **JIT/PAM workflows** — Approval, expiry, revocation, and session accountability closely match the operational model. The missing pieces are agent-specific tool schemas, parameter constraints, and a clear provenance link from a natural-language task to machine actions.

4. **Macaroons** — Their caveat/attenuation model maps naturally to expiry, target host, allowed resource, and operation restrictions. A bundle token could eventually use a macaroon-like delegated authority structure, although an MVP need not invent cryptography.

5. **OPA as a policy decision point** — OPA can evaluate each requested tool invocation against a manifest and live context. It should be a pluggable evaluator, not the product’s identity.

6. **Vault leases and dynamic secrets** — The proposed system should request short-lived downstream credentials per bundle or subtask rather than hand agents static secrets.

7. **in-toto/SLSA attestations** — The proposed receipt design has a direct analogue in structured, signed statements about execution. The product should adopt this mindset without claiming supply-chain equivalence.

8. **Linux sudoers/polkit and MAC/sandbox controls** — These remain the ultimate local enforcement mechanisms. The product’s role is to generate or select narrowly scoped enforcement paths, not to supplant them.

---

## 3. MCP and agent landscape

### MCP

MCP standardizes a protocol for models/clients to reach tools and resources. Its authorization direction uses OAuth-style authorization for protected servers, including audience validation and optional scope negotiation. This is necessary but intentionally incomplete: it does not define a portable, task-scoped policy object that coordinates multiple tools, hosts, credentials, and audit records.

A task-scoped authority layer should therefore sit around or in front of MCP:

```text
Human approval
      ↓
Task authority manifest
      ↓
Policy gateway / MCP proxy
      ↓
MCP tool servers and adapters
      ↓
OS, cloud IAM, SaaS APIs, credentials
```

The gateway receives every tool call, checks it against the active manifest and live state, obtains or presents constrained credentials, forwards only allowed operations, and produces a receipt.

### Current agent products

Claude Code, Codex, and OpenHands demonstrate an important separation:

- Permission/approval controls determine whether an operation may be attempted.
- Sandboxing limits what a process can reach after it runs.
- The host identity, network configuration, mounts, tokens, and service accounts still determine the real ceiling of authority.

These products provide useful session-level rules, allow/deny lists, sandbox modes, and command-by-command approvals. Their public models do not generally provide a portable task manifest that carries an enforceable authority boundary across multiple remote systems and credentials.

### Product opportunity

The opportunity is not a better confirmation dialog. It is a replacement for repeated, low-context approvals with one high-context approval:

> Approve this bounded operational plan, its exact authority, its expiry, and its evidence requirements.

That is valuable only when the bundle is visibly narrower than the identity’s standing access and is actually enforced at every relevant boundary.

---

## 4. Static-by-default authority model

### Decision

A bundle is static after approval by default. It may only lose authority during its lifetime; it must not gain authority implicitly.

If the agent discovers it needs additional authority, it creates a separate extension request containing:

- the current bundle ID and receipt-chain reference;
- the specific new capability or resource requested;
- the stated reason and observed evidence;
- the exact proposed duration;
- the incremental risk and affected resource;
- whether the original task intent still covers the request.

A human or an explicit policy may approve a new bundle or a separately signed amendment. The original bundle remains unchanged.

### Why static-by-default is right

- It makes pre-execution review real instead of aspirational.
- It prevents adaptive planning from silently becoming privilege escalation.
- It reduces prompt-injection blast radius: untrusted content can influence work only inside a fixed authority envelope.
- It yields a legible delegation and audit chain.
- It makes replay and forensic analysis feasible because the authority state is immutable for each receipt.
- It avoids difficult semantics around dynamic policy expansion, inherited privileges, and conflicting approvals.

### Controlled flexibility

Static does not mean inflexible. The manifest can include narrowly specified safe variation, such as:

- scan any Wi-Fi network, but do not connect;
- query status for a declared set of systemd units;
- load only modules from a named allowlist;
- activate only an existing connection whose UUID matches a listed value;
- write only files under a generated temporary directory;
- retry allowed actions up to a bounded count.

This gives the agent room to adapt without granting it discretion to discover and seize new classes of authority.

---

## 5. Recommended MVP

### Product form

Build an MCP gateway or sidecar for remote Linux operations. Start with one controlled host or host group and a small set of typed administrative tools. Do not start with arbitrary shell execution.

### MVP capabilities

1. **Manifest creation and review**
   - YAML or JSON document with a stable ID, version, issuer, subject agent/session, explicit TTL, purpose, tool allowlist, resource selectors, parameter constraints, deny rules, and receipt requirement.
   - Human-readable approval view generated from the same canonical manifest.

2. **Binding and lifecycle**
   - Bind one immutable manifest to an agent session.
   - Short default TTL, explicit expiry, immediate revocation, and no implicit renewal.
   - Authority may be narrowed mid-session but not expanded.

3. **Gateway enforcement**
   - Expose only tools named in the manifest.
   - Validate JSON arguments against schema plus manifest predicates.
   - Reject unknown tools, unlisted argument values, broad globs, unsafe resource identifiers, and arbitrary shell strings.
   - Enforce deny rules before allow rules.

4. **Constrained host adapters**
   - Implement typed operations such as `network.status`, `wifi.scan`, `systemd.status`, `journal.query`, `kernel.module.load`, `kernel.module.unload`, `network.radio.set`, and `network.connection.activate`.
   - Each adapter maps to narrow underlying controls such as a dedicated service account, polkit action, tightly defined sudoers command, systemd service, or privileged helper.
   - The agent never receives general `sudo`, root, or a raw shell as part of the MVP.

5. **Credential delegation**
   - The gateway—not the agent—obtains a short-lived downstream credential or invokes a privileged helper.
   - Use existing systems where possible: Vault for leased secrets, cloud STS/OIDC for cloud actions, OAuth token exchange for SaaS APIs, and local host controls for Linux operations.
   - Enforce the ceiling rule: the generated credential and adapter authority must be no broader than the manifest.

6. **Receipts**
   - Write one append-only receipt per attempted action, including manifest ID/version/hash, session and agent identity, tool and normalized arguments, decision, enforcement adapter, downstream credential reference without secret material, result, timestamps, target resources, and parent receipt ID.
   - Include denial and failure receipts, not only successful actions.
   - Hash-chain receipts initially; add signatures or external transparency storage only when there is a concrete multi-party verification requirement.

### Example manifest

```yaml
apiVersion: authority.example/v1
kind: TaskAuthority
metadata:
  id: tsa-wifi-2026-09-25-001
  version: 1
  purpose: Diagnose and test the b43/wl Wi-Fi driver path on host lab-mbp-01

binding:
  agent: agent:network-debugger
  session: sess_01J...
  host: ssh://lab-mbp-01

lifetime:
  notAfter: 2026-09-26T02:30:00Z
  renewable: false
  expansion: prohibited

allow:
  - tool: network.status
  - tool: wifi.scan
  - tool: systemd.status
    args:
      unit:
        enum: [NetworkManager.service, wpa_supplicant.service]
  - tool: journal.query
    args:
      unit:
        enum: [NetworkManager.service]
      sinceMinutes:
        maximum: 120
  - tool: kernel.module.set
    args:
      name:
        enum: [b43, wl]
      state:
        enum: [loaded, unloaded]
  - tool: network.radio.set
    args:
      wifi:
        enum: [on, off]

 deny:
  - tool: shell.exec
  - tool: package.install
  - tool: system.reboot
  - tool: filesystem.write

receipts:
  required: true
  retention: 90d
```

The actual policy must include target-specific constraints where possible. For example, activation should allow only named preexisting connection UUIDs, not arbitrary connection definitions or secrets.

---

## 6. Security analysis

### Risks mitigated

| Risk | How the model helps | Remaining limitation |
|---|---|---|
| Standing broad credentials | Short-lived bundles and downstream credentials attenuate access | Underlying service accounts and privileged helpers must also be narrow. |
| Approval fatigue | One reviewed task envelope replaces repeated low-context confirmations | A bundle can still be too broad; the approval UI must show operational impact clearly. |
| Prompt injection | A malicious instruction cannot expand the approved authority | It can still misuse allowed authority; treat all tool inputs as untrusted. |
| Arbitrary-shell escalation | Typed tools and argument validation eliminate many command-construction paths | Typed adapters may themselves contain implementation bugs. |
| Weak forensics | Receipts link each action to a concrete authority basis | Logs must be protected from tampering and include enough normalized context. |
| Stale access | Explicit TTL and revocation limit duration | Revocation propagation and cached downstream credentials need testing. |
| Confused deputy | Bind manifest, agent/session, target, and downstream audience | The gateway must never accept caller-provided authority references without verification. |

### Risks introduced or amplified

| Risk | Design response |
|---|---|
| Bundle becomes a broad “temporary admin” role | Require typed capabilities, bounded resources, explicit deny rules, and a visual diff against the standing authority ceiling. |
| Hidden privilege in adapters | Maintain an adapter authority inventory; test each adapter independently; run privileged code in narrow helpers rather than the gateway process. |
| Composition of bundles creates escalation | No implicit composition. Multiple bundles require an explicit merged review/approval and a new immutable ID. |
| TOCTOU between approval and action | Revalidate live target/resource conditions at invocation time; use immutable IDs/UUIDs rather than mutable names; record the observed state in receipts. |
| Policy/manifest mismatch | Compile and test manifests against adapters; reject unsupported semantics rather than silently approximating them. |
| Receipt tampering | Append-only storage, hash chaining, separation of writer from agent, and optional signatures/export to an independent log. |
| Data leakage through allowed read operations | Model read access as a capability with data classifiers, query limits, redaction, and output controls—not as intrinsically harmless. |

### Critical principle

Authorization, sandboxing, tool exposure, credential delegation, and audit are complementary:

- **Authorization** decides whether an operation is allowed.
- **Tool exposure** determines which operations the agent can attempt.
- **Sandboxing** constrains process reachability after execution starts.
- **Credential delegation** determines which downstream identity actually reaches a protected system.
- **Audit/provenance** records what occurred and under which authority.

No one layer substitutes for the others.

---

## 7. Terminology

### Recommended name: task-scoped authority

Use **task-scoped authority** as the architectural term and **task authority manifest** as the artifact.

Why it works:

- “Authority” accurately captures the delegated right to cause effects.
- “Task-scoped” is understandable to product, security, and operations audiences.
- It does not overclaim novelty or imply that the manifest is itself the sole enforcement mechanism.
- It supports related terms: authority issuer, authority ceiling, authority extension, authority receipt, and authority revocation.

### Other names

| Term | Assessment |
|---|---|
| Capability bundle | Clear, but can imply an implementation based on object capabilities and may obscure the task lifecycle. Good informal shorthand. |
| Task capability manifest | Accurate but longer and more jargon-heavy. Reasonable artifact name if “authority” is politically loaded. |
| Execution envelope | Product-friendly but ambiguous: could mean sandboxing, runtime environment, or deployment package. |
| Session capability profile | Implies a session-level configuration; weaker connection to a discrete task and approval boundary. |
| Ephemeral permission bundle | Descriptive but awkward and overly focused on expiry. |
| Agent execution manifest | Clear but does not emphasize authorization or constrained authority. |

---

## 8. Build recommendation and validation

### Recommendation

Proceed with a prototype if the target use case has all three properties:

1. The agent needs to perform multiple related operations over a bounded interval.
2. Existing per-command approvals are disruptive or do not scale to unattended work.
3. The agent’s current runtime identity would otherwise have materially broader authority than the task needs.

Remote diagnostics and controlled remediation are a strong first use case. The Wi-Fi-driver example is suitable because it has clear escalation boundaries, reversible actions, observable state, and concrete unsafe actions to exclude.

### First prototype test

Build one MCP gateway plus one Linux host adapter set. Run a controlled evaluation using 10–20 realistic remote-operations tasks:

- Compare per-command approval with a pre-approved static authority manifest.
- Measure approval count, operator review time, task completion, denied unsafe attempts, time to reconstruct what occurred, and number of cases requiring an authority extension.
- Inject benign prompt-injection-style instructions into logs, tickets, or command output and verify that the gateway denies all operations outside the static manifest.
- Test expiry, immediate revocation, target/resource substitution attempts, retry behavior, malformed arguments, and bundle-composition attempts.

### Success criteria

The idea is worth extending if the prototype demonstrates:

- less approval overhead without an increase in authority breadth;
- reliable prevention of unapproved tool or argument use;
- clear, reconstructable receipt chains usable by another engineer or agent;
- manageable manifest authoring and review; and
- a recurring need across more than one operational domain.

If manifest authoring is painful or most tasks require frequent authority expansion, do not generalize prematurely. Improve task discovery, templates, and simulation first—or accept that the use case is better served by interactive approvals.

---

## 9. References

### Primary specifications and official documentation

1. Model Context Protocol, Authorization specification: https://modelcontextprotocol.io/specification/draft/basic/authorization
2. Model Context Protocol, Security Best Practices: https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices
3. RFC 8693, OAuth 2.0 Token Exchange: https://www.rfc-editor.org/info/rfc8693/
4. AWS STS AssumeRoleWithWebIdentity documentation: https://awscli.amazonaws.com/v2/documentation/api/2.22.8/reference/sts/assume-role-with-web-identity.html
5. HashiCorp Vault, Lease, Renew, and Revoke: https://developer.hashicorp.com/vault/docs/concepts/lease
6. SPIFFE concepts: https://spiffe.io/docs/latest/spiffe/concepts/
7. GitHub Actions, authentication with GITHUB_TOKEN: https://docs.github.com/actions/reference/authentication-in-a-workflow
8. GitHub Actions, OpenID Connect reference: https://docs.github.com/actions/reference/openid-connect-reference
9. Open Policy Agent documentation: https://openpolicyagent.org/docs
10. Linux capabilities(7): https://man7.org/linux/man-pages/man7/capabilities.7.html
11. sudoers(5): https://man7.org/linux/man-pages/man5/sudoers.5.html
12. in-toto Attestation Framework: https://github.com/in-toto/attestation
13. SLSA / in-toto overview: https://slsa.dev/blog/2023/05/in-toto-and-slsa
14. Claude Code permissions: https://code.claude.com/docs/en/permissions
15. Claude Code sandboxing: https://code.claude.com/docs/en/sandboxing
16. ChatGPT Codex sandboxing: https://learn.chatgpt.com/docs/sandboxing
17. OpenHands security and action confirmation: https://docs.openhands.dev/sdk/guides/security
18. NIST, AI agent standards initiative: https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative
19. NIST concept paper on software and AI-agent security adoption: https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd
20. Macaroons paper, NDSS: https://www.ndss-symposium.org/wp-content/uploads/2017/09/04_3_1.pdf
21. Zanzibar paper: https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/

### Bottom line

Task-scoped authority is worth building as an agent safety and operations product layer when it is implemented as **static-by-default, enforcement-backed, credential-attenuating, and receipt-producing**. The opportunity is a disciplined composition of mature security mechanisms around a bounded agent task—not a claim to have invented a new security foundation.
