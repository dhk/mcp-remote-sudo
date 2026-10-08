# Roadmap: operator-in-the-loop diagnosis and remediation

Status: proposed
Tracking: #45
Builds on: [`task-scoped-remote-authority.md`](task-scoped-remote-authority.md) (#31), self-update Task Pack (#16, PR #17)

## 1. The goal

An operator notices a problem on a machine running mcp-remote-sudo. With Claude, they should be able to:

1. **See** the problem through typed, read-only diagnostics.
2. **Ask** which tool surfaces the investigation needs, and get back a concrete, reviewable authority proposal.
3. **Ship and enable** those surfaces: install the relevant Task Pack and grant a narrow, expiring authority with one
   operator command.
4. **Diagnose, test and change** interactively. Claude proposes each step, the operator confirms each change, and
   every attempt leaves a receipt.

The thing you ship is a **Task Pack**: a versioned bundle of typed operations, authority templates and the host
privileges they need. It replaces one-off scripts.

### The principle: the client reasons, the server enforces

The remote server never decides how to solve a problem. Claude, working with the operator, does the reasoning. The
server stays small and predictable: it exposes the typed operations the active authority allows, checks every
invocation, runs fixed adapters and writes receipts. Keeping the intelligence on the client side is what makes it safe
to give the server the ability to change things.

## 2. What exists today

Today the server has:

- a TaskAuthority manifest: binding, absolute expiry, `renewable: false`, `expansion: prohibited`, and allow and deny
  rules with `enum`, `minimum` and `maximum` constraints
- tool exposure and invocation checks driven by that manifest
- read-only adapters: system, network, Wi-Fi, systemd status, bounded journal, and the PR #29 Wi-Fi diagnostic pack
- hash-chained, append-only receipts
- a loopback-only Streamable HTTP listener, reached through an SSH port forward
- a one-command installer with a hardened systemd unit (`NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectKernelModules`, …)

## 3. What the first real investigation showed

On 2026-10-03, mcp-remote-sudo was used to diagnose a recurring Broadcom `wl` Wi-Fi failure on `lobster`. The
failure follows the same pattern every time:

1. The access point disconnects the host.
2. A scan stays pending inside `wl`.
3. `wpa_supplicant` rejects every further scan.
4. NetworkManager reports `ssid-not-found`, then goes silent until a reboot.

The read-only MCP path worked. Every decisive step still needed SSH or root scripts:

| Need | What happened | Gap → issue |
|---|---|---|
| Previous-boot logs and a time window | not possible through MCP; used SSH | journal boot and time bounds → #33 |
| Kernel driver evidence | all 200 lines were `[UFW BLOCK] IN=wlp2s0`, because `wlp` matched | noise filtering → #34 |
| Unknown manifest keys | nested unknown keys are silently accepted (found in review) | fail closed → #48 |
| Driver version | `modinfo` failed under `ProtectKernelModules=true` | read sysfs instead → #35 |
| "Did an explicit scan reproduce it?" | the scan may have come from cache | explicit rescan → #35 |
| Gateway and Internet probes | `ping` file capabilities blocked by `NoNewPrivileges` | scoped ICMP support → #36 |
| Upgrading the install | the installer would have moved the port to 8765, already used by another service, and overwritten the authority | preserve port and authority → #36 |
| Granting a new authority | a hand-written root script: back up, validate, replace, restart, verify | admin CLI and hot reload → #38 |
| Confirming receipts | the receipts file is root-only | `receipts.tail` and verification → #37 |
| Deciding what to authorize | read the source code | `authority.propose` → #40 |
| Trying a recovery | impossible by design; there is no mutation path | helper, confirmation, remediation pack → #41–#43 |

There was also a documentation gap: the original design and research documents (PR #4) were merged into a stacked
branch and never reached `main` (#31).

## 4. Target architecture

```text
 Claude (reasons)                      operator (approves)
      │  MCP over SSH port forward            │ sudo
      ▼                                       ▼
┌────────────────────────────┐     ┌─────────────────────────┐
│ mcp-remote-sudo (unpriv.)  │     │ mcp-remote-sudo-admin   │
│  pack registry ──► tools   │     │ validate/diff/grant/    │
│  authority evaluator       │◄────│ revoke/status/receipts  │
│  authority.propose ────────┼────►│ grant --proposal <id>   │
│  confirmation (elicitation)│     └─────────────────────────┘
│  receipts (+ tail)         │  SIGHUP reload, no restart
└────────────┬───────────────┘
             │ typed JSON over Unix socket (SO_PEERCRED-checked)
             ▼
┌────────────────────────────┐
│ mcp-remote-sudo-helper     │  root, socket-activated, own hardening,
│  fixed op table            │  re-checks the active manifest,
│  (radio, unit restart,     │  shared with self-update (#16)
│   module reload, update)   │
└────────────────────────────┘
```

### Task Packs (#32)

A pack declares a set of operations. Each operation has:

- a dotted name, such as `wifi.scan`
- an MCP tool name
- typed parameters
- an adapter
- a `mutating` flag
- the host privileges it needs

Packs also ship authority templates: `read-only`, and `remediate` where relevant. There are two built-in packs,
`core` and `wifi`. External packs register through the `mcp_remote_sudo.packs` entry-point group.

**Installed is not the same as authorized.** A pack being installed only makes its operations available. The active
authority decides what is actually exposed. If the authority allows an operation that no installed pack provides, the
server fails at startup.

**Shipping a pack.** Packs are ordinary Python distributions:

- **Built-in packs** ship inside mcp-remote-sudo and update with it (#16).
- **External packs** are installed by the operator, never by the agent, with
  `mcp-remote-sudo-admin pack install --requirements <lockfile>` (#38). The lockfile pins every distribution, including
  dependencies, to an exact version and hash. Installation accepts **wheels only** (`--only-binary :all:
  --require-hashes --no-deps` against the lockfile), so no build hooks ever run as root. It installs into the service's
  own virtualenv only, never system-wide, refuses to replace mcp-remote-sudo's own distributions, and then reloads.
- `pack list` shows the installed packs and which of their operations the active authority currently exposes.
- `pack remove` uninstalls a pack. It refuses while the active authority still references any of its operations.

Installing a pack grants nothing. Authority still comes only from a `grant`.

### Operator administration (#37–#39)

`mcp-remote-sudo-admin` turns the hand-written script from the lobster session into a product:

- `validate` and `diff` check a manifest without changing anything.
- `pack list`, `pack install` and `pack remove` manage installed packs (see above).
- `grant` validates the manifest, checks the binding, backs up the current authority, replaces it atomically, sends
  SIGHUP and checks health.
- `revoke` installs an expired deny-all authority.
- `status` reports the current state.
- `receipts verify` checks the receipt chain.

Every grant gets its own session ID, so each investigation has its own receipt trail. The operator's sudo password
stays the approval point. Claude never holds root.

### Proposals (#40)

`authority.propose(purpose, operations, constraints, ttl_minutes)` takes operations from the installed packs and builds
a manifest from their templates. It stores the result as a proposal and returns the YAML, a diff against the current
authority, and the proposal's SHA-256 digest. **It grants nothing**: `expansion: prohibited` still holds.

The proposal store is writable by the unprivileged service, so the operator grants **by content, not by ID**:
`admin grant --proposal <id> --sha256 <digest>`. The admin command first copies the proposal into root-owned staging,
then checks the digest against the one the operator reviewed, re-validates, and only then installs it. A proposal swapped
after review fails the digest check.

### Controlled mutation (#41–#43)

- **Helper (#41).** Privileged work runs in a root-owned helper started on demand through a socket. Using `sudo` is not
  an option, because the main service keeps `NoNewPrivileges=true`. The helper only accepts requests from the service
  user, only runs operations from its own fixed table, and re-checks the active manifest itself as a second layer of
  defence.
- **Confirmation (#42).** Mutating operations need per-action confirmation, at one of two strengths the grant chooses:
  - `confirmation: operator` (the default for mutation templates). The helper itself refuses to act until a root-owned
    approval record exists for that exact request: request ID, operation, arguments and manifest hash. The operator
    creates it with `admin approve <request-id>`, which needs sudo. Code running as the service user cannot forge it, so
    this control holds even if the service user is compromised.
  - `confirmation: elicitation`. The server asks through MCP elicitation, and refuses if the client can't ask. This is
    a convenience and accountability control, **not** a boundary against code running as the service user, which can
    reach the helper socket directly. Against that threat, the boundary is the helper's fixed operation table plus its
    re-check of the manifest. The documentation says so explicitly.
  - `confirmation: grant-only` skips per-action confirmation, and must be stated explicitly in the grant.
- **First remediation pack (#43).** `wifi-remediate` provides radio toggle, restart of an allowlisted unit, and reload
  of an allowlisted module. These are the recovery steps for the lobster pattern, from least to most invasive, and
  every receipt records the inverse operation where one exists (a service restart, for example, has none).

## 5. Plan and parallelism

Work runs in three lanes. The lanes only run in parallel where their files don't overlap, so there's no risk of rebase
or merge conflicts.

| Lane | Issues | Files | Order |
|---|---|---|---|
| Docs | #30, #31 | `docs/design/*`, `docs/research/*` | parallel with everything |
| Installer | #36, then helper installation as part of #41 | `install/*`, `tests/test_installer.sh`, `docs/installation/*` | parallel with the runtime lane until #41 |
| Runtime | #48 → #32 → #33 → #34 → #35 → #37 → #38 → #39 → #40 → #41 → #42 → #43 | `src/*`, `tests/*.py`, `pyproject.toml`, `docs/task-packs/*` | strictly one after another |

Other rules:

- **README edits** happen only in the final PR of a phase, so lanes never contend for that file.
- **#16 (self-update)** starts after #41.
- **#44 (end-to-end on lobster)** comes last and needs the operator.

### Merge gate (every PR)

A PR merges only when both of these are true:

1. CI (`test`) is green on the head commit.
2. Copilot has reviewed the head commit, and every Copilot thread is resolved: either fixed, or answered with a
   rationale. When fixes are pushed, review is requested again.

## 6. Non-goals

These are unchanged from the original design:

- an arbitrary shell
- general sudo or root
- package management
- arbitrary filesystem writes
- reboot
- automatic expansion of authority
- multi-host orchestration
- replacing SSH as the transport

## 7. Done means

The lobster scenario runs end to end without SSH for diagnosis and without hand-written root scripts (#44):

1. Claude sees the stuck-scan pattern through the `wifi` and `core` packs.
2. Claude proposes a `wifi-remediate` authority.
3. The operator grants it with one command.
4. Claude walks the recovery steps, with the operator confirming each one.
5. `admin receipts verify` shows the full, untampered record.
