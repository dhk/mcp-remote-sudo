# repo-template

A starting point for new personal repos, distilled from patterns already
working across dhk's other repos (`work-ledger`, `familiar-places`, `fossil`,
`crucible`, `skill-map`). Three goals drove the shape:

- **Instructive** — a stranger, human or Claude, can orient fast.
- **Build in public** — the repo's own files carry the argument; nothing
  depends on private context to make sense.
- **Workflow-visible** — session continuity is a file, not a lost thread.

## Use it

```bash
cp -r template/ ~/Documents/dev/<new-repo-name>
cd ~/Documents/dev/<new-repo-name>
# fill in the <placeholders> in README.md, CLAUDE.md, HANDOFF.md
git init && git add -A && git commit -m "Initial scaffold from repo-template"
```

Then work through [`SETUP.md`](template/SETUP.md) — the repo *settings* a file
copy cannot carry.

## What's in it, and why

| File | Answers | Pattern it's drawn from |
|---|---|---|
| `README.md` | What is this, why does it exist, what's actually done vs. planned | familiar-places (names its competitor), work-ledger (status honesty, links design issues instead of restating them), crucible ("check me out") |
| `CLAUDE.md` | Stack, architecture, conventions, **workflow rules** | Every repo's CLAUDE.md; workflow rules specifically from fossil |
| `HANDOFF.md` | Where did I leave off, what's next, known gotchas | familiar-places/handoff.md |
| `docs/snapshots/` | Frozen record of a design session or pivot, dated | fossil/context-snapshot.md, reading-with-ears' dated snapshots (relocated out of repo root — see below) |
| `SETUP.md` | The repo settings that a file copy cannot carry — branch protection, Actions permissions, Pages, secrets, and the local `gh` scope | Learned by hitting each one; see the file's closing note |
| `docs/design/` | Why a decision was made, not just what it is | praxis's four-question CONTRIBUTING.md frame, crucible/docs/concepts |
| `.scratch/` (gitignored) | Ephemeral working files — never committed | adventures-in-ai, work-ledger, crucible, reading-with-ears all already do this |
| `LICENSE` | Building in public means someone else can actually use this | Present in nearly every repo already |

## What's deliberately left out by default

`CONTRIBUTING.md` and `.github/ISSUE_TEMPLATE/` aren't in the base template —
most of these repos are solo build-in-public, not soliciting outside PRs. Add
them per-repo (skill-map's `CONTRIBUTING.md` is a good model) once a project
actually wants contributors.

CI workflows (`.github/workflows/`) are project-specific by nature — copy the
relevant one from `praxis`, `crucible`, `skill-map`, `tricorder`, or (for an
Astro/Node static site — build + non-blocking `astro check`, since a
type-check step usually needs to start informational until a codebase earns
a hard gate) `DHK-website`, rather than templating a generic one that won't
fit.

## HANDOFF.md vs. docs/snapshots/ — the split that matters

`HANDOFF.md` is **one file, always current, overwritten each session** — the
first thing a fresh session (you or Claude) should read: where things stand,
what's next, what to watch out for.

`docs/snapshots/YYYY-MM-DD-<topic>.md` is the opposite: **write-once,
permanent** — the output of a design sprint or the reasoning behind a pivot,
worth keeping forever.

Don't let one collapse into the other. reading-with-ears' dated snapshot
files committed loose at the repo root are the cautionary example — right
instinct (capture the session), wrong location (repo root, not `docs/`;
accumulating, not superseding a living handoff doc).
