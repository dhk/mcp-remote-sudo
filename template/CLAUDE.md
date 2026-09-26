# CLAUDE.md

This file provides guidance to Claude Code when working with code in this
repository.

## What this is

<One paragraph: purpose, stack, the one architectural idea that matters
most — the thing a fresh session most needs to know before touching code.>

## Workflow Rules

**All work in this repo must go through branches and PRs.** (Delete or
relax this section if that's genuinely not how you work here — but decide
that on purpose, don't drift into it by default.)

- Never commit directly to `main`
- Every task starts with a GitHub issue
- Every issue gets its own branch (`feat/`, `fix/`, `chore/`, `docs/` prefix)
- Every branch gets a PR before merging
- PRs should reference the issue they close (`Closes #N`)

## Architecture

<Key files, data flow, the non-obvious decisions — what a fresh session
needs and can't infer from reading code alone.>

## Commands

```bash
<the commands you actually run — dev, test, build, deploy>
```

## Conventions

<Naming, formatting, patterns that would surprise a contributor seeing this
code for the first time.>

## Notes for next session

<Anything discovered this session the next session shouldn't have to
rediscover. If this grows past a few bullets, it belongs in HANDOFF.md
instead — this section is for small, code-adjacent notes, not session
state.>
