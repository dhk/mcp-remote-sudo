# Setup

Things a new repo needs that **cannot be copied from a template**, because they
are GitHub *settings* rather than files. `cp -r template/` and "Use this
template" both carry files only.

Work through this once, when the repo is created. Most repos need only the first
two.

---

## Branch protection — require pull requests

Keeps `main` reviewable and stops a stray `git push origin main`.

```bash
gh api -X PUT repos/<owner>/<repo>/branches/main/protection \
  --input - <<'JSON'
{
  "required_pull_request_reviews": {"required_approving_review_count": 0},
  "required_status_checks": null,
  "enforce_admins": false,
  "restrictions": null
}
JSON
```

`required_approving_review_count: 0` still forces the PR — it just doesn't
require someone else to approve it, which on a solo repo would deadlock.

**Only available on public repos, or private repos on GitHub Pro.** On a private
repo without Pro the API returns 403 and the discipline has to come from you.

## Actions permissions

Default is fine for most repos. Two cases need a change.

**A workflow that opens pull requests.** `permissions: pull-requests: write` in
the workflow is *not* sufficient — a separate repository policy gates the
capability, and without it `gh pr create` fails with:

```
GitHub Actions is not permitted to create or approve pull requests
```

```bash
gh api -X PUT repos/<owner>/<repo>/actions/permissions/workflow \
  -F default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=true
```

Leave this **off** unless a workflow actually needs it. Enabling it lets *any*
workflow in the repo open PRs with `GITHUB_TOKEN`. It does not let Actions merge
into a protected branch, so a PR-required rule still holds.

**A workflow that pushes commits.** Add `permissions: contents: write` to the
job. Note this grants repository write; it does **not** exempt a push from
branch protection. A bot cannot push to a protected `main` no matter what
permissions it holds — have it open a PR instead.

## Pages

Only if the repo publishes a site.

```bash
gh api -X POST repos/<owner>/<repo>/pages \
  -F 'source[branch]=main' -F 'source[path]=/'
```

## Secrets

Never commit them; set them per-repo.

```bash
gh secret set OPENROUTER_API_KEY --repo <owner>/<repo>
```

## Local gh scope

Pushing anything under `.github/workflows/` needs the `workflow` scope, which
the default OAuth token lacks. Symptom:

```
refusing to allow an OAuth App to create or update workflow ... without `workflow` scope
```

Fix it once, globally:

```bash
gh auth refresh -s workflow
```

Or push that branch over SSH explicitly, which bypasses the OAuth token
entirely.

---

## Why this file exists

Every item here was learned by hitting it. The Actions-permissions one cost an
hour: the failure surfaced as `GH006: Protected branch update failed`, which led
to the workflow's `permissions:` block, which was the wrong layer — a *policy*
gates the capability independently of the *token scope*. Two different
mechanisms, one indistinguishable symptom.

A checklist turns each of those into a lookup.
