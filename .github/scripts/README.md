# `.github/scripts/`

Operator-side GitHub repository configuration scripts. These are
**one-shot** scripts run by the repo owner from a workstation with
the `gh` CLI authenticated as `chika5105`. They are NOT invoked by
GitHub Actions and do not run in CI.

GitHub stores branch-protection rules in repository settings, not in
git. These scripts are the auditable source for the intended settings,
but the owner must run them against GitHub for the rules to take
effect. Private repositories may require GitHub Pro, Team, or
Enterprise before GitHub accepts branch protection; public repositories
can use it on the free plan.

## Files

### `protect-main.sh`

Configures branch protection on `main` so that:

- Only the repo owner (`chika5105`) can push or merge to `main`. All
  other contributors must open a pull request and cannot merge it.
- Pull requests CANNOT merge until these CI checks succeed:
  - `spec-graph` — `cargo xtask spec-graph --strict` is green.
  - `build-images / cargo check + test (ubuntu-22.04)` — workspace
    compiles and tests pass on Linux.
  - `build-images / dashboard-fe build` — changed operator-dashboard
    frontend inputs produce a production Vite build.
  - `build-images / raxis-site build` — changed marketing/docs-site
    inputs produce a production Next.js build.
  - `cla-check / cla` — the CLA-agreement checkbox in the PR
    description (from [`.github/PULL_REQUEST_TEMPLATE.md`](../PULL_REQUEST_TEMPLATE.md)) is ticked.
    The CLA itself lives at [`raxis/CLA.md`](../../raxis/CLA.md).
- Force-pushes to `main` are denied.
- Branch deletions are denied.
- Pull requests require one stale-dismissed CODEOWNER approval.
  [`.github/CODEOWNERS`](../CODEOWNERS) names only `@chika5105`, so
  approval by anyone else can be useful review signal but does not
  satisfy the merge gate.
- Stale PRs must rebase on the new `main` before merge
  (`required_status_checks.strict = true`).
- Open conversations on a PR must be resolved before merge.
- Repo admins/owners are bound by the same branch protection
  (`enforce_admins = true`) so the branch rule is consistent.

#### Run it

```bash
gh auth switch --user chika5105     # only if you have multiple gh accounts
bash .github/scripts/protect-main.sh
```

The script is idempotent — re-running it just re-applies the same
configuration via `PUT`.

#### Inspect current protection

```bash
gh api repos/chika5105/raxis/branches/main/protection | jq .
```

#### Adjust required checks

Edit the `REQUIRED_CHECKS` array in `protect-main.sh`. The check
names match the GitHub Actions UI's display name, which for jobs in
matrix configurations is `<workflow-name> / <job-name>
(<matrix-key>)`.

## Why scripts and not Terraform / Pulumi?

This repo currently has one branch with a small protection profile.
A bash + `gh api` script is shorter than the equivalent IaC, runs
without provisioning a state backend, and is auditable in a single
file. If the repo ever grows multiple long-lived branches with
distinct protection profiles, this directory can be promoted to
Terraform's `github_branch_protection_v3` resource without breaking
the script-driven baseline.
