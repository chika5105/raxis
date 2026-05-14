# `.github/scripts/`

Operator-side GitHub repository configuration scripts. These are
**one-shot** scripts run by the repo owner from a workstation with
the `gh` CLI authenticated as `chika5105`. They are NOT invoked by
GitHub Actions and do not run in CI.

## Files

### `protect-main.sh`

Configures branch protection on `main` so that:

- Only the repo owner (`chika5105`) can push directly to `main`. All
  other contributors must open a pull request.
- Pull requests CANNOT merge until these CI checks succeed:
  - `spec-graph` — `cargo xtask spec-graph --strict` is green.
  - `build-images / cargo check + test (ubuntu-22.04)` — workspace
    compiles and tests pass on Linux.
- Force-pushes to `main` are denied.
- Branch deletions are denied.
- Stale PRs must rebase on the new `main` before merge
  (`required_status_checks.strict = true`).
- Open conversations on a PR must be resolved before merge.
- Repo admins (the owner) are NOT bound by status checks
  (`enforce_admins = false`) — the owner can ship an emergency hotfix
  even when the matrix itself is broken. Direct-push by the owner
  remains the primary escape hatch.

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
