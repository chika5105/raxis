# RAXIS Scenario Catalogue

> **Audience.** Operators who completed
> [`../getting-started/`](../getting-started/) and want runnable
> examples beyond the first initiative.

The numbered folders are the fifty end-to-end examples used by the
website. They are written to run against the same Homebrew production
shape as the getting-started guide:

- Runtime bundle: `RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"`.
- Data dir: `RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"` unless
  you intentionally created a disposable data dir.
- Operator key convenience: `RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"`.
- Managed repos: `$RAXIS_DATA_DIR/repositories/<repository_id>`.
- Prefer repository ids that match the real repo name, such as `api`,
  `web`, or `hello-world`. Older scenario fixtures may still use
  `main`; that is a repository id, not a branch name.
- Kernel worktrees: `$RAXIS_DATA_DIR/worktrees`.

RAXIS does not execute against the directory you happen to be in. The
kernel clones from the managed repository named by the plan's
`[workspace] repository` field into its own managed worktrees, then
fast-forwards the admitted `target_ref`.

---

## Standard Homebrew Runner

Use this shape for every scenario that has a `plan.toml`:

```bash
export RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
export RAXIS_DATA_DIR="${RAXIS_DATA_DIR:-$(brew --prefix)/var/lib/raxis}"
export RAXIS_OPERATOR_KEY="${RAXIS_OPERATOR_KEY:-$HOME/raxis-keys/operator_private.pem}"
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"

# The Homebrew setup helper starts the supervisor/kernel daemon.
# Check it before submitting work:
raxis-supervisor status --data-dir "$RAXIS_DATA_DIR"

# In this terminal, stand in the scenario folder.
cd /path/to/raxis/guides/scenarios/01-hello-world

# Seed the managed repo used by this scenario fixture.
rm -rf "$RAXIS_MAIN_REPO"
install -d "$(dirname "$RAXIS_MAIN_REPO")"
git init -q "$RAXIS_MAIN_REPO"
git -C "$RAXIS_MAIN_REPO" symbolic-ref HEAD refs/heads/main

# Materialise the files this scenario starts from, then commit them.
printf '# scenario seed\n' > "$RAXIS_MAIN_REPO/README.md"
git -C "$RAXIS_MAIN_REPO" -c user.email=demo@raxis.local -c user.name=Demo add .
git -C "$RAXIS_MAIN_REPO" -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"

# Validate, submit, approve, watch.
PLAN_PATH="$PWD/plan.toml"
raxis plan validate "$PLAN_PATH"
INIT_ID="$(raxis submit plan "$PLAN_PATH" --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
echo "INIT_ID=$INIT_ID"
raxis plan approve "$INIT_ID"
raxis initiative show "$INIT_ID" --with-tasks
```

After completion, inspect the merged result in the canonical repo:

```bash
git -C "$RAXIS_MAIN_REPO" log --oneline -5
raxis verify-chain
raxis doctor
```

---

## Reruns and Task IDs

Checked-in scenario plans use readable task IDs like `greeter`,
`adder`, and `reviewer`. Those are good for learning, but task IDs are
stored globally in `kernel.db`. If you rerun the same plan in the same
data dir and see odd admission behavior, use a fresh `RAXIS_DATA_DIR`
or edit the scenario plan to make the task IDs unique.

The getting-started page shows a timestamped task ID pattern for
repeatable local demos.

---

## Bringing Your Own Repo

For real work, adopt a clone into a named managed repository. Do not
symlink an arbitrary checkout into the data dir unless you are doing
low-level debugging and understand the risk to your working tree.

```bash
export RAXIS_REPO_ID="$(basename /path/to/your/repo)"
raxis repo adopt "$RAXIS_REPO_ID" /path/to/your/repo
raxis repo status "$RAXIS_REPO_ID"
```

For 0.2.0 multi-repo plans, adopt additional repositories and set the
plan field:

```toml
[workspace]
name       = "API change"
lane_id    = "default"
target_ref = "refs/heads/main"
repository = "api"
```

Then:

```bash
raxis repo adopt api /path/to/api-repo
raxis repo status api
```

---

## CLI State Names

Current CLI state filters are bucket names:

```bash
raxis initiative list --state active
raxis initiative list --state completed
raxis initiative list --state quarantined
raxis initiative list --state all
```

Do not script against the older `--state Draft` / `--state Completed`
examples. Prefer capturing the initiative ID directly from
`raxis submit plan` as shown above.

---

## What the Fifty Scenarios Cover

| Range | Focus |
|---|---|
| 01-05 | Minimal execution, review, witnesses, and regression loops. |
| 06-15 | Multi-task plans, panels, sequencing, API/docs/database changes. |
| 16-25 | Rollouts, compliance, refactors, conflict handling, limits. |
| 26-35 | Abort paths, verifier families, symbol indexing, egress. |
| 36-40 | Credential proxies and deny-by-default networking. |
| 41-44 | Read-only/control-plane operations: audit replay, operator rotation, epoch advance, session revocation. |
| 45 | Admission rejection; success means no initiative is created. |
| 46 | Two concurrent initiatives in the same kernel. |
| 47-50 | Recovery, provider failover, budget exhaustion, and full feature shipment. |

Each numbered page keeps the scenario-specific seed files, policy
delta, and success criteria. Use this page as the shared runner and
the individual page for what makes that scenario interesting.
