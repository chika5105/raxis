# RAXIS Scenario Catalogue

> **Audience.** Operators who completed
> [`../getting-started/`](../getting-started/) and want runnable
> examples beyond the first initiative.

The numbered folders are the fifty end-to-end examples used by the
website. They are written to run against the same Homebrew production
shape as the getting-started guide:

- Runtime bundle: `RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"`.
- Data dir: `RAXIS_DATA_DIR="$HOME/.raxis"` unless you intentionally
  created a disposable data dir.
- Operator key convenience: `RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"`.
- Canonical source repo: `$RAXIS_DATA_DIR/repositories/main`.
- Kernel worktrees: `$RAXIS_DATA_DIR/worktrees`.

RAXIS does not execute against the directory you happen to be in. The
kernel clones from `$RAXIS_DATA_DIR/repositories/main` into its own
managed worktrees, then fast-forwards the admitted `target_ref`.

---

## Standard Homebrew Runner

Use this shape for every scenario that has a `plan.toml`:

```bash
export RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
export RAXIS_DATA_DIR="${RAXIS_DATA_DIR:-$HOME/.raxis}"
export RAXIS_OPERATOR_KEY="${RAXIS_OPERATOR_KEY:-$HOME/raxis-keys/operator_private.pem}"
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"

# In another terminal, keep the kernel running with the same env:
#   raxis-kernel

# In this terminal, stand in the scenario folder.
cd /path/to/raxis/guides/scenarios/01-hello-world

# Seed the canonical repo for the scenario.
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
