# RAXIS demo: sample Git repo + minimal plan

This directory is a **template** for operator-side E2E testing. Running `setup.sh` creates:

- **`repo/`** — a tiny Git repo with commits under **`src/`** and **`tests/`** (matching the minimal plan path allowlist).
- **`plan/`** — **`plan.toml`** ready to sign (**`plan.sig`** is created by `raxis policy sign`).

## Quick start

```bash
# 1. Materialize demo (argument = destination parent; defaults to TMPDIR).
./setup.sh /tmp/raxis-e2e-demo

# Prints paths: DEMO_ROOT, REPO_ROOT, PLAN_DIR, HEAD_OID, PARENT_OID

# 2. Point RAXIS policy [sessions] allowed_worktree_roots at the *parent* of
#    any worktree you add (e.g. /tmp or /tmp/raxis-e2e-demo), then sign policy.

# 3. Start kernel, sign plan, submit + approve:
#    raxis policy sign "$PLAN_DIR/plan.toml" --key operator_private.pem
#    raxis plan submit test-minimal-001 "$PLAN_DIR"
#    raxis plan approve test-minimal-001

# 4. Git worktree for a planner session (example):
#    lineage="$(uuidgen | tr '[:upper:]' '[:lower:]')"
#    wt="/tmp/raxis-e2e-worktrees/$lineage"
#    mkdir -p "$(dirname "$wt")"
#    git -C "$REPO_ROOT" worktree add "$wt" -b "agents/$lineage"
```

Full ceremony details: [`README.md`](../README.md) (Quick Start), [`specs/v1/cli-ceremony.md`](../specs/v1/cli-ceremony.md).
