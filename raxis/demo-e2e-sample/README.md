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

# 3. Start kernel, sign plan, submit + approve.
#    The kernel always mints a fresh UUID for the new initiative; the
#    first argument to `plan submit` is a free-form label shown in CLI
#    output, NOT the canonical id. Capture the UUID from stdout and
#    pass it to `plan approve` (and to every later `plan reject`,
#    `initiative abort`, `task retry`, etc.):
#
#    raxis policy sign "$PLAN_DIR/plan.toml" --key operator_private.pem
#    SUBMIT_OUT="$(raxis plan submit demo "$PLAN_DIR")"
#    echo "$SUBMIT_OUT"
#    INIT_ID="$(printf '%s\n' "$SUBMIT_OUT" \
#                 | awk '/^Initiative/ {print $2; exit}')"
#    raxis plan approve "$INIT_ID"

# 4. Git worktree for a planner session (example):
#    lineage="$(uuidgen | tr '[:upper:]' '[:lower:]')"
#    wt="/tmp/raxis-e2e-worktrees/$lineage"
#    mkdir -p "$(dirname "$wt")"
#    git -C "$REPO_ROOT" worktree add "$wt" -b "agents/$lineage"
```

Full ceremony details: [`README.md`](../README.md) (Quick Start), [`specs/v1/cli-ceremony.md`](../specs/v1/cli-ceremony.md).
