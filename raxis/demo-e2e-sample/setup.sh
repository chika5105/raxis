#!/usr/bin/env bash
# Creates a reproducible demo tree: repo/ + plan/plan.toml
#
# Usage:
#   ./setup.sh [DEST]
#
# DEST  Parent directory for the demo (default: mktemp under ${TMPDIR:-/tmp}).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEST="${1:-}"
if [[ -z "${DEST}" ]]; then
  DEST="$(mktemp -d "${TMPDIR:-/tmp}/raxis-e2e-demo.XXXXXX")"
else
  mkdir -p "${DEST}"
  DEST="$(cd "${DEST}" && pwd)"
fi

REPO="${DEST}/repo"
PLAN="${DEST}/plan"

if [[ -d "${REPO}/.git" ]]; then
  echo "error: repo already exists at ${REPO} — pick an empty DEST or remove it" >&2
  exit 1
fi

mkdir -p "${PLAN}" "${REPO}/src" "${REPO}/tests"

cp "${SCRIPT_DIR}/plan/plan.toml" "${PLAN}/plan.toml"

cd "${REPO}"
git init

# Normalize default branch name to main (portable across older git that lack `git init -b`).
git config user.email "demo-local@raxis.invalid"
git config user.name "RAXIS Demo"

cat > README.md <<'EOF'
# RAXIS E2E sample repo

Two commits touching `src/` and `tests/` so you can experiment with SingleCommit ranges.
EOF

cat > src/lib.rs <<'EOF'
/// Demo crate root for RAXIS path allowlist checks.
pub fn demo_message() -> &'static str {
    "raxis-demo"
}
EOF

cat > tests/smoke.rs <<'EOF'
#[test]
fn smoke() {
    assert_eq!(raxis_demo::demo_message(), "raxis-demo");
}
EOF

# Minimal crate marker so paths look like a real Rust layout (kernel only diffs commits).
cat > Cargo.toml <<'EOF'
[package]
name = "raxis-demo"
version = "0.0.0"
edition = "2021"
EOF

git add README.md Cargo.toml src/lib.rs tests/smoke.rs
git commit -m "demo: initial commit"
git branch -M main

echo "" >> src/lib.rs
git add src/lib.rs
git commit -m "demo: extend lib"

HEAD="$(git rev-parse HEAD)"
PARENT="$(git rev-parse HEAD^)"

cat <<EOF

RAXIS demo sample created:

  DEMO_ROOT   ${DEST}
  REPO_ROOT   ${REPO}
  PLAN_DIR    ${PLAN}

  HEAD (40 hex)     ${HEAD}
  HEAD^ (40 hex)    ${PARENT}

Next steps:

  1. Add REPO_ROOT (or the parent of future worktrees) to your policy's
     [sessions].allowed_worktree_roots, then re-sign and load the policy.

  2. Sign the plan:
       raxis policy sign ${PLAN}/plan.toml --key <operator_private.pem>

  3. Submit the plan. The kernel ALWAYS mints a fresh UUID v4 as the
     canonical initiative_id; the first argument to "plan submit" is a
     free-form label shown only in CLI output, NOT the kernel-side id.
     The kernel echoes the assigned UUID on its success line:
         "Initiative <uuid> created. Status: Draft"
     Capture it for the next step:

       SUBMIT_OUT="\$(raxis plan submit demo ${PLAN})"
       echo "\$SUBMIT_OUT"
       INIT_ID="\$(printf '%s\\n' "\$SUBMIT_OUT" \\
                  | awk '/^Initiative/ {print \$2; exit}')"

  4. Approve using the kernel-assigned UUID — NOT the label from step 3:

       raxis plan approve "\$INIT_ID"

  (Same rule applies to "plan reject", "initiative abort", "task retry",
   etc. They all key off the UUID echoed by "plan submit".)

Planner smoke (SingleCommit vacuous diff): base_sha=head_sha=${HEAD}

EOF
