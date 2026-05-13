#!/usr/bin/env bash
# raxis/scripts/check-no-real-anthropic-key.sh
#
# Pre-commit / CI guard for INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01.
#
# Walks `raxis/live-e2e/examples/` and exits non-zero if any file
# contains a byte string matching the real-Anthropic-key regex:
#
#   sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}
#
# Wire into your local pre-commit hook with:
#
#   cat > .git/hooks/pre-commit <<'SH'
#   #!/usr/bin/env bash
#   set -euo pipefail
#   raxis/scripts/check-no-real-anthropic-key.sh
#   SH
#   chmod +x .git/hooks/pre-commit
#
# CI invocation:
#
#   bash raxis/scripts/check-no-real-anthropic-key.sh
#
# The script is intentionally NOT installed automatically — modifying
# the operator's git hooks behind their back is its own footgun. The
# `raxis/live-e2e/examples/README.md` documents the wire-up; the
# operator runs it once per clone.

set -euo pipefail

# Resolve the repo root from this script's location so the guard
# works whether the caller invokes it from the workspace root, from
# `raxis/`, or from anywhere else.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
raxis_root="$(cd "$script_dir/.." && pwd)"
examples_dir="$raxis_root/live-e2e/examples"

if [[ ! -d "$examples_dir" ]]; then
    echo "check-no-real-anthropic-key: $examples_dir does not exist; nothing to check." >&2
    exit 0
fi

# Real Anthropic API keys are of the form `sk-ant-apiNN-...` where
# NN is a two-digit version number (`01`, `02`, `03` are the
# currently-issued series) and the body is at least 20 characters
# of `[A-Za-z0-9_-]`. The placeholder file uses
# `PLACEHOLDER_REPLACE_ME_WITH_REAL_KEY` which obviously does not
# match. ANYTHING that looks like a real key under examples/
# rejects the commit.
#
# We prefer `rg` (ripgrep) when present (much faster and handles
# binary files correctly); fall back to `grep -r -P` (Perl regex)
# which all reasonable Linux/macOS installations carry, and
# finally to `grep -r -E` (POSIX extended regex) for the broadest
# compatibility floor.
regex='sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}'

matched=""
if command -v rg >/dev/null 2>&1; then
    if rg --no-config --color=never --hidden --no-messages \
           "$regex" "$examples_dir" >/dev/null 2>&1; then
        matched="$(rg --no-config --color=never --hidden --no-messages \
                       -n "$regex" "$examples_dir" || true)"
    fi
elif grep -P -r -l "$regex" "$examples_dir" >/dev/null 2>&1; then
    matched="$(grep -P -r -n "$regex" "$examples_dir" || true)"
elif grep -E -r -l 'sk-ant-api[0-9][0-9]-[A-Za-z0-9_-]{20,}' "$examples_dir" \
        >/dev/null 2>&1; then
    matched="$(grep -E -r -n \
                 'sk-ant-api[0-9][0-9]-[A-Za-z0-9_-]{20,}' \
                 "$examples_dir" || true)"
fi

if [[ -n "$matched" ]]; then
    cat >&2 <<EOF
check-no-real-anthropic-key: REJECTED — a real-looking Anthropic API
key was found under $examples_dir:

$matched

The only allowed Anthropic-credential file in examples/credentials/
is anthropic.env.placeholder, and its value MUST be the literal
string PLACEHOLDER_REPLACE_ME_WITH_REAL_KEY (or any other value
that does NOT match the real-key regex
sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}).

INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01 (raxis/specs/invariants.md
§11.10) prohibits checking a real Anthropic API key into the repo.

Remediation:

  1. Revert the offending file:
     git checkout raxis/live-e2e/examples/credentials/anthropic.env.placeholder
  2. If a refresh of the example bundle wrote a real key, that is a
     bug in maybe_refresh_examples (kernel/tests/extended_e2e_support/
     kernel_driver.rs) — file an issue and DO NOT \`git add\` the
     refresh output until the bug is fixed.
  3. If you intentionally pasted a real key into the file, rotate
     the key in your Anthropic console immediately — assume it is
     compromised the moment it touched the worktree.

EOF
    exit 1
fi

echo "check-no-real-anthropic-key: OK ($examples_dir is clean)."
