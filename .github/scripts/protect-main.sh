#!/usr/bin/env bash
# Configure branch protection on `main` for chika5105/aegis-ai.
#
# Outcome (after this script runs):
#
#   - `main` is restricted: only the repository OWNER (the personal
#     user account that owns the repo) can push directly. Every other
#     contributor must open a PR.
#   - PRs to `main` REQUIRE these CI checks to pass before merge:
#       * spec-graph                          (cargo xtask spec-graph --strict)
#       * build-images / cargo check + test   (matrix: ubuntu-22.04, macos-14)
#       * build-images / cargo check + test (Linux only) is sufficient as a
#         minimum gate; the macOS arm is informational so contributors
#         without macOS can still get green if Linux passes.
#   - Force-pushes are disabled.
#   - Branch deletions are disabled.
#   - Even repo admins/owners are NOT subject to status-check enforcement
#     (`enforce_admins=false`) so the owner can land an emergency
#     hotfix without satisfying the matrix when the matrix itself is
#     broken. This is the conventional escape hatch; the OWNER's
#     direct-push privilege is the *primary* escape hatch.
#
# Why this design:
#
#   - GitHub's only mechanism to bound "who can push directly" on a
#     branch is the `restrictions` block (paid plans only on private
#     repos; available on public repos for free). Personal-account
#     repos automatically grant push to the owner; the `restrictions`
#     block therefore reduces to "no one EXCEPT the owner". For a
#     personal account, an empty `restrictions.users` array
#     EXCLUDES contributors but PRESERVES owner access.
#
#   - This is configured idempotently via `gh api`. Re-running the
#     script is a no-op (PUT is the API verb).
#
# Prerequisites:
#
#   - `gh auth status` — authenticated as the repo owner (chika5105).
#   - `jq` — available on PATH.
#
# Usage:
#
#     bash .github/scripts/protect-main.sh
#
# To inspect current protection without changing it:
#
#     gh api -H "Accept: application/vnd.github+json" \
#       repos/chika5105/aegis-ai/branches/main/protection | jq .
#
# Reference:
#
#   - https://docs.github.com/en/rest/branches/branch-protection#update-branch-protection
#
set -euo pipefail

OWNER_REPO="${OWNER_REPO:-chika5105/aegis-ai}"
BRANCH="${BRANCH:-main}"

if ! command -v gh >/dev/null 2>&1; then
    echo "error: gh CLI not found (install: https://cli.github.com/)" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq not found (install: https://stedolan.github.io/jq/)" >&2
    exit 1
fi

# Verify the calling user is the repo owner. Direct-push restriction
# is only meaningful if the script is run by the owner.
ME="$(gh api user -q .login)"
if [ "${ME}" != "chika5105" ]; then
    echo "warn: current gh user is '${ME}', not 'chika5105'." >&2
    echo "      Branch protection on a personal-account repo can only" >&2
    echo "      be configured by the owner. The PUT will fail with 403" >&2
    echo "      unless you switch accounts via 'gh auth switch'." >&2
fi

# Required status checks. These are the GitHub Actions check names
# (the `name:` field in each workflow's `jobs.<id>.name` after job
# IDs are mapped through GitHub's check-name rendering rule, which is
# `<workflow-name> / <job-name>`).
#
# Spec-graph publishes its check as just "spec-graph" (no slash)
# because the workflow name and the job name are both spec-graph
# and GitHub collapses identical pairs.
declare -a REQUIRED_CHECKS=(
    "spec-graph"
    "build-images / cargo check + test (ubuntu-22.04)"
)

# Build the JSON body from the array safely via jq.
JSON_BODY="$(jq -n --argjson checks "$(printf '%s\n' "${REQUIRED_CHECKS[@]}" \
    | jq -R . | jq -s .)" '{
    required_status_checks: {
        strict: true,
        checks: ($checks | map({context: ., app_id: -1}))
    },
    enforce_admins: false,
    required_pull_request_reviews: null,
    restrictions: {
        users: [],
        teams: [],
        apps:  []
    },
    required_linear_history: false,
    allow_force_pushes:      false,
    allow_deletions:         false,
    block_creations:         false,
    required_conversation_resolution: true,
    lock_branch:             false,
    allow_fork_syncing:      false
}')"

echo "applying protection to ${OWNER_REPO}:${BRANCH} ..."
echo "  required checks:"
for c in "${REQUIRED_CHECKS[@]}"; do
    printf '    %s\n' "$c"
done

echo "${JSON_BODY}" | gh api \
    --method PUT \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "repos/${OWNER_REPO}/branches/${BRANCH}/protection" \
    --input -

echo
echo "ok: protection applied. Verify:"
echo "  gh api repos/${OWNER_REPO}/branches/${BRANCH}/protection | jq ."
