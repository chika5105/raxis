#!/usr/bin/env bash
# Configure branch protection on `main` for chika5105/raxis.
#
# Outcome (after this script runs):
#
#   - `main` is restricted: only chika5105 can push or merge.
#     Every other contributor must open a PR.
#   - PRs to `main` REQUIRE these CI checks to pass before merge:
#       * spec-graph                          (cargo xtask spec-graph --strict)
#       * build-images / cargo check + test   (matrix: ubuntu-22.04, macos-14)
#       * build-images / cargo check + test (Linux only) is sufficient as a
#         minimum gate; the macOS arm is informational so contributors
#         without macOS can still get green if Linux passes.
#       * cla-check / cla                     (verifies the CLA-agreement
#         checkbox in the PR description is ticked; the agreement itself
#         lives at raxis/CLA.md and the checkbox is part of the PR
#         template at .github/PULL_REQUEST_TEMPLATE.md).
#   - PRs to `main` REQUIRE CODEOWNER approval. `.github/CODEOWNERS`
#     names only @chika5105, so another approval does not satisfy the
#     merge gate.
#   - Force-pushes are disabled.
#   - Branch deletions are disabled.
#   - Repo admins/owners ARE subject to this protection
#     (`enforce_admins=true`) so the branch behaves the same way for
#     everyone.
#
# Why this design:
#
#   - GitHub's branch-protection API gates direct pushes/merges via
#     the `restrictions` block and gates PR approval via required
#     CODEOWNER review. Keeping both pointed at chika5105 makes the
#     rule auditable and explicit.
#
#   - This is configured idempotently via `gh api`. Re-running the
#     script is a no-op (PUT is the API verb).
#
# Prerequisites:
#
#   - `gh auth status` — authenticated as the repo owner (chika5105).
#   - `jq` — available on PATH.
#   - GitHub branch protection is available for the repo. If the repo
#     is private, GitHub may require GitHub Pro/Team/Enterprise; public
#     repos can enable this on the free plan.
#
# Usage:
#
#     bash .github/scripts/protect-main.sh
#
# To inspect current protection without changing it:
#
#     gh api -H "Accept: application/vnd.github+json" \
#       repos/chika5105/raxis/branches/main/protection | jq .
#
# Reference:
#
#   - https://docs.github.com/en/rest/branches/branch-protection#update-branch-protection
#
set -euo pipefail

OWNER_REPO="${OWNER_REPO:-chika5105/raxis}"
OWNER_USER="${OWNER_USER:-chika5105}"
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
if [ "${ME}" != "${OWNER_USER}" ]; then
    echo "warn: current gh user is '${ME}', not '${OWNER_USER}'." >&2
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
    "build-images / dashboard-fe build"
    "build-images / raxis-site build"
    "cla-check / cla"
)

# Build the JSON body from the array safely via jq.
JSON_BODY="$(jq -n \
    --arg owner "${OWNER_USER}" \
    --argjson checks "$(printf '%s\n' "${REQUIRED_CHECKS[@]}" \
    | jq -R . | jq -s .)" '{
    required_status_checks: {
        strict: true,
        checks: ($checks | map({context: ., app_id: -1}))
    },
    enforce_admins: true,
    required_pull_request_reviews: {
        dismissal_restrictions: {
            users: [$owner],
            teams: []
        },
        dismiss_stale_reviews: true,
        require_code_owner_reviews: true,
        required_approving_review_count: 1,
        require_last_push_approval: true,
        bypass_pull_request_allowances: {
            users: [],
            teams: [],
            apps: []
        }
    },
    restrictions: {
        users: [$owner],
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
echo "  owner approver/merger: ${OWNER_USER}"
echo "  required checks:"
for c in "${REQUIRED_CHECKS[@]}"; do
    printf '    %s\n' "$c"
done

if ! echo "${JSON_BODY}" | gh api \
        --method PUT \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "repos/${OWNER_REPO}/branches/${BRANCH}/protection" \
        --input -; then
    echo >&2
    echo "error: GitHub rejected the branch-protection update." >&2
    echo "       For private repos, branch protection may require GitHub Pro," >&2
    echo "       Team, or Enterprise. Make the repo public or enable the plan" >&2
    echo "       feature, then re-run this script." >&2
    exit 1
fi

echo
echo "ok: protection applied. Verify:"
echo "  gh api repos/${OWNER_REPO}/branches/${BRANCH}/protection | jq ."
