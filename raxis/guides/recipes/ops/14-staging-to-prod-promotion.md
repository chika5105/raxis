# Promote a plan from staging to production

> **Topic:** Operations | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

A safe promotion flow: ship the plan to staging, observe, then run
the same plan on production with the production policy. Covers the
config-drift hazards and how to detect them before they bite.

---

## Why this exists

`plan.toml` is environment-agnostic; the same plan can run on a
dev sandbox, staging, or production. But the **policy** differs:
lanes, budgets, allowed verifier images, signed operators. A plan
that works in staging may fail admission in production for any of
these reasons.

The promotion flow makes the policy delta explicit before you
attempt the prod run.

---

## Steps

### 1. Run the plan in staging

Assume `RAXIS_DATA_DIR_STAGING=/var/raxis-staging` is the staging
install:

```bash
RAXIS_DATA_DIR=$RAXIS_DATA_DIR_STAGING \
RAXIS_OPERATOR_KEY=/etc/raxis/staging.key \
raxis submit plan ./plans/feature-x.toml --no-dry-run
```

Capture the canonical bundle:

```bash
RAXIS_DATA_DIR=$RAXIS_DATA_DIR_STAGING raxis initiative show <init_id> \
  --bundle --to /tmp/staging-bundle
```

After approval, observe the run:

```bash
RAXIS_DATA_DIR=$RAXIS_DATA_DIR_STAGING raxis explain <task_id>
RAXIS_DATA_DIR=$RAXIS_DATA_DIR_STAGING raxis log <init_id> --kind WitnessRecorded
RAXIS_DATA_DIR=$RAXIS_DATA_DIR_STAGING raxis budget --initiative <init_id>
```

If the staging run is healthy (all witnesses pass, all reviewers
approved, no escalations), proceed.

### 2. Diff the policy bundles

```bash
RAXIS_DATA_DIR=$RAXIS_DATA_DIR_STAGING raxis policy show > /tmp/staging-policy.toml
RAXIS_DATA_DIR=/var/raxis-prod        raxis policy show > /tmp/prod-policy.toml

raxis policy diff /tmp/staging-policy.toml /tmp/prod-policy.toml
# Output: structured semantic diff highlighting:
#   - operators added/removed
#   - lane caps changed
#   - allowed verifier images changed
#   - allowed_egress at task-level (n/a, plan-side)
```

Common findings:

- Staging has a verifier image (`rg-pre-commit-v2`) prod doesn't.
- Prod has a tighter lane budget.
- Prod has stricter `[host_capacity]` floors.

For each, decide: install in prod, or skip the plan.

### 3. Pre-flight on production policy

The plan may pass in staging but fail prod admission. Use
`raxis plan validate` against the prod policy:

```bash
# plan validate inspects the local plan + applicable policy.
RAXIS_DATA_DIR=/var/raxis-prod \
raxis plan validate /tmp/staging-bundle/plan.toml
# Expected: validation_ok
# OR (with explicit failures):
# - lane "auth-work" not present in policy
# - vm_image "executor-rust-v1" not in [[vm_images]]
# - allowed_egress "api.example.com:443" not pre-approved
```

Address any failure by either:

- Updating the prod policy (signed by prod operators).
- Modifying the plan to use prod-available resources.

### 4. Submit to prod

```bash
RAXIS_DATA_DIR=/var/raxis-prod \
RAXIS_OPERATOR_KEY=/etc/raxis/prod.key \
raxis submit plan /tmp/staging-bundle/plan.toml --no-dry-run
```

Note: use the canonical plan from staging (`/tmp/staging-bundle/plan.toml`),
not the original on-disk file. The bundle's plan.toml is what
staging actually saw — if your editor or formatter changed the
file in between, you want the staging-canonical version.

After admission:

```bash
RAXIS_DATA_DIR=/var/raxis-prod raxis initiative list --state active --json | jq '.rows[]'
# Approve.
RAXIS_DATA_DIR=/var/raxis-prod raxis plan approve <prod_init_id>
```

### 5. Observe the prod run

```bash
RAXIS_DATA_DIR=/var/raxis-prod raxis explain <task_id>
RAXIS_DATA_DIR=/var/raxis-prod raxis log <prod_init_id> --follow
RAXIS_DATA_DIR=/var/raxis-prod raxis budget --initiative <prod_init_id>
```

If anything diverges from the staging run, abort and triage:

```bash
RAXIS_DATA_DIR=/var/raxis-prod raxis initiative abort <prod_init_id> \
  --reason "promotion: divergence from staging behavior"
```

Compare staging and prod logs:

```bash
diff <(jq -c '{kind, payload}' /tmp/staging-log.json) \
     <(jq -c '{kind, payload}' /tmp/prod-log.json)
```

---

## What can drift between staging and prod

| Drift | Detection | Mitigation |
|---|---|---|
| Verifier image versions | `raxis policy diff` | Pin verifier image with sha in plan; promote sha to prod. |
| Lane budgets | `raxis budget` | Pre-confirm prod lane has enough budget; raise temporarily if needed. |
| Operator certs | `raxis cert list` | Mint prod-signed certs; ensure CI bot has `permitted_ops`. |
| Provider list | `raxis providers status` | Either install the same providers in prod, or pin `provider_id` in plan. |
| Credential ids | `raxis credential list` | Use the same credential ids across envs; rotate secrets, not ids. |
| Egress allowlist (per-task) | `raxis plan validate` | Plan's `allowed_egress` is environment-agnostic; prod-side it must match what your prod kernel proxy permits. |

---

## Common errors

| Symptom | Fix |
|---|---|
| `submit plan: ADMIT_DENIED_RESOURCE` (lane / image) | The prod policy lacks the resource. See step 2. |
| `plan validate: failed in staging, passes in prod` | Staging policy is stricter; can usually ignore. |
| Prod run produces different witness shas than staging | Either input differs (worktree HEAD, time-of-day) or verifier non-determinism. Pin `target_ref` in plan. |
| Plan succeeded in staging but is silently skipped in prod | Check `[[lanes]]` priority — plan may be deprioritized; or prod kernel is throttling. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis policy diff` | Semantic diff of two policy bundles. |
| `raxis plan validate` | Pre-flight a plan against current policy. |
| `raxis initiative show --bundle --to` | Capture canonical plan from staging. |
| `raxis budget --initiative <id>` | Cost view per initiative. |
| `raxis explain <task_id>` | Decision tree for divergence triage. |

---

## Variations

- **CI-driven promotion.** A CI workflow runs staging, then auto-
  promotes if staging is green. Pair with a manual `plan approve`
  in prod for a human checkpoint.
- **Identical policy.** For deterministic promotion, sync prod
  policy to staging weekly via a controlled diff-and-sign workflow.
- **Per-region promotion.** Stage → prod-east → prod-west; each
  region runs the same plan independently with region-specific
  credentials.
- **Canary plan.** A small plan that exercises only one task, then
  the full plan. Catches drift before the full run.
