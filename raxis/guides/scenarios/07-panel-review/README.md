# Scenario 07 — Panel Review (3 Reviewers, 1 Executor)

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~12 min | **Provider:** Anthropic

One Executor, three Reviewers covering different concerns
(correctness, style, security). After this scenario you understand
how multiple Reviewers compose, how the kernel injects each
Reviewer's critique back into the Executor on rejection, and the
practical limits of running multiple sequential review rounds.

> **Status (V2.5).** A plan-time ceiling field
> (`max_review_rejections`) is reserved for V2.6 — see
> §12.13. As of V2.5 the kernel bumps
> `subtask_activations.review_reject_count` once per terminal
> rejection round (the substrate the future ceiling check
> reads), but the plan parser does not yet accept any retry-
> ceiling key from `[[tasks]]`. The Orchestrator harness still
> decides when to give up.

---

## Prerequisites

Same as scenario 01.

---

## What this scenario demonstrates

- Three Reviewers all pinned to the same Executor's
  `evaluation_sha`.
- The kernel routes EACH Reviewer's `SubmitReview` independently;
  any one rejection bounces the Executor.
- All Reviewers' critiques are concatenated into the Executor's
  next system-prompt seed.

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

cargo init --lib --name demo07 -q
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"

cp /path/to/raxis/guides/scenarios/07-panel-review/plan.toml ./plan.toml
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan   ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"

raxis initiative show "$INIT_ID" --with-tasks
```

---

## What "success" looks like

```yaml
implementer:        Completed
correctness_review: Completed
style_review:       Completed
security_review:    Completed
```

If ANY of the three Reviewers rejects, the Executor reboots with all
rejection critiques prepended.

---

## Variations

- **Make security strict.** Edit the security Reviewer's prompt to
  reject any function that doesn't validate inputs. Watch the
  Executor cycle 1–2 times.
- **Fan out to 5 Reviewers.** Add cosmetic + comment-quality
  Reviewers; observe latency increase but throughput unchanged
  thanks to lane-budget reservations.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$RAXIS_MAIN_REPO"
```

---

## Cross-references

- Pattern: [`../../patterns/panel-review.md`](../../patterns/panel-review.md).
- Spec: `specs/v2/agent-disagreement.md` for the rejection FSM.
