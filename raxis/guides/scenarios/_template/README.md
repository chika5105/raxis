# Scenario Template

> **Complexity:** ⭐ – ⭐⭐⭐⭐⭐ | **Wall clock:** ~N minutes | **Provider:** Anthropic / OpenAI / …

One-paragraph summary of what the operator will end up with after running
this scenario. State the *outcome*, not the *steps* — the steps come
later in the README.

---

## Prerequisites

- **One-time setup complete.** See [`../../SETUP.md`](../../SETUP.md).
- **Kernel running** (`raxis-kernel` in another terminal).
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported** in this shell.
- **Provider credentials** configured for the providers this scenario
  uses; see the scenario's `credential.toml` for the list.

If your install pre-dates this scenario, run the three-line
"Confirming an existing install" check at the bottom of `SETUP.md`
before continuing.

---

## What this scenario demonstrates

Bullet list, one item per concept. Each item should be one short
sentence so an operator scanning the catalogue knows whether to
spend time here.

- The first concept this scenario teaches.
- The second concept.
- The third concept.

---

## Repository setup

If this scenario uses a real upstream repo, name it here with a
specific commit SHA and the rationale for choosing it. If it
materializes its own scratch repo, drop the materialization commands
in this section verbatim.

```bash
export DEMO_ROOT="/tmp/raxis-scenario-XX"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

# Materialize the scratch repo
git init -q
echo "# Demo" > README.md
git add . && git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Files in this scenario

| File | Purpose |
|---|---|
| `plan.toml` | The plan the operator signs and submits. |
| `policy.toml` | Local-policy snippet showing the deltas this scenario needs on top of `SETUP.md`'s baseline. |
| `credential.toml` | Placeholder credentials. Replace `REPLACE_ME` markers with real values; commit nothing. |

---

## Run it

> Each scenario expects a kernel already running (per `SETUP.md`).

```bash
# 1. Validate the plan locally before submitting.
raxis plan validate "$PWD/plan.toml"

# 2. (Optional) merge this scenario's policy delta into your live
#    policy.toml, then re-sign.
#    See "Policy delta" below.

# 3. Submit + approve.
raxis submit plan "$PWD/plan.toml" --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"

# 4. Watch.
raxis inspect-initiative "$INIT_ID" --with-tasks
```

The expected progression: ` ... step-by-step description ...`.

---

## Policy delta

Append the contents of `policy.toml` to your live
`$RAXIS_DATA_DIR/policy/policy.toml`, re-sign, then either restart the
kernel or run `raxis epoch advance` to swap in the new bundle live.

```bash
# Append + re-sign + epoch-advance (live).
cat ./policy.toml >> "$RAXIS_DATA_DIR/policy/policy.toml"
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig    "$RAXIS_DATA_DIR/policy/policy.sig"
```

---

## What "success" looks like

- `raxis plan validate` exits 0.
- `raxis plan approve` reports `tasks_admitted: N`.
- `raxis inspect-initiative <id>` eventually shows every task at
  `Completed`.
- `raxis verify-chain` exits 0 with a non-zero record count.

---

## Variations

A short list of single-knob changes the operator can make to explore
the system further. Examples: change the clone strategy, add a
Reviewer, increase the retry budget, scope the path allowlist tighter.

---

## Tear-down

```bash
# Abort the initiative if it's still running.
raxis initiative abort "$INIT_ID" 2>/dev/null || true

# Remove the scratch repo.
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Concepts touched: <link to the relevant `CONCEPTS.md` section>.
- Pattern this scenario instantiates: <link to `../../patterns/<pattern>.md` if applicable>.
- Spec back-references: <link to relevant V2 spec sections>.
