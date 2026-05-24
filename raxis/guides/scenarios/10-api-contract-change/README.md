# Scenario 10 — API Contract Change

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~12 min | **Provider:** Anthropic

Backend handler + matching test + matching docs in three coordinated
tasks. After this scenario you understand how the kernel keeps three
disjoint path allowlists composable and how `cross_cutting_artifacts`
on the Orchestrator handles shared lockfiles.

---

## Prerequisites

Same as scenario 04 (cargo on $PATH).

---

## What this scenario demonstrates

- Three Executors with disjoint allowlists (`src/`, `tests/`,
  `docs/`).
- A coordinated change across all three.
- The Orchestrator's role at IntegrationMerge time.

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

cargo init --lib --name demo10 -q
mkdir -p tests docs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/10-api-contract-change/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$RAXIS_MAIN_REPO"
```

---

## Cross-references

- Spec: `specs/v2/v2-deep-spec.md §Step 11` — hybrid allowlist.
