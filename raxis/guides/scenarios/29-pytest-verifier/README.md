# Scenario 29 — pytest Verifier

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

A `pytest` mechanical witness for a Python project.

---

## Prerequisites

Same as scenario 04 plus a Python 3.11+ install with `pytest` on
$PATH.

---

## What this scenario demonstrates

- Mechanical witness with a non-Rust toolchain.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-29"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
cat > src/calc.py <<'PY'
def add(a, b): return a + b
PY
cat > tests/test_calc.py <<'PY'
from src.calc import add
def test_add(): assert add(2, 3) == 5
PY
mkdir -p tests
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"
```
