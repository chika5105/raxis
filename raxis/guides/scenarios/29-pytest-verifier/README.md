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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/src"
cd "$RAXIS_MAIN_REPO"

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

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/29-pytest-verifier/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```
