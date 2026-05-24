# Scenario 33 — Coverage Witness

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~12 min | **Provider:** Anthropic

`cargo llvm-cov` based mechanical witness that ensures coverage
remains above a threshold.

---

## Prerequisites

Same as scenario 04 plus `cargo llvm-cov` (`cargo install
cargo-llvm-cov`).

---

## What this scenario demonstrates

- Coverage as a hard gate.
- A multi-step witness pipeline (`cargo test` then `llvm-cov` then
  threshold check).

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

cargo init --lib --name demo33 -q
cat > src/lib.rs <<'RS'
pub fn add(a: i64, b: i64) -> i64 { a + b }
#[cfg(test)] mod tests { use super::*; #[test] fn t() { assert_eq!(add(1,2),3); } }
RS
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/33-coverage-witness/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```
