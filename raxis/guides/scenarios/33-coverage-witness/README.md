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
export DEMO_ROOT="/tmp/raxis-scenario-33"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --lib --name demo33 -q
cat > src/lib.rs <<'RS'
pub fn add(a: i64, b: i64) -> i64 { a + b }
#[cfg(test)] mod tests { use super::*; #[test] fn t() { assert_eq!(add(1,2),3); } }
RS
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
