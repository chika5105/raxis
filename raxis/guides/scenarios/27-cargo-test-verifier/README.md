# Scenario 27 — cargo test Verifier

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

A cargo-test mechanical witness gates the Executor's commit. Failing
tests block the commit.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- `kind = "Mechanical"` witness running `cargo test`.
- Witness exit-code semantics (`exit_code_eq = 0`).

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

cargo init --lib --name demo27 -q
cat > src/lib.rs <<'RS'
pub fn fact(n: u32) -> u64 {
  if n <= 1 { 1 } else { (n as u64) * fact(n - 1) }
}
#[cfg(test)]
mod tests {
  use super::*;
  #[test] fn t0() { assert_eq!(fact(0), 1); }
  #[test] fn t5() { assert_eq!(fact(5), 120); }
}
RS
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/27-cargo-test-verifier/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```
