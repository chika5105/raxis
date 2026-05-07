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
export DEMO_ROOT="/tmp/raxis-scenario-27"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

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

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"
```
