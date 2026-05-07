# Scenario 19 — Refactor a Shared Utility

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~15 min | **Provider:** Anthropic

Move a function from `src/utils.rs` into its own module
`src/strings.rs` and update *all* callers. Demonstrates careful
multi-file edits with a single-Executor task that must scope its
allowlist to the entire `src/` tree.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- A "global rename"-style refactor that requires touching multiple
  files in `src/`.
- A `cargo build` mechanical witness ensuring everything compiles.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-19"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --bin --name demo19 -q
cat > src/utils.rs <<'RS'
pub fn slugify(s: &str) -> String { s.to_lowercase().replace(' ', "-") }
RS
cat > src/main.rs <<'RS'
mod utils;
fn main() {
  println!("{}", utils::slugify("Hello World"));
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
