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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

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

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/19-refactor-shared-utility/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```
