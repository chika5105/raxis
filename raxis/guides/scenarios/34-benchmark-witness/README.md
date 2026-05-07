# Scenario 34 — Benchmark Witness

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~15 min | **Provider:** Anthropic

`criterion`-based bench mechanical witness that asserts a perf budget
hasn't regressed.

---

## Prerequisites

Same as scenario 04. `criterion` will be added by the bootstrap.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-34"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --lib --name demo34 -q
cargo add --dev criterion -q
cat > src/lib.rs <<'RS'
pub fn naive_sum(xs: &[u64]) -> u64 { xs.iter().sum() }
RS
mkdir -p benches
cat > benches/sum.rs <<'RS'
use criterion::{black_box, criterion_group, criterion_main, Criterion};
fn b(c: &mut Criterion) {
  c.bench_function("naive_sum_1k", |b| {
    let v: Vec<u64> = (0..1000).collect();
    b.iter(|| demo34::naive_sum(black_box(&v)))
  });
}
criterion_group!(g, b);
criterion_main!(g);
RS
cat >> Cargo.toml <<'TOML'
[[bench]]
name = "sum"
harness = false
TOML
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
