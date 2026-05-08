// xtask/src/main.rs — workspace task runner.
//
// Invoked as `cargo xtask <target>` via the `.cargo/config.toml`
// alias. Currently exposes a single target — `spec-graph` — that
// implements the V2 cross-spec consistency checks specified in
// `specs/v2/v2-deep-spec.md §Spec-Graph Lint`.

mod spec_graph;
mod license_check;

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let target = args.first().cloned();
    let strict = args.iter().any(|a| a == "--strict");
    args.retain(|a| a != "--strict");
    match target.as_deref() {
        Some("spec-graph") => spec_graph::run(spec_graph::RunMode::with_strict(strict))
            .context("spec-graph"),
        Some("spec-graph-lint") => spec_graph::run(spec_graph::RunMode::with_strict(strict))
            .context("spec-graph"),
        Some("license-check") => license_check::run(strict)
            .context("license-check"),
        Some(other) => anyhow::bail!(
            "unknown xtask target: {other:?}\n\
             available: spec-graph [--strict], license-check [--strict]"
        ),
        None => anyhow::bail!(
            "usage: cargo xtask <target> [flags]\n\
             available targets:\n  \
             spec-graph     [--strict]  — cross-spec consistency lint\n  \
             license-check  [--strict]  — enforce SSPL-1.0 across all crates"
        ),
    }
}
