// xtask/src/main.rs — workspace task runner.
//
// Invoked as `cargo xtask <target>` via the `.cargo/config.toml`
// alias. Currently exposes a single target — `spec-graph` — that
// implements the V2 cross-spec consistency checks specified in
// `specs/v2/v2-deep-spec.md §Spec-Graph Lint`.

mod dev_keys;
mod spec_graph;
mod license_check;

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let target = args.first().cloned();
    // `--strict` is only meaningful for spec-graph / license-check;
    // we strip it from the inner-args list for dev-keys callers
    // who never pass it.
    let strict = args.iter().any(|a| a == "--strict");
    args.retain(|a| a != "--strict");
    match target.as_deref() {
        Some("spec-graph") => spec_graph::run(spec_graph::RunMode::with_strict(strict))
            .context("spec-graph"),
        Some("spec-graph-lint") => spec_graph::run(spec_graph::RunMode::with_strict(strict))
            .context("spec-graph"),
        Some("license-check") => license_check::run(strict)
            .context("license-check"),
        Some("dev-keys") => {
            // Drop the leading "dev-keys" so the inner parser sees
            // its own subcommands at args[0].
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            dev_keys::run(&tail).context("dev-keys")
        }
        Some(other) => anyhow::bail!(
            "unknown xtask target: {other:?}\n\
             available: spec-graph [--strict], license-check [--strict], dev-keys"
        ),
        None => anyhow::bail!(
            "usage: cargo xtask <target> [flags]\n\
             available targets:\n  \
             spec-graph     [--strict]              — cross-spec consistency lint\n  \
             license-check  [--strict]              — enforce SSPL-1.0 across all crates\n  \
             dev-keys init  [--dir <PATH>] [--force] — emit local-build signing keypair\n                                              (release-and-distribution.md §8)"
        ),
    }
}
