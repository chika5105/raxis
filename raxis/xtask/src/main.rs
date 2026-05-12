// xtask/src/main.rs — workspace task runner.
//
// Invoked as `cargo xtask <target>` via the `.cargo/config.toml`
// alias. Currently exposes a single target — `spec-graph` — that
// implements the V2 cross-spec consistency checks specified in
// `specs/v2/v2-deep-spec.md §Spec-Graph Lint`.

mod dev_codesign;
mod dev_kernel;
mod dev_keys;
mod dev_prereqs;
mod images;
mod license_check;
mod linux_microvm;
mod linux_prereqs;
mod perf;
mod spec_graph;

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let target = args.first().cloned();
    // `--strict` is only meaningful for spec-graph / license-check;
    // we strip it from the inner-args list for dev-keys / dev-codesign
    // callers who never pass it.
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
        Some("dev-codesign") => {
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            dev_codesign::run(&tail).context("dev-codesign")
        }
        Some("dev-prereqs") => {
            // `cargo xtask dev-prereqs [--install] [--scope ...] [--arch ...]`
            // — verify / install the AVF demo prerequisites
            // (AVF_DEMO.md §0). Drop the leading subcommand so the
            // inner parser sees flag args at args[0].
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            dev_prereqs::run(&tail).context("dev-prereqs")
        }
        Some("images") => {
            // `cargo xtask images <subcommand> [args...]`
            let mut rest = args.into_iter().skip(1);
            let sub = rest.next().ok_or_else(|| anyhow::anyhow!(
                "missing images subcommand; available: dev-kernel, dev-stage, build-all"
            ))?;
            let tail: Vec<String> = rest.collect();
            match sub.as_str() {
                "dev-kernel" => dev_kernel::run(&tail).context("images dev-kernel"),
                "dev-stage"  => images::run_dev_stage(&tail).context("images dev-stage"),
                "build-all"  => images::run_build_all(&tail).context("images build-all"),
                other        => anyhow::bail!(
                    "unknown images subcommand: {other:?}; \
                     available: dev-kernel, dev-stage, build-all"
                ),
            }
        }
        Some("linux-microvm") => {
            // `cargo xtask linux-microvm <verb> [args...]` —
            // one-shot Firecracker bundle orchestrator. See
            // `specs/v2/isolation-linux-microvm.md §9`.
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            linux_microvm::run(&tail).context("linux-microvm")
        }
        Some("perf") => {
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            perf::run(&tail).context("perf")
        }
        Some("linux-prereqs") => {
            // `cargo xtask linux-prereqs [--json]` — Linux Firecracker
            // substrate host preflight. See
            // `specs/v2/isolation-linux-microvm.md §9`.
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            linux_prereqs::run(&tail).context("linux-prereqs")
        }
        Some(other) => anyhow::bail!(
            "unknown xtask target: {other:?}\n\
             available: spec-graph [--strict], license-check [--strict], \
             dev-keys, dev-codesign, dev-prereqs, images, linux-microvm, linux-prereqs"
        ),
        None => anyhow::bail!(
            "usage: cargo xtask <target> [flags]\n\
             available targets:\n  \
             spec-graph     [--strict]                 — cross-spec consistency lint\n  \
             license-check  [--strict]                 — enforce SSPL-1.0 across all crates\n  \
             dev-keys init  [--dir <PATH>] [--force]   — emit local-build signing keypair\n                                                 (release-and-distribution.md §8)\n  \
             dev-codesign   [--profile <P>]            — ad-hoc codesign target/<P>/raxis-kernel\n                 [--entitlements <PATH>]    against release/raxis.entitlements\n                 [--binary <NAME>]          (macOS only; no-op on Linux)\n                                                 (system-requirements.md §5.2)\n  \
             dev-prereqs    [--install]                 — verify / install AVF demo prerequisites\n                 [--scope user|workspace]   (Homebrew, musl-cross, openssl@3,\n                 [--arch aarch64|x86_64]    rustup musl target, codesign, cargo);\n                 [--skip-cargo-config]     idempotently patches\n                                                 ~/.cargo/config.toml linker pin.\n                                                 (demo-e2e-sample/AVF_DEMO.md §0)\n  \
             images dev-kernel                          — stage Linux guest-kernel binary at\n                 (--from-file <PATH> | --url <URL> --sha256 <HEX>) \n                 [--install-dir <PATH>] [--arch <ARCH>] [--force]\n                                                 <install_dir>/kernel/vmlinux\n                                                 (system-requirements.md §11)\n  \
             images dev-stage --role <ROLE>             — cross-compile raxis-planner-<role>\n                 [--target <TRIPLE>]                       and stage it into images/<role>/rootfs/init\n                                                 (planner-harness.md §14.4)\n  \
             images build-all                           — pack staged rootfs into signed cpio.gz\n                 [--role <ROLE>] [--install-dir <P>]       initramfs and lay out under\n                 [--signing-key <PATH>]                    <install_dir>/images/raxis-<role>-<kver>.{{img,manifest.toml}}\n                                                 (planner-harness.md §14.4 + e2e-live-test-gap.md)\n  \
             linux-microvm bundle                       — one-shot Firecracker bundle:\n                 [--install-dir <PATH>] [--arch <ARCH>]      stage reference vmlinux + every\n                 [--kernel-from-file <PATH>]                 canonical role's signed initramfs\n                 [--kernel-url <URL>] [--kernel-sha256 <HEX>]   under <install_dir>/\n                 [--target <TRIPLE>] [--signing-key <PATH>]    (isolation-linux-microvm.md §9)\n                 [--role <ROLE>] [--skip-kernel] [--skip-stage] [--force]\n  \
             linux-prereqs                              — Linux substrate host preflight:\n                 [--json]                                  /dev/kvm, vhost_vsock, kvm group,\n                                                           kernel ≥ 5.10, cgroup v2, firecracker(1),\n                                                           virtiofsd(1) (V3 prereq, Warn-only)\n                                                           (isolation-linux-microvm.md §9)"
        ),
    }
}
