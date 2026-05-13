// xtask/src/main.rs — workspace task runner.
//
// Invoked as `cargo xtask <target>` via the `.cargo/config.toml`
// alias. Currently exposes a single target — `spec-graph` — that
// implements the V2 cross-spec consistency checks specified in
// `specs/v2/v2-deep-spec.md §Spec-Graph Lint`.

mod browser;
mod dev_codesign;
mod dev_kernel;
mod dev_keys;
mod dev_prereqs;
mod dev_reset;
mod images;
mod license_check;
mod linux_microvm;
mod linux_prereqs;
mod macos_firewall;
mod observability;
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
        Some("observability") => {
            // `cargo xtask observability {up,down,status,urls}` —
            // standalone wrapper around the OTel + Prometheus +
            // Grafana subset of the live-e2e compose stack so an
            // operator can review the dashboards without running
            // the full live-e2e harness. See
            // `xtask/src/observability.rs` header.
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            observability::run(&tail).context("observability")
        }
        Some("linux-prereqs") => {
            // `cargo xtask linux-prereqs [--json]` — Linux Firecracker
            // substrate host preflight. See
            // `specs/v2/isolation-linux-microvm.md §9`.
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            linux_prereqs::run(&tail).context("linux-prereqs")
        }
        Some("macos-firewall-prereq") => {
            // `cargo xtask macos-firewall-prereq [--dry-run]` —
            // one-time setup that allowlists the raxis host binaries
            // in the macOS Application Firewall so the
            // "allow `raxis-kernel` to accept incoming network
            // connections" popup never appears on a fresh
            // `cargo build`. No-op on non-macOS hosts. See
            // `xtask/src/macos_firewall.rs` for the inventory of
            // managed binaries and the Strategy A vs B trade-off.
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            macos_firewall::run_prereq(&tail).context("macos-firewall-prereq")
        }
        Some("macos-firewall-status") => {
            // `cargo xtask macos-firewall-status` — read-only
            // companion to `macos-firewall-prereq`. Prints the
            // current allowlist state for every raxis host binary.
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            macos_firewall::run_status(&tail).context("macos-firewall-status")
        }
        Some("dev-reset") => {
            // `cargo xtask dev-reset notifications [--data-dir <P>] [--dry-run]`
            // — Phase 2 of dashboard-hardening §2 / INV-NOTIF-SCOPE-01.
            // Wipes the operator-notifications projection
            // (`<data_dir>/kernel.db::notifications` table +
            // `<data_dir>/notifications/inbox.jsonl`) so the next
            // kernel boot starts the inbox empty AFTER the
            // `notification_priority` filter took effect. The
            // audit chain at `<data_dir>/audit/` is NEVER touched
            // — that's the whole point of the audit-vs-
            // notification separation.
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            dev_reset::run(&tail).context("dev-reset")
        }
        Some(other) => anyhow::bail!(
            "unknown xtask target: {other:?}\n\
             available: spec-graph [--strict], license-check [--strict], \
             dev-keys, dev-codesign, dev-prereqs, dev-reset, images, \
             linux-microvm, linux-prereqs, macos-firewall-prereq, \
             macos-firewall-status, perf, observability"
        ),
        None => anyhow::bail!(
            "usage: cargo xtask <target> [flags]\n\
             available targets:\n  \
             spec-graph     [--strict]                 — cross-spec consistency lint\n  \
             license-check  [--strict]                 — enforce SSPL-1.0 across all crates\n  \
             dev-keys init  [--dir <PATH>] [--force]   — emit local-build signing keypair\n                                                 (release-and-distribution.md §8)\n  \
             dev-codesign   [--profile <P>]            — ad-hoc codesign target/<P>/raxis-kernel\n                 [--entitlements <PATH>]    against release/raxis.entitlements\n                 [--binary <NAME>]          (macOS only; no-op on Linux)\n                                                 (system-requirements.md §5.2)\n  \
             dev-prereqs    [--install]                 — verify / install AVF demo prerequisites\n                 [--scope user|workspace]   (Homebrew, musl-cross, openssl@3,\n                 [--arch aarch64|x86_64]    rustup musl target, codesign, cargo);\n                 [--skip-cargo-config]     idempotently patches\n                                                 ~/.cargo/config.toml linker pin.\n                                                 (demo-e2e-sample/AVF_DEMO.md §0)\n  \
             dev-reset notifications                    — wipe the operator-notifications inbox\n                 [--data-dir <PATH>]                       projection (kernel.db::notifications\n                 [--dry-run]                               table + notifications/inbox.jsonl)\n                                                           so the next kernel boot starts empty\n                                                           AFTER the notification_priority\n                                                           filter took effect. The audit chain\n                                                           at <data_dir>/audit/ is NEVER touched\n                                                           (INV-NOTIF-SCOPE-01).\n  \
             images dev-kernel                          — stage Linux guest-kernel binary at\n                 (--from-file <PATH> | --url <URL> --sha256 <HEX>) \n                 [--install-dir <PATH>] [--arch <ARCH>] [--force]\n                                                 <install_dir>/kernel/vmlinux\n                                                 (system-requirements.md §11)\n  \
             images dev-stage --role <ROLE>             — cross-compile raxis-planner-<role>\n                 [--target <TRIPLE>]                       and stage it into images/<role>/rootfs/init\n                                                 (planner-harness.md §14.4)\n  \
             images build-all                           — pack staged rootfs into signed cpio.gz\n                 [--role <ROLE>] [--install-dir <P>]       initramfs and lay out under\n                 [--signing-key <PATH>]                    <install_dir>/images/raxis-<role>-<kver>.{{img,manifest.toml}}\n                                                 (planner-harness.md §14.4 + e2e-live-test-gap.md)\n  \
             linux-microvm bundle                       — one-shot Firecracker bundle:\n                 [--install-dir <PATH>] [--arch <ARCH>]      stage reference vmlinux + every\n                 [--kernel-from-file <PATH>]                 canonical role's signed initramfs\n                 [--kernel-url <URL>] [--kernel-sha256 <HEX>]   under <install_dir>/\n                 [--target <TRIPLE>] [--signing-key <PATH>]    (isolation-linux-microvm.md §9)\n                 [--role <ROLE>] [--skip-kernel] [--skip-stage] [--force]\n  \
             linux-prereqs                              — Linux substrate host preflight:\n                 [--json]                                  /dev/kvm, vhost_vsock, kvm group,\n                                                           kernel ≥ 5.10, cgroup v2, firecracker(1),\n                                                           virtiofsd(1) (V3 prereq, Warn-only)\n                                                           (isolation-linux-microvm.md §9)\n  \
             macos-firewall-prereq                      — one-time `socketfilterfw --add` /\n                 [--dry-run]                                `--unblockapp` of every raxis host\n                 [--release-only | --debug-only]            binary so the macOS firewall popup\n                                                           does not re-appear on every\n                                                           `cargo build`. Auto-runs as part of\n                                                           `dev-prereqs` on macOS.\n  \
             macos-firewall-status                      — read-only listing of the firewall\n                                                           allowlist state for every raxis host\n                                                           binary.\n  \
             perf {{vm-cold-boot,audit-throughput,all}}  — drive the perf harness against the\n                 [--iterations N] [--backend ...]            live-e2e Prometheus + Grafana stack\n                                                         (specs/v3/observability-prometheus.md;\n                                                          guides/recipes/ops/16-measure-perf.md)\n  \
             observability {{up,down,status,urls}}       — bring up / tear down / probe the\n                 [--no-open] [--full] [--volumes]            OTel-collector + Prometheus + Grafana\n                 [--dashboard <UID>]                         subset of the live-e2e compose\n                                                         stack as a STANDALONE surface. Pinned\n                                                         to the `raxis-live-e2e-test` compose\n                                                         project namespace. The `up` flow\n                                                         prints Grafana / Prometheus URLs +\n                                                         per-dashboard deep-links, and on\n                                                         macOS / Linux opens the Grafana home\n                                                         in the default browser. Use this\n                                                         when you want to inspect the\n                                                         dashboards WITHOUT running a full\n                                                         live-e2e or `cargo xtask perf` run."
        ),
    }
}
