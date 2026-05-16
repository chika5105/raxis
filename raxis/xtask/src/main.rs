// xtask/src/main.rs — workspace task runner.
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
mod hygiene;
mod hygiene_install;
mod images;
mod license_check;
mod linux_microvm;
mod linux_prereqs;
mod macos_firewall;
mod observability;
mod perf;
mod spec_graph;
mod trust_anchor;

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
            // verify / install the AVF demo prerequisites
            // (AVF_DEMO.md §0). Drop the leading subcommand so the
            // inner parser sees flag args at args[0].
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            dev_prereqs::run(&tail).context("dev-prereqs")
        }
        Some("images") => {
            // `cargo xtask images <subcommand> [args...]`
            // Three subcommands, each with a single, distinct purpose:
            //   bake                 — the one-and-only baker. Runs
            //                          the full per-role pipeline
            //                          (rootfs build → planner
            //                          cross-compile → signed
            //                          initramfs) for every role and
            //                          writes the resulting `.img`
            //                          plus signed `manifest.toml`
            //                          into `<install_dir>/images/`.
            //   dev-kernel           — install / refresh the Linux
            //                          guest-kernel binary
            //                          (`<install_dir>/kernel/vmlinux`)
            //                          that the microVM substrate
            //                          boots into. Separate from
            //                          `bake` because the guest
            //                          kernel is an external pinned
            //                          artefact, not a raxis output.
            //   verify-trust-anchor  — read-only diagnostic that
            //                          confirms a built raxis-kernel
            //                          binary embeds the expected
            //                          signing-key fingerprint as
            //                          `EXPECTED_KERNEL_SIGNING_KEY_BYTES`.
            // Earlier iterations exposed every intermediate step
            // (`bake-rootfs`, `dev-stage`, `build-all`, `preflight`,
            // a partially-wired `bake-release` variant). These were
            // collapsed into `bake` to remove the "did I run the
            // four sub-steps in the right order?" failure mode.
            let mut rest = args.into_iter().skip(1);
            let sub = rest.next().ok_or_else(|| anyhow::anyhow!(
                "missing images subcommand; available: bake, dev-kernel, \
                 verify-trust-anchor"
            ))?;
            let tail: Vec<String> = rest.collect();
            match sub.as_str() {
                "bake"                => images::run_bake(&tail).context("images bake"),
                "dev-kernel"          => dev_kernel::run(&tail).context("images dev-kernel"),
                "verify-trust-anchor" => images::run_verify_trust_anchor(&tail)
                    .context("images verify-trust-anchor"),
                other                 => anyhow::bail!(
                    "unknown images subcommand: {other:?}; \
                     available: bake, dev-kernel, verify-trust-anchor"
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
        Some("hygiene") => {
            // `cargo xtask hygiene [--dry-run] [--max-age-days N]
            //                      [--keep BRANCH ...] [--main-ref REF]`
            // sweep `git worktree list` and prune parent-side
            //   worktrees whose branch tip has landed to the
            //   resolved "main" ref AND whose files are not
            //   actively held open. The merge-base reference is
            //   auto-detected from
            //   `git symbolic-ref --short refs/remotes/origin/HEAD`
            //   (so forks / repos with a renamed default branch
            //   Just Work) and falls back to `origin/main` when
            //   no `origin/HEAD` is configured. Pass `--main-ref`
            //   to override. See `INV-HOST-HYGIENE-01` and
            //   `xtask/src/hygiene.rs` header for the motivation
            //   (the multi-GiB `target/` per worktree that filled
            //   902 GiB and tripped `DiskFullHaltEntered`).
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            hygiene::run(&tail).context("hygiene")
        }
        Some("hygiene-install-timer") => {
            // `cargo xtask hygiene-install-timer
            //                 [--system] [--uninstall] [--dry-run]`
            // install the periodic hygiene-sweep timer.
            //   * macOS: per-user LaunchAgent at
            //     `~/Library/LaunchAgents/com.raxis.hygiene.plist`
            //     bootstrapped via `launchctl bootstrap gui/$UID`.
            //   * Linux: systemd user-scope (default) or system
            //     (`--system`) at `~/.config/systemd/user/` or
            //     `/etc/systemd/system/`, enabled with
            //     `systemctl [--user] enable --now raxis-hygiene.timer`.
            //   * `--dry-run` prints every write/exec without
            //     touching disk.
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            hygiene_install::run(&tail).context("hygiene-install-timer")
        }
        Some("hygiene-check") => {
            // `cargo xtask hygiene-check [--threshold-pct N]`
            // read-only `df -P` probe across the repo volume,
            //   `/private/tmp`, and `/var/folders/*` (AVF guest
            //   dir). Exits non-zero when ANY monitored volume is
            //   above `--threshold-pct` (default 85). The live-e2e
            //   harness uses the 90% form as a sub-second
            //   preflight (INV-HOST-HYGIENE-01).
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            hygiene::run_check(&tail).context("hygiene-check")
        }
        Some("dev-reset") => {
            // `cargo xtask dev-reset notifications [--data-dir <P>] [--dry-run]`
            // Phase 2 of dashboard-hardening §2 / INV-NOTIF-SCOPE-01.
            // Wipes the operator-notifications projection
            // (`<data_dir>/kernel.db::notifications` table +
            // `<data_dir>/notifications/inbox.jsonl`) so the next
            // kernel boot starts the inbox empty AFTER the
            // `notification_priority` filter took effect. The
            // audit chain at `<data_dir>/audit/` is NEVER touched
            // that's the whole point of the audit-vs-
            // notification separation.
            let tail: Vec<String> = args.into_iter().skip(1).collect();
            dev_reset::run(&tail).context("dev-reset")
        }
        Some(other) => anyhow::bail!(
            "unknown xtask target: {other:?}\n\
             available: spec-graph [--strict], license-check [--strict], \
             dev-keys, dev-codesign, dev-prereqs, dev-reset, hygiene, \
             hygiene-check, hygiene-install-timer, \
             images {{bake|preflight|dev-kernel|bake-rootfs|dev-stage|build-all}}, \
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
             hygiene        [--dry-run]                — prune parent-side `git worktree`s whose\n                 [--max-age-days N]                       branch tip has landed to the resolved\n                 [--keep BRANCH ...]                      \"main\" ref AND whose files are not\n                 [--main-ref REF]                          actively held open. The main ref is\n                                                          auto-detected via `git symbolic-ref` so\n                                                          forks / non-`main` default branches Just\n                                                          Work; --main-ref overrides. Skips the\n                                                          main checkout, anything on --keep, and\n                                                          the worktree the xtask itself was invoked\n                                                          from. Prints disk-before / disk-after\n                                                          to stderr. (INV-HOST-HYGIENE-01)\n  \
             hygiene-check  [--threshold-pct N]         — read-only `df -P` probe across the repo\n                                                          volume, /private/tmp, and /var/folders/*.\n                                                          Exits non-zero when any volume exceeds\n                                                          --threshold-pct (default 85). Used as\n                                                          live-e2e preflight at 90%.\n                                                          (INV-HOST-HYGIENE-01)\n  \
             hygiene-install-timer                      — install the periodic hygiene-sweep timer\n                 [--system]                                  (every 6h via launchd on macOS or\n                 [--uninstall]                               systemd on Linux; user-scope by default,\n                 [--dry-run]                                 --system for shared hosts).\n                                                          (INV-HOST-HYGIENE-01,\n                                                           guides/operator/18-host-hygiene.md)\n  \
             dev-reset notifications                    — wipe the operator-notifications inbox\n                 [--data-dir <PATH>]                       projection (kernel.db::notifications\n                 [--dry-run]                               table + notifications/inbox.jsonl)\n                                                           so the next kernel boot starts empty\n                                                           AFTER the notification_priority\n                                                           filter took effect. The audit chain\n                                                           at <data_dir>/audit/ is NEVER touched\n                                                           (INV-NOTIF-SCOPE-01).\n  \
             images bake                                — single-command end-to-end bake:\n                 [--role <ROLE>]...                        preflight + bake-rootfs + dev-stage +\n                 [--install-dir <PATH>]                    build-all + vmlinux stage. Fails closed\n                 [--signing-key <PATH>]                    on any missing input BEFORE producing\n                 [--builder <B>]                           an artefact. Writes a per-role\n                 [--kernel-from-file <PATH>]               integrity manifest at\n                 [--force] [--no-cache]                    <install_dir>/images/<stem>-<kver>.bake.json\n                                                          recording the SHA of every input + output\n                                                          so a re-run with no changes is a fast\n                                                          no-op. Stages the canonical Linux\n                                                          guest-kernel binary at\n                                                          <install_dir>/kernel/vmlinux\n                                                          (resolution: --kernel-from-file →\n                                                          $RAXIS_DEV_KERNEL_SOURCE → already-staged\n                                                          → /usr/local/lib/raxis/kernel/vmlinux).\n                                                          (canonical-images.md §7;\n                                                          INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01,\n                                                          INV-IMAGE-BAKE-VMLINUX-STAGED-01,\n                                                          INV-IMAGE-BAKE-MANIFEST-INTEGRITY-01,\n                                                          INV-IMAGE-BAKE-NO-CIRCULAR-CONTAINERFILE-01)\n  \
             images preflight                           — read-only verifier of every input\n                 [--role <ROLE>]...                        `bake` would need (container builder\n                 [--install-dir <PATH>]                    + daemon, signing key, vmlinux,\n                 [--signing-key <PATH>]                    Containerfile graph acyclicity,\n                 [--builder <B>]                           per-role manifest.toml). Useful in CI\n                 [--kernel-from-file <PATH>]               to surface missing-input failures\n                                                          BEFORE spending time on a bake that\n                                                          would later abort.\n  \
             images dev-kernel                          — stage Linux guest-kernel binary at\n                 (--from-file <PATH> | --url <URL> --sha256 <HEX>) \n                 [--install-dir <PATH>] [--arch <ARCH>] [--force]\n                                                 <install_dir>/kernel/vmlinux\n                                                 (system-requirements.md §11)\n  \
             images bake-rootfs --role <ROLE>           — docker build per-role Containerfile\n                 [--builder docker|podman|buildah]         and extract OCI rootfs into\n                 [--platform <PLAT>] [--keep]              images/<role>/rootfs/. Auto-detects\n                                                           docker → podman → buildah on $PATH;\n                                                           --platform defaults to the OCI shape\n                                                           of `default_target_triple()`. Run\n                                                           BEFORE dev-stage; dev-stage overlays\n                                                           the planner binary on top.\n  \
             images dev-stage --role <ROLE>             — cross-compile raxis-planner-<role>\n                 [--target <TRIPLE>]                       and stage it into images/<role>/rootfs/init\n                                                 (planner-harness.md §14.4)\n  \
             images build-all                           — pack staged rootfs into signed cpio.gz\n                 [--role <ROLE>] [--install-dir <P>]       initramfs and lay out under\n                 [--signing-key <PATH>]                    <install_dir>/images/raxis-<role>-<kver>.{{img,manifest.toml}}\n                                                 (planner-harness.md §14.4 + )\n  \
             linux-microvm bundle                       — one-shot Firecracker bundle:\n                 [--install-dir <PATH>] [--arch <ARCH>]      stage reference vmlinux + every\n                 [--kernel-from-file <PATH>]                 canonical role's signed initramfs\n                 [--kernel-url <URL>] [--kernel-sha256 <HEX>]   under <install_dir>/\n                 [--target <TRIPLE>] [--signing-key <PATH>]    (isolation-linux-microvm.md §9)\n                 [--role <ROLE>] [--skip-kernel] [--skip-stage] [--force]\n  \
             linux-prereqs                              — Linux substrate host preflight:\n                 [--json]                                  /dev/kvm, vhost_vsock, kvm group,\n                                                           kernel ≥ 5.10, cgroup v2, firecracker(1),\n                                                           virtiofsd(1) (V3 prereq, Warn-only)\n                                                           (isolation-linux-microvm.md §9)\n  \
             macos-firewall-prereq                      — one-time `socketfilterfw --add` /\n                 [--dry-run]                                `--unblockapp` of every raxis host\n                 [--release-only | --debug-only]            binary so the macOS firewall popup\n                                                           does not re-appear on every\n                                                           `cargo build`. Auto-runs as part of\n                                                           `dev-prereqs` on macOS.\n  \
             macos-firewall-status                      — read-only listing of the firewall\n                                                           allowlist state for every raxis host\n                                                           binary.\n  \
             perf {{vm-cold-boot,audit-throughput,all}}  — drive the perf harness against the\n                 [--iterations N] [--backend ...]            live-e2e Prometheus + Grafana stack\n                                                         (specs/v3/observability-prometheus.md;\n                                                          guides/recipes/ops/16-measure-perf.md)\n  \
             observability {{up,down,status,urls}}       — bring up / tear down / probe the\n                 [--no-open] [--full] [--volumes]            OTel-collector + Prometheus + Grafana\n                 [--dashboard <UID>]                         subset of the live-e2e compose\n                                                         stack as a STANDALONE surface. Pinned\n                                                         to the `raxis-live-e2e-test` compose\n                                                         project namespace. The `up` flow\n                                                         prints Grafana / Prometheus URLs +\n                                                         per-dashboard deep-links, and on\n                                                         macOS / Linux opens the Grafana home\n                                                         in the default browser. Use this\n                                                         when you want to inspect the\n                                                         dashboards WITHOUT running a full\n                                                         live-e2e or `cargo xtask perf` run."
        ),
    }
}
