//! `cargo xtask macos-firewall-prereq` and `macos-firewall-status`
//! — one-time setup that adds raxis host binaries to the macOS
//! Application Firewall allowlist so the recurring
//!
//! ```text
//! Do you want the application "raxis-kernel" to accept incoming
//! network connections?
//! ```
//!
//! popup never appears on a fresh `cargo build`.
//!
//! ## Why developers see the popup
//!
//! macOS' Application Firewall (`/usr/libexec/ApplicationFirewall/
//! socketfilterfw`, the user-space socket-filter from
//! `/System/Library/PrivateFrameworks/SocketFilter.framework`) inspects
//! every binary that calls `bind(2)` on a TCP/UDP socket and prompts
//! the GUI user the first time it sees a binary identity it hasn't
//! seen before. "Identity" here is a code-signing identity if the
//! binary is Developer-ID-signed, or the absolute on-disk path if the
//! binary is ad-hoc-signed (which every `cargo build` output is).
//!
//! Because every `cargo build --release` re-emits a new
//! `target/release/raxis-kernel` whose ad-hoc CDHash differs from the
//! previous build, the firewall treats each rebuild as a new identity
//! and re-prompts. For a developer who rebuilds a dozen times an hour
//! that translates to a dozen modal popups they have to dismiss while
//! the kernel boots.
//!
//! ## What this module does (Strategy A — per-binary path allowlist)
//!
//! For each raxis host binary that binds a network port (see
//! [`RAXIS_HOST_BINS`]) and currently exists under
//! `<workspace>/target/{debug,release}/<bin>`, this module:
//!
//!   1. Calls `sudo /usr/libexec/ApplicationFirewall/socketfilterfw
//!      --add <abs_path>` — registers the absolute path with the
//!      firewall's allowlist. Idempotent: re-running on an already-
//!      added path is a documented no-op.
//!   2. Calls `sudo /usr/libexec/ApplicationFirewall/socketfilterfw
//!      --unblockapp <abs_path>` — sets the per-path policy to
//!      "Allow incoming connections" (the alternative is "Block
//!      incoming connections" which would defeat the purpose).
//!
//! Both commands require root because `socketfilterfw` mutates
//! system firewall state (`/Library/Preferences/com.apple.alf.plist`).
//! We elevate exactly once per invocation by running `sudo -v` at the
//! top of the subcommand so the operator sees a single password
//! prompt instead of one per binary.
//!
//! ## Why not Strategy B (stable codesigning identity)
//!
//! Strategy B is a stable self-signed code-signing identity in the
//! user's login keychain plus a `cargo build` wrapper that re-signs
//! every output binary. Identity-based firewall rules survive binary
//! moves (rename `target/`, copy to a different worktree, etc.), but
//! the moving parts add up:
//!
//!   * Operators have to mint a self-signed Apple-developer-style
//!     code-signing identity (`security create-keychain`,
//!     `Certificate Assistant.app` workflow, then
//!     `security import` into the login keychain). There is no
//!     one-shot CLI for this on stock macOS.
//!   * Every `cargo build` output binary has to be re-signed
//!     against the identity, which means wrapping `cargo build` in
//!     a per-build hook (`cargo xtask build` that runs
//!     `codesign --sign <identity>` on every output). Easy to forget,
//!     easy to skip, and breaks vanilla `cargo build` muscle memory.
//!   * Operators on managed devices may not have permission to add
//!     keychain certs in the first place.
//!
//! Strategy A wins on developer-experience surface area: it works
//! with vanilla `cargo build`, requires zero per-build hooks, and the
//! `sudo` prompt is a one-time event during `cargo xtask dev-prereqs`.
//! Strategy B is documented as future-work for operators who want
//! identity-based rules that survive worktree migrations.
//!
//! ## What this module does NOT do
//!
//!   * Disable the firewall globally — that would weaken the host's
//!     security posture for non-raxis traffic. Per-binary allowlist
//!     only.
//!   * Grant blanket network permission to `cargo` or `target/` —
//!     same reason; only the specific raxis binaries are added.
//!   * Re-enable a disabled firewall — if `socketfilterfw
//!     --getglobalstate` reports the firewall is OFF, we no-op. The
//!     operator's machine, the operator's policy.
//!   * Codesign anything — `cargo xtask dev-codesign` remains the
//!     authoritative path for ad-hoc-signing the kernel against
//!     `release/raxis.entitlements`.
//!
//! ## Inventory of host binaries managed
//!
//! See [`RAXIS_HOST_BINS`] for the canonical list. Briefly:
//!
//! | Binary                | Why it binds                                                          |
//! | --------------------- | --------------------------------------------------------------------- |
//! | `raxis-kernel`        | dashboard HTTP listener + every credential-proxy 127.0.0.1 listener   |
//! | `raxis-otel-pusher`   | 127.0.0.1 health endpoint                                             |
//! | `raxis-live-e2e`      | many 127.0.0.1 listeners for credential-proxy / gateway slice tests   |
//!
//! Notes on the host-side binary set:
//!
//!   * `raxis-gateway` makes outbound HTTPS calls to provider APIs
//!     and connects to the kernel via a UDS — it does not bind any
//!     TCP/UDP port on the host, so the firewall does not prompt
//!     for it.
//!   * `raxis-tproxy` is Linux-only at runtime; the macOS build
//!     immediately exits with `EX_USAGE` before any bind, so the
//!     firewall never sees it.
//!   * `raxis-orchestrator` / `raxis-executor` / `raxis-reviewer`
//!     are cross-compiled to `*-unknown-linux-musl` and run inside
//!     the AVF guest — they never run on the macOS host.
//!   * `raxis` (CLI), `raxis-image-builder`, `raxis-verifier-stub`
//!     either talk to the kernel via UDS or do not open network
//!     sockets at all.
//!
//! ## Public API
//!
//!   * [`run_prereq`] — entry point for `cargo xtask
//!     macos-firewall-prereq`.
//!   * [`run_status`] — entry point for `cargo xtask
//!     macos-firewall-status`.
//!   * [`run_prereq_as_dev_prereqs_step`] — variant with the same
//!     contract as `run_prereq` but expressed as `Result<(), String>`
//!     so `dev_prereqs::run_with_args` can fold it into its
//!     hard-failure list without introducing a circular module
//!     dependency.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Absolute path to Apple's user-space firewall control binary. Lives
/// in `/usr/libexec` (system-managed; survives major OS upgrades) and
/// has been stable since at least macOS 10.10. We pin the absolute
/// path rather than relying on `$PATH` because this directory is not
/// on `$PATH` for an interactive shell by default.
pub const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// Cargo profile names whose `target/<profile>/<bin>` outputs we
/// allowlist. We do not allowlist `target/debug/deps/*` per-test
/// binaries — they each have unique random suffixes and would create
/// unbounded firewall churn. The recipe documents that test runs
/// inside `cargo test` may still see one popup per test binary; the
/// fix there is a separate concern (see future-work in the recipe).
const CARGO_PROFILES: &[&str] = &["debug", "release"];

/// Inventory of raxis host binaries that bind TCP / UDP ports on the
/// host machine. Each entry is `(binary_name, reason)`. The reason is
/// surfaced in stderr logs and in the recipe's "what does this
/// allow" summary so operators can audit each path before consenting
/// to the `sudo` elevation.
///
/// Source-of-truth: this list mirrors a manual audit of every `[[bin]]`
/// target in the `raxis` workspace (Cargo.toml under `kernel/`,
/// `gateway/`, `cli/`, `tproxy/`, `pusher/`, `live-e2e/`,
/// `crates/planner-orchestrator/`, `crates/planner-executor/`,
/// `crates/planner-reviewer/`, `crates/image-builder/`, and
/// `crates/verifier-stub/`) cross-referenced against
/// `TcpListener::bind` / `UdpSocket::bind` call sites in the produced
/// binary's reachable code. See module-level doc for the rationale on
/// each excluded binary.
pub const RAXIS_HOST_BINS: &[(&str, &str)] = &[
    (
        "raxis-kernel",
        "binds the dashboard HTTP listener (`crates/dashboard/src/server.rs`) and the \
         per-credential-proxy 127.0.0.1 listeners spawned by the kernel's credential-proxy \
         manager (postgres, mongodb, mysql, mssql, redis, smtp, http, aws, gcp, azure)",
    ),
    (
        "raxis-otel-pusher",
        "binds the 127.0.0.1 OTLP-pusher health endpoint (`pusher/src/health.rs`) so the \
         kernel supervisor and `raxis status` can readiness-check the pusher",
    ),
    (
        "raxis-live-e2e",
        "binds many short-lived 127.0.0.1 TCP listeners for the credential-proxy / gateway \
         slice tests (`live-e2e/src/slice_*_proxy.rs`); without an allowlist entry every \
         `--slice` invocation re-prompts",
    ),
];

// ---------------------------------------------------------------------------
// CLI surface — `cargo xtask macos-firewall-prereq`
// ---------------------------------------------------------------------------

/// Parsed args for `cargo xtask macos-firewall-prereq`.
#[derive(Debug, Clone, Default)]
struct PrereqArgs {
    /// When set, print the commands that would run (annotated with
    /// `[dry-run]`) but do not invoke `sudo` or `socketfilterfw`. Lets
    /// the operator audit the proposed change before consenting to the
    /// elevation.
    dry_run: bool,
    /// When set, only consider `target/release/<bin>` paths. Mutually
    /// exclusive with `debug_only`.
    release_only: bool,
    /// When set, only consider `target/debug/<bin>` paths. Mutually
    /// exclusive with `release_only`.
    debug_only: bool,
}

impl PrereqArgs {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut out = Self::default();
        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--dry-run" => out.dry_run = true,
                "--release-only" => out.release_only = true,
                "--debug-only" => out.debug_only = true,
                "-h" | "--help" => {
                    print_prereq_help();
                    std::process::exit(0);
                }
                other => bail!("unknown macos-firewall-prereq arg: {other}"),
            }
            i += 1;
        }
        if out.release_only && out.debug_only {
            bail!("--release-only and --debug-only are mutually exclusive");
        }
        Ok(out)
    }

    fn profiles(&self) -> &'static [&'static str] {
        match (self.release_only, self.debug_only) {
            (true, false) => &["release"],
            (false, true) => &["debug"],
            _ => CARGO_PROFILES,
        }
    }
}

fn print_prereq_help() {
    eprintln!(
        "usage: cargo xtask macos-firewall-prereq [--dry-run] \
         [--release-only | --debug-only]\n\
         \n\
         One-time setup that adds the raxis host binaries to the\n\
         macOS Application Firewall allowlist so the\n\
         \n  \
           Do you want the application \"raxis-kernel\" to accept\n  \
           incoming network connections?\n\
         \n\
         popup never appears on a fresh `cargo build`. Per-binary\n\
         path-based allowlist only — does NOT disable the firewall\n\
         globally.\n\
         \n\
         What it does:\n  \
         1. Probes the host (no-op on non-macOS).\n  \
         2. Locates `socketfilterfw(8)`.\n  \
         3. Skips with a clear message if the firewall is disabled.\n  \
         4. Caches `sudo` once via `sudo -v`.\n  \
         5. For each raxis binary that exists at\n     \
            <workspace>/target/{{debug,release}}/<bin>, runs\n     \
            `sudo socketfilterfw --add` + `--unblockapp`.\n  \
         6. Prints a summary table of every binary's resulting state.\n\
         \n\
         Flags:\n  \
         --dry-run        Print proposed commands, do nothing.\n  \
         --release-only   Only allowlist target/release/* paths.\n  \
         --debug-only     Only allowlist target/debug/* paths.\n\
         \n\
         See also: cargo xtask macos-firewall-status."
    );
}

/// Entry point invoked from `xtask/src/main.rs` when the operator
/// runs `cargo xtask macos-firewall-prereq [...]` directly.
pub fn run_prereq(argv: &[String]) -> Result<()> {
    let args = PrereqArgs::parse(argv)?;
    do_run_prereq(&args)
}

/// `dev_prereqs::run_with_args` calls this so its hard-failure list
/// can include firewall problems without `xtask::dev_prereqs` having
/// to depend on this module's `Args` type. Returns `Ok(())` on
/// success; `Err(message)` (a flat human string) on failure so it
/// composes with the `Vec<String>` that `dev_prereqs` already
/// accumulates.
pub fn run_prereq_as_dev_prereqs_step() -> Result<(), String> {
    let args = PrereqArgs::default();
    do_run_prereq(&args).map_err(|e| format!("{e}"))
}

fn do_run_prereq(args: &PrereqArgs) -> Result<()> {
    log_event(
        "info",
        "macos_firewall_prereq_begin",
        &[
            ("dry_run", args.dry_run.to_string()),
            (
                "profiles",
                serde_json_array(args.profiles().iter().copied()),
            ),
        ],
    );

    if !cfg!(target_os = "macos") {
        log_event(
            "info",
            "macos_firewall_prereq_noop",
            &[
                ("reason", quote("non-macOS host")),
                ("target_os", quote(std::env::consts::OS)),
            ],
        );
        return Ok(());
    }

    if !Path::new(SOCKETFILTERFW).exists() {
        bail!(
            "expected `{SOCKETFILTERFW}` to exist on macOS but it does not. \
             This subcommand requires the system Application Firewall binary \
             (shipped with every supported macOS release). On a stock install \
             you should never see this error; if you do, your macOS install \
             may be missing the SocketFilter framework — file a raxis bug."
        );
    }

    match query_firewall_globalstate() {
        Ok(FirewallGlobalState::On) | Ok(FirewallGlobalState::OnBlockAll) => {
            log_event(
                "info",
                "macos_firewall_globalstate",
                &[("state", quote("on"))],
            );
        }
        Ok(FirewallGlobalState::Off) => {
            log_event(
                "info",
                "macos_firewall_prereq_noop",
                &[
                    ("reason", quote("firewall disabled globally")),
                    (
                        "hint",
                        quote(
                            "no popup will appear when the firewall is off; \
                             this is a no-op",
                        ),
                    ),
                ],
            );
            return Ok(());
        }
        Err(e) => {
            // Don't fail hard — `--getglobalstate` is informational,
            // and a stale macOS may surface unexpected text. Surface
            // the diagnostic and continue.
            log_event(
                "warn",
                "macos_firewall_globalstate_unknown",
                &[("reason", quote(&e.to_string()))],
            );
        }
    }

    let workspace_root = workspace_root_from_cwd()
        .context("resolve workspace root for `target/{debug,release}/<bin>` paths")?;

    let plan = build_plan(&workspace_root, args.profiles());

    if plan.present.is_empty() && plan.missing.is_empty() {
        // Should be impossible — RAXIS_HOST_BINS is non-empty — but
        // guard so a future refactor that empties the list surfaces
        // as a clear error instead of a silent success.
        bail!("internal: macos_firewall::RAXIS_HOST_BINS is empty; nothing to allowlist");
    }

    if plan.present.is_empty() {
        eprintln!(
            "no raxis host binaries are currently built under {}/target/{{{}}}.",
            workspace_root.display(),
            args.profiles().join(","),
        );
        eprintln!(
            "build the host binaries first (e.g. `cargo build -p raxis-kernel \
             -p raxis-otel-pusher -p raxis-live-e2e`), then re-run \
             `cargo xtask macos-firewall-prereq`."
        );
        for entry in &plan.missing {
            log_event(
                "info",
                "macos_firewall_prereq_deferred",
                &[
                    ("binary", quote(entry.binary)),
                    ("path", quote(&entry.path.display().to_string())),
                ],
            );
        }
        return Ok(());
    }

    print_consent_banner(&plan, args.dry_run);

    if !args.dry_run {
        prime_sudo().context(
            "could not cache sudo credentials via `sudo -v`. \
             Some managed devices disallow sudo for the active user; \
             on those hosts the firewall popup cannot be suppressed \
             from this subcommand and the operator must dismiss the \
             popup manually on each fresh build.",
        )?;
    }

    let mut applied: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for entry in &plan.present {
        match apply_one(&entry.path, args.dry_run) {
            Ok(()) => {
                applied.push(format!("{} ({})", entry.binary, entry.path.display()));
                log_event(
                    "info",
                    "macos_firewall_prereq_added",
                    &[
                        ("binary", quote(entry.binary)),
                        ("profile", quote(entry.profile)),
                        ("path", quote(&entry.path.display().to_string())),
                        ("dry_run", args.dry_run.to_string()),
                    ],
                );
            }
            Err(e) => {
                failures.push(format!(
                    "{} ({}): {}",
                    entry.binary,
                    entry.path.display(),
                    e
                ));
                log_event(
                    "error",
                    "macos_firewall_prereq_add_failed",
                    &[
                        ("binary", quote(entry.binary)),
                        ("path", quote(&entry.path.display().to_string())),
                        ("reason", quote(&e.to_string())),
                    ],
                );
            }
        }
    }

    for entry in &plan.missing {
        log_event(
            "info",
            "macos_firewall_prereq_deferred",
            &[
                ("binary", quote(entry.binary)),
                ("profile", quote(entry.profile)),
                ("path", quote(&entry.path.display().to_string())),
            ],
        );
    }

    print_summary(&plan, args.dry_run);

    if !failures.is_empty() {
        bail!(
            "macos-firewall-prereq could not allowlist {} binary path(s):\n  - {}",
            failures.len(),
            failures.join("\n  - "),
        );
    }

    log_event(
        "info",
        "macos_firewall_prereq_ok",
        &[
            ("added", applied.len().to_string()),
            ("deferred", plan.missing.len().to_string()),
        ],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI surface — `cargo xtask macos-firewall-status`
// ---------------------------------------------------------------------------

/// Entry point invoked from `xtask/src/main.rs` when the operator
/// runs `cargo xtask macos-firewall-status [...]`. Read-only — never
/// mutates firewall state.
pub fn run_status(argv: &[String]) -> Result<()> {
    if argv.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!(
            "usage: cargo xtask macos-firewall-status\n\
             \n\
             Prints the current macOS Application Firewall state for\n\
             every raxis host binary (built or not). Read-only — does\n\
             NOT modify the allowlist. Use `cargo xtask macos-firewall-prereq`\n\
             to add missing entries."
        );
        return Ok(());
    }
    if !argv.is_empty() {
        bail!(
            "macos-firewall-status takes no positional args; got {argv:?}. \
             Pass `--help` for usage."
        );
    }

    if !cfg!(target_os = "macos") {
        log_event(
            "info",
            "macos_firewall_status_noop",
            &[
                ("reason", quote("non-macOS host")),
                ("target_os", quote(std::env::consts::OS)),
            ],
        );
        return Ok(());
    }

    if !Path::new(SOCKETFILTERFW).exists() {
        bail!("expected `{SOCKETFILTERFW}` to exist on macOS but it does not");
    }

    match query_firewall_globalstate() {
        Ok(state) => {
            eprintln!("Application Firewall global state: {}", state.label());
        }
        Err(e) => {
            eprintln!(
                "Application Firewall global state: unknown ({e}). \
                 Continuing with --listapps query."
            );
        }
    }

    let workspace_root = workspace_root_from_cwd()
        .context("resolve workspace root for the binary path inventory")?;

    let plan = build_plan(&workspace_root, CARGO_PROFILES);
    let listing = read_listapps().context("read `socketfilterfw --listapps` output")?;

    println!();
    println!("raxis host binaries — Application Firewall allowlist state:");
    println!();

    let mut summary_rows: Vec<(String, String, &'static str)> = Vec::new();
    for entry in plan.present.iter().chain(plan.missing.iter()) {
        let path_str = entry.path.display().to_string();
        let on_disk = entry.exists_on_disk;
        let allow = listing
            .iter()
            .any(|l| l.path == path_str && matches!(l.policy, AppPolicy::Allow));
        let block = listing
            .iter()
            .any(|l| l.path == path_str && matches!(l.policy, AppPolicy::Block));

        let state: &'static str = if !on_disk {
            "MISSING (binary not yet built; will be added on next prereq run)"
        } else if allow {
            "Allow incoming connections"
        } else if block {
            "Block incoming connections (run `cargo xtask macos-firewall-prereq`)"
        } else {
            "Not in allowlist (run `cargo xtask macos-firewall-prereq`)"
        };

        summary_rows.push((entry.binary.to_owned(), path_str, state));
    }

    print_status_table(&summary_rows);
    Ok(())
}

// ---------------------------------------------------------------------------
// Plan construction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PlanEntry {
    binary: &'static str,
    /// Why the binary needs the allowlist entry, surfaced in the
    /// consent banner.
    reason: &'static str,
    profile: &'static str,
    path: PathBuf,
    exists_on_disk: bool,
}

#[derive(Debug, Clone, Default)]
struct Plan {
    /// Binaries whose `target/<profile>/<bin>` exists on disk. These
    /// are the ones we will actually `--add` / `--unblockapp`.
    present: Vec<PlanEntry>,
    /// Binaries whose `target/<profile>/<bin>` does not exist yet.
    /// We log them as deferred so the operator knows to re-run the
    /// subcommand after they `cargo build` the missing profile.
    missing: Vec<PlanEntry>,
}

fn build_plan(workspace_root: &Path, profiles: &'static [&'static str]) -> Plan {
    let mut plan = Plan::default();
    for (binary, reason) in RAXIS_HOST_BINS {
        for profile in profiles {
            let path = workspace_root.join("target").join(profile).join(binary);
            let exists = path.exists();
            let entry = PlanEntry {
                binary,
                reason,
                profile,
                path,
                exists_on_disk: exists,
            };
            if exists {
                plan.present.push(entry);
            } else {
                plan.missing.push(entry);
            }
        }
    }
    plan
}

// ---------------------------------------------------------------------------
// Consent banner + summary table
// ---------------------------------------------------------------------------

fn print_consent_banner(plan: &Plan, dry_run: bool) {
    eprintln!();
    eprintln!(
        "About to {} the macOS Application Firewall to allowlist the\n\
         following raxis host binaries (per-path; per-binary; the\n\
         firewall stays enabled for everything else):",
        if dry_run {
            "[dry-run] modify"
        } else {
            "modify"
        },
    );
    eprintln!();
    let mut by_binary: std::collections::BTreeMap<&str, (&str, Vec<&Path>)> =
        std::collections::BTreeMap::new();
    for e in &plan.present {
        by_binary
            .entry(e.binary)
            .or_insert_with(|| (e.reason, Vec::new()))
            .1
            .push(&e.path);
    }
    for (binary, (reason, paths)) in &by_binary {
        eprintln!("  • {binary} — {reason}");
        for p in paths {
            eprintln!("      {}", p.display());
        }
    }
    eprintln!();
    if !dry_run {
        eprintln!(
            "This requires `sudo` because `socketfilterfw` mutates\n\
             /Library/Preferences/com.apple.alf.plist. You will be\n\
             prompted for your password once."
        );
        eprintln!();
    }
}

fn print_summary(plan: &Plan, dry_run: bool) {
    let mut rows: Vec<(String, String, &'static str)> = Vec::new();
    for e in &plan.present {
        let state = if dry_run {
            "[dry-run] would be Allow"
        } else {
            "Allow incoming connections"
        };
        rows.push((e.binary.to_owned(), e.path.display().to_string(), state));
    }
    for e in &plan.missing {
        rows.push((
            e.binary.to_owned(),
            e.path.display().to_string(),
            "MISSING (binary not yet built; will be added on next prereq run)",
        ));
    }
    println!();
    println!("macOS Application Firewall — raxis host binaries:");
    println!();
    print_status_table(&rows);
}

fn print_status_table(rows: &[(String, String, &'static str)]) {
    let bin_w = rows.iter().map(|r| r.0.len()).max().unwrap_or(6).max(6);
    let path_w = rows.iter().map(|r| r.1.len()).max().unwrap_or(4).max(4);
    println!(
        "  {bin:<bin_w$}  {path:<path_w$}  state",
        bin = "binary",
        path = "path",
        bin_w = bin_w,
        path_w = path_w,
    );
    println!(
        "  {dash:<bin_w$}  {dash:<path_w$}  -----",
        dash = "------",
        bin_w = bin_w,
        path_w = path_w,
    );
    for (bin, path, state) in rows {
        println!(
            "  {bin:<bin_w$}  {path:<path_w$}  {state}",
            bin = bin,
            path = path,
            state = state,
            bin_w = bin_w,
            path_w = path_w,
        );
    }
    println!();
}

// ---------------------------------------------------------------------------
// `socketfilterfw` invocation primitives
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallGlobalState {
    /// `--getglobalstate` reports state 1 (on, default profile).
    On,
    /// `--getglobalstate` reports state 2 (on, block-all profile).
    OnBlockAll,
    /// `--getglobalstate` reports state 0 (off).
    Off,
}

impl FirewallGlobalState {
    fn label(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::OnBlockAll => "on (block all)",
            Self::Off => "off",
        }
    }
}

fn query_firewall_globalstate() -> Result<FirewallGlobalState> {
    let out = Command::new(SOCKETFILTERFW)
        .arg("--getglobalstate")
        .output()
        .with_context(|| format!("spawn `{SOCKETFILTERFW} --getglobalstate`"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail!(
            "`socketfilterfw --getglobalstate` exited {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            out.status,
        );
    }
    parse_globalstate(&stdout)
}

/// Parse the human-readable `--getglobalstate` output. Apple's phrasing
/// has been stable across macOS 10.15 → 14 → 15 but we accept any
/// reasonable variant by sniffing for the literal numeric state code
/// embedded in the line, e.g. `Firewall is enabled. (State = 1)`.
fn parse_globalstate(stdout: &str) -> Result<FirewallGlobalState> {
    for line in stdout.lines() {
        if let Some(eq) = line.find("State = ") {
            let rest = &line[eq + "State = ".len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            match digits.as_str() {
                "0" => return Ok(FirewallGlobalState::Off),
                "1" => return Ok(FirewallGlobalState::On),
                "2" => return Ok(FirewallGlobalState::OnBlockAll),
                other => bail!(
                    "unrecognised `socketfilterfw --getglobalstate` State value: {other:?} \
                     (full line: {line:?}). File a raxis bug if your macOS reports a value \
                     not in 0..=2."
                ),
            }
        }
    }
    // Fallback: keyword sniff. Stable since macOS 10.10.
    let lower = stdout.to_lowercase();
    if lower.contains("disabled") {
        Ok(FirewallGlobalState::Off)
    } else if lower.contains("block all") {
        Ok(FirewallGlobalState::OnBlockAll)
    } else if lower.contains("enabled") {
        Ok(FirewallGlobalState::On)
    } else {
        bail!("could not parse `socketfilterfw --getglobalstate` output: {stdout:?}");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AppPolicy {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListedApp {
    path: String,
    policy: AppPolicy,
}

fn read_listapps() -> Result<Vec<ListedApp>> {
    let out = Command::new(SOCKETFILTERFW)
        .arg("--listapps")
        .output()
        .with_context(|| format!("spawn `{SOCKETFILTERFW} --listapps`"))?;
    if !out.status.success() {
        bail!(
            "`socketfilterfw --listapps` exited {}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    Ok(parse_listapps(&stdout))
}

/// Parse `--listapps` output. Apple's format (stable since macOS
/// 10.10) is:
///
/// ```text
/// Total number of apps = N
/// 1 : /abs/path/to/app
///              (Allow incoming connections)
/// 2 : /abs/path/to/other
///              (Block incoming connections)
/// ```
///
/// We scan pairwise: every line that matches `^\s*\d+ : ` is a path
/// header; the next non-empty line carries the policy in parentheses.
/// Unknown policy text is mapped to `Allow` because Apple's only two
/// canonical labels are "Allow incoming connections" and "Block
/// incoming connections".
fn parse_listapps(stdout: &str) -> Vec<ListedApp> {
    let mut out = Vec::new();
    let lines: Vec<&str> = stdout.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(path) = parse_listapps_path_line(line) {
            // Next non-empty line is the policy line.
            let mut j = i + 1;
            let mut policy = AppPolicy::Allow;
            while j < lines.len() {
                let probe = lines[j].trim();
                if probe.is_empty() {
                    j += 1;
                    continue;
                }
                if probe.contains("(Block") {
                    policy = AppPolicy::Block;
                } else if probe.contains("(Allow") {
                    policy = AppPolicy::Allow;
                } else {
                    // Not a policy line — back up so the outer loop
                    // can re-process it as a possible path header.
                    j -= 1;
                }
                break;
            }
            out.push(ListedApp { path, policy });
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

fn parse_listapps_path_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let colon = trimmed.find(" : ")?;
    let head = &trimmed[..colon];
    if !head.chars().all(|c| c.is_ascii_digit()) || head.is_empty() {
        return None;
    }
    let path = trimmed[colon + " : ".len()..].trim();
    if path.starts_with('/') {
        // Apple's --listapps tail-pads each path line with a single
        // trailing space; preserve the path verbatim by trimming
        // explicit whitespace.
        Some(path.trim_end().to_owned())
    } else {
        None
    }
}

/// Cache the operator's sudo credentials with `sudo -v`. Returns
/// `Ok(())` if sudo accepts the password (or already cached), `Err`
/// if the operator cancels the prompt or `sudo` is unavailable.
fn prime_sudo() -> Result<()> {
    let status = Command::new("sudo")
        .arg("-v")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("spawn `sudo -v`; is sudo installed and on $PATH?")?;
    if !status.success() {
        bail!(
            "`sudo -v` exited {} — the macOS firewall allowlist requires root \
             because socketfilterfw mutates /Library/Preferences/com.apple.alf.plist",
            status,
        );
    }
    Ok(())
}

/// Apply the two-step `--add` + `--unblockapp` allowlist for a single
/// binary path. Idempotent at the firewall layer.
fn apply_one(path: &Path, dry_run: bool) -> Result<()> {
    let path_str = path.to_string_lossy().into_owned();
    let cmds: [(&str, [&str; 4]); 2] = [
        ("add", ["sudo", SOCKETFILTERFW, "--add", path_str.as_str()]),
        (
            "unblockapp",
            ["sudo", SOCKETFILTERFW, "--unblockapp", path_str.as_str()],
        ),
    ];
    for (label, argv) in cmds {
        if dry_run {
            // Stable, copy-pastable banner so an operator auditing
            // the proposed change can paste it into a terminal.
            let mut writer = std::io::stderr().lock();
            let _ = writeln!(
                writer,
                "  [dry-run] {} {} {} {}",
                argv[0], argv[1], argv[2], argv[3],
            );
            continue;
        }
        let status = Command::new(argv[0])
            .arg(argv[1])
            .arg(argv[2])
            .arg(argv[3])
            .status()
            .with_context(|| format!("spawn `sudo {SOCKETFILTERFW} --{label} {path_str}`"))?;
        if !status.success() {
            bail!(
                "`sudo {SOCKETFILTERFW} --{label} {path_str}` exited {}",
                status,
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn workspace_root_from_cwd() -> Result<PathBuf> {
    let mut cwd: PathBuf = std::env::current_dir().context("cannot read CWD")?;
    loop {
        let candidate = cwd.join("Cargo.toml");
        if candidate.exists() {
            let s = std::fs::read_to_string(&candidate)
                .with_context(|| format!("read {}", candidate.display()))?;
            if s.contains("[workspace]") {
                return Ok(cwd);
            }
        }
        if !cwd.pop() {
            bail!(
                "could not find workspace root (no Cargo.toml with \
                 [workspace] in any ancestor of CWD)"
            );
        }
    }
}

/// Hand-rolled JSON event log line, matching the style used by every
/// other xtask module (`dev_prereqs`, `dev_codesign`, `images`).
fn log_event(level: &str, event: &str, fields: &[(&str, String)]) {
    let mut buf = format!("{{\"level\":\"{level}\",\"event\":\"{event}\"");
    for (k, v) in fields {
        buf.push(',');
        buf.push('"');
        buf.push_str(k);
        buf.push('"');
        buf.push(':');
        buf.push_str(v);
    }
    buf.push('}');
    eprintln!("{buf}");
}

fn quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn serde_json_array<I>(items: I) -> String
where
    I: IntoIterator<Item = &'static str>,
{
    let mut out = String::from("[");
    let mut first = true;
    for item in items {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&quote(item));
    }
    out.push(']');
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prereq_args_default_is_apply_both_profiles() {
        let args = PrereqArgs::parse(&[]).unwrap();
        assert!(!args.dry_run);
        assert!(!args.release_only);
        assert!(!args.debug_only);
        assert_eq!(args.profiles(), CARGO_PROFILES);
    }

    #[test]
    fn prereq_args_dry_run_flag_is_recognised() {
        let argv = vec!["--dry-run".to_owned()];
        let args = PrereqArgs::parse(&argv).unwrap();
        assert!(args.dry_run);
    }

    #[test]
    fn prereq_args_release_only_narrows_profiles() {
        let argv = vec!["--release-only".to_owned()];
        let args = PrereqArgs::parse(&argv).unwrap();
        assert_eq!(args.profiles(), &["release"]);
    }

    #[test]
    fn prereq_args_debug_only_narrows_profiles() {
        let argv = vec!["--debug-only".to_owned()];
        let args = PrereqArgs::parse(&argv).unwrap();
        assert_eq!(args.profiles(), &["debug"]);
    }

    #[test]
    fn prereq_args_release_and_debug_only_is_mutually_exclusive() {
        let argv = vec!["--release-only".to_owned(), "--debug-only".to_owned()];
        let err = PrereqArgs::parse(&argv).unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn prereq_args_unknown_flag_is_rejected() {
        let argv = vec!["--what".to_owned()];
        let err = PrereqArgs::parse(&argv).unwrap_err().to_string();
        assert!(
            err.contains("unknown macos-firewall-prereq arg"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_globalstate_recognises_state_one() {
        let s = "Firewall is enabled. (State = 1)\n";
        assert_eq!(parse_globalstate(s).unwrap(), FirewallGlobalState::On);
    }

    #[test]
    fn parse_globalstate_recognises_state_two_block_all() {
        let s = "Firewall is enabled. (State = 2)\n";
        assert_eq!(
            parse_globalstate(s).unwrap(),
            FirewallGlobalState::OnBlockAll
        );
    }

    #[test]
    fn parse_globalstate_recognises_state_zero() {
        let s = "Firewall is disabled. (State = 0)\n";
        assert_eq!(parse_globalstate(s).unwrap(), FirewallGlobalState::Off);
    }

    #[test]
    fn parse_globalstate_falls_back_to_keyword_sniff() {
        // No State = N suffix — older macOS variants sometimes
        // omitted the parenthesis. We fall back to the keyword.
        assert_eq!(
            parse_globalstate("Firewall is disabled.\n").unwrap(),
            FirewallGlobalState::Off,
        );
        assert_eq!(
            parse_globalstate("Firewall is enabled.\n").unwrap(),
            FirewallGlobalState::On,
        );
    }

    #[test]
    fn parse_globalstate_rejects_unparseable() {
        let err = parse_globalstate("hello world\n").unwrap_err().to_string();
        assert!(err.contains("could not parse"), "got: {err}");
    }

    #[test]
    fn parse_listapps_one_allow_one_block() {
        let s = "Total number of apps = 2 \n\
                 1 : /usr/local/bin/foo \n\
                              (Allow incoming connections)\n\
                 2 : /usr/local/bin/bar \n\
                              (Block incoming connections)\n";
        let parsed = parse_listapps(s);
        assert_eq!(
            parsed,
            vec![
                ListedApp {
                    path: "/usr/local/bin/foo".to_owned(),
                    policy: AppPolicy::Allow
                },
                ListedApp {
                    path: "/usr/local/bin/bar".to_owned(),
                    policy: AppPolicy::Block
                },
            ]
        );
    }

    #[test]
    fn parse_listapps_handles_trailing_whitespace_apple_emits() {
        // Apple appends a trailing space after every path.
        let s = "1 : /Applications/Foo.app \n\
                              (Allow incoming connections)\n";
        let parsed = parse_listapps(s);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].path, "/Applications/Foo.app");
        assert_eq!(parsed[0].policy, AppPolicy::Allow);
    }

    #[test]
    fn parse_listapps_skips_lines_without_path_header() {
        let s = "Total number of apps = 0 \n\
                 (no apps registered)\n";
        let parsed = parse_listapps(s);
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_listapps_path_line_requires_absolute_path() {
        assert!(parse_listapps_path_line("1 : foo").is_none());
        assert_eq!(
            parse_listapps_path_line("1 : /abs/path"),
            Some("/abs/path".to_owned())
        );
        assert!(parse_listapps_path_line("not a path").is_none());
        assert!(parse_listapps_path_line("Total number of apps = 5").is_none());
    }

    #[test]
    fn build_plan_partitions_present_and_missing_per_profile() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path();
        // Stage a fake `target/debug/raxis-kernel` so it ends up in
        // `present`. Leave `target/release/raxis-kernel` missing so
        // it ends up in `missing`. Also do not create the other
        // binaries so they all end up in `missing`.
        let debug_kernel = workspace.join("target/debug/raxis-kernel");
        std::fs::create_dir_all(debug_kernel.parent().unwrap()).unwrap();
        std::fs::write(&debug_kernel, b"fake binary").unwrap();

        let plan = build_plan(workspace, CARGO_PROFILES);
        assert_eq!(
            plan.present.len(),
            1,
            "only debug raxis-kernel should be present, got: {:?}",
            plan.present,
        );
        assert_eq!(plan.present[0].binary, "raxis-kernel");
        assert_eq!(plan.present[0].profile, "debug");
        assert_eq!(plan.present[0].path, debug_kernel);

        // 3 binaries × 2 profiles = 6 candidate entries; 1 is
        // present (debug raxis-kernel), the rest are missing.
        let total_candidates = RAXIS_HOST_BINS.len() * CARGO_PROFILES.len();
        assert_eq!(plan.missing.len(), total_candidates - 1);
    }

    #[test]
    fn build_plan_release_only_yields_release_paths() {
        let dir = tempfile::tempdir().unwrap();
        let plan = build_plan(dir.path(), &["release"]);
        for entry in plan.present.iter().chain(plan.missing.iter()) {
            assert_eq!(entry.profile, "release");
            assert!(
                entry.path.to_string_lossy().contains("target/release"),
                "bad path: {}",
                entry.path.display(),
            );
        }
    }

    #[test]
    fn raxis_host_bins_are_unique_and_documented() {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for (binary, reason) in RAXIS_HOST_BINS {
            assert!(
                seen.insert(binary),
                "duplicate binary in RAXIS_HOST_BINS: {binary}"
            );
            assert!(
                !reason.is_empty(),
                "binary {binary:?} in RAXIS_HOST_BINS must carry a non-empty reason"
            );
        }
    }

    #[test]
    fn quote_escapes_quotes_and_backslashes() {
        assert_eq!(quote("a\"b"), r#""a\"b""#);
        assert_eq!(quote("a\\b"), r#""a\\b""#);
        assert_eq!(quote("a\nb"), r#""a\nb""#);
    }

    #[test]
    fn serde_json_array_encodes_strings() {
        assert_eq!(serde_json_array(["a", "b"]), r#"["a","b"]"#);
        assert_eq!(serde_json_array::<[&'static str; 0]>([]), "[]");
    }
}
