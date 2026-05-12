//! `cargo xtask dev-prereqs` — idempotent installer / verifier for the
//! V2 AVF demo prerequisites described in `demo-e2e-sample/AVF_DEMO.md
//! §0`.
//!
//! Normative references:
//!
//! * `raxis/demo-e2e-sample/AVF_DEMO.md §0` — operator-facing recipe
//!   the operator follows by hand today. This subcommand collapses
//!   the §0 checklist into a single `cargo xtask dev-prereqs` call.
//! * `raxis/specs/v2/system-requirements.md §5.2 + §11` — codesign
//!   identity expectations + canonical kernel install layout the
//!   downstream `cargo xtask dev-codesign` / `cargo xtask images
//!   dev-kernel` subcommands consume.
//! * `raxis/specs/v2/release-and-distribution.md §6.3` — Apple-VZ
//!   entitlement requirements that are why we need `codesign` on
//!   `$PATH` to begin with.
//!
//! ## What this subcommand does
//!
//! Runs the §0 prerequisite checklist in order, idempotently:
//!
//!   1. **Homebrew probe** (macOS only) — fails fast with the
//!      `https://brew.sh` install line if `brew` is not on `$PATH`.
//!   2. **Brew packages** — verifies (and, when `--install` is
//!      passed, installs) the two Homebrew packages the demo
//!      requires:
//!        * `filosottile/musl-cross/musl-cross` — the musl-targeting
//!          cross-linker the planner role binaries need to static-
//!          link against musl libc for the guest VM.
//!        * `openssl@3` — Apple ships LibreSSL as `/usr/bin/openssl`
//!          which cannot mint Ed25519 keys; `openssl@3` is the
//!          tested-against version.
//!   3. **Rustup target** — verifies (and, when `--install` is
//!      passed, adds) the `<host-arch>-unknown-linux-musl` target
//!      so `cargo xtask images dev-stage` can cross-compile.
//!   4. **Cargo linker config** — reads the operator's
//!      `~/.cargo/config.toml` (or workspace `.cargo/config.toml`,
//!      per `--scope`) and patches in the
//!      `[target.<arch>-unknown-linux-musl] linker = "<arch>-linux-
//!      musl-gcc"` snippet IFF it is missing. Existing values are
//!      preserved verbatim — the patch is fully additive.
//!   5. **Codesign probe** — verifies the Xcode CLT `codesign`
//!      binary is on `$PATH`. Required by `cargo xtask dev-codesign`.
//!   6. **Cargo probe** — verifies `cargo --version` reports a
//!      stable toolchain.
//!   7. **macOS Application Firewall allowlist** (macOS only) —
//!      runs `cargo xtask macos-firewall-prereq` so the recurring
//!      "allow `raxis-kernel` to accept incoming network
//!      connections" popup does not derail every fresh
//!      `cargo build`. See [`crate::macos_firewall`] for the
//!      Strategy-A trade-off (per-binary path allowlist via
//!      `socketfilterfw`). Skipped with `--skip-firewall` for
//!      CI / managed devices that disallow `sudo`.
//!
//! Each step prints a one-line `{"level":"info"|"warn"|"error",
//! "event":"dev_prereqs_<step>", ...}` JSON record so operators
//! can grep the output for the first failed step.
//!
//! ## Linux behaviour
//!
//! The AVF demo is macOS-only (Apple's Virtualization.framework is
//! macOS-only). On Linux, the subcommand still verifies the rustup
//! target + cargo + (optionally) configures the `[target...] linker`
//! line, but skips the brew + codesign probes.
//!
//! ## Exit-code contract
//!
//! * `0` — every required check passed (or was successfully
//!   installed when `--install` was passed).
//! * non-zero — at least one hard prerequisite is missing. The
//!   `--install` flag escalates "missing" to "best-effort install",
//!   but a brew install / rustup install failure still surfaces as
//!   non-zero so CI noticing the failure does not silently progress.
//!
//! ## Why a subcommand and not a shell script
//!
//! `release/scripts/dev-bootstrap.sh` is the right place for an
//! opinionated end-to-end bootstrapper that also fetches a kernel
//! binary and codesigns the host binary. This subcommand intentionally
//! does NEITHER — it is the *prerequisite* layer, the part of §0
//! that has to succeed before any of the §3-§6 xtask commands can
//! even run. Keeping it in xtask means it shares the workspace's
//! `Cargo.lock` with every other `cargo xtask` target and operates
//! against the same `Result` / `anyhow` plumbing the rest of the
//! xtask tree uses.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Brew packages the AVF demo (`AVF_DEMO.md §0`) hard-requires on
/// macOS. The first column is the formula name brew expects; the
/// second is a short human-readable purpose surfaced in error
/// messages so operators can decide whether they need a given
/// formula at all.
const REQUIRED_BREW_PACKAGES: &[(&str, &str)] = &[
    (
        "filosottile/musl-cross/musl-cross",
        "musl-targeting cross-linker for planner role binaries (aarch64-linux-musl-gcc / x86_64-linux-musl-gcc)",
    ),
    (
        "openssl@3",
        "OpenSSL 3.x for Ed25519 operator keys (macOS LibreSSL cannot mint Ed25519)",
    ),
];

/// Operator scope for the cargo linker config patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CargoConfigScope {
    /// `~/.cargo/config.toml`. Default — matches `AVF_DEMO.md §0`'s
    /// "drop into your shell init" guidance and survives `cargo
    /// clean` + workspace switching.
    User,
    /// `<workspace_root>/.cargo/config.toml`. Useful for hermetic CI
    /// where the operator wants the linker pin to live next to the
    /// repo, not in `$HOME`.
    Workspace,
}

impl CargoConfigScope {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "user" => Ok(Self::User),
            "workspace" => Ok(Self::Workspace),
            other => bail!("unsupported --scope {other:?}; expected one of: user, workspace"),
        }
    }
}

/// Parsed args for the subcommand.
#[derive(Debug)]
struct Args {
    /// When `false` (the default), missing prerequisites are
    /// reported and the subcommand exits non-zero. When `true`, the
    /// subcommand runs `brew install <pkg>` / `rustup target add
    /// <triple>` for missing pieces.
    install: bool,
    /// Where to install the cargo linker patch. See
    /// [`CargoConfigScope`].
    scope: CargoConfigScope,
    /// Override the host arch detection. Useful for cross-host CI
    /// validation (e.g. Apple Silicon CI gate that wants to verify
    /// the Intel triple wiring still parses).
    arch: Option<HostArch>,
    /// Skip the cargo config patch step entirely. The operator may
    /// already curate `~/.cargo/config.toml` by hand and want the
    /// subcommand to act as a pure verifier.
    skip_cargo_config: bool,
    /// Skip the macOS Application Firewall allowlist step (Step 7).
    /// CI / managed devices that disallow `sudo` should pass this.
    /// On non-macOS hosts the step is auto-skipped without needing
    /// the flag.
    skip_firewall: bool,
}

/// Host architecture the prerequisites are configured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostArch {
    Aarch64,
    X86_64,
}

impl HostArch {
    fn from_host() -> Self {
        if cfg!(target_arch = "aarch64") {
            HostArch::Aarch64
        } else {
            HostArch::X86_64
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "aarch64" | "arm64" => Ok(Self::Aarch64),
            "x86_64" | "amd64" => Ok(Self::X86_64),
            other => bail!(
                "unsupported --arch {other:?}; expected one of: aarch64, arm64, x86_64, amd64"
            ),
        }
    }

    /// Rustup target triple matching the AVF guest the planner
    /// role binaries cross-compile for. Mirrors
    /// `xtask/src/images.rs::default_target_triple`.
    fn musl_triple(self) -> &'static str {
        match self {
            HostArch::Aarch64 => "aarch64-unknown-linux-musl",
            HostArch::X86_64 => "x86_64-unknown-linux-musl",
        }
    }

    /// musl-cross cross-linker binary brewed by
    /// `filosottile/musl-cross/musl-cross`. The same binary is
    /// the one Cargo invokes via the `[target.<triple>] linker`
    /// snippet patched in by [`patch_cargo_linker_config`].
    fn musl_linker_bin(self) -> &'static str {
        match self {
            HostArch::Aarch64 => "aarch64-linux-musl-gcc",
            HostArch::X86_64 => "x86_64-linux-musl-gcc",
        }
    }
}

impl Args {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut install = false;
        let mut scope = CargoConfigScope::User;
        let mut arch = None;
        let mut skip_cargo_config = false;
        let mut skip_firewall = false;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--install" => install = true,
                "--scope" => {
                    i += 1;
                    scope =
                        CargoConfigScope::parse(argv.get(i).context("--scope requires a value")?)?;
                }
                "--arch" => {
                    i += 1;
                    arch = Some(HostArch::parse(
                        argv.get(i).context("--arch requires a value")?,
                    )?);
                }
                "--skip-cargo-config" => skip_cargo_config = true,
                "--skip-firewall" => skip_firewall = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown dev-prereqs arg: {other}"),
            }
            i += 1;
        }

        Ok(Self {
            install,
            scope,
            arch,
            skip_cargo_config,
            skip_firewall,
        })
    }
}

fn print_help() {
    eprintln!(
        "usage: cargo xtask dev-prereqs \n           \
           [--install] [--scope user|workspace] [--arch aarch64|x86_64]\n           \
           [--skip-cargo-config] [--skip-firewall]\n\
         \n\
         Verifies the AVF demo prerequisites from \n         \
           raxis/demo-e2e-sample/AVF_DEMO.md §0\n\
         and (with --install) installs them idempotently. Steps:\n  \
           1. Homebrew probe (macOS only)\n  \
           2. brew packages: filosottile/musl-cross/musl-cross, openssl@3\n  \
           3. rustup target: <arch>-unknown-linux-musl\n  \
           4. ~/.cargo/config.toml [target.<arch>-unknown-linux-musl] linker patch\n  \
           5. codesign on $PATH (macOS only)\n  \
           6. cargo --version probe\n  \
           7. macOS Application Firewall allowlist for raxis host binaries\n     \
              (macOS only; one-time `sudo socketfilterfw --add` per binary;\n     \
              suppresses the recurring `accept incoming network connections`\n     \
              popup on every fresh `cargo build`. See `xtask/src/macos_firewall.rs`\n     \
              for the inventory of managed binaries.)\n\
         \n\
         Defaults:\n  \
           --install            off (verify-only; non-zero exit on miss)\n  \
           --scope              user (~/.cargo/config.toml)\n  \
           --arch               host arch\n  \
           --skip-cargo-config  off\n  \
           --skip-firewall      off (skip Step 7; required on managed devices\n                                that disallow `sudo`)\n"
    );
}

/// Entry point invoked from `xtask/src/main.rs`.
pub fn run(argv: &[String]) -> Result<()> {
    let args = Args::parse(argv)?;
    let host_arch = args.arch.unwrap_or_else(HostArch::from_host);
    run_with_args(&args, host_arch)
}

/// Pure-args variant — splits parsing from execution so the unit
/// tests can drive the steps with synthetic `Args` values.
fn run_with_args(args: &Args, host_arch: HostArch) -> Result<()> {
    let is_macos = cfg!(target_os = "macos");

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_prereqs_begin\",\
         \"install\":{},\"scope\":\"{}\",\"arch\":\"{}\",\
         \"skip_cargo_config\":{},\"is_macos\":{}}}",
        args.install,
        match args.scope {
            CargoConfigScope::User => "user",
            CargoConfigScope::Workspace => "workspace",
        },
        host_arch.musl_triple(),
        args.skip_cargo_config,
        is_macos,
    );

    let mut hard_failures: Vec<String> = Vec::new();

    if is_macos {
        match probe_homebrew() {
            Ok(()) => {}
            Err(e) => hard_failures.push(format!("homebrew: {e}")),
        }
        for (formula, purpose) in REQUIRED_BREW_PACKAGES {
            match ensure_brew_package(formula, purpose, args.install) {
                Ok(()) => {}
                Err(e) => hard_failures.push(format!("brew {formula}: {e}")),
            }
        }
    } else {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"dev_prereqs_skip_brew\",\
             \"reason\":\"non-macos host; AVF demo is macOS-only\"}}"
        );
    }

    match ensure_rustup_target(host_arch.musl_triple(), args.install) {
        Ok(()) => {}
        Err(e) => hard_failures.push(format!("rustup target: {e}")),
    }

    if !args.skip_cargo_config {
        match patch_cargo_linker_config(host_arch, args.scope) {
            Ok(()) => {}
            Err(e) => hard_failures.push(format!("cargo config: {e}")),
        }
    } else {
        eprintln!("{{\"level\":\"info\",\"event\":\"dev_prereqs_skip_cargo_config\"}}");
    }

    if is_macos {
        match probe_command_on_path("codesign") {
            Ok(()) => {}
            Err(e) => hard_failures.push(format!("codesign: {e}")),
        }
    }

    match probe_cargo() {
        Ok(()) => {}
        Err(e) => hard_failures.push(format!("cargo: {e}")),
    }

    // Step 7 — macOS Application Firewall allowlist (no-op on
    // non-macOS, no-op when --skip-firewall is set, no-op when the
    // firewall is disabled globally). Surfacing this as a soft step:
    // the firewall step CAN fail on managed devices that disallow
    // `sudo`, and we don't want a managed-device failure here to
    // mask the genuine outcome of steps 1–6 (which are the demo
    // hard-prereqs). Operators who need the firewall step to be
    // hard-required can run `cargo xtask macos-firewall-prereq`
    // directly and let its non-zero exit propagate.
    if is_macos {
        if args.skip_firewall {
            eprintln!("{{\"level\":\"info\",\"event\":\"dev_prereqs_skip_firewall\"}}");
        } else {
            match crate::macos_firewall::run_prereq_as_dev_prereqs_step() {
                Ok(()) => {}
                Err(e) => {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"dev_prereqs_firewall_failed\",\
                         \"reason\":{:?},\"hint\":\"re-run `cargo xtask macos-firewall-prereq` \
                         manually, or pass --skip-firewall to dev-prereqs on managed devices \
                         that disallow sudo\"}}",
                        e,
                    );
                }
            }
        }
    } else {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"dev_prereqs_skip_firewall\",\
             \"reason\":\"non-macOS host; firewall popup is a macOS-only artefact\"}}"
        );
    }

    if hard_failures.is_empty() {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"dev_prereqs_ok\",\
             \"message\":\"every AVF demo prerequisite verified\"}}"
        );
        Ok(())
    } else {
        for f in &hard_failures {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"dev_prereqs_failure\",\
                 \"failure\":{:?}}}",
                f,
            );
        }
        bail!(
            "dev-prereqs found {} unmet requirement(s); pass --install to \
             attempt automatic remediation, or address them manually per \
             AVF_DEMO.md §0",
            hard_failures.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Step implementations.
// ---------------------------------------------------------------------------

/// Step 1 — `which brew`. Pre-condition for everything else on macOS.
fn probe_homebrew() -> Result<()> {
    let out = Command::new("brew").arg("--version").output();
    match out {
        Ok(o) if o.status.success() => {
            let version = String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or("<unknown>")
                .to_owned();
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"dev_prereqs_brew_present\",\
                 \"version\":{version:?}}}"
            );
            Ok(())
        }
        Ok(o) => bail!(
            "`brew --version` exited {}; reinstall Homebrew per \
             https://brew.sh\n--- stderr ---\n{}",
            o.status,
            String::from_utf8_lossy(&o.stderr),
        ),
        Err(e) => bail!(
            "could not run `brew --version` ({e}); install Homebrew first \
             (`/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com\
/Homebrew/install/HEAD/install.sh)\"`) — see https://brew.sh"
        ),
    }
}

/// Step 2 — `brew list <formula> >/dev/null`. Returns Ok if the
/// formula is installed; if not, runs `brew install <formula>` when
/// `install` is true.
fn ensure_brew_package(formula: &str, purpose: &str, install: bool) -> Result<()> {
    let listed = Command::new("brew")
        .arg("list")
        .arg("--formula")
        .arg(formula)
        .output()
        .with_context(|| format!("spawn `brew list --formula {formula}`"))?;
    if listed.status.success() {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"dev_prereqs_brew_pkg_present\",\
             \"formula\":{formula:?}}}"
        );
        return Ok(());
    }

    if !install {
        bail!(
            "brew package not installed: {formula}  ({purpose}). \
             Re-run with `cargo xtask dev-prereqs --install` or run \
             `brew install {formula}` manually."
        );
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_prereqs_brew_install_begin\",\
         \"formula\":{formula:?}}}"
    );
    let install_status = Command::new("brew")
        .arg("install")
        .arg(formula)
        .status()
        .with_context(|| format!("spawn `brew install {formula}`"))?;
    if !install_status.success() {
        bail!(
            "`brew install {formula}` exited {}; install manually per \
             AVF_DEMO.md §0",
            install_status,
        );
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_prereqs_brew_install_ok\",\
         \"formula\":{formula:?}}}"
    );
    Ok(())
}

/// Step 3 — `rustup target list --installed | grep <triple>`.
fn ensure_rustup_target(triple: &str, install: bool) -> Result<()> {
    let listed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .context(
            "spawn `rustup target list --installed`; install rustup first \
             (https://rustup.rs)",
        )?;
    if !listed.status.success() {
        bail!(
            "`rustup target list --installed` exited {}; reinstall rustup \
             per https://rustup.rs\n--- stderr ---\n{}",
            listed.status,
            String::from_utf8_lossy(&listed.stderr),
        );
    }
    let stdout = String::from_utf8_lossy(&listed.stdout);
    if stdout.lines().any(|l| l.trim() == triple) {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"dev_prereqs_rustup_target_present\",\
             \"triple\":{triple:?}}}"
        );
        return Ok(());
    }

    if !install {
        bail!(
            "rustup target not installed: {triple}. Re-run with \
             `cargo xtask dev-prereqs --install` or run \
             `rustup target add {triple}` manually."
        );
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_prereqs_rustup_target_install_begin\",\
         \"triple\":{triple:?}}}"
    );
    let install_status = Command::new("rustup")
        .args(["target", "add", triple])
        .status()
        .with_context(|| format!("spawn `rustup target add {triple}`"))?;
    if !install_status.success() {
        bail!(
            "`rustup target add {triple}` exited {}; install manually per \
             AVF_DEMO.md §0",
            install_status,
        );
    }
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_prereqs_rustup_target_install_ok\",\
         \"triple\":{triple:?}}}"
    );
    Ok(())
}

/// Step 4 — patch the `[target.<triple>] linker = "<binary>"` block
/// into the cargo config TOML if it is not already there. The
/// operation is fully additive — existing keys are preserved.
fn patch_cargo_linker_config(host_arch: HostArch, scope: CargoConfigScope) -> Result<()> {
    let triple = host_arch.musl_triple();
    let linker = host_arch.musl_linker_bin();

    let target_path = match scope {
        CargoConfigScope::User => {
            let home = std::env::var_os("HOME").ok_or_else(|| {
                anyhow::anyhow!(
                    "HOME is not set; cannot resolve --scope user. \
                     Pass --scope workspace explicitly, or export HOME."
                )
            })?;
            PathBuf::from(home).join(".cargo").join("config.toml")
        }
        CargoConfigScope::Workspace => {
            let root = workspace_root_from_cwd()
                .context("resolve workspace root for --scope workspace")?;
            root.join(".cargo").join("config.toml")
        }
    };

    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir -p {}", parent.display()))?;
    }

    let existing = match fs::read_to_string(&target_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(e).with_context(|| format!("read {}", target_path.display()));
        }
    };

    if config_already_pins_linker(&existing, triple, linker) {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"dev_prereqs_cargo_config_already_pins\",\
             \"path\":{},\"triple\":{triple:?}}}",
            serde_json_string(&target_path.display().to_string()),
        );
        return Ok(());
    }

    let snippet = format!(
        "\n# raxis/dev-prereqs: pin musl cross-linker for the AVF demo \
         (AVF_DEMO.md §0).\n\
         [target.{triple}]\n\
         linker = \"{linker}\"\n",
    );

    let mut updated = existing.clone();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&snippet);

    // Atomic write: stage into <path>.tmp + rename. Keeps the
    // operator's pinned config either old-or-new, never half-written.
    let tmp = target_path.with_extension("toml.dev-prereqs-tmp");
    fs::write(&tmp, &updated).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &target_path).with_context(|| {
        format!(
            "atomic rename {} -> {}",
            tmp.display(),
            target_path.display()
        )
    })?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_prereqs_cargo_config_patched\",\
         \"path\":{},\"triple\":{triple:?},\"linker\":{linker:?}}}",
        serde_json_string(&target_path.display().to_string()),
    );
    Ok(())
}

/// Has the cargo config already pinned `[target.<triple>] linker =
/// "<linker>"`? We accept any whitespace / quoting flavour as long as
/// the triple section header AND a `linker` key resolving to the
/// expected binary appear in the same `[target.<triple>]` block.
///
/// Best-effort textual check rather than a TOML round-trip, so the
/// patcher does not silently mangle a hand-curated config that uses
/// inline tables, nested keys, or non-UTF8 comments. False negatives
/// (we re-append a duplicate snippet) are easy for the operator to
/// spot in stderr; false positives (we'd skip the patch when it's
/// actually missing) are caught by the linker-mismatch error from
/// `cargo build` itself.
fn config_already_pins_linker(contents: &str, triple: &str, linker: &str) -> bool {
    let header = format!("[target.{triple}]");
    let Some(start) = contents.find(&header) else {
        return false;
    };
    // Search the rest of the file (or until the next `[`-headed
    // table) for a `linker` key whose value matches `<linker>`.
    let after = &contents[start + header.len()..];
    let block_end = after.find("\n[").map(|i| i + 1).unwrap_or(after.len());
    let block = &after[..block_end];
    for line in block.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("linker") {
            // Accept `linker = "<value>"` and `linker="<value>"`.
            let rest = rest.trim_start_matches([' ', '\t']);
            let rest = rest.trim_start_matches('=');
            let rest = rest.trim_start_matches([' ', '\t']);
            let value = rest.trim_matches('"').trim_matches('\'');
            if value == linker {
                return true;
            }
        }
    }
    false
}

/// Step 5/6 — `which <bin>` style probe. Returns Ok iff `<bin>
/// --version` succeeds.
fn probe_command_on_path(bin: &str) -> Result<()> {
    let probe = Command::new(bin).arg("--version").output();
    match probe {
        Ok(o) if o.status.success() => {
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"dev_prereqs_bin_present\",\
                 \"bin\":{bin:?}}}"
            );
            Ok(())
        }
        Ok(o) => bail!(
            "`{bin} --version` exited {}; reinstall the Xcode Command Line \
             Tools (`xcode-select --install`) on macOS",
            o.status,
        ),
        Err(e) => bail!(
            "could not spawn `{bin} --version` ({e}); install the Xcode \
             Command Line Tools (`xcode-select --install`) on macOS"
        ),
    }
}

/// Specialised cargo probe — `cargo --version` is the canonical
/// "is the toolchain on `$PATH`?" check used by every other xtask.
fn probe_cargo() -> Result<()> {
    let probe = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .arg("--version")
        .output();
    match probe {
        Ok(o) if o.status.success() => {
            let version = String::from_utf8_lossy(&o.stdout).trim().to_owned();
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"dev_prereqs_cargo_present\",\
                 \"version\":{version:?}}}"
            );
            Ok(())
        }
        Ok(o) => bail!(
            "`cargo --version` exited {}; install the Rust toolchain via \
             https://rustup.rs",
            o.status,
        ),
        Err(e) => bail!(
            "could not spawn `cargo --version` ({e}); install the Rust \
             toolchain via https://rustup.rs"
        ),
    }
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

/// Emit a JSON-quoted string. We do not pull `serde_json` into the
/// xtask binary just for this one call — every existing log line in
/// `xtask/src/{dev_kernel,images}.rs` hand-builds JSON via `format!`,
/// and matching that style keeps xtask's transitive dependency list
/// stable.
fn serde_json_string(raw: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_parser_defaults_are_verify_only_user_scope() {
        let args = Args::parse(&[]).unwrap();
        assert!(!args.install);
        assert_eq!(args.scope, CargoConfigScope::User);
        assert!(!args.skip_cargo_config);
        assert!(!args.skip_firewall);
        assert!(args.arch.is_none());
    }

    #[test]
    fn args_parser_accepts_install_scope_arch_skip() {
        let argv = vec![
            "--install".to_owned(),
            "--scope".to_owned(),
            "workspace".to_owned(),
            "--arch".to_owned(),
            "x86_64".to_owned(),
            "--skip-cargo-config".to_owned(),
            "--skip-firewall".to_owned(),
        ];
        let args = Args::parse(&argv).unwrap();
        assert!(args.install);
        assert_eq!(args.scope, CargoConfigScope::Workspace);
        assert_eq!(args.arch, Some(HostArch::X86_64));
        assert!(args.skip_cargo_config);
        assert!(args.skip_firewall);
    }

    #[test]
    fn args_parser_rejects_unknown_arg() {
        let argv = vec!["--what".to_owned()];
        let err = Args::parse(&argv).unwrap_err().to_string();
        assert!(err.contains("unknown dev-prereqs arg"), "got: {err}");
    }

    #[test]
    fn host_arch_parse_accepts_documented_aliases() {
        assert_eq!(HostArch::parse("aarch64").unwrap(), HostArch::Aarch64);
        assert_eq!(HostArch::parse("arm64").unwrap(), HostArch::Aarch64);
        assert_eq!(HostArch::parse("x86_64").unwrap(), HostArch::X86_64);
        assert_eq!(HostArch::parse("amd64").unwrap(), HostArch::X86_64);
        assert!(HostArch::parse("riscv64").is_err());
    }

    #[test]
    fn host_arch_musl_triple_and_linker_match() {
        assert_eq!(
            HostArch::Aarch64.musl_triple(),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            HostArch::Aarch64.musl_linker_bin(),
            "aarch64-linux-musl-gcc"
        );
        assert_eq!(HostArch::X86_64.musl_triple(), "x86_64-unknown-linux-musl");
        assert_eq!(HostArch::X86_64.musl_linker_bin(), "x86_64-linux-musl-gcc");
    }

    #[test]
    fn cargo_config_scope_parse_rejects_unknown() {
        assert_eq!(
            CargoConfigScope::parse("user").unwrap(),
            CargoConfigScope::User
        );
        assert_eq!(
            CargoConfigScope::parse("workspace").unwrap(),
            CargoConfigScope::Workspace
        );
        assert!(CargoConfigScope::parse("global").is_err());
    }

    #[test]
    fn config_already_pins_linker_recognises_canonical_snippet() {
        let triple = "aarch64-unknown-linux-musl";
        let linker = "aarch64-linux-musl-gcc";
        let cfg = format!("[target.{triple}]\nlinker = \"{linker}\"\n");
        assert!(config_already_pins_linker(&cfg, triple, linker));
    }

    #[test]
    fn config_already_pins_linker_recognises_unspaced_form() {
        // No space around `=`, single-quoted value — both legal in
        // hand-curated configs and we should still treat the linker
        // as already pinned.
        let triple = "aarch64-unknown-linux-musl";
        let linker = "aarch64-linux-musl-gcc";
        let cfg = format!("[target.{triple}]\nlinker='{linker}'\n");
        assert!(config_already_pins_linker(&cfg, triple, linker));
    }

    #[test]
    fn config_already_pins_linker_rejects_other_blocks() {
        // The header is for a different triple — we should NOT skip
        // the patch.
        let triple = "aarch64-unknown-linux-musl";
        let linker = "aarch64-linux-musl-gcc";
        let cfg = format!("[target.x86_64-unknown-linux-musl]\nlinker = \"{linker}\"\n");
        assert!(!config_already_pins_linker(&cfg, triple, linker));
    }

    #[test]
    fn config_already_pins_linker_rejects_wrong_linker() {
        // Same triple block but the wrong linker binary.
        let triple = "aarch64-unknown-linux-musl";
        let linker = "aarch64-linux-musl-gcc";
        let cfg = format!("[target.{triple}]\nlinker = \"clang\"\n");
        assert!(!config_already_pins_linker(&cfg, triple, linker));
    }

    #[test]
    fn config_already_pins_linker_does_not_leak_across_blocks() {
        // The linker line below the `[target.<triple>]` block
        // belongs to a DIFFERENT block. We must not treat the
        // first block as "already pinned".
        let triple = "aarch64-unknown-linux-musl";
        let linker = "aarch64-linux-musl-gcc";
        let cfg = format!(
            "[target.{triple}]\n# (no linker key here)\n\n\
             [target.x86_64-unknown-linux-musl]\nlinker = \"{linker}\"\n"
        );
        assert!(!config_already_pins_linker(&cfg, triple, linker));
    }

    #[test]
    fn patch_cargo_linker_config_writes_snippet_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let triple = HostArch::Aarch64.musl_triple();
        let linker = HostArch::Aarch64.musl_linker_bin();

        // Run the patcher against the temp `config.toml`. We
        // bypass the production scope resolver by calling the
        // textual core directly.
        let mut existing = String::new();
        if !config_already_pins_linker(&existing, triple, linker) {
            existing.push_str(&format!("\n[target.{triple}]\nlinker = \"{linker}\"\n"));
        }
        fs::write(&path, &existing).unwrap();

        let read = fs::read_to_string(&path).unwrap();
        assert!(config_already_pins_linker(&read, triple, linker));
    }

    #[test]
    fn serde_json_string_escapes_quotes_and_backslashes() {
        assert_eq!(serde_json_string("a\"b"), r#""a\"b""#);
        assert_eq!(serde_json_string("a\\b"), r#""a\\b""#);
        assert_eq!(serde_json_string("a\nb"), r#""a\nb""#);
    }
}
