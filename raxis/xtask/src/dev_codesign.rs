//! `cargo xtask dev-codesign` — ad-hoc codesign for local AVF demos.
//!
//! Normative reference: `raxis/specs/v2/system-requirements.md §5.2`
//! ("Apple Virtualization.framework entitlements") and
//! `raxis/release/raxis.entitlements` (the canonical entitlements
//! plist).
//!
//! ## What this command does
//!
//! Runs the `codesign(1)` invocation that satisfies macOS's
//! `Virtualization.framework` entitlement check on a local-build
//! `target/{profile}/raxis-kernel` binary, so a developer can boot a
//! real AVF microVM without first publishing a Developer ID-signed
//! release. The exact incantation is:
//!
//! ```text
//! codesign --sign -                       \
//!          --entitlements release/raxis.entitlements \
//!          --options runtime              \
//!          --force                        \
//!          target/<profile>/raxis-kernel
//! ```
//!
//! ## Why ad-hoc (`--sign -`) is sufficient on macOS
//!
//! On macOS 13+ the Virtualization.framework accepts ad-hoc signed
//! binaries that carry the `com.apple.security.virtualization`
//! entitlement, *provided* the binary is launched directly by the
//! signing user. Distribution still requires a Developer ID and
//! notarization (per `release-and-distribution.md §3`); this command
//! is exclusively for the local demo / live-E2E workflow, where the
//! same shell session that built the binary also runs it.
//!
//! ## Why this lives in `xtask`, not a shell script
//!
//! Keeping the recipe in Rust means one canonical source of truth for
//! the entitlement path + flag set. Shell snippets in
//! `system-requirements.md` go stale; `cargo xtask dev-codesign`
//! does not.
//!
//! ## Exit-code contract
//!
//! * `0`   — codesign succeeded (or the host is non-macOS, in which
//!   case we no-op + log).
//! * `non-zero` — `codesign` exited non-zero, the binary was not on
//!   disk, or the entitlements file was not at
//!   `release/raxis.entitlements` relative to the workspace root.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Default profile when `--profile` is not passed.
const DEFAULT_PROFILE: &str = "release";

/// Default entitlements path, relative to the workspace root.
const DEFAULT_ENTITLEMENTS: &str = "release/raxis.entitlements";

/// Default binary name. Operators can override per
/// `cargo xtask dev-codesign --binary <name>` if a future fork
/// renames the kernel binary.
const DEFAULT_BINARY: &str = "raxis-kernel";

/// Parsed arguments for `cargo xtask dev-codesign`.
#[derive(Debug)]
struct Args {
    /// Cargo profile dir under `target/`. Defaults to `release`.
    profile:      String,
    /// Optional entitlements override. Defaults to
    /// `release/raxis.entitlements`.
    entitlements: PathBuf,
    /// Binary basename. Defaults to `raxis-kernel`.
    binary:       String,
}

impl Args {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut profile      = DEFAULT_PROFILE.to_owned();
        let mut entitlements = PathBuf::from(DEFAULT_ENTITLEMENTS);
        let mut binary       = DEFAULT_BINARY.to_owned();

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--profile" => {
                    i += 1;
                    let v = argv.get(i).context("--profile requires a value")?;
                    profile = v.clone();
                }
                "--entitlements" => {
                    i += 1;
                    let v = argv.get(i).context("--entitlements requires a path")?;
                    entitlements = PathBuf::from(v);
                }
                "--binary" => {
                    i += 1;
                    let v = argv.get(i).context("--binary requires a name")?;
                    binary = v.clone();
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown dev-codesign arg: {other}"),
            }
            i += 1;
        }

        Ok(Self { profile, entitlements, binary })
    }
}

fn print_help() {
    eprintln!(
        "usage: cargo xtask dev-codesign [--profile <PROFILE>] \
         [--entitlements <PATH>] [--binary <NAME>]\n\
         \n\
         Ad-hoc codesigns target/<PROFILE>/<BINARY> against \
         <PATH> so AVF accepts the binary on the local host. \
         No-op on non-macOS hosts.\n\
         \n\
         Defaults:\n  \
         --profile      release\n  \
         --entitlements release/raxis.entitlements\n  \
         --binary       raxis-kernel\n"
    );
}

/// Entry point invoked by `xtask/src/main.rs`.
pub fn run(argv: &[String]) -> Result<()> {
    let args = Args::parse(argv)?;

    if !cfg!(target_os = "macos") {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"dev_codesign_noop\",\
             \"reason\":\"non-macOS host; codesign is macOS-only\",\
             \"target_os\":\"{}\"}}",
            std::env::consts::OS,
        );
        return Ok(());
    }

    // Resolve the workspace root by walking up from CWD until we find
    // a `Cargo.toml` with `[workspace]`. xtask is always invoked from
    // the workspace root via `cargo xtask` (the `.cargo/config.toml`
    // alias), so CWD == workspace root in practice — but we double-
    // check rather than trust the invariant.
    let workspace_root = workspace_root_from_cwd()?;

    let entitlements_abs = if args.entitlements.is_absolute() {
        args.entitlements.clone()
    } else {
        workspace_root.join(&args.entitlements)
    };
    if !entitlements_abs.exists() {
        bail!(
            "entitlements file not found: {} (cwd={}; pass --entitlements <PATH> to \
             override or run from the workspace root)",
            entitlements_abs.display(),
            workspace_root.display(),
        );
    }

    let binary_abs = workspace_root
        .join("target")
        .join(&args.profile)
        .join(&args.binary);
    if !binary_abs.exists() {
        bail!(
            "binary not found: {} (build it first: `cargo build -p raxis-kernel \
             --profile {}`)",
            binary_abs.display(),
            args.profile,
        );
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_codesign_invoke\",\
         \"binary\":\"{}\",\"entitlements\":\"{}\",\"profile\":\"{}\"}}",
        binary_abs.display(),
        entitlements_abs.display(),
        args.profile,
    );

    let status = Command::new("codesign")
        .arg("--sign")
        .arg("-")
        .arg("--entitlements")
        .arg(&entitlements_abs)
        .arg("--options")
        .arg("runtime")
        .arg("--force")
        .arg(&binary_abs)
        .status()
        .context("failed to spawn `codesign`; is the Xcode command-line tools install present?")?;

    if !status.success() {
        bail!(
            "codesign failed with exit status {} on {}",
            status,
            binary_abs.display(),
        );
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_codesign_ok\",\
         \"binary\":\"{}\"}}",
        binary_abs.display(),
    );

    // Best-effort verification — `codesign --verify --verbose` tells
    // the operator the entitlements were applied as expected. We do
    // not bail on a verify failure because some CI environments don't
    // ship `codesign --verify` (they're rare, but the post-sign
    // verification is informational rather than a contract).
    let _ = Command::new("codesign")
        .arg("--verify")
        .arg("--verbose=2")
        .arg(&binary_abs)
        .status();

    Ok(())
}

/// Walk up from CWD until we find a `Cargo.toml` containing
/// `[workspace]`. Returns the directory containing that file.
fn workspace_root_from_cwd() -> Result<PathBuf> {
    let mut cwd: PathBuf = std::env::current_dir()
        .context("cannot read CWD")?;
    loop {
        let candidate = cwd.join("Cargo.toml");
        if candidate.exists() {
            let s = std::fs::read_to_string(&candidate).with_context(|| {
                format!("read {}", candidate.display())
            })?;
            // Cheap heuristic: a workspace root's manifest has a
            // `[workspace]` section. `cargo metadata` would be more
            // robust but pulls in `cargo` as a build dep we'd
            // rather avoid.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_parser_uses_documented_defaults_when_no_flags_passed() {
        let args = Args::parse(&[]).unwrap();
        assert_eq!(args.profile, "release");
        assert_eq!(args.entitlements, PathBuf::from("release/raxis.entitlements"));
        assert_eq!(args.binary, "raxis-kernel");
    }

    #[test]
    fn args_parser_round_trips_explicit_overrides() {
        let argv = vec![
            "--profile".to_owned(),      "debug".to_owned(),
            "--entitlements".to_owned(), "/etc/raxis.ents".to_owned(),
            "--binary".to_owned(),       "raxis-kernel-fork".to_owned(),
        ];
        let args = Args::parse(&argv).unwrap();
        assert_eq!(args.profile,      "debug");
        assert_eq!(args.entitlements, PathBuf::from("/etc/raxis.ents"));
        assert_eq!(args.binary,       "raxis-kernel-fork");
    }

    #[test]
    fn args_parser_rejects_unknown_flag() {
        let argv = vec!["--nope".to_owned()];
        let err  = Args::parse(&argv).unwrap_err().to_string();
        assert!(err.contains("unknown dev-codesign arg"), "got: {err}");
    }

    #[test]
    fn args_parser_requires_value_for_each_flag() {
        for flag in ["--profile", "--entitlements", "--binary"] {
            let argv = vec![flag.to_owned()];
            let err  = Args::parse(&argv).unwrap_err().to_string();
            assert!(
                err.contains("requires"),
                "flag {flag} should bail when value is missing; got: {err}",
            );
        }
    }
}
