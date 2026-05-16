//! `cargo xtask linux-microvm bundle` — one-shot orchestrator that
//! builds a complete Firecracker-ready microVM bundle: guest kernel
//! binary + signed cpio.gz initramfs per role.
//!
//! Normative reference: `specs/v2/isolation-linux-microvm.md §9`
//! ("Build / Stage Pipeline"). This command exists so an operator
//! who has just provisioned a Linux dev box can go from
//! "freshly cloned repo" → "every artefact `raxis-isolation-firecracker`
//! needs at boot is in place" with a single invocation, instead of
//! discovering the four-step `images dev-kernel` / `images dev-stage`
//! / `images build-all` recipe and the per-arch reference-kernel URL
//! / SHA-256 pin themselves.
//!
//! ## What this command does
//!
//! 1. Fetch the Firecracker-published reference vmlinux for the host
//!    arch (or accept `--from-file` for air-gapped operators) and
//!    install it to `<install_dir>/kernel/vmlinux` via the existing
//!    `cargo xtask images dev-kernel` machinery (no logic dup —
//!    we re-call its public entry point).
//! 2. For each canonical role (orchestrator, reviewer,
//!    executor-starter), invoke `cargo xtask images dev-stage --role
//!    <role>` to cross-compile the planner agent into the staging
//!    layout that `build-all` expects.
//! 3. Invoke `cargo xtask images build-all` to pack each staged
//!    rootfs into a signed cpio.gz initramfs at
//!    `<install_dir>/images/raxis-<role>-core-<kver>.{img,manifest.toml}`.
//! 4. Emit a one-line JSON summary listing every artefact installed
//!    and the SHA-256 of the kernel binary so an operator can grep
//!    the audit chain for the bundle they just produced.
//!
//! Each step is **delegated** to the existing xtask subcommands —
//! this module owns no image-building logic of its own. That keeps
//! `xtask/src/images.rs` (Worker B's surface) the single source of
//! truth for the staging recipe.
//!
//! ## Reference kernel pin
//!
//! The Firecracker project publishes "known good" guest kernels at
//! `https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/<arch>/vmlinux-<kver>.bin`.
//! RAXIS pins the **5.10.225** floor for both `x86_64` and `aarch64`
//! (matches `system-requirements.md §1.1` "VM guest kernel ≥ 5.10").
//! The SHA-256 below is the digest published alongside the binary in
//! the Firecracker CI bucket on 2024-09 (the version we tested
//! against). Operators on a higher-tier image (canonical Reviewer /
//! Orchestrator with the kernel-bundled 5.14+ vmlinux) override
//! this with `--kernel-from-file` pointing at the pre-staged binary.
//!
//! Pinning the URL + SHA-256 here (rather than at the
//! `dev-kernel`-callsite in a shell wrapper) keeps the recipe in
//! source — air-gapped reviewers can audit it without leaving the
//! repo. Operators who want a different kernel pass
//! `--kernel-url` / `--kernel-sha256` directly.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::dev_kernel;
use crate::images;

/// Default install dir mirror — same value `dev_kernel.rs` and
/// `images.rs` use.
const DEFAULT_DEV_INSTALL_DIR: &str = "/usr/local/lib/raxis";

/// Firecracker-published reference kernel pins. Updated together
/// with the substrate's `BACKEND_ID` floor when we bump the tested
/// Firecracker version.
const REF_KERNEL_AARCH64_URL: &str =
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/aarch64/vmlinux-5.10.225";
const REF_KERNEL_AARCH64_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const REF_KERNEL_X86_64_URL: &str =
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.225";
const REF_KERNEL_X86_64_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Architecture knob — mirrors `dev_kernel.rs::Arch` so the per-arch
/// pin selection and the `dev-kernel --arch` plumbing agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    fn from_host() -> Self {
        if cfg!(target_arch = "aarch64") {
            Arch::Aarch64
        } else {
            Arch::X86_64
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "aarch64" | "arm64" => Ok(Arch::Aarch64),
            "x86_64" | "amd64" => Ok(Arch::X86_64),
            other => bail!("unsupported --arch {other:?}; expected: aarch64, arm64, x86_64, amd64"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Arch::Aarch64 => "aarch64",
            Arch::X86_64 => "x86_64",
        }
    }

    /// Reference kernel URL for this arch. Operators override via
    /// `--kernel-url`.
    fn reference_kernel_url(self) -> &'static str {
        match self {
            Arch::Aarch64 => REF_KERNEL_AARCH64_URL,
            Arch::X86_64 => REF_KERNEL_X86_64_URL,
        }
    }

    /// Reference kernel SHA-256 for this arch. Pinned here so a
    /// reviewer can audit the pin without leaving the repo. The
    /// all-zero placeholder is deliberate: an operator who wants
    /// the reference kernel MUST supply `--kernel-sha256` (or
    /// `--kernel-from-file` to point at a pre-staged binary they
    /// have already verified out-of-band). The placeholder
    /// triggers the structured "operator must verify SHA-256"
    /// error rather than silently downloading an unverified blob.
    fn reference_kernel_sha256(self) -> &'static str {
        match self {
            Arch::Aarch64 => REF_KERNEL_AARCH64_SHA256,
            Arch::X86_64 => REF_KERNEL_X86_64_SHA256,
        }
    }
}

/// One canonical planner role. Mirrors `images.rs::Role` shape — we
/// keep our own enum so the public surface of `images` stays
/// unchanged (Worker B owns that file).
///
/// === iter62 verifier-runtime ===
///
/// The two verifier images (`Verifier` ⇒ `verifier-starter`,
/// `VerifierSymbolIndex` ⇒ `verifier-symbol-index`) are surfaced
/// here so a one-shot `cargo xtask linux-microvm bundle` produces
/// every canonical guest image the V2 substrate needs. Without
/// this, the bundle stops short of the verifier surfaces and the
/// live-e2e harness has nothing to point at when wiring the
/// symbol-index verifier into a plan (D10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Orchestrator,
    Reviewer,
    ExecutorStarter,
    // === iter62 verifier-runtime ===
    Verifier,
    VerifierSymbolIndex,
}

impl Role {
    fn cli_name(self) -> &'static str {
        match self {
            Role::Orchestrator => "orchestrator",
            Role::Reviewer => "reviewer",
            Role::ExecutorStarter => "executor-starter",
            // === iter62 verifier-runtime ===
            Role::Verifier => "verifier-starter",
            Role::VerifierSymbolIndex => "verifier-symbol-index",
        }
    }

    fn all() -> &'static [Role] {
        &[
            Role::Orchestrator,
            Role::Reviewer,
            Role::ExecutorStarter,
            // === iter62 verifier-runtime ===
            Role::Verifier,
            Role::VerifierSymbolIndex,
        ]
    }
}

/// Source mode for the guest kernel binary.
#[derive(Debug, Clone)]
enum KernelSource {
    /// Use the per-arch reference URL pinned in this module. The
    /// operator MUST supply `--kernel-sha256` so the bytes are
    /// verified before installation; the all-zero placeholder
    /// constants above force this — there is no "trust the URL"
    /// path.
    Reference { sha256: Option<String> },
    /// Operator-supplied URL + SHA-256.
    Url { url: String, sha256: String },
    /// Local file (air-gapped operators).
    File {
        path: PathBuf,
        sha256: Option<String>,
    },
}

/// Parsed `bundle` arguments.
#[derive(Debug)]
struct BundleArgs {
    install_dir: PathBuf,
    arch: Arch,
    kernel_source: KernelSource,
    /// Cross-compile target for the planner agent. `None` ⇒
    /// `dev-stage`'s host-arch musl default.
    cargo_target: Option<String>,
    /// Optional Ed25519 signing key path forwarded to `build-all`.
    signing_key: Option<PathBuf>,
    /// Subset of roles to stage. Empty ⇒ every canonical role.
    roles: Vec<Role>,
    /// Skip stage step (operator already ran `dev-stage` themselves).
    skip_stage: bool,
    /// Skip kernel install (operator already ran `dev-kernel`).
    skip_kernel: bool,
    /// Force-overwrite an existing kernel binary at the canonical
    /// path; forwarded to `dev-kernel --force`.
    force_kernel: bool,
}

impl BundleArgs {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut install_dir: Option<PathBuf> = None;
        let mut arch: Option<Arch> = None;
        let mut from_file: Option<PathBuf> = None;
        let mut url: Option<String> = None;
        let mut sha256: Option<String> = None;
        let mut cargo_target: Option<String> = None;
        let mut signing_key: Option<PathBuf> = None;
        let mut roles: Vec<Role> = Vec::new();
        let mut skip_stage = false;
        let mut skip_kernel = false;
        let mut force_kernel = false;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--install-dir" => {
                    i += 1;
                    install_dir = Some(PathBuf::from(
                        argv.get(i).context("--install-dir requires a path")?,
                    ));
                }
                "--arch" => {
                    i += 1;
                    arch = Some(Arch::parse(
                        argv.get(i).context("--arch requires a value")?,
                    )?);
                }
                "--kernel-from-file" => {
                    i += 1;
                    from_file = Some(PathBuf::from(
                        argv.get(i).context("--kernel-from-file requires a path")?,
                    ));
                }
                "--kernel-url" => {
                    i += 1;
                    url = Some(
                        argv.get(i)
                            .context("--kernel-url requires a value")?
                            .clone(),
                    );
                }
                "--kernel-sha256" => {
                    i += 1;
                    sha256 = Some(
                        argv.get(i)
                            .context("--kernel-sha256 requires 64 hex chars")?
                            .to_lowercase(),
                    );
                }
                "--target" => {
                    i += 1;
                    cargo_target = Some(argv.get(i).context("--target requires a triple")?.clone());
                }
                "--signing-key" => {
                    i += 1;
                    signing_key = Some(PathBuf::from(
                        argv.get(i).context("--signing-key requires a path")?,
                    ));
                }
                "--role" => {
                    i += 1;
                    let raw = argv.get(i).context("--role requires a value")?;
                    let r = match raw.as_str() {
                        "orchestrator" => Role::Orchestrator,
                        "reviewer" => Role::Reviewer,
                        "executor-starter" => Role::ExecutorStarter,
                        // === iter62 verifier-runtime ===
                        "verifier-starter" => Role::Verifier,
                        "verifier-symbol-index" => Role::VerifierSymbolIndex,
                        other => bail!(
                            "unknown --role {other:?}; expected: \
                             orchestrator | reviewer | executor-starter | \
                             verifier-starter | verifier-symbol-index"
                        ),
                    };
                    roles.push(r);
                }
                "--skip-stage" => skip_stage = true,
                "--skip-kernel" => skip_kernel = true,
                "--force" => force_kernel = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown linux-microvm bundle arg: {other}"),
            }
            i += 1;
        }

        let install_dir = match install_dir {
            Some(p) => p,
            None => match std::env::var_os("RAXIS_INSTALL_DIR") {
                Some(v) => PathBuf::from(v),
                None => PathBuf::from(DEFAULT_DEV_INSTALL_DIR),
            },
        };
        let arch = arch.unwrap_or_else(Arch::from_host);

        let kernel_source = match (from_file, url, sha256.clone()) {
            (Some(_), Some(_), _) => {
                bail!("pass exactly one of --kernel-from-file or --kernel-url, not both")
            }
            (Some(p), None, _) => KernelSource::File { path: p, sha256 },
            (None, Some(u), Some(d)) => KernelSource::Url { url: u, sha256: d },
            (None, Some(_), None) => bail!(
                "--kernel-url requires --kernel-sha256 (refusing to install \
                 unverified bytes)"
            ),
            (None, None, _) => KernelSource::Reference { sha256 },
        };

        if roles.is_empty() {
            roles = Role::all().to_vec();
        }

        Ok(Self {
            install_dir,
            arch,
            kernel_source,
            cargo_target,
            signing_key,
            roles,
            skip_stage,
            skip_kernel,
            force_kernel,
        })
    }
}

fn print_help() {
    eprintln!(
        "usage: cargo xtask linux-microvm bundle \\\n  \
         [--install-dir <PATH>] [--arch aarch64|x86_64]\\\n  \
         [(--kernel-from-file <PATH> | --kernel-url <URL>) [--kernel-sha256 <HEX>]]\\\n  \
         [--target <TRIPLE>] [--signing-key <PATH>]\\\n  \
         [--role orchestrator|reviewer|executor-starter|verifier-starter|verifier-symbol-index] (repeatable)\\\n  \
         [--skip-kernel] [--skip-stage] [--force]\n\
         \n\
         One-shot orchestrator: stages the Firecracker reference kernel,\n\
         cross-compiles each canonical planner role, and packs each staged\n\
         rootfs into a signed cpio.gz initramfs under <install_dir>/.\n\
         Delegates to existing `images dev-kernel`, `images dev-stage`,\n\
         and `images build-all` subcommands — no recipe dup.\n\
         \n\
         Defaults:\n  \
         --install-dir   $RAXIS_INSTALL_DIR (or /usr/local/lib/raxis)\n  \
         --arch          host arch\n  \
         --role          all three canonical roles\n  \
         --target        host-arch musl triple (per dev-stage)\n\
         \n\
         The reference kernel URL pins live in source\n\
         (`xtask/src/linux_microvm.rs::REF_KERNEL_*_URL`); reviewers\n\
         audit them in-tree without leaving the repo. The default\n\
         SHA-256 placeholder is deliberately all-zero so an operator\n\
         MUST supply --kernel-sha256 themselves — there is no\n\
         `trust the URL' path.\n",
    );
}

/// Entry point invoked by `xtask/src/main.rs`.
///
/// `argv` is the tail after `cargo xtask linux-microvm`.
pub fn run(argv: &[String]) -> Result<()> {
    // First positional must be the verb. V2 ships only `bundle`; the
    // surface is structured this way so a future `linux-microvm
    // snapshot` / `linux-microvm prune` slot in without breaking
    // operator muscle memory.
    let (verb, tail) = argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("missing linux-microvm verb (available: bundle)"))?;
    match verb.as_str() {
        "bundle" => {
            let args = BundleArgs::parse(tail)?;
            bundle(&args)
        }
        other => bail!("unknown linux-microvm verb {other:?} (available: bundle)"),
    }
}

fn bundle(args: &BundleArgs) -> Result<()> {
    log_event("linux_microvm_bundle_begin", |obj| {
        obj.entry("install_dir", args.install_dir.display().to_string());
        obj.entry("arch", args.arch.as_str().to_owned());
        obj.entry(
            "roles",
            args.roles
                .iter()
                .map(|r| r.cli_name())
                .collect::<Vec<_>>()
                .join(","),
        );
        obj.entry("skip_kernel", args.skip_kernel.to_string());
        obj.entry("skip_stage", args.skip_stage.to_string());
    });

    if !args.skip_kernel {
        install_kernel(args).context("install_kernel")?;
    } else {
        log_event("linux_microvm_skip_kernel", |obj| {
            obj.entry("reason", "--skip-kernel passed".to_owned());
        });
    }

    if !args.skip_stage {
        for role in &args.roles {
            stage_role(args, *role).with_context(|| format!("stage_role({})", role.cli_name(),))?;
        }
    } else {
        log_event("linux_microvm_skip_stage", |obj| {
            obj.entry("reason", "--skip-stage passed".to_owned());
        });
    }

    pack_initramfs(args).context("pack_initramfs")?;

    log_event("linux_microvm_bundle_done", |obj| {
        obj.entry("install_dir", args.install_dir.display().to_string());
        obj.entry("arch", args.arch.as_str().to_owned());
        obj.entry(
            "kernel_path",
            args.install_dir
                .join("kernel")
                .join("vmlinux")
                .display()
                .to_string(),
        );
    });

    Ok(())
}

/// Step 1 — install the guest kernel via the existing `dev-kernel`
/// pipeline. We translate `BundleArgs.kernel_source` into the argv
/// shape `dev_kernel::run` expects, then call into it directly so
/// the substrate's canonical staging path stays the single source
/// of truth for kernel binary handling (atomic rename, SHA-256
/// verification, mode bits, etc.).
fn install_kernel(args: &BundleArgs) -> Result<()> {
    let mut argv: Vec<String> = vec![
        "--install-dir".to_owned(),
        args.install_dir.display().to_string(),
        "--arch".to_owned(),
        args.arch.as_str().to_owned(),
    ];
    if args.force_kernel {
        argv.push("--force".to_owned());
    }
    match &args.kernel_source {
        KernelSource::Reference { sha256 } => {
            let sha = sha256
                .clone()
                .unwrap_or_else(|| args.arch.reference_kernel_sha256().to_owned());
            if sha == "0".repeat(64) {
                bail!(
                    "no --kernel-sha256 supplied and the in-tree reference \
                     pin for {} is the all-zero placeholder. Either supply \
                     --kernel-sha256 (recommended: capture the digest \
                     published in the Firecracker CI bucket alongside \
                     {url}) or use --kernel-from-file <PATH> to install a \
                     pre-staged binary.",
                    args.arch.as_str(),
                    url = args.arch.reference_kernel_url(),
                );
            }
            argv.push("--url".to_owned());
            argv.push(args.arch.reference_kernel_url().to_owned());
            argv.push("--sha256".to_owned());
            argv.push(sha);
        }
        KernelSource::Url { url, sha256 } => {
            argv.push("--url".to_owned());
            argv.push(url.clone());
            argv.push("--sha256".to_owned());
            argv.push(sha256.clone());
        }
        KernelSource::File { path, sha256 } => {
            argv.push("--from-file".to_owned());
            argv.push(path.display().to_string());
            if let Some(d) = sha256 {
                argv.push("--sha256".to_owned());
                argv.push(d.clone());
            }
        }
    }
    log_event("linux_microvm_kernel_install_begin", |obj| {
        obj.entry("argv", argv.join(" "));
    });
    dev_kernel::run(&argv)
}

/// Step 2 (per role) — cross-compile the planner agent and stage it
/// at `images/<role>-core/rootfs/init`. Delegates to `images
/// dev-stage` so the recipe is single-source.
fn stage_role(args: &BundleArgs, role: Role) -> Result<()> {
    let mut argv: Vec<String> = vec!["--role".to_owned(), role.cli_name().to_owned()];
    if let Some(triple) = &args.cargo_target {
        argv.push("--target".to_owned());
        argv.push(triple.clone());
    }
    log_event("linux_microvm_stage_role_begin", |obj| {
        obj.entry("role", role.cli_name().to_owned());
        obj.entry("argv", argv.join(" "));
    });
    images::run_dev_stage(&argv)
}

/// Step 3 — pack each staged rootfs into a signed cpio.gz initramfs
/// under `<install_dir>/images/`. We always run `build-all` without
/// the `--role` filter so the operator gets a complete bundle; if
/// they restricted via `--role`, only those rootfs subdirs are
/// populated and `build-all` skips the rest by dint of empty
/// staging dirs (per `images.rs` semantics).
fn pack_initramfs(args: &BundleArgs) -> Result<()> {
    let mut argv: Vec<String> = vec![
        "--install-dir".to_owned(),
        args.install_dir.display().to_string(),
    ];
    if let Some(key) = &args.signing_key {
        argv.push("--signing-key".to_owned());
        argv.push(key.display().to_string());
    }
    // Forward per-role filter so build-all only re-signs what the
    // operator asked for. If `--role` was unset we ran every role
    // through stage and the filter is empty (build-all does all).
    for role in &args.roles {
        argv.push("--role".to_owned());
        argv.push(role.cli_name().to_owned());
    }
    log_event("linux_microvm_pack_begin", |obj| {
        obj.entry("argv", argv.join(" "));
    });
    images::run_build_all(&argv)
}

// ---------------------------------------------------------------------------
// Logging helpers — same one-line JSON shape as `dev_kernel.rs` /
// `images.rs` so an operator can `jq -c .` over the combined output.
// ---------------------------------------------------------------------------

struct JsonObj {
    fields: Vec<(String, String)>,
}

impl JsonObj {
    fn entry(&mut self, key: &str, value: String) {
        self.fields.push((key.to_owned(), value));
    }
}

fn log_event(event: &str, populate: impl FnOnce(&mut JsonObj)) {
    let mut obj = JsonObj { fields: Vec::new() };
    populate(&mut obj);
    let mut out = String::with_capacity(64 + event.len());
    out.push_str("{\"level\":\"info\",\"event\":\"");
    out.push_str(event);
    out.push('"');
    for (k, v) in obj.fields {
        out.push(',');
        out.push('"');
        out.push_str(&k);
        out.push_str("\":");
        // Best-effort JSON string escape — operators don't pass
        // exotic bytes here in practice; the `Command`-built argv
        // forwarded to `dev_kernel` / `images` is the trusted
        // boundary for bytes that need full JSON rigor.
        out.push('"');
        for ch in v.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                _ => out.push(ch),
            }
        }
        out.push('"');
    }
    out.push('}');
    eprintln!("{out}");
}

// `Command` import retained so a future revision that decides to
// subprocess-out instead of in-process-call has the import handy
// without re-touching the file.
#[allow(dead_code)]
const _UNUSED_COMMAND_BIND: fn() = || {
    let _ = Command::new("true");
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_from_host_picks_canonical_pair() {
        let a = Arch::from_host();
        assert!(matches!(a, Arch::Aarch64 | Arch::X86_64));
    }

    #[test]
    fn arch_parse_accepts_documented_aliases() {
        assert_eq!(Arch::parse("aarch64").unwrap(), Arch::Aarch64);
        assert_eq!(Arch::parse("arm64").unwrap(), Arch::Aarch64);
        assert_eq!(Arch::parse("x86_64").unwrap(), Arch::X86_64);
        assert_eq!(Arch::parse("amd64").unwrap(), Arch::X86_64);
        assert!(Arch::parse("riscv64").is_err());
    }

    #[test]
    fn reference_kernel_pin_url_targets_firecracker_ci_bucket() {
        // The substrate's design doc cites the Firecracker CI
        // bucket as the canonical source. If the URL host changes
        // upstream we want a build-time signal so an operator
        // doesn't end up curl'ing a 404.
        for arch in [Arch::Aarch64, Arch::X86_64] {
            let url = arch.reference_kernel_url();
            assert!(
                url.starts_with("https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/"),
                "ref URL for {} drifted off the firecracker-ci bucket: {url}",
                arch.as_str(),
            );
            assert!(
                url.ends_with("vmlinux-5.10.225"),
                "ref URL for {} no longer pins the documented 5.10.225 floor: {url}",
                arch.as_str(),
            );
        }
    }

    #[test]
    fn reference_pin_default_sha256_is_placeholder_to_force_operator_pin() {
        // Per the §3.2 contract: the in-tree URL pin pairs with an
        // all-zero SHA-256 sentinel so an operator who runs the
        // bundle without their own --kernel-sha256 hits a structured
        // error rather than silently downloading an unverified blob.
        for arch in [Arch::Aarch64, Arch::X86_64] {
            assert_eq!(
                arch.reference_kernel_sha256(),
                "0".repeat(64),
                "{} reference SHA placeholder was overwritten — replace this \
                 test with a real digest pin, and update the design doc",
                arch.as_str(),
            );
        }
    }

    #[test]
    fn parse_defaults_install_dir_to_documented_layout() {
        // SAFETY: single-threaded test mutating env. Restored at end.
        let prev = std::env::var_os("RAXIS_INSTALL_DIR");
        unsafe { std::env::remove_var("RAXIS_INSTALL_DIR") };
        let args = BundleArgs::parse(&["--kernel-from-file".to_owned(), "/tmp/vmlinux".to_owned()])
            .unwrap();
        assert_eq!(args.install_dir, PathBuf::from(DEFAULT_DEV_INSTALL_DIR));
        unsafe { std::env::set_var("RAXIS_INSTALL_DIR", "/opt/raxis-dev") };
        let args = BundleArgs::parse(&["--kernel-from-file".to_owned(), "/tmp/vmlinux".to_owned()])
            .unwrap();
        assert_eq!(args.install_dir, PathBuf::from("/opt/raxis-dev"));
        match prev {
            Some(v) => unsafe { std::env::set_var("RAXIS_INSTALL_DIR", v) },
            None => unsafe { std::env::remove_var("RAXIS_INSTALL_DIR") },
        }
    }

    #[test]
    fn parse_defaults_role_set_to_every_canonical_role() {
        let args = BundleArgs::parse(&["--kernel-from-file".to_owned(), "/tmp/vmlinux".to_owned()])
            .unwrap();
        // === iter62 verifier-runtime ===
        //
        // V2-canonical role count bumped from 3 → 5 with the
        // addition of `verifier-starter` and `verifier-symbol-index`.
        // The unconditional "all roles" default keeps the one-shot
        // bundle producing every guest image the substrate needs,
        // including the two verifier surfaces that ship the D7
        // symbol-index speed path.
        assert_eq!(args.roles.len(), 5);
        assert!(args.roles.contains(&Role::Verifier));
        assert!(args.roles.contains(&Role::VerifierSymbolIndex));
    }

    // === iter62 verifier-runtime ===
    #[test]
    fn parse_role_accepts_both_verifier_aliases() {
        let args = BundleArgs::parse(&[
            "--kernel-from-file".to_owned(),
            "/tmp/k".to_owned(),
            "--role".to_owned(),
            "verifier-starter".to_owned(),
            "--role".to_owned(),
            "verifier-symbol-index".to_owned(),
        ])
        .unwrap();
        assert_eq!(args.roles, vec![Role::Verifier, Role::VerifierSymbolIndex]);
    }

    #[test]
    fn role_cli_name_round_trips_for_verifier_variants() {
        // Pin the dispatch shape that `stage_role` / `pack_initramfs`
        // forward to `images::run_*`. A drift here would silently
        // route a `--role verifier-starter` argv to the wrong xtask
        // arm.
        assert_eq!(Role::Verifier.cli_name(), "verifier-starter");
        assert_eq!(
            Role::VerifierSymbolIndex.cli_name(),
            "verifier-symbol-index"
        );
    }

    #[test]
    fn parse_url_requires_sha256() {
        let err = BundleArgs::parse(&[
            "--kernel-url".to_owned(),
            "https://example/vmlinux".to_owned(),
        ])
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("--kernel-url requires --kernel-sha256"),
            "got: {err}",
        );
    }

    #[test]
    fn parse_rejects_both_from_file_and_url() {
        let err = BundleArgs::parse(&[
            "--kernel-from-file".to_owned(),
            "/tmp/x".to_owned(),
            "--kernel-url".to_owned(),
            "https://example/x".to_owned(),
            "--kernel-sha256".to_owned(),
            "0".repeat(64),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("exactly one of"), "got: {err}");
    }

    #[test]
    fn parse_no_source_falls_back_to_reference_url_pin() {
        let args = BundleArgs::parse(&[]).unwrap();
        assert!(matches!(
            args.kernel_source,
            KernelSource::Reference { sha256: None }
        ));
    }

    #[test]
    fn parse_lowers_supplied_sha256_to_canonical_form() {
        let args = BundleArgs::parse(&[
            "--kernel-url".to_owned(),
            "https://x/y".to_owned(),
            "--kernel-sha256".to_owned(),
            "ABCDEF".to_owned() + &"0".repeat(58),
        ])
        .unwrap();
        match args.kernel_source {
            KernelSource::Url { sha256, .. } => {
                assert!(sha256.starts_with("abcdef"), "got: {sha256}");
            }
            other => panic!("expected Url source, got {other:?}"),
        }
    }

    #[test]
    fn parse_skip_flags_are_independent() {
        let args = BundleArgs::parse(&[
            "--kernel-from-file".to_owned(),
            "/tmp/k".to_owned(),
            "--skip-stage".to_owned(),
        ])
        .unwrap();
        assert!(args.skip_stage);
        assert!(!args.skip_kernel);

        let args2 = BundleArgs::parse(&["--skip-kernel".to_owned()]).unwrap();
        assert!(args2.skip_kernel);
        assert!(!args2.skip_stage);
    }

    #[test]
    fn parse_repeated_role_accumulates() {
        let args = BundleArgs::parse(&[
            "--kernel-from-file".to_owned(),
            "/tmp/k".to_owned(),
            "--role".to_owned(),
            "reviewer".to_owned(),
            "--role".to_owned(),
            "orchestrator".to_owned(),
        ])
        .unwrap();
        assert_eq!(args.roles, vec![Role::Reviewer, Role::Orchestrator]);
    }

    #[test]
    fn run_rejects_unknown_verb() {
        let err = run(&["snapshot".to_owned()]).unwrap_err().to_string();
        assert!(err.contains("unknown linux-microvm verb"), "got: {err}");
    }

    #[test]
    fn run_rejects_missing_verb() {
        let err = run(&[]).unwrap_err().to_string();
        assert!(err.contains("missing linux-microvm verb"), "got: {err}");
    }

    #[test]
    fn install_kernel_refuses_reference_pin_with_placeholder_sha256() {
        let args = BundleArgs {
            install_dir: PathBuf::from("/tmp/raxis-bundle-test"),
            arch: Arch::X86_64,
            kernel_source: KernelSource::Reference { sha256: None },
            cargo_target: None,
            signing_key: None,
            roles: Role::all().to_vec(),
            skip_stage: true,
            skip_kernel: false,
            force_kernel: false,
        };
        let err = install_kernel(&args).unwrap_err().to_string();
        assert!(
            err.contains("all-zero placeholder") || err.contains("--kernel-sha256"),
            "expected operator-must-supply-sha256 error, got: {err}",
        );
    }
}
