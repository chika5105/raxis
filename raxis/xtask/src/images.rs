//! `cargo xtask images dev-stage` and `cargo xtask images build-all` —
//! the two-step macOS-hermetic dev-host pipeline that produces signed
//! initramfs rootfs blobs for AVF / Firecracker microVM boot.
//!
//! Normative references:
//!
//! * `raxis/specs/v2/planner-harness.md §14.4 — Image-build pipeline`
//!   — the production EROFS pipeline. This module is the dev-host
//!   companion that emits the same signed-manifest shape but with
//!   `image_format = RootfsInitramfsCpio` instead.
//! * `raxis/specs/v2/e2e-live-test-gap.md` — the `mkfs.erofs`-on-macOS
//!   blocker. `dev-stage` + `build-all` together remove the EROFS
//!   tooling dependency for local AVF demos.
//! * `raxis/crates/initramfs-builder/` — the cpio.gz writer the
//!   `build-all` step drives.
//!
//! ## Two-step pipeline
//!
//! ```text
//! 1. cargo xtask images dev-stage   --role <ROLE> [--target <TRIPLE>]
//!      → cross-compiles raxis-planner-<role> for the guest target
//!      → places the binary at images/<role>-core/rootfs/init
//!        (Linux unpacks the initramfs and execs `/init` as PID 1;
//!         skipping the /usr/local/bin/* layout keeps the dev image
//!         small and removes the need to ship busybox).
//!
//! 2. cargo xtask images build-all   [--role <ROLE>] [--install-dir <PATH>]
//!      → walks images/<role>-core/rootfs/, packs into cpio.gz via
//!        raxis-initramfs-builder
//!      → calls raxis-image-builder to emit the signed manifest with
//!        image_format=RootfsInitramfsCpio
//!      → drops:
//!          $RAXIS_INSTALL_DIR/images/raxis-<role>-core-<kver>.img
//!          $RAXIS_INSTALL_DIR/images/raxis-<role>-core-<kver>.manifest.toml
//! ```
//!
//! ## Why `dev-stage` shells out to `cargo` for the cross-compile
//!
//! Cross-compiling a workspace member from xtask with the Cargo
//! library API requires linking against `cargo` as a build dependency
//! — adding ~600 transitive crates to a build-tooling binary that
//! exists to be small. Shelling out keeps xtask's Cargo.toml under 10
//! deps and uses the same toolchain resolution the developer would
//! get from `cargo build --target <TRIPLE>`. The trade-off is that
//! `dev-stage` requires the developer to have the target installed
//! (`rustup target add aarch64-unknown-linux-musl`) and a musl linker
//! on `$PATH` (`brew install filosottile/musl-cross/musl-cross` on
//! macOS); we surface a clear remediation hint when either is absent.
//!
//! ## Why the dev-host pipeline ships a separate manifest
//!
//! `image-builder`'s `assemble_manifest` already takes
//! `BuildInputs.image_format` as an input. `build-all` constructs a
//! `BuildInputs` with `image_format = RootfsInitramfsCpio` and feeds
//! that through the same signing path the production EROFS pipeline
//! uses. The kernel verifies BOTH shapes via the same
//! `read_verified_image_format` helper added in
//! `crates/canonical-images`, so dev-built images and prod-built
//! images cannot be confused at boot.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Workspace-relative path to the per-role staging dir. Mirrors the
/// `images/<role>/rootfs/` layout `raxis-image-builder` already
/// expects.
const STAGING_PARENT: &str = "images";

/// Default install dir if neither `--install-dir` nor
/// `RAXIS_INSTALL_DIR` is set. Mirrors `dev_kernel.rs`.
const DEFAULT_DEV_INSTALL_DIR: &str = "/usr/local/lib/raxis";

/// One canonical role this pipeline knows how to stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Orchestrator,
    Reviewer,
    ExecutorStarter,
}

impl Role {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "orchestrator"     => Ok(Role::Orchestrator),
            "reviewer"         => Ok(Role::Reviewer),
            "executor-starter" => Ok(Role::ExecutorStarter),
            other => bail!(
                "unsupported --role {other:?}; expected one of: \
                 orchestrator, reviewer, executor-starter"
            ),
        }
    }

    fn all() -> &'static [Role] {
        &[Role::Orchestrator, Role::Reviewer, Role::ExecutorStarter]
    }

    fn workspace_crate(self) -> &'static str {
        match self {
            Role::Orchestrator    => "raxis-planner-orchestrator",
            Role::Reviewer        => "raxis-planner-reviewer",
            Role::ExecutorStarter => "raxis-planner-executor",
        }
    }

    /// Filename of the produced binary (matches the `[[bin]] name`
    /// in each planner crate's Cargo.toml).
    fn binary_name(self) -> &'static str {
        match self {
            Role::Orchestrator    => "raxis-orchestrator",
            Role::Reviewer        => "raxis-reviewer",
            Role::ExecutorStarter => "raxis-executor",
        }
    }

    fn images_subdir(self) -> &'static str {
        match self {
            Role::Orchestrator    => "orchestrator-core",
            Role::Reviewer        => "reviewer-core",
            Role::ExecutorStarter => "executor-starter",
        }
    }

    /// Filename stem for the produced `.img` / `.manifest.toml`
    /// blobs, matching `image-manifest::Role::artefact_stem`.
    fn artefact_stem(self) -> &'static str {
        match self {
            Role::Orchestrator    => "raxis-orchestrator-core",
            Role::Reviewer        => "raxis-reviewer-core",
            Role::ExecutorStarter => "raxis-executor-starter",
        }
    }

    fn manifest_role(self) -> raxis_image_manifest::Role {
        match self {
            Role::Orchestrator    => raxis_image_manifest::Role::Orchestrator,
            Role::Reviewer        => raxis_image_manifest::Role::Reviewer,
            Role::ExecutorStarter => raxis_image_manifest::Role::ExecutorStarter,
        }
    }
}

/// Default cross-compile target. `--target` overrides; otherwise we
/// pick the musl triple matching the host arch since AVF and
/// Firecracker on macOS Apple Silicon both run aarch64 guests, and
/// Linux x86_64 hosts run x86_64 guests.
fn default_target_triple() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-musl"
    } else {
        "x86_64-unknown-linux-musl"
    }
}

// ---------------------------------------------------------------------------
// dev-stage
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct DevStageArgs {
    role:           Role,
    target:         String,
    workspace_root: PathBuf,
    cargo:          String,
}

impl DevStageArgs {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut role:   Option<Role>     = None;
        let mut target: Option<String>   = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--role" => {
                    i += 1;
                    role = Some(Role::parse(
                        argv.get(i).context("--role requires a value")?,
                    )?);
                }
                "--target" => {
                    i += 1;
                    target = Some(argv.get(i).context("--target requires a triple")?.clone());
                }
                "-h" | "--help" => {
                    eprintln!(
                        "usage: cargo xtask images dev-stage --role <ROLE> [--target <TRIPLE>]\n  \
                         --role     orchestrator | reviewer | executor-starter\n  \
                         --target   default: {default}\n",
                        default = default_target_triple(),
                    );
                    std::process::exit(0);
                }
                other => bail!("unknown dev-stage arg: {other}"),
            }
            i += 1;
        }

        let role = role.context("--role is required")?;
        let target = target.unwrap_or_else(|| default_target_triple().to_owned());
        let workspace_root = workspace_root_from_cwd()?;
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

        Ok(Self { role, target, workspace_root, cargo })
    }
}

/// Entry point for `cargo xtask images dev-stage`.
pub fn run_dev_stage(argv: &[String]) -> Result<()> {
    let args = DevStageArgs::parse(argv)?;
    dev_stage(&args)
}

fn dev_stage(args: &DevStageArgs) -> Result<()> {
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_stage_begin\",\
         \"role\":{:?},\"target\":{:?},\"workspace_root\":{:?}}}",
        args.role.workspace_crate(),
        args.target,
        args.workspace_root.display().to_string(),
    );

    // Cross-compile: `cargo build -p <crate> --release --target <triple>`.
    let status = Command::new(&args.cargo)
        .current_dir(&args.workspace_root)
        .args([
            "build",
            "-p",
            args.role.workspace_crate(),
            "--release",
            "--target",
            &args.target,
        ])
        .status()
        .context(
            "failed to spawn cargo for cross-compile; is the toolchain on $PATH?",
        )?;
    if !status.success() {
        bail!(
            "cross-compile failed (exit {}). Likely causes:\n  \
             1. target {} not installed:  rustup target add {target}\n  \
             2. musl linker missing:       brew install filosottile/musl-cross/musl-cross  (macOS)\n  \
             3. .cargo/config.toml lacks  [target.{target}.linker]  (run `rustup show` to inspect)",
            status,
            args.target,
            target = args.target,
        );
    }

    // Locate the built binary.
    let built = args
        .workspace_root
        .join("target")
        .join(&args.target)
        .join("release")
        .join(args.role.binary_name());
    if !built.exists() {
        bail!(
            "expected cross-compiled binary not found at {} after `cargo build` \
             succeeded. Did the planner crate's [[bin]] name change?",
            built.display(),
        );
    }

    // Stage into images/<role>/rootfs/init. Linux unpacks the
    // initramfs and execs `/init` as PID 1 — placing the planner
    // there sidesteps the need to ship busybox + a wrapper script in
    // the dev pipeline. Production EROFS images keep the
    // /usr/local/bin/raxis-* layout per planner-harness.md §14.4.
    let staging_root = args
        .workspace_root
        .join(STAGING_PARENT)
        .join(args.role.images_subdir())
        .join("rootfs");
    fs::create_dir_all(&staging_root)
        .with_context(|| format!("create {}", staging_root.display()))?;
    let dest = staging_root.join("init");
    fs::copy(&built, &dest)
        .with_context(|| format!("copy {} -> {}", built.display(), dest.display()))?;

    // chmod 755 — cpio writer reads mode bits from the host file.
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&dest)
        .with_context(|| format!("stat {}", dest.display()))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&dest, perms)
        .with_context(|| format!("chmod {}", dest.display()))?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"dev_stage_ok\",\
         \"role\":{:?},\"binary\":{:?},\"staged_at\":{:?}}}",
        args.role.workspace_crate(),
        built.display().to_string(),
        dest.display().to_string(),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// build-all
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BuildAllArgs {
    /// `None` = build every role for which `images/<role>/rootfs/`
    /// is non-empty.
    role:           Option<Role>,
    install_dir:    PathBuf,
    workspace_root: PathBuf,
    /// Path to the Ed25519 signing-key hex file. Defaults to
    /// `$HOME/.config/raxis/keys/raxis-dev-signing.key.hex`
    /// (`release-and-distribution.md §8.1`). The build-all
    /// step requires this exists; mint one with
    /// `cargo xtask dev-keys init` if absent.
    signing_key:    PathBuf,
}

impl BuildAllArgs {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut role:        Option<Role>    = None;
        let mut install_dir: Option<PathBuf> = None;
        let mut signing_key: Option<PathBuf> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--role" => {
                    i += 1;
                    role = Some(Role::parse(
                        argv.get(i).context("--role requires a value")?,
                    )?);
                }
                "--install-dir" => {
                    i += 1;
                    install_dir = Some(PathBuf::from(
                        argv.get(i).context("--install-dir requires a path")?,
                    ));
                }
                "--signing-key" => {
                    i += 1;
                    signing_key = Some(PathBuf::from(
                        argv.get(i).context("--signing-key requires a path")?,
                    ));
                }
                "-h" | "--help" => {
                    eprintln!(
                        "usage: cargo xtask images build-all [--role <ROLE>] \
                         [--install-dir <PATH>] [--signing-key <PATH>]\n\
                         \n\
                         Pack staged rootfs trees into signed initramfs cpio.gz \
                         blobs and lay them out at <install_dir>/images/.\n"
                    );
                    std::process::exit(0);
                }
                other => bail!("unknown build-all arg: {other}"),
            }
            i += 1;
        }

        let install_dir = install_dir
            .or_else(|| std::env::var_os("RAXIS_INSTALL_DIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DEV_INSTALL_DIR));
        let signing_key = signing_key.or_else(default_signing_key_path).ok_or_else(|| {
            anyhow::anyhow!(
                "could not resolve --signing-key (HOME unset?). Pass --signing-key \
                 <PATH> or run `cargo xtask dev-keys init` first."
            )
        })?;
        let workspace_root = workspace_root_from_cwd()?;

        Ok(Self { role, install_dir, signing_key, workspace_root })
    }
}

fn default_signing_key_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("raxis")
            .join("keys")
            .join("raxis-dev-signing.key.hex"),
    )
}

/// Entry point for `cargo xtask images build-all`.
pub fn run_build_all(argv: &[String]) -> Result<()> {
    let args = BuildAllArgs::parse(argv)?;
    build_all(&args)
}

fn build_all(args: &BuildAllArgs) -> Result<()> {
    if !args.signing_key.exists() {
        bail!(
            "signing key not found at {}. Run `cargo xtask dev-keys init` first \
             (release-and-distribution.md §8.1).",
            args.signing_key.display(),
        );
    }

    let signing_key = load_signing_key(&args.signing_key)?;

    let roles_to_build: Vec<Role> = match args.role {
        Some(r) => vec![r],
        None => Role::all()
            .iter()
            .copied()
            .filter(|r| {
                let staging = args
                    .workspace_root
                    .join(STAGING_PARENT)
                    .join(r.images_subdir())
                    .join("rootfs");
                staging.exists()
                    && std::fs::read_dir(&staging)
                        .map(|mut d| d.next().is_some())
                        .unwrap_or(false)
            })
            .collect(),
    };

    if roles_to_build.is_empty() {
        bail!(
            "no roles to build. Either pass --role <ROLE> explicitly or run \
             `cargo xtask images dev-stage --role <ROLE>` first to populate \
             images/<role>-core/rootfs/."
        );
    }

    let images_dir = args.install_dir.join("images");
    fs::create_dir_all(&images_dir)
        .with_context(|| format!("create {}", images_dir.display()))?;

    for role in roles_to_build {
        build_one_role(role, args, &signing_key, &images_dir)?;
    }
    Ok(())
}

fn build_one_role(
    role:        Role,
    args:        &BuildAllArgs,
    signing_key: &ed25519_dalek::SigningKey,
    images_dir:  &Path,
) -> Result<()> {
    use raxis_image_builder::{assemble_manifest, enumerate_rootfs, BuildInputs};
    use raxis_image_manifest::{fingerprint_signing_key, ImageFormat};

    let images_subdir = args
        .workspace_root
        .join(STAGING_PARENT)
        .join(role.images_subdir());
    let rootfs_dir = images_subdir.join("rootfs");
    let inputs_path = images_subdir.join("manifest.toml");

    if !rootfs_dir.exists() {
        bail!(
            "rootfs staging dir {} does not exist; run `cargo xtask images dev-stage \
             --role {role:?}` first",
            rootfs_dir.display(),
        );
    }
    if !inputs_path.exists() {
        bail!(
            "build-inputs file {} does not exist (the in-tree fixture)",
            inputs_path.display(),
        );
    }

    // Read BuildInputs and force image_format = RootfsInitramfsCpio.
    // The in-tree manifest.toml currently encodes the production EROFS
    // pipeline's parameters (erofs_version, tar_version) — those stay
    // accurate for the production build path. The dev pipeline ignores
    // them at signing time except for the canonical bundle_hash input.
    let inputs_toml = fs::read_to_string(&inputs_path)
        .with_context(|| format!("read {}", inputs_path.display()))?;
    let mut inputs: BuildInputs = toml::from_str(&inputs_toml)
        .with_context(|| format!("parse {}", inputs_path.display()))?;
    inputs.image_format = ImageFormat::RootfsInitramfsCpio;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"build_all_role_begin\",\
         \"role\":{:?},\"rootfs_dir\":{:?}}}",
        role.workspace_crate(),
        rootfs_dir.display().to_string(),
    );

    // Assemble the cpio.gz bytes with the initramfs-builder.
    let cpio_gz = pack_initramfs(&rootfs_dir, inputs.source_date_epoch)?;

    // Write the .img blob to <install_dir>/images/<stem>-<kver>.img.
    let img_path = images_dir.join(format!(
        "{stem}-{kver}.img",
        stem = role.artefact_stem(),
        kver = inputs.kernel_version,
    ));
    fs::write(&img_path, &cpio_gz)
        .with_context(|| format!("write {}", img_path.display()))?;

    // Compute the .img digest for the manifest.
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&cpio_gz);
    let img_sha256_hex = hex::encode(hasher.finalize());

    // Assert the parsed BuildInputs role agrees with the role we're
    // building — catches a stale manifest.toml fixture.
    if inputs.role != role.manifest_role() {
        bail!(
            "build-inputs role {:?} disagrees with --role {role:?} (expected {:?})",
            inputs.role,
            role.manifest_role(),
        );
    }

    // Walk the staging tree and turn it into ManifestFile entries.
    let files = enumerate_rootfs(&rootfs_dir)?;
    let signing_fp_hex = hex::encode(fingerprint_signing_key(&signing_key.verifying_key()));
    let mut m = assemble_manifest(&inputs, files, signing_fp_hex, img_sha256_hex)?;

    // Sign + write the .manifest.toml sibling.
    raxis_image_builder::sign_manifest(&mut m, signing_key)?;

    let manifest_path = images_dir.join(format!(
        "{stem}-{kver}.manifest.toml",
        stem = role.artefact_stem(),
        kver = inputs.kernel_version,
    ));
    fs::write(&manifest_path, m.to_toml())
        .with_context(|| format!("write {}", manifest_path.display()))?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"build_all_role_ok\",\
         \"role\":{:?},\"img\":{:?},\"manifest\":{:?},\
         \"image_size_bytes\":{},\"image_sha256\":{:?}}}",
        role.workspace_crate(),
        img_path.display().to_string(),
        manifest_path.display().to_string(),
        cpio_gz.len(),
        m.image_artefact_sha256,
    );

    Ok(())
}

fn pack_initramfs(rootfs_dir: &Path, source_date_epoch: u64) -> Result<Vec<u8>> {
    use raxis_initramfs_builder::InitramfsBuilder;

    let mut b = InitramfsBuilder::new().with_source_date_epoch(source_date_epoch);
    b.add_tree_from_disk(rootfs_dir, "")
        .with_context(|| format!("walk staging tree {}", rootfs_dir.display()))?;
    let bytes = b.finalise_to_cpio_gz()
        .context("finalise cpio.gz")?;
    Ok(bytes)
}

fn load_signing_key(p: &Path) -> Result<ed25519_dalek::SigningKey> {
    use ed25519_dalek::SigningKey;

    let s = fs::read_to_string(p)
        .with_context(|| format!("read signing key {}", p.display()))?;
    let s = s.trim();
    if s.len() != 64 {
        bail!(
            "signing key at {} is {} chars; expected 64 lowercase hex",
            p.display(),
            s.len(),
        );
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(s, &mut bytes).with_context(|| {
        format!("hex-decode signing key at {}", p.display())
    })?;
    Ok(SigningKey::from_bytes(&bytes))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn workspace_root_from_cwd() -> Result<PathBuf> {
    let mut cwd: PathBuf = std::env::current_dir().context("cannot read CWD")?;
    loop {
        let candidate = cwd.join("Cargo.toml");
        if candidate.exists() {
            let s = std::fs::read_to_string(&candidate).with_context(|| {
                format!("read {}", candidate.display())
            })?;
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
    fn role_parse_accepts_documented_aliases_and_rejects_unknown() {
        assert_eq!(Role::parse("orchestrator").unwrap(),     Role::Orchestrator);
        assert_eq!(Role::parse("reviewer").unwrap(),         Role::Reviewer);
        assert_eq!(Role::parse("executor-starter").unwrap(), Role::ExecutorStarter);
        assert!(Role::parse("Reviewer").is_err());
        assert!(Role::parse("orchestrators").is_err());
    }

    #[test]
    fn role_metadata_table_matches_image_manifest_artefact_stems() {
        for r in Role::all() {
            assert_eq!(
                r.artefact_stem(),
                r.manifest_role().artefact_stem(),
                "role {r:?} stem must match image-manifest crate's mapping",
            );
        }
    }

    #[test]
    fn dev_stage_args_default_target_matches_host_arch() {
        let argv = vec!["--role".to_owned(), "orchestrator".to_owned()];
        let args = DevStageArgs::parse(&argv).expect("parse");
        assert_eq!(args.target, default_target_triple());
    }

    #[test]
    fn build_all_args_default_install_dir_is_documented_layout() {
        let prev_install = std::env::var_os("RAXIS_INSTALL_DIR");
        let prev_home    = std::env::var_os("HOME");
        // SAFETY: single-threaded test; restored at end.
        unsafe {
            std::env::remove_var("RAXIS_INSTALL_DIR");
            std::env::set_var("HOME", "/tmp/nonexistent-home-for-test");
        }
        let argv = vec![];
        let args = BuildAllArgs::parse(&argv).expect("parse");
        assert_eq!(args.install_dir, PathBuf::from(DEFAULT_DEV_INSTALL_DIR));
        // SAFETY: see above.
        unsafe {
            match prev_install {
                Some(v) => std::env::set_var("RAXIS_INSTALL_DIR", v),
                None    => std::env::remove_var("RAXIS_INSTALL_DIR"),
            }
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None    => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn pack_initramfs_round_trips_a_one_file_tree() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("init"), b"#!/bin/sh\necho hi\n").unwrap();
        let bytes = pack_initramfs(tmp.path(), 1).unwrap();
        // gzip magic.
        assert_eq!(&bytes[0..2], &[0x1f, 0x8b]);
    }

    #[test]
    fn load_signing_key_rejects_short_input() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"deadbeef").unwrap();
        let err = load_signing_key(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("expected 64"), "got: {err}");
    }
}
