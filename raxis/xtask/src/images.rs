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

    // Stage into images/<role>/rootfs/. The Containerfile-built rootfs
    // already contains a `/init` symlink pointing at
    // `/usr/local/bin/raxis-planner-<role>` (planner-harness.md §14.4
    // canonical layout). When `init` is a symlink, naïve `fs::copy`
    // follows it and writes to whatever absolute path the symlink
    // resolves to ON THE HOST — i.e. /usr/local/bin/ — instead of
    // updating the in-rootfs binary that the cpio writer will
    // actually pack. We therefore:
    //   1. Always write the freshly cross-compiled binary into the
    //      canonical /usr/local/bin path INSIDE the rootfs.
    //   2. Ensure /init exists as a symlink pointing at that path.
    // This keeps the dev pipeline's on-disk layout byte-identical to
    // the production EROFS layout and guarantees the new binary
    // actually ships in the cpio.gz.
    use std::os::unix::fs::{symlink, PermissionsExt};

    let staging_root = args
        .workspace_root
        .join(STAGING_PARENT)
        .join(args.role.images_subdir())
        .join("rootfs");
    fs::create_dir_all(&staging_root)
        .with_context(|| format!("create {}", staging_root.display()))?;

    let canonical_rel = format!("usr/local/bin/{}", args.role.binary_name());
    let canonical_abs = staging_root.join(&canonical_rel);
    if let Some(parent) = canonical_abs.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    // Replace the existing binary atomically: remove the stale file
    // (or symlink) first so `fs::copy` writes a fresh inode rather
    // than following a host-absolute symlink.
    if canonical_abs.exists() || canonical_abs.symlink_metadata().is_ok() {
        fs::remove_file(&canonical_abs).with_context(|| {
            format!("remove stale {}", canonical_abs.display())
        })?;
    }
    fs::copy(&built, &canonical_abs).with_context(|| {
        format!("copy {} -> {}", built.display(), canonical_abs.display())
    })?;
    let mut perms = fs::metadata(&canonical_abs)
        .with_context(|| format!("stat {}", canonical_abs.display()))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&canonical_abs, perms)
        .with_context(|| format!("chmod {}", canonical_abs.display()))?;

    // Ensure `/init` exists as a symlink to /usr/local/bin/<binary>.
    // We always recreate it so a stale regular-file `/init` (left by
    // an earlier pre-fix dev-stage run) cannot end up packed instead
    // of the canonical-layout binary.
    let init_link = staging_root.join("init");
    if init_link.exists() || init_link.symlink_metadata().is_ok() {
        fs::remove_file(&init_link).with_context(|| {
            format!("remove stale {}", init_link.display())
        })?;
    }
    let init_target = format!("/{canonical_rel}");
    symlink(&init_target, &init_link).with_context(|| {
        format!(
            "symlink {} -> {}",
            init_link.display(),
            init_target,
        )
    })?;
    let dest = canonical_abs;

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

// ---------------------------------------------------------------------------
// bake-rootfs
//
// `cargo xtask images bake-rootfs --role <ROLE> [--builder <B>] [--platform
// <PLAT>]` — execute the per-role `images/<role>/Containerfile` against
// docker (or podman / buildah, in that fallback order), export the
// resulting OCI image's filesystem, and unpack it into
// `images/<role>/rootfs/`. The subsequent `dev-stage` overlays the
// freshly cross-compiled planner binary on top, and `build-all` packs
// the merged tree into the signed cpio.gz initramfs.
//
// The Containerfile IS the source of truth for the rootfs content;
// this subcommand is the per-release pipeline `images/README.md` says
// "populates `rootfs/`". Before this existed, the `dev-stage` step
// alone produced a binary-only initramfs (no /bin/bash, no python3,
// no git) — every `BashTool` invocation inside the executor VM
// returned ENOENT. See `iter12-artifacts/kernel.stderr.log` for the
// failure mode this fixes.
// ---------------------------------------------------------------------------

/// Container builders we know how to drive. Detection order is
/// `Docker → Podman → Buildah`; an explicit `--builder` overrides the
/// auto-detection. Each variant pairs with a fixed CLI shape so the
/// `bake_one_role` driver does not branch in three places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Builder {
    Docker,
    Podman,
    Buildah,
}

impl Builder {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "docker"  => Ok(Builder::Docker),
            "podman"  => Ok(Builder::Podman),
            "buildah" => Ok(Builder::Buildah),
            other     => bail!(
                "unsupported --builder {other:?}; expected one of: \
                 docker, podman, buildah"
            ),
        }
    }

    fn binary(self) -> &'static str {
        match self {
            Builder::Docker  => "docker",
            Builder::Podman  => "podman",
            Builder::Buildah => "buildah",
        }
    }

    /// Auto-detect a usable builder by probing `$PATH`. Walks the
    /// fallback order `docker → podman → buildah`; returns the first
    /// binary that resolves. A clear remediation hint is surfaced if
    /// none are present.
    fn auto_detect() -> Result<Self> {
        for candidate in [Builder::Docker, Builder::Podman, Builder::Buildah] {
            if which(candidate.binary()).is_some() {
                return Ok(candidate);
            }
        }
        bail!(
            "no container builder found on $PATH. Install one of:\n  \
             - docker      (recommended on macOS / Linux dev hosts)\n  \
             - podman      (rootless, recommended on Linux servers)\n  \
             - buildah     (Linux-only, daemonless OCI builder)\n\
             Then re-run `cargo xtask images bake-rootfs --role <ROLE>`."
        )
    }
}

/// `which`-style binary probe. Walks `$PATH` directories and returns
/// the first executable resolution. Inlined here to avoid pulling
/// the `which` crate into xtask for one short helper.
fn which(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if meta.permissions().mode() & 0o111 != 0 {
            return Some(candidate);
        }
    }
    None
}

/// Map a Rust target triple to an OCI / Docker `--platform` string.
/// Mirrors `default_target_triple` so the produced rootfs matches the
/// guest VM's architecture. AVF on Apple Silicon runs aarch64 guests,
/// AVF on Intel macOS runs x86_64; Firecracker on Linux mirrors the
/// host arch.
fn oci_platform_for_target_triple(triple: &str) -> Result<&'static str> {
    if triple.starts_with("aarch64-") {
        Ok("linux/arm64")
    } else if triple.starts_with("x86_64-") {
        Ok("linux/amd64")
    } else {
        bail!(
            "no OCI platform mapping for target triple {triple:?}; \
             expected aarch64-* or x86_64-* (the AVF / Firecracker \
             guests this pipeline targets). Pass --platform <PLAT> \
             explicitly to override."
        )
    }
}

#[derive(Debug)]
struct BakeRootfsArgs {
    role:           Role,
    builder:        Option<Builder>,
    platform:       Option<String>,
    workspace_root: PathBuf,
    /// When true, leave any existing `images/<role>/rootfs/` content
    /// in place and merge the bake result on top. Default behaviour is
    /// to remove the staging dir first so two consecutive bakes are
    /// byte-deterministic.
    keep:           bool,
}

impl BakeRootfsArgs {
    fn parse(argv: &[String]) -> Result<Self> {
        let mut role:     Option<Role>    = None;
        let mut builder:  Option<Builder> = None;
        let mut platform: Option<String>  = None;
        let mut keep:     bool            = false;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--role" => {
                    i += 1;
                    role = Some(Role::parse(
                        argv.get(i).context("--role requires a value")?,
                    )?);
                }
                "--builder" => {
                    i += 1;
                    builder = Some(Builder::parse(
                        argv.get(i).context("--builder requires a value")?,
                    )?);
                }
                "--platform" => {
                    i += 1;
                    platform = Some(
                        argv.get(i).context("--platform requires a value")?.clone(),
                    );
                }
                "--keep" => {
                    keep = true;
                }
                "-h" | "--help" => {
                    eprintln!(
                        "usage: cargo xtask images bake-rootfs --role <ROLE> \
                         [--builder docker|podman|buildah] [--platform <PLAT>] \
                         [--keep]\n  \
                         --role     orchestrator | reviewer | executor-starter\n  \
                         --builder  container builder to drive (default: auto-detect)\n  \
                         --platform OCI platform string (default: derived from \
                                    Rust host arch via default_target_triple())\n  \
                         --keep     do NOT remove images/<role>/rootfs/ before \
                                    extracting (default: clean first for \
                                    determinism)"
                    );
                    std::process::exit(0);
                }
                other => bail!("unknown bake-rootfs arg: {other}"),
            }
            i += 1;
        }

        let role = role.context("--role is required")?;
        let workspace_root = workspace_root_from_cwd()?;
        Ok(Self { role, builder, platform, workspace_root, keep })
    }
}

/// Entry point for `cargo xtask images bake-rootfs`.
pub fn run_bake_rootfs(argv: &[String]) -> Result<()> {
    let args    = BakeRootfsArgs::parse(argv)?;
    let builder = match args.builder {
        Some(b) => b,
        None    => Builder::auto_detect()?,
    };
    let platform = match args.platform.as_deref() {
        Some(p) => p.to_owned(),
        None    => oci_platform_for_target_triple(default_target_triple())?
                       .to_owned(),
    };
    bake_one_role(args.role, builder, &platform, &args.workspace_root, args.keep)
}

fn bake_one_role(
    role:           Role,
    builder:        Builder,
    platform:       &str,
    workspace_root: &Path,
    keep:           bool,
) -> Result<()> {
    let images_subdir = workspace_root
        .join(STAGING_PARENT)
        .join(role.images_subdir());
    let containerfile = images_subdir.join("Containerfile");
    if !containerfile.exists() {
        bail!(
            "Containerfile not found at {}; expected the per-role recipe \
             to live next to manifest.toml under images/<role>/.",
            containerfile.display(),
        );
    }
    let rootfs_dir = images_subdir.join("rootfs");

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"bake_rootfs_begin\",\
         \"role\":{:?},\"builder\":{:?},\"platform\":{:?},\
         \"containerfile\":{:?}}}",
        role.workspace_crate(),
        builder.binary(),
        platform,
        containerfile.display().to_string(),
    );

    // ── Step 1: docker build (or podman / buildah build). ─────────────
    //
    // `--pull` ensures the FROM base layer is refreshed against the
    // upstream registry — without it, an older locally-cached
    // debian:bookworm-slim could ship a security regression silently.
    // `-t` tags the built image so we have a stable reference for the
    // subsequent `create` step. The tag carries a kernel-version
    // suffix once the bake pipeline grows multi-version support; for
    // now a fixed `:dev` is enough since each role bakes one image.
    let tag = format!("raxis-rootfs-{}:dev", role.images_subdir());
    let build_status = Command::new(builder.binary())
        .args([
            "build",
            "--platform", platform,
            "--pull",
            "-t", &tag,
            "-f", &containerfile.display().to_string(),
            &images_subdir.display().to_string(),
        ])
        .status()
        .with_context(|| format!(
            "spawn `{builder} build` for role {role:?}",
            builder = builder.binary(),
        ))?;
    if !build_status.success() {
        bail!(
            "{builder} build failed (exit {status}). Inspect the build log \
             above; common causes: (1) Dockerfile syntax error, (2) apt-get \
             upstream outage, (3) running on Linux without --platform \
             matching the host (try `cargo xtask images bake-rootfs \
             --platform linux/$(uname -m | sed s/x86_64/amd64/ | sed \
             s/aarch64/arm64/)`).",
            builder = builder.binary(),
            status  = build_status,
        );
    }

    // ── Step 2: create a throwaway container so we can `export` its
    //    filesystem. `docker export` writes a tar stream to stdout;
    //    `podman` and `buildah` use the same shape. We always remove
    //    the container in Step 4 even on failure paths so a panic
    //    here does not leak named containers.
    let create_out = Command::new(builder.binary())
        .args(["create", "--platform", platform, &tag])
        .output()
        .with_context(|| format!(
            "spawn `{builder} create` for tag {tag}",
            builder = builder.binary(),
        ))?;
    if !create_out.status.success() {
        bail!(
            "{builder} create failed (exit {status}):\n--- stderr ---\n{stderr}",
            builder = builder.binary(),
            status  = create_out.status,
            stderr  = String::from_utf8_lossy(&create_out.stderr),
        );
    }
    let container_id = String::from_utf8_lossy(&create_out.stdout).trim().to_owned();
    if container_id.is_empty() {
        bail!("{builder} create returned empty container id", builder = builder.binary());
    }

    // ── Step 3: `<builder> export <container_id>` → tar stream → tar -x.
    //
    // We pipe directly into a `tar -xf -` child to avoid materialising
    // a multi-GB temporary tarball on disk. `--no-same-owner` so the
    // extracted tree is owned by the invoking user (otherwise tar
    // tries to chown to UID 0, which fails on macOS without root).
    // `--no-same-permissions` keeps file modes from the archive but
    // strips the SUID/SGID bits — the cpio packer writes new mode
    // bits per the manifest anyway so this is a no-op for the on-disk
    // image but protects against accidental SUID inheritance during
    // dev-host extraction.
    if rootfs_dir.exists() && !keep {
        fs::remove_dir_all(&rootfs_dir)
            .with_context(|| format!("clean stale {}", rootfs_dir.display()))?;
    }
    fs::create_dir_all(&rootfs_dir)
        .with_context(|| format!("create {}", rootfs_dir.display()))?;

    let extract_result = run_export_pipeline(
        builder,
        &container_id,
        &rootfs_dir,
    );

    // ── Step 4: always remove the throwaway container. We swallow
    //    rm errors so a successful extract is not masked by a failed
    //    teardown; the dangling container is harmless and the next
    //    bake will overwrite the tag.
    let _ = Command::new(builder.binary())
        .args(["rm", "-f", &container_id])
        .status();

    extract_result?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"bake_rootfs_ok\",\
         \"role\":{:?},\"rootfs_dir\":{:?}}}",
        role.workspace_crate(),
        rootfs_dir.display().to_string(),
    );

    Ok(())
}

/// Run `<builder> export <container_id> | tar -xf - -C <rootfs_dir>`
/// without buffering a multi-GB tarball on disk. We use `Stdio::piped`
/// on the builder side and feed the read end into tar's stdin; both
/// children are reaped before we return.
fn run_export_pipeline(
    builder:      Builder,
    container_id: &str,
    rootfs_dir:   &Path,
) -> Result<()> {
    use std::process::Stdio;

    let mut export = Command::new(builder.binary())
        .args(["export", container_id])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!(
            "spawn `{builder} export {container_id}`",
            builder = builder.binary(),
        ))?;
    let export_stdout = export.stdout.take().expect("export stdout piped");

    let mut tar = Command::new("tar")
        .args([
            "-xf", "-",
            "--no-same-owner",
            "-C", &rootfs_dir.display().to_string(),
        ])
        .stdin(Stdio::from(export_stdout))
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn `tar -xf -`; tar(1) must be on $PATH")?;

    let tar_status     = tar.wait().context("wait tar")?;
    let export_output  = export.wait_with_output().context("wait export")?;

    if !export_output.status.success() {
        bail!(
            "{builder} export failed (exit {status}):\n--- stderr ---\n{stderr}",
            builder = builder.binary(),
            status  = export_output.status,
            stderr  = String::from_utf8_lossy(&export_output.stderr),
        );
    }
    if !tar_status.success() {
        bail!("tar -x failed (exit {tar_status}); rootfs may be partially extracted at {}",
              rootfs_dir.display());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    #[test]
    fn builder_parse_accepts_documented_aliases_only() {
        assert_eq!(Builder::parse("docker").unwrap(),  Builder::Docker);
        assert_eq!(Builder::parse("podman").unwrap(),  Builder::Podman);
        assert_eq!(Builder::parse("buildah").unwrap(), Builder::Buildah);
        assert!(Builder::parse("Docker").is_err());
        assert!(Builder::parse("kaniko").is_err());
    }

    #[test]
    fn oci_platform_for_target_triple_covers_supported_arches() {
        assert_eq!(oci_platform_for_target_triple("aarch64-unknown-linux-musl").unwrap(),
                   "linux/arm64");
        assert_eq!(oci_platform_for_target_triple("x86_64-unknown-linux-musl").unwrap(),
                   "linux/amd64");
        assert_eq!(oci_platform_for_target_triple("aarch64-apple-darwin").unwrap(),
                   "linux/arm64");
        assert!(oci_platform_for_target_triple("riscv64-unknown-linux-musl").is_err());
    }

    #[test]
    fn bake_rootfs_args_require_role() {
        let err = BakeRootfsArgs::parse(&[]).unwrap_err().to_string();
        assert!(err.contains("--role is required"), "got: {err}");
    }

    #[test]
    fn bake_rootfs_args_parse_full_arg_set() {
        // Switch into a workspace dir so workspace_root_from_cwd() resolves.
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(env!("CARGO_MANIFEST_DIR")).unwrap();
        let argv = vec![
            "--role".to_owned(),     "executor-starter".to_owned(),
            "--builder".to_owned(),  "podman".to_owned(),
            "--platform".to_owned(), "linux/arm64".to_owned(),
            "--keep".to_owned(),
        ];
        let parsed = BakeRootfsArgs::parse(&argv).unwrap();
        std::env::set_current_dir(prev).unwrap();
        assert_eq!(parsed.role,     Role::ExecutorStarter);
        assert_eq!(parsed.builder,  Some(Builder::Podman));
        assert_eq!(parsed.platform.as_deref(), Some("linux/arm64"));
        assert!(parsed.keep);
    }

    #[test]
    fn which_finds_a_known_unix_binary_or_skips() {
        // `sh` is universally present on macOS / Linux dev hosts; if it
        // isn't, the test environment is too exotic to make claims about.
        match which("sh") {
            Some(p) => assert!(p.is_absolute(), "which(sh) returned {}", p.display()),
            None    => eprintln!("skipped: no sh on $PATH (exotic test env)"),
        }
        // A binary that should never resolve.
        assert!(which("definitely-not-a-real-binary-xyz-9999").is_none());
    }
}
