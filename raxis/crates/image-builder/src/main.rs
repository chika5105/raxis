//! `raxis-image-builder` — CLI driver for the canonical-image build
//! pipeline.
//!
//! Two subcommands:
//!
//! - `build <role>` — read `images/<role>/manifest.toml`, walk
//!   `images/<role>/rootfs/`, write `out/<role>.manifest.json`.
//! - `verify <manifest>` — independent re-verification entry point
//!   used by `raxis doctor canonical-images` and CI.
//!
//! Hermetic posture: `build` never spawns a network-using subprocess
//! and refuses to invoke any package manager (cargo, npm, pip, …).
//! The kernel signing key is loaded from the path in
//! `RAXIS_IMAGE_SIGNING_KEY`; the file must be `0600`.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{SigningKey, VerifyingKey};
use raxis_image_builder::{build_and_sign, compute_artefact_digest_hex, read_inputs, BuildInputs};
use raxis_image_manifest::{verify, ImageManifest, Role};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "raxis-image-builder",
    version,
    about = "Reproducible canonical-image builder for RAXIS"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Build the manifest for one canonical image.
    Build {
        /// Which canonical image to build.
        #[arg(value_enum)]
        role: RoleArg,
        /// Source directory; defaults to `images/<role>/`.
        #[arg(long)]
        source_dir: Option<PathBuf>,
        /// Output manifest path; defaults to `out/<role>.manifest.json`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Path to the packed `<role>-<kernel_version>.img` blob.
        /// The builder streams its bytes through SHA-256 and pins the
        /// digest into `manifest.image_artefact_sha256`. Required for
        /// signed builds (omitted only when `--unsigned` is set, where
        /// a deterministic placeholder is used so test builds remain
        /// hermetic).
        #[arg(long)]
        image_artefact: Option<PathBuf>,
        /// Skip signing (for in-tree determinism tests). The output
        /// manifest will have a placeholder signature; production
        /// builds MUST omit this flag.
        #[arg(long)]
        unsigned: bool,
    },
    /// Verify a manifest against the kernel's expected signing key.
    Verify {
        /// Manifest path.
        manifest: PathBuf,
        /// Public-key file (32 raw bytes, hex-encoded). Defaults to
        /// the env var `RAXIS_IMAGE_VERIFY_KEY`.
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum RoleArg {
    Reviewer,
    Orchestrator,
    ExecutorStarter,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Self {
        match r {
            RoleArg::Reviewer => Role::Reviewer,
            RoleArg::Orchestrator => Role::Orchestrator,
            RoleArg::ExecutorStarter => Role::ExecutorStarter,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build {
            role,
            source_dir,
            out,
            image_artefact,
            unsigned,
        } => {
            let r: Role = role.into();
            let source = source_dir.unwrap_or_else(|| Path::new("images").join(r.as_dir_name()));
            let inputs_path = source.join(raxis_image_builder::INPUT_MANIFEST_NAME);
            let inputs: BuildInputs = read_inputs(&inputs_path)
                .with_context(|| format!("reading {}", inputs_path.display()))?;
            let rootfs = source.join("rootfs");
            let signing_key = if unsigned {
                SigningKey::from_bytes(&[0u8; 32])
            } else {
                load_signing_key()?
            };

            // Resolve the image-artefact digest. Production builds
            // MUST pass `--image-artefact` so the manifest commits to
            // the .img blob the kernel will boot. Unsigned builds
            // (used only in determinism CI) accept a fixed placeholder
            // digest because they never reach the kernel boot path.
            let image_artefact_sha256_hex = match (&image_artefact, unsigned) {
                (Some(p), _) => compute_artefact_digest_hex(p)
                    .with_context(|| format!("hashing image artefact {}", p.display()))?,
                (None, true) => "0".repeat(64),
                (None, false) => anyhow::bail!(
                    "--image-artefact <path> is required for signed builds; \
                     pass the .img blob whose SHA-256 should be pinned in the \
                     manifest's `image_artefact_sha256` field. (Use --unsigned \
                     only for determinism CI.)",
                ),
            };

            let manifest =
                build_and_sign(&inputs, &rootfs, image_artefact_sha256_hex, &signing_key)
                    .with_context(|| format!("building {}", inputs_path.display()))?;
            let out_path = out.unwrap_or_else(|| {
                PathBuf::from("out").join(format!("{}.manifest.toml", r.as_dir_name()))
            });
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&out_path, manifest.to_toml())
                .with_context(|| format!("writing {}", out_path.display()))?;
            println!(
                "raxis-image-builder: wrote {} (role={:?}, files={}, bundle_hash={})",
                out_path.display(),
                r,
                manifest.files.len(),
                &manifest.bundle_hash,
            );
            Ok(())
        }
        Cmd::Verify {
            manifest,
            public_key,
        } => {
            let s = std::fs::read_to_string(&manifest)
                .with_context(|| format!("reading {}", manifest.display()))?;
            let m: ImageManifest = ImageManifest::from_toml(&s)
                .with_context(|| format!("parsing {}", manifest.display()))?;
            let vk = load_verifying_key(public_key.as_deref())?;
            verify(&m, &vk).with_context(|| format!("verifying {}", manifest.display()))?;
            println!(
                "raxis-image-builder: verified {} (role={:?}, bundle_hash={})",
                manifest.display(),
                m.role,
                m.bundle_hash,
            );
            Ok(())
        }
    }
}

fn load_signing_key() -> Result<SigningKey> {
    use std::os::unix::fs::PermissionsExt;
    let path: PathBuf = std::env::var_os("RAXIS_IMAGE_SIGNING_KEY")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "RAXIS_IMAGE_SIGNING_KEY env var is not set. Set it to the \
             path of the 32-byte hex-encoded Ed25519 signing key file."
            )
        })?;
    let meta = std::fs::metadata(&path)
        .with_context(|| format!("stat({}) for signing key", path.display()))?;
    let mode = meta.permissions().mode() & 0o7777;
    if mode != 0o600 {
        anyhow::bail!(
            "signing key at {} has mode 0o{:o}; refusing to load (must be 0o600)",
            path.display(),
            mode,
        );
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("read({})", path.display()))?;
    let bytes = hex::decode(raw.trim())
        .with_context(|| format!("decoding hex signing key at {}", path.display()))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "signing key at {} is {} bytes; expected 32",
            path.display(),
            bytes.len(),
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

fn load_verifying_key(path: Option<&Path>) -> Result<VerifyingKey> {
    let p: PathBuf = if let Some(p) = path {
        p.to_path_buf()
    } else {
        std::env::var_os("RAXIS_IMAGE_VERIFY_KEY")
            .map(PathBuf::from)
            .ok_or_else(|| {
                anyhow::anyhow!("no public key supplied (--public-key or RAXIS_IMAGE_VERIFY_KEY)")
            })?
    };
    let raw = std::fs::read_to_string(&p).with_context(|| format!("read({})", p.display()))?;
    let bytes = hex::decode(raw.trim())
        .with_context(|| format!("decoding hex public key at {}", p.display()))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "public key at {} is {} bytes; expected 32",
            p.display(),
            bytes.len(),
        );
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Ok(VerifyingKey::from_bytes(&k)?)
}
