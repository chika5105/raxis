//! `cargo xtask dev-keys init` — local-build signing helper.
//!
//! Normative reference: `raxis/specs/v2/release-and-distribution.md
//! §8.1–§8.2` ("local-build signing flow").
//!
//! ## Dev signing key (iter61 update — INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01)
//!
//! As of iter61, `cargo xtask images bake` (the umbrella image-bake
//! pipeline) auto-generates a per-clone Ed25519 keypair on first run
//! and persists it under
//! `<workspace>/.git/info/raxis-signing-key/{sk.hex,pk.hex}`. The
//! public half is exported as `RAXIS_KERNEL_SIGNING_KEY_HEX` into
//! every cargo subprocess `bake` spawns, so a sibling `cargo build
//! -p raxis-kernel` from the same shell sees the matching trust
//! anchor without the operator setting any env var.
//!
//! `cargo xtask dev-keys init` (this command) remains the legacy /
//! "shared-across-clones" seam: a developer who wants ONE keypair
//! across multiple worktrees runs `dev-keys init` once into
//! `$HOME/.config/raxis/keys/` and then passes
//! `--signing-key $HOME/.config/raxis/keys/raxis-dev-signing.key.hex`
//! to `cargo xtask images bake`. CI / release workflows take the
//! same `--signing-key <PATH>` shape and pre-set
//! `RAXIS_KERNEL_SIGNING_KEY_HEX` from a secret — the autogen path
//! is bypassed entirely in those flows.
//!
//! ## What this command does
//!
//! Generates a fresh Ed25519 keypair on the OS RNG and writes both
//! halves to `~/.config/raxis/keys/` (or a caller-supplied
//! directory) as hex-encoded files matching the formats the rest of
//! the workspace already consumes:
//!
//! * `raxis-dev-signing.key.hex` — 64 lowercase hex chars; the
//!   PRIVATE half. Mode `0600`. Read by
//!   `raxis-image-builder::load_signing_key` via the
//!   `RAXIS_IMAGE_SIGNING_KEY` env var.
//! * `raxis-dev-signing.pub.hex` — 64 lowercase hex chars; the
//!   PUBLIC half. Mode `0644`. Read by
//!   `canonical-images/build.rs` via the
//!   `RAXIS_KERNEL_SIGNING_KEY_HEX` env var (the developer
//!   exports it at shell-rc time).
//!
//! ## Why hex, not PEM
//!
//! `image-builder::load_signing_key` already speaks hex; the kernel
//! `build.rs` already speaks hex. A PEM intermediate would force
//! `openssl pkey | tail -c 32 | xxd` plumbing the developer does
//! not need. The single-format choice keeps the producer
//! (image-builder) and the consumer (kernel `build.rs`) on the
//! same wire shape.
//!
//! ## Refuse-overwrite contract
//!
//! On a directory that already contains `raxis-dev-signing.key.hex`
//! we refuse the operation and exit non-zero. A developer who
//! re-runs `cargo xtask dev-keys init` by accident must not
//! silently lose the key half that signed their existing canonical
//! images — without it those images become un-rebuildable. Pass
//! `--force` to overwrite.
//!
//! ## Exit-code contract
//!
//! * `0` — success.
//! * `non-zero` (anyhow::bail) — bad arg, refuse-overwrite,
//!   filesystem error.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};

const PRIV_FILENAME: &str = "raxis-dev-signing.key.hex";
const PUB_FILENAME: &str = "raxis-dev-signing.pub.hex";

/// Default keys directory: `$HOME/.config/raxis/keys/`. Documented
/// shape from `release-and-distribution.md §8.1`.
fn default_keys_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME is not set; pass --dir <PATH> explicitly"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("raxis")
        .join("keys"))
}

#[derive(Debug, Clone)]
pub struct InitOpts {
    pub dir: PathBuf,
    pub force: bool,
    pub quiet: bool,
}

pub fn run(args: &[String]) -> Result<()> {
    let mut sub: Option<&str> = None;
    let mut tail: Vec<String> = Vec::new();
    for a in args {
        if sub.is_none() && !a.starts_with('-') {
            sub = Some(a.as_str());
        } else {
            tail.push(a.clone());
        }
    }
    match sub {
        Some("init") => {
            let opts = parse_init_args(&tail)?;
            init(&opts)
        }
        Some(other) => bail!("unknown dev-keys subcommand: {other:?} (available: init)"),
        None => bail!(
            "usage: cargo xtask dev-keys <subcommand>\n\
             available subcommands:\n  \
             init [--dir <PATH>] [--force] [--quiet]"
        ),
    }
}

fn parse_init_args(args: &[String]) -> Result<InitOpts> {
    let mut dir: Option<PathBuf> = None;
    let mut force = false;
    let mut quiet = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--force" => force = true,
            "--quiet" => quiet = true,
            "--dir" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow!("missing value for --dir"))?;
                if v.is_empty() {
                    bail!("--dir cannot be empty");
                }
                dir = Some(PathBuf::from(v));
                i += 1;
            }
            other => bail!("unknown dev-keys init flag: {other:?}"),
        }
        i += 1;
    }
    let dir = match dir {
        Some(d) => d,
        None => default_keys_dir()?,
    };
    Ok(InitOpts { dir, force, quiet })
}

pub fn init(opts: &InitOpts) -> Result<()> {
    fs::create_dir_all(&opts.dir)
        .with_context(|| format!("creating keys dir {}", opts.dir.display(),))?;
    set_dir_mode_0700(&opts.dir)?;

    let priv_path = opts.dir.join(PRIV_FILENAME);
    let pub_path = opts.dir.join(PUB_FILENAME);

    if !opts.force {
        for p in [&priv_path, &pub_path] {
            if p.exists() {
                bail!(
                    "refusing to overwrite existing {}; pass --force to replace \
                     (without the matching private half, manifests signed by \
                     the previous keypair become un-rebuildable)",
                    p.display(),
                );
            }
        }
    }

    // Generate a fresh keypair on the OS RNG.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let priv_hex = hex::encode(signing_key.to_bytes());
    let pub_hex = hex::encode(verifying_key.to_bytes());

    // Write priv half (mode 0600) atomically. The atomic write
    // protects against a partial file landing on disk if the
    // process is killed mid-write.
    write_atomic_with_mode(&priv_path, &priv_hex, 0o600)?;
    // Write pub half (mode 0644).
    write_atomic_with_mode(&pub_path, &pub_hex, 0o644)?;

    if !opts.quiet {
        eprintln!("dev-keys: wrote {}", priv_path.display());
        eprintln!("dev-keys: wrote {}", pub_path.display());
        eprintln!();
        eprintln!("To bake the public key as the kernel's trust anchor and to");
        eprintln!("teach raxis-image-builder where the private half lives, drop");
        eprintln!("this snippet into your ~/.zshrc / ~/.bashrc:");
        eprintln!();
        eprintln!(
            "  export RAXIS_KERNEL_SIGNING_KEY_HEX=\"$(cat {pub_})\"",
            pub_ = pub_path.display()
        );
        eprintln!(
            "  export RAXIS_IMAGE_SIGNING_KEY=\"{priv_}\"",
            priv_ = priv_path.display()
        );
        eprintln!();
        eprintln!("Then re-build the kernel:");
        eprintln!();
        eprintln!("  cargo build --release -p raxis-kernel");
        eprintln!();
        eprintln!("Reference: raxis/specs/v2/release-and-distribution.md §8.");
    }

    Ok(())
}

#[cfg(unix)]
fn set_dir_mode_0700(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(p)
        .with_context(|| format!("stat({})", p.display(),))?
        .permissions();
    perms.set_mode(0o700);
    fs::set_permissions(p, perms).with_context(|| format!("chmod 0700 {}", p.display(),))
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_atomic_with_mode(path: &Path, contents: &str, mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("path {} has no parent directory", path.display(),))?;
    let tmp = dir.join(format!(".{}.tmp", uniq()));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("create({})", tmp.display()))?;
        f.write_all(contents.as_bytes())
            .with_context(|| format!("write({})", tmp.display()))?;
        // Append a trailing newline so `cat` of the file is
        // pleasant on the shell prompt and exhibits the same
        // shape that `xxd -p -c 64 input` would have produced.
        f.write_all(b"\n")
            .with_context(|| format!("write({})", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync({})", tmp.display()))?;
    }
    // Belt-and-braces: explicitly chmod after rename in case the
    // open(O_CREAT, mode) call above honoured umask.
    fs::rename(&tmp, path)
        .with_context(|| format!("rename({} -> {})", tmp.display(), path.display(),))?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_atomic_with_mode(path: &Path, contents: &str, _mode: u32) -> Result<()> {
    fs::write(path, contents)?;
    Ok(())
}

fn uniq() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_writes_both_halves_and_returns_64_hex_chars_each() {
        let tmp = TempDir::new().unwrap();
        let opts = InitOpts {
            dir: tmp.path().to_path_buf(),
            force: false,
            quiet: true,
        };
        init(&opts).unwrap();

        let priv_hex = fs::read_to_string(tmp.path().join(PRIV_FILENAME)).unwrap();
        let pub_hex = fs::read_to_string(tmp.path().join(PUB_FILENAME)).unwrap();
        // We append a trailing newline; trim before length checks.
        assert_eq!(priv_hex.trim_end_matches('\n').len(), 64);
        assert_eq!(pub_hex.trim_end_matches('\n').len(), 64);
        assert!(priv_hex
            .trim_end_matches('\n')
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert!(pub_hex
            .trim_end_matches('\n')
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn init_priv_is_mode_0600_and_pub_is_mode_0644() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = TempDir::new().unwrap();
            init(&InitOpts {
                dir: tmp.path().to_path_buf(),
                force: false,
                quiet: true,
            })
            .unwrap();
            let priv_mode = fs::metadata(tmp.path().join(PRIV_FILENAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let pub_mode = fs::metadata(tmp.path().join(PUB_FILENAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(priv_mode, 0o600);
            assert_eq!(pub_mode, 0o644);
        }
    }

    #[test]
    fn init_pub_hex_matches_signing_key_to_verifying_key() {
        let tmp = TempDir::new().unwrap();
        init(&InitOpts {
            dir: tmp.path().to_path_buf(),
            force: false,
            quiet: true,
        })
        .unwrap();

        let priv_hex = fs::read_to_string(tmp.path().join(PRIV_FILENAME)).unwrap();
        let pub_hex = fs::read_to_string(tmp.path().join(PUB_FILENAME)).unwrap();
        let priv_bytes = hex::decode(priv_hex.trim_end_matches('\n')).unwrap();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&priv_bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        let derived_pub = hex::encode(signing_key.verifying_key().to_bytes());
        assert_eq!(derived_pub, pub_hex.trim_end_matches('\n'));
    }

    #[test]
    fn init_refuses_to_overwrite_existing_priv_without_force() {
        let tmp = TempDir::new().unwrap();
        init(&InitOpts {
            dir: tmp.path().to_path_buf(),
            force: false,
            quiet: true,
        })
        .unwrap();
        let err = init(&InitOpts {
            dir: tmp.path().to_path_buf(),
            force: false,
            quiet: true,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("refusing to overwrite"), "got: {msg}");
    }

    #[test]
    fn init_overwrites_when_force_is_set() {
        let tmp = TempDir::new().unwrap();
        init(&InitOpts {
            dir: tmp.path().to_path_buf(),
            force: false,
            quiet: true,
        })
        .unwrap();
        let first_priv = fs::read_to_string(tmp.path().join(PRIV_FILENAME)).unwrap();
        init(&InitOpts {
            dir: tmp.path().to_path_buf(),
            force: true,
            quiet: true,
        })
        .unwrap();
        let second_priv = fs::read_to_string(tmp.path().join(PRIV_FILENAME)).unwrap();
        assert_ne!(
            first_priv, second_priv,
            "--force must produce a fresh keypair, not preserve the old one"
        );
    }

    #[test]
    fn init_creates_dir_if_missing() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("nested").join("keys");
        assert!(!nested.exists());
        init(&InitOpts {
            dir: nested.clone(),
            force: false,
            quiet: true,
        })
        .unwrap();
        assert!(nested.join(PRIV_FILENAME).exists());
        assert!(nested.join(PUB_FILENAME).exists());
    }

    #[test]
    fn parse_init_args_default_dir_uses_home() {
        let saved_home = std::env::var_os("HOME");
        std::env::set_var("HOME", "/tmp/raxis-xtask-tests-home");
        let opts = parse_init_args(&[]).unwrap();
        assert_eq!(
            opts.dir,
            PathBuf::from("/tmp/raxis-xtask-tests-home/.config/raxis/keys"),
        );
        if let Some(h) = saved_home {
            std::env::set_var("HOME", h);
        }
    }

    #[test]
    fn parse_init_args_explicit_dir_wins() {
        let opts = parse_init_args(&["--dir".to_owned(), "/explicit/path".to_owned()]).unwrap();
        assert_eq!(opts.dir, PathBuf::from("/explicit/path"));
    }

    #[test]
    fn parse_init_args_force_and_quiet_are_recognised() {
        let opts = parse_init_args(&[
            "--dir".to_owned(),
            "/d".to_owned(),
            "--force".to_owned(),
            "--quiet".to_owned(),
        ])
        .unwrap();
        assert!(opts.force);
        assert!(opts.quiet);
    }

    #[test]
    fn parse_init_args_rejects_empty_dir() {
        let err = parse_init_args(&["--dir".to_owned(), "".to_owned()]).unwrap_err();
        assert!(err.to_string().contains("--dir cannot be empty"));
    }

    #[test]
    fn parse_init_args_rejects_unknown_flag() {
        let err = parse_init_args(&["--bogus".to_owned()]).unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn run_dispatches_init_subcommand() {
        let tmp = TempDir::new().unwrap();
        run(&[
            "init".to_owned(),
            "--dir".to_owned(),
            tmp.path().to_string_lossy().into_owned(),
            "--quiet".to_owned(),
        ])
        .unwrap();
        assert!(tmp.path().join(PRIV_FILENAME).exists());
    }

    #[test]
    fn run_rejects_unknown_subcommand() {
        let err = run(&["bogus".to_owned()]).unwrap_err();
        assert!(err.to_string().contains("unknown dev-keys subcommand"));
    }

    #[test]
    fn run_with_no_args_prints_usage() {
        let err = run(&[]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("usage:"));
        assert!(msg.contains("init"));
    }
}
