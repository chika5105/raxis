//! Per-clone dev signing keypair autogen + discovery for the
//! canonical-image trust anchor.
//!
//! Normative references:
//!
//! * `specs/invariants.md::INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01`
//!   (release-profile fail-loud contract).
//! * `specs/invariants.md::INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01`
//!   (xtask seam — pre-iter62 the FIRST autogen entry point).
//! * `specs/invariants.md::INV-IMAGE-TRUST-ANCHOR-DEV-FALLBACK-01`
//!   (iter62 — `crates/canonical-images/build.rs` is the SECOND
//!   autogen entry point; both write to `.git/info/raxis-signing-key/`
//!   and converge on a single per-clone artefact).
//! * `specs/v3/canonical-image-trust-anchor.md` §4 (dev workflow).
//!
//! ## Why a shared crate (not duplicated inline)
//!
//! The keypair-mint logic lives in exactly two callsites today:
//!
//! 1. `xtask::images::run_bake_inner` — the operator-facing
//!    `cargo xtask images bake` driver. Mints + persists the keypair
//!    on first run, then exports the public half into the
//!    `RAXIS_KERNEL_SIGNING_KEY_HEX` env var for every cargo
//!    subprocess `bake` spawns. Pre-iter61, this was the ONLY
//!    autogen entry point.
//! 2. `crates/canonical-images/build.rs` (iter62) — the kernel-side
//!    seam that bakes the public half into the kernel binary at
//!    compile time. After the env-var resolution chain (steps 1+2 of
//!    `resolve_trust_anchor_bytes`) misses, the build script reads
//!    `<workspace>/.git/info/raxis-signing-key/pk.hex` if present
//!    AND, on dev profiles, mints a fresh keypair if the file is
//!    absent.
//!
//! Two disjoint codepaths reading + writing the SAME on-disk artefact
//! is exactly the shape that drifts. A bare `cargo test -p raxis-kernel`
//! that took the build.rs auto-mint path would generate one keypair
//! shape; a subsequent `cargo xtask images bake` that took the xtask
//! auto-mint path would generate a different shape; the on-disk
//! files would disagree about modes / encoding / trailing newline; the
//! `INV-IMAGE-VERIFY-REJECT-MISMATCH-01` "wrong-key" failure mode
//! would re-emerge.
//!
//! Centralising the logic in this crate guarantees both seams write
//! byte-identical artefacts (same hex encoding, same trailing newline,
//! same parent-dir mode, same per-file mode) and read them through
//! the same validator. The price is one extra workspace member; the
//! win is that the per-clone artefact has exactly one producer.
//!
//! ## Threading model
//!
//! Every public function in this crate is synchronous and blocking.
//! There is no async surface because the only callsites are
//! single-threaded drivers (`build.rs` is single-threaded by Cargo
//! contract; `xtask::run_bake_inner` is single-threaded at the bake
//! call boundary). The crate intentionally does NOT take a tokio
//! dependency.
//!
//! ## Why `.git/info/`
//!
//! See `specs/v3/canonical-image-trust-anchor.md §4.1` for the
//! design rationale. TL;DR: `.git/info/` is the canonical
//! "per-clone, never tracked" home for repository-local state
//! (`man gitrepository-layout`); using it removes the gitignore
//! step entirely (git itself refuses to stage anything under
//! `.git/`). A `git clone` produces a fresh `.git/info/` per
//! checkout, so two checkouts of the same repo on the same host
//! get distinct dev keypairs by construction.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;

/// Canonical relative path segments under the workspace root. Pinned
/// here so the xtask (`cargo xtask images bake`) and the kernel
/// build script (`crates/canonical-images/build.rs`) write the same
/// directory.
pub const GIT_INFO_KEY_DIR_REL: &[&str] = &[".git", "info", "raxis-signing-key"];

/// Filename of the private-half hex file. 64 lowercase hex chars +
/// trailing newline; mode `0600` on Unix.
pub const SK_FILENAME: &str = "sk.hex";

/// Filename of the public-half hex file. 64 lowercase hex chars +
/// trailing newline; mode `0600` on Unix (uniform with `sk.hex`
/// per iter62 hardening — the public half is non-sensitive but
/// uniform perms across both halves are simpler to reason about
/// and avoid a future hand-edit accidentally widening the dir's
/// posture).
pub const PK_FILENAME: &str = "pk.hex";

/// Length of an Ed25519 verifying-key fingerprint in bytes.
pub const KEY_LEN_BYTES: usize = 32;

/// Length of the hex-encoded form (no trailing newline).
pub const KEY_LEN_HEX: usize = KEY_LEN_BYTES * 2;

/// Compute the absolute path of `.git/info/raxis-signing-key/`
/// under the supplied workspace root. Pure-data: no IO.
///
/// `workspace_root` MUST be the directory that contains the
/// `.git/` subdirectory the operator is iterating against (i.e.
/// the `git rev-parse --show-toplevel` output, NOT a worktree's
/// `.git` file). The kernel build script and the xtask both
/// resolve this via `find_workspace_root_from`.
pub fn git_info_signing_key_dir(workspace_root: &Path) -> PathBuf {
    let mut p = workspace_root.to_path_buf();
    for seg in GIT_INFO_KEY_DIR_REL {
        p.push(seg);
    }
    p
}

/// Path of the public-half hex file under `workspace_root`.
pub fn pk_path(workspace_root: &Path) -> PathBuf {
    git_info_signing_key_dir(workspace_root).join(PK_FILENAME)
}

/// Path of the private-half hex file under `workspace_root`.
pub fn sk_path(workspace_root: &Path) -> PathBuf {
    git_info_signing_key_dir(workspace_root).join(SK_FILENAME)
}

/// Outcome returned by [`ensure_dev_signing_keypair`]. The two
/// boolean states (`generated_now` true / false) drive a stable
/// one-liner the umbrella `cargo xtask images bake` driver prints
/// on stderr; `pk_hex` is the 64-lowercase-hex public-half string
/// ready to drop into `RAXIS_KERNEL_SIGNING_KEY_HEX`.
#[derive(Debug, Clone)]
pub struct DevSigningKeypair {
    /// Absolute path of the private-half hex file.
    pub sk_path: PathBuf,
    /// Absolute path of the public-half hex file.
    pub pk_path: PathBuf,
    /// 64 lowercase hex characters. Always validated before this
    /// struct is returned (length + alphabet); callers may forward
    /// directly into env / build-script output.
    pub pk_hex: String,
    /// `true` iff this call minted the keypair from the OS RNG;
    /// `false` iff a prior call had already laid it down on disk.
    pub generated_now: bool,
}

/// Errors returned by the discovery / mint helpers.
#[derive(Debug)]
pub enum DevSigningKeyError {
    /// `pk.hex` exists on disk but its contents do not match the
    /// expected shape (64 lowercase hex chars). The on-disk file is
    /// likely truncated, hand-edited, or written by a tool that
    /// disagrees with this crate's writer. Operator remediation:
    /// delete both `sk.hex` and `pk.hex` and re-run `cargo xtask
    /// images bake` (or any cargo command that triggers the
    /// kernel-side autogen) to regenerate them in lockstep.
    PkHexCorrupt {
        /// The path that was found to be corrupt.
        path: PathBuf,
        /// Operator-actionable detail.
        detail: String,
    },
    /// I/O error during read / write / mkdir / chmod.
    Io {
        /// What we were trying to do when the I/O error fired.
        operation: String,
        /// The path the operation was working with.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// `getrandom` failed. The OS is in a state where
    /// `/dev/urandom` is unavailable; this is unrecoverable from a
    /// build script's perspective.
    Random(getrandom::Error),
}

impl std::fmt::Display for DevSigningKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DevSigningKeyError::PkHexCorrupt { path, detail } => write!(
                f,
                "dev signing pk.hex at {} is corrupt: {detail} \
                 (delete both sk.hex and pk.hex and re-run \
                 `cargo xtask images bake` to regenerate)",
                path.display(),
            ),
            DevSigningKeyError::Io {
                operation,
                path,
                source,
            } => write!(f, "{operation} {}: {source}", path.display()),
            DevSigningKeyError::Random(e) => {
                write!(f, "OS RNG (getrandom) failed: {e}")
            }
        }
    }
}

impl std::error::Error for DevSigningKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DevSigningKeyError::PkHexCorrupt { .. } => None,
            DevSigningKeyError::Io { source, .. } => Some(source),
            DevSigningKeyError::Random(e) => Some(e),
        }
    }
}

/// Read `<workspace>/.git/info/raxis-signing-key/pk.hex` if it
/// exists, validate it, and return the 32 raw bytes.
///
/// Returns `Ok(None)` when the file does not exist (the early
/// "first cargo build before any bake" state — the caller decides
/// whether to mint or fall through to the all-zero placeholder).
/// Returns `Err` only when the file IS present but malformed —
/// silently degrading on a hand-edited file would mask the
/// operator-actionable corruption.
pub fn read_existing_pk_bytes(
    workspace_root: &Path,
) -> Result<Option<[u8; KEY_LEN_BYTES]>, DevSigningKeyError> {
    let p = pk_path(workspace_root);
    if !p.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&p).map_err(|e| DevSigningKeyError::Io {
        operation: "read".to_owned(),
        path: p.clone(),
        source: e,
    })?;
    let trimmed = raw.trim_matches(['\n', '\r', ' '].as_ref());
    Ok(Some(decode_hex_or_corrupt(trimmed, &p)?))
}

/// Idempotent autogen at `.git/info/raxis-signing-key/{sk,pk}.hex`.
///
/// On first call: creates the parent directory (mode `0700`),
/// mints a fresh Ed25519 keypair from the OS RNG, writes both
/// halves atomically (via `tmp + rename`), and returns
/// `generated_now = true`. On every subsequent call: stat-+-read
/// fast path; returns `generated_now = false` and the existing
/// `pk_hex`.
///
/// `INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01` (xtask seam) and
/// `INV-IMAGE-TRUST-ANCHOR-DEV-FALLBACK-01` (build.rs seam) both
/// pin this function as the SOLE writer of the on-disk artefact.
/// The two callers converge on the same bytes by construction.
pub fn ensure_dev_signing_keypair(
    workspace_root: &Path,
) -> Result<DevSigningKeypair, DevSigningKeyError> {
    let dir = git_info_signing_key_dir(workspace_root);
    let sk_p = dir.join(SK_FILENAME);
    let pk_p = dir.join(PK_FILENAME);

    if sk_p.exists() && pk_p.exists() {
        let pk_hex = read_pk_hex_validated(&pk_p)?;
        return Ok(DevSigningKeypair {
            sk_path: sk_p,
            pk_path: pk_p,
            pk_hex,
            generated_now: false,
        });
    }

    fs::create_dir_all(&dir).map_err(|e| DevSigningKeyError::Io {
        operation: "create_dir_all".to_owned(),
        path: dir.clone(),
        source: e,
    })?;
    set_dir_mode_0700(&dir)?;

    let mut seed = [0u8; KEY_LEN_BYTES];
    getrandom::getrandom(&mut seed).map_err(DevSigningKeyError::Random)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let pk_bytes = signing_key.verifying_key().to_bytes();

    let sk_hex = hex::encode(signing_key.to_bytes());
    let pk_hex = hex::encode(pk_bytes);

    // Both halves are written at mode 0600 (iter62 hardening). The
    // private half MUST be 0600; the public half is non-sensitive
    // but we tighten it too so a subsequent `chmod -R` audit on
    // the dir sees one uniform mode instead of two.
    write_atomic_with_mode(&sk_p, &sk_hex, 0o600)?;
    write_atomic_with_mode(&pk_p, &pk_hex, 0o600)?;

    Ok(DevSigningKeypair {
        sk_path: sk_p,
        pk_path: pk_p,
        pk_hex,
        generated_now: true,
    })
}

fn read_pk_hex_validated(pk_p: &Path) -> Result<String, DevSigningKeyError> {
    let raw = fs::read_to_string(pk_p).map_err(|e| DevSigningKeyError::Io {
        operation: "read".to_owned(),
        path: pk_p.to_owned(),
        source: e,
    })?;
    let trimmed = raw.trim_matches(['\n', '\r', ' '].as_ref()).to_owned();
    validate_hex_alphabet(&trimmed, pk_p)?;
    Ok(trimmed)
}

fn validate_hex_alphabet(s: &str, p: &Path) -> Result<(), DevSigningKeyError> {
    if s.len() != KEY_LEN_HEX {
        return Err(DevSigningKeyError::PkHexCorrupt {
            path: p.to_owned(),
            detail: format!(
                "expected {KEY_LEN_HEX} lowercase hex characters; got {} bytes",
                s.len()
            ),
        });
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(DevSigningKeyError::PkHexCorrupt {
            path: p.to_owned(),
            detail: "contains non-lowercase-hex bytes".to_owned(),
        });
    }
    Ok(())
}

fn decode_hex_or_corrupt(s: &str, p: &Path) -> Result<[u8; KEY_LEN_BYTES], DevSigningKeyError> {
    validate_hex_alphabet(s, p)?;
    let mut out = [0u8; KEY_LEN_BYTES];
    hex::decode_to_slice(s, &mut out).map_err(|e| DevSigningKeyError::PkHexCorrupt {
        path: p.to_owned(),
        detail: format!("hex decode failed: {e}"),
    })?;
    Ok(out)
}

#[cfg(unix)]
fn set_dir_mode_0700(p: &Path) -> Result<(), DevSigningKeyError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(p)
        .map_err(|e| DevSigningKeyError::Io {
            operation: "metadata".to_owned(),
            path: p.to_owned(),
            source: e,
        })?
        .permissions();
    perms.set_mode(0o700);
    fs::set_permissions(p, perms).map_err(|e| DevSigningKeyError::Io {
        operation: "chmod 0700".to_owned(),
        path: p.to_owned(),
        source: e,
    })
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_: &Path) -> Result<(), DevSigningKeyError> {
    Ok(())
}

#[cfg(unix)]
fn write_atomic_with_mode(
    path: &Path,
    contents: &str,
    mode: u32,
) -> Result<(), DevSigningKeyError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let dir = path.parent().ok_or_else(|| DevSigningKeyError::Io {
        operation: "parent".to_owned(),
        path: path.to_owned(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "no parent"),
    })?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let tmp = dir.join(format!(".{stamp}.tmp"));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| DevSigningKeyError::Io {
                operation: "create".to_owned(),
                path: tmp.clone(),
                source: e,
            })?;
        f.write_all(contents.as_bytes())
            .map_err(|e| DevSigningKeyError::Io {
                operation: "write".to_owned(),
                path: tmp.clone(),
                source: e,
            })?;
        // Trailing newline so a `cat <pk>` of the file is shell-pleasant
        // and matches the shape `xxd -p -c 64 input` would produce.
        f.write_all(b"\n").map_err(|e| DevSigningKeyError::Io {
            operation: "write".to_owned(),
            path: tmp.clone(),
            source: e,
        })?;
        f.sync_all().map_err(|e| DevSigningKeyError::Io {
            operation: "fsync".to_owned(),
            path: tmp.clone(),
            source: e,
        })?;
    }
    fs::rename(&tmp, path).map_err(|e| DevSigningKeyError::Io {
        operation: "rename".to_owned(),
        path: path.to_owned(),
        source: e,
    })?;
    let mut perms = fs::metadata(path)
        .map_err(|e| DevSigningKeyError::Io {
            operation: "metadata".to_owned(),
            path: path.to_owned(),
            source: e,
        })?
        .permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms).map_err(|e| DevSigningKeyError::Io {
        operation: "chmod".to_owned(),
        path: path.to_owned(),
        source: e,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_atomic_with_mode(
    path: &Path,
    contents: &str,
    _mode: u32,
) -> Result<(), DevSigningKeyError> {
    fs::write(path, format!("{contents}\n")).map_err(|e| DevSigningKeyError::Io {
        operation: "write".to_owned(),
        path: path.to_owned(),
        source: e,
    })
}

// ---------------------------------------------------------------------------
// Workspace-root discovery (used by callers that don't already know it)
// ---------------------------------------------------------------------------

/// Walk upward from `start` looking for the workspace root: the
/// first ancestor that contains a `Cargo.toml` declaring
/// `[workspace]` at the top level.
///
/// Mirrors `xtask::images::workspace_root_from_cwd` exactly so the
/// kernel-side `crates/canonical-images/build.rs` and the
/// operator-facing `cargo xtask images bake` driver agree on the
/// same `<workspace>/.git/info/raxis-signing-key/` location even
/// when the workspace lives under an outer git checkout (e.g. the
/// canonical raxis repo layout where the workspace is `<repo>/raxis/`
/// and the `.git/` is at `<repo>/.git/`).
///
/// Note: we deliberately do NOT require a `.git/` entry at the
/// same level — callers that need a `.git/info/raxis-signing-key/`
/// directory will create it themselves under the workspace root,
/// matching the xtask iter61 seam. If a workspace's `Cargo.toml`
/// lives at a path with no `.git/` (e.g. a vendored extract under
/// `~/.cargo/registry/`), the resolution still succeeds and the
/// caller writes the autogen artefact under a synthesised
/// `.git/info/raxis-signing-key/` next to the workspace manifest.
///
/// Returns `None` when the walk hits the filesystem root without
/// finding a workspace-root manifest — typically a `cargo publish`
/// staged crate extracted into `~/.cargo/registry/` where there is
/// no workspace manifest above the package dir. Callers fall back
/// to "no workspace root" in that case (which means: no auto-mint,
/// the env-var resolution chain is the only input).
pub fn find_workspace_root_from(start: &Path) -> Option<PathBuf> {
    let mut cur: Option<&Path> = Some(start);
    while let Some(c) = cur {
        let cargo = c.join("Cargo.toml");
        if cargo.exists() {
            if let Ok(content) = fs::read_to_string(&cargo) {
                if is_workspace_manifest(&content) {
                    return Some(c.to_owned());
                }
            }
        }
        cur = c.parent();
    }
    None
}

/// Heuristic: a `Cargo.toml` is a workspace-root manifest when it
/// contains a top-level `[workspace]` table header. We do NOT
/// pull in a TOML parser for this — the build script's
/// dependency footprint MUST stay tiny. The substring check is
/// sufficient for the canonical raxis layout (the only string
/// `[workspace]` could appear in a non-workspace manifest is a
/// `# [workspace]`-prefixed comment, which we accept as a false
/// positive — the cost is one extra dir-walk hit which would only
/// matter on an exotic Cargo.toml hand-edit).
fn is_workspace_manifest(content: &str) -> bool {
    content.lines().any(|l| {
        l.trim_start_matches([' ', '\t'].as_ref())
            .starts_with("[workspace]")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_layout_matches_xtask_iter61() {
        let ws = Path::new("/ws");
        let dir = git_info_signing_key_dir(ws);
        assert_eq!(dir, PathBuf::from("/ws/.git/info/raxis-signing-key"));
        assert_eq!(
            sk_path(ws),
            PathBuf::from("/ws/.git/info/raxis-signing-key/sk.hex"),
        );
        assert_eq!(
            pk_path(ws),
            PathBuf::from("/ws/.git/info/raxis-signing-key/pk.hex"),
        );
    }

    #[test]
    fn first_run_mints_and_persists_under_dot_git_info() {
        let tmp = tempfile::tempdir().unwrap();
        // Pre-create `.git/` so `find_workspace_root_from` would
        // accept this dir if a caller used it. For the helper itself
        // the parent directory is sufficient.
        std::fs::create_dir_all(tmp.path().join(".git").join("info")).unwrap();

        let kp = ensure_dev_signing_keypair(tmp.path()).expect("first run mints");
        assert!(kp.generated_now, "first run must report generated_now=true");
        assert!(kp.sk_path.exists(), "sk.hex must land on disk");
        assert!(kp.pk_path.exists(), "pk.hex must land on disk");
        assert_eq!(kp.pk_hex.len(), KEY_LEN_HEX);
        assert!(
            kp.pk_hex
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "pk_hex must be lowercase hex"
        );
    }

    #[test]
    fn second_run_reuses_existing_keypair_byte_for_byte() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git").join("info")).unwrap();

        let first = ensure_dev_signing_keypair(tmp.path()).expect("first run");
        assert!(first.generated_now);

        let sk1 = std::fs::read_to_string(&first.sk_path).unwrap();
        let pk1 = std::fs::read_to_string(&first.pk_path).unwrap();

        let second = ensure_dev_signing_keypair(tmp.path()).expect("second run");
        assert!(
            !second.generated_now,
            "second run must report generated_now=false"
        );

        let sk2 = std::fs::read_to_string(&second.sk_path).unwrap();
        let pk2 = std::fs::read_to_string(&second.pk_path).unwrap();
        assert_eq!(sk1, sk2, "sk.hex must survive a second call byte-for-byte");
        assert_eq!(pk1, pk2, "pk.hex must survive a second call byte-for-byte");
        assert_eq!(first.pk_hex, second.pk_hex);
    }

    #[test]
    fn pk_hex_round_trips_to_signing_key() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git").join("info")).unwrap();

        let kp = ensure_dev_signing_keypair(tmp.path()).expect("first run");
        let sk_hex = std::fs::read_to_string(&kp.sk_path).unwrap();
        let trimmed = sk_hex.trim_matches(['\n', '\r', ' '].as_ref());
        let mut bytes = [0u8; KEY_LEN_BYTES];
        hex::decode_to_slice(trimmed, &mut bytes).unwrap();
        let derived_pk_hex = hex::encode(SigningKey::from_bytes(&bytes).verifying_key().to_bytes());
        assert_eq!(
            derived_pk_hex, kp.pk_hex,
            "pk.hex must be the verifying-key half of sk.hex"
        );
    }

    #[test]
    fn read_existing_pk_bytes_returns_none_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git").join("info")).unwrap();
        assert!(read_existing_pk_bytes(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn read_existing_pk_bytes_returns_bytes_after_mint() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git").join("info")).unwrap();
        let kp = ensure_dev_signing_keypair(tmp.path()).expect("mint");

        let bytes = read_existing_pk_bytes(tmp.path())
            .expect("no error")
            .expect("file is present after mint");
        assert_eq!(hex::encode(bytes), kp.pk_hex);
    }

    #[test]
    fn read_existing_pk_bytes_rejects_short_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = git_info_signing_key_dir(tmp.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(PK_FILENAME), "deadbeef\n").unwrap();
        let err = read_existing_pk_bytes(tmp.path()).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("is corrupt"), "got: {msg}");
    }

    #[test]
    fn read_existing_pk_bytes_rejects_non_hex() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = git_info_signing_key_dir(tmp.path());
        std::fs::create_dir_all(&dir).unwrap();
        // 64 chars but not lowercase hex (uppercase + non-hex).
        std::fs::write(
            dir.join(PK_FILENAME),
            format!("{}\n", "Z".repeat(KEY_LEN_HEX)),
        )
        .unwrap();
        let err = read_existing_pk_bytes(tmp.path()).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("is corrupt"), "got: {msg}");
    }

    #[cfg(unix)]
    #[test]
    fn first_run_files_have_secure_modes_and_pk_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git").join("info")).unwrap();
        let kp = ensure_dev_signing_keypair(tmp.path()).unwrap();

        let dir = git_info_signing_key_dir(tmp.path());
        let sk_mode = std::fs::metadata(&kp.sk_path).unwrap().permissions().mode() & 0o777;
        let pk_mode = std::fs::metadata(&kp.pk_path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            sk_mode, 0o600,
            "sk.hex must be mode 0600 (only the owner reads the private half)"
        );
        // iter62 hardening — uniform 0600 across both halves; pin
        // the contract so a future "loosen pk.hex back to 0644"
        // refactor trips this witness.
        assert_eq!(
            pk_mode, 0o600,
            "pk.hex must be mode 0600 (uniform with sk.hex per iter62; \
             a future widening must update INV-IMAGE-DEV-SIGNING-KEY-AUTOGEN-01)"
        );
        assert_eq!(
            dir_mode, 0o700,
            "raxis-signing-key/ dir must be mode 0700 (no other users may \
             see the private half through the parent dir's listing)"
        );
    }

    /// Iter62 chmod-at-write witness: both files MUST land on disk
    /// with the secure mode bits set BEFORE the function returns to
    /// its caller. Pins the chmod-after-write order so a future
    /// refactor that splits write + chmod into separate phases
    /// cannot leave a window where another process could `open()`
    /// the just-published file at a wider umask-derived mode.
    #[cfg(unix)]
    #[test]
    fn first_run_chmod_lands_before_function_returns() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git").join("info")).unwrap();
        let kp = ensure_dev_signing_keypair(tmp.path()).unwrap();
        // Re-stat from scratch so we are reading the on-disk
        // perms, not anything cached on the returned struct.
        let sk_meta = std::fs::metadata(&kp.sk_path).expect("sk.hex on disk");
        let pk_meta = std::fs::metadata(&kp.pk_path).expect("pk.hex on disk");
        assert_eq!(sk_meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(pk_meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn find_workspace_root_walks_up_to_workspace_manifest() {
        // Canonical layout: the workspace's Cargo.toml is the marker;
        // a sibling `.git/` is NOT required (the workspace may live
        // under an outer git checkout, e.g. raxis's `<repo>/raxis/`
        // workspace under `<repo>/.git/`).
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("workspace");
        let inner = ws.join("crates").join("foo").join("src");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(
            ws.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/foo\"]\n",
        )
        .unwrap();
        // Per-package manifest along the walk; MUST NOT short-circuit
        // because it has no `[workspace]` header.
        std::fs::write(
            ws.join("crates").join("foo").join("Cargo.toml"),
            "[package]\nname = \"foo\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        let found = find_workspace_root_from(&inner).expect("workspace found");
        assert_eq!(
            found.canonicalize().unwrap(),
            ws.canonicalize().unwrap(),
            "must walk up to the dir whose Cargo.toml contains [workspace]"
        );
    }

    #[test]
    fn find_workspace_root_returns_none_when_no_workspace_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let inner = tmp.path().join("crates").join("foo").join("src");
        std::fs::create_dir_all(&inner).unwrap();
        // Per-package manifest only; no [workspace] anywhere up the
        // tree (the `cargo publish`-staged extract case).
        std::fs::write(
            tmp.path().join("crates").join("foo").join("Cargo.toml"),
            "[package]\nname = \"foo\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        assert!(find_workspace_root_from(&inner).is_none());
    }

    #[test]
    fn find_workspace_root_skips_commented_workspace_marker() {
        // Hand-edited Cargo.toml with `# [workspace]` in a comment
        // SHOULD also short-circuit (we accept the false positive in
        // the substring check; pin the contract so a future tightening
        // would have to update this witness).
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(
            ws.join("Cargo.toml"),
            "# [workspace] — TODO uncomment\n[package]\nname=\"x\"\nversion=\"0\"\n",
        )
        .unwrap();
        // The commented-out marker still trips the substring check
        // because `# [workspace]` after trim_start passes
        // `starts_with("[workspace]")` only if `#` is stripped —
        // which it is NOT. Pin the negative behaviour.
        assert!(
            find_workspace_root_from(&ws).is_none(),
            "lines starting with `# ` are NOT treated as workspace markers"
        );
    }
}
