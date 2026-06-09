//! Embedded-gateway feature flag.
//!
//! When the `embedded-gateway` Cargo feature is enabled (release
//! builds; CI configures `RAXIS_GATEWAY_BINARY=...` at compile
//! time), the `raxis-gateway` binary is baked into the kernel
//! ELF/Mach-O as a `&'static [u8]` and materialised at boot to
//! a kernel-private directory. The supervisor then spawns from
//! that path instead of `policy.gateway.binary_path`.
//!
//! When the feature is **off** (default; `cargo build` for dev),
//! this module exposes a no-op `materialize` that returns
//! `Ok(None)`, so the supervisor falls back to the configured
//! external `binary_path` — the historical fast-iteration path.
//!
//! # Threat model
//!
//! `peripherals.md §3.2` already restricts gateway spawning to a
//! single kernel-supervised subprocess with a fresh per-spawn auth
//! token. This module closes the residual gap that an attacker
//! with write access to `binary_path` (a separate file on disk)
//! could swap a tampered binary between the kernel's existence
//! check and its `Command::new`. By embedding the bytes in the
//! kernel binary itself we collapse the trust boundary down to
//! whatever ships the kernel — code signing, dm-verity, IMA, etc.
//! are all V3 concerns layered on top.
//!
//! # On-disk layout
//!
//! When the feature is on the materialiser writes
//! `<data_dir>/runtime/embedded-gateway/raxis-gateway` with mode
//! `0500` inside a parent directory at mode `0700`. We atomically
//! rewrite the file every kernel boot so a kernel upgrade implicitly
//! replaces the materialised binary; no separate upgrade dance.
//!
//! Linux `memfd_create` would let us avoid the on-disk hop
//! entirely, but it requires kernel 3.17+ and complicates macOS
//! parity (no equivalent primitive). The on-disk hop in a
//! kernel-private directory is the V2 floor; `memfd_create` /
//! macOS `fcntl(F_NOCACHE)` are V3.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Compile-time-embedded gateway bytes. `None` when the
/// `embedded-gateway` feature is off, so the supervisor falls
/// back to the external `binary_path`.
#[cfg(feature = "embedded-gateway")]
const EMBEDDED_GATEWAY_BYTES: Option<&'static [u8]> =
    Some(include_bytes!(env!("RAXIS_GATEWAY_BINARY")));

#[cfg(not(feature = "embedded-gateway"))]
const EMBEDDED_GATEWAY_BYTES: Option<&'static [u8]> = None;

/// Errors materialising the embedded gateway. Currently only
/// I/O — the bytes are validated at compile time by `include_bytes!`.
#[derive(thiserror::Error, Debug)]
pub enum MaterializeError {
    #[error("create gateway dir at {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("write gateway bytes to {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("set permissions on {path}: {source}")]
    Permissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Materialise the embedded gateway under
/// `<data_dir>/runtime/embedded-gateway/raxis-gateway` and return
/// the absolute path. Returns `Ok(None)` when the feature is off
/// (caller falls back to the configured external binary).
///
/// Idempotent across boots — the parent directory is recreated
/// with `0700` mode, the file is overwritten with the embedded
/// bytes, and the executable bit is set fresh. We do **not** try
/// to detect "bytes already match" and skip the write: the cost
/// of a one-time disk write at boot is negligible and the
/// "always overwrite" rule eliminates the question of "what if
/// the operator manually replaced the file mid-run". The kernel
/// supervisor calls this exactly once at startup, before
/// `spawn_and_supervise`.
pub fn materialize(data_dir: &Path) -> Result<Option<PathBuf>, MaterializeError> {
    let bytes = match EMBEDDED_GATEWAY_BYTES {
        Some(b) => b,
        None => return Ok(None),
    };

    let dir = data_dir.join("runtime").join("embedded-gateway");
    std::fs::create_dir_all(&dir).map_err(|e| MaterializeError::CreateDir {
        path: dir.clone(),
        source: e,
    })?;
    set_dir_mode_0700(&dir)?;

    let bin = dir.join("raxis-gateway");
    write_executable_atomically(&dir, &bin, bytes)?;

    Ok(Some(bin))
}

fn write_executable_atomically(
    dir: &Path,
    bin: &Path,
    bytes: &[u8],
) -> Result<(), MaterializeError> {
    let tmp = dir.join(format!(
        ".raxis-gateway.tmp.{}.{}",
        std::process::id(),
        unique_temp_suffix()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| MaterializeError::Write {
                path: tmp.clone(),
                source: e,
            })?;
        file.write_all(bytes).map_err(|e| MaterializeError::Write {
            path: tmp.clone(),
            source: e,
        })?;
        file.sync_all().map_err(|e| MaterializeError::Write {
            path: tmp.clone(),
            source: e,
        })?;
        set_file_mode_0500(&tmp)?;
        drop(file);
        std::fs::rename(&tmp, bin).map_err(|e| MaterializeError::Write {
            path: bin.to_path_buf(),
            source: e,
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn unique_temp_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(unix)]
fn set_dir_mode_0700(path: &Path) -> Result<(), MaterializeError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms).map_err(|e| MaterializeError::Permissions {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(unix)]
fn set_file_mode_0500(path: &Path) -> Result<(), MaterializeError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o500);
    std::fs::set_permissions(path, perms).map_err(|e| MaterializeError::Permissions {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_path: &Path) -> Result<(), MaterializeError> {
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode_0500(_path: &Path) -> Result<(), MaterializeError> {
    Ok(())
}

/// True when the kernel was compiled with the embedded gateway
/// blob. Surfaces in boot logs and `raxis doctor` so operators
/// can confirm which build mode they are running.
pub const fn is_embedded() -> bool {
    EMBEDDED_GATEWAY_BYTES.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialize_off_returns_none() {
        if is_embedded() {
            // When CI builds with the feature on this test is a no-op
            // for the negative case; the positive-case test below
            // covers the flag.
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let out = materialize(tmp.path()).unwrap();
        assert!(out.is_none());
    }

    #[cfg(feature = "embedded-gateway")]
    #[test]
    fn materialize_on_writes_executable() {
        let tmp = tempfile::tempdir().unwrap();
        let p = materialize(tmp.path()).unwrap().expect("path");
        let md = std::fs::metadata(&p).unwrap();
        assert!(md.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(md.permissions().mode() & 0o7777, 0o500);
        }
    }

    #[cfg(unix)]
    #[test]
    fn atomic_rewrite_repairs_execute_only_existing_gateway() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("runtime").join("embedded-gateway");
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("raxis-gateway");
        std::fs::write(&bin, b"old").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o500)).unwrap();

        write_executable_atomically(&dir, &bin, b"new").unwrap();

        assert_eq!(std::fs::read(&bin).unwrap(), b"new");
        let mode = std::fs::metadata(&bin).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o500);
    }
}
