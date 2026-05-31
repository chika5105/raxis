// raxis-cli::commands::dashboard — Dashboard-side maintenance
// commands.
//
// Spec: `specs/v2/self-healing-supervisor.md §10` (Operator session
// continuity across supervisor-triggered restarts) and
// `specs/v2/dashboard-hardening.md
// §INV-DASHBOARD-JWT-SECRET-PERSISTENT-01`.
//
// **Why this module exists.** Once the dashboard's HS256 signing
// secret moved on-disk to `<data_dir>/auth/dashboard_jwt.secret`,
// operators needed an explicit "kick everyone out" lever they could
// pull after a suspected secret compromise — without having to wait
// for every operator JWT to expire (1h default TTL) or to delete the
// secret file by hand and restart the kernel. Rotation:
//
//   1. Bumps the persisted `secret_generation` counter (1 → 2 → ...).
//   2. Mints a fresh 32-byte HMAC key.
//   3. Atomically replaces the secret file (`0600`).
//
// The next request a pre-rotation operator sends arrives with a JWT
// whose `gen` claim no longer matches the live signer's generation,
// so `JwtSigner::verify` rejects it with `InvalidJwt` and the
// dashboard middleware bounces the operator to `/login`. The
// HMAC alone would already reject the token (the secret bytes
// changed), but the explicit `gen` check is a defence-in-depth lane
// against any future change that re-uses secret bytes (e.g. a
// hypothetical key-derivation scheme on top of a long-lived root
// secret).
//
// Wire shape:
//
//     $ raxis dashboard rotate-jwt-secret
//     ✓ rotated dashboard JWT signing secret
//     generation:  2
//     path:        /home/op/.raxis/auth/dashboard_jwt.secret
//
//     $ raxis dashboard rotate-jwt-secret --json
//     {
//       "ok": true,
//       "generation": 2,
//       "path": "/home/op/.raxis/auth/dashboard_jwt.secret"
//     }
//
// The command is intentionally NOT a kernel ceremony — it does not
// open `operator.sock`, does not require `--operator-key`, and works
// even when the kernel is not running. Rotation is a local
// file-system mutation under the data dir, which the operator
// already owns. A running kernel keeps using the in-memory secret
// it loaded at boot until its next restart, at which point it picks
// up the rotated file. Operators who want immediate rotation can
// `raxis-supervisor stop` then `raxis-supervisor start` (or kick
// the kernel directly with `SIGTERM`) after running this command.

#![forbid(unsafe_code)]

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use raxis_dashboard::jwt_secret;
use sha2::{Digest, Sha256};
use tar::EntryType;

use crate::errors::CliError;
use crate::GlobalFlags;

/// `raxis dashboard rotate-jwt-secret [--json]`. Bumps the
/// persisted `secret_generation` counter at
/// `<data_dir>/auth/dashboard_jwt.secret` and mints a fresh
/// 32-byte HMAC-SHA-256 key. Writes the file `0600` (auth dir
/// `0700`) on Unix.
///
/// Side effects: invalidates every pre-rotation operator JWT.
pub fn run_rotate_jwt_secret(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut json = false;
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown flag for `dashboard rotate-jwt-secret`: {other}"
                )));
            }
        }
    }

    let data_dir = flags.data_dir().clone();
    let path: PathBuf = jwt_secret::secret_path(&data_dir);
    // The `LoadError` variants surfaced by `jwt_secret::rotate` don't
    // map cleanly onto any single existing `CliError` variant — `Rng`
    // is closest to a crypto failure but the dashboard JWT secret is
    // not a `raxis_crypto::CryptoError`, and `Corrupt` /
    // `PermissionTighten` are about local file-system state rather
    // than cryptographic operations. We funnel everything except the
    // raw `Io` case through `CliError::Key`, which is already the
    // catch-all for "operator-facing key-management failure" and
    // takes a `String` payload — cheaper than introducing a new
    // variant for one CLI command.
    let rotated = jwt_secret::rotate(&data_dir).map_err(|e| match e {
        jwt_secret::LoadError::Io(io) => CliError::Io {
            path: path.display().to_string(),
            source: io,
        },
        jwt_secret::LoadError::Rng(msg) => CliError::Key(format!(
            "rng failure while minting fresh dashboard JWT secret: {msg}",
        )),
        jwt_secret::LoadError::Corrupt(msg) => CliError::Key(format!(
            "existing secret file at {} is corrupt: {msg} \
             (operator should remove the file and let the next \
              kernel boot mint a fresh one — note this WILL log out \
              every operator currently using the dashboard)",
            path.display(),
        )),
        jwt_secret::LoadError::PermissionTighten(msg) => CliError::Key(format!(
            "could not tighten permissions on the secret file: {msg}"
        )),
    })?;

    if json {
        let out = serde_json::json!({
            "ok": true,
            "generation": rotated.generation,
            "path": path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("✓ rotated dashboard JWT signing secret");
        println!("generation:  {}", rotated.generation);
        println!("path:        {}", path.display());
        println!();
        println!(
            "Every previously-issued operator JWT is now invalid. \
             Operators currently logged into the dashboard will be \
             bounced to /login on their next request. The running \
             kernel keeps using its in-memory secret until it next \
             restarts; restart the kernel (or run \
             `raxis-supervisor stop` then `raxis-supervisor start`) \
             to make rotation take effect immediately."
        );
    }
    Ok(())
}

/// `raxis dashboard install-bundle --from-file <bundle.tar.gz>
/// --sha256 <hex> [--json]`. Installs a verified dashboard static
/// bundle under `<data_dir>/dashboard/releases/<sha256>/dist` and
/// atomically points `<data_dir>/dashboard/current` at it.
///
/// This is the fast UI-only patch path. It intentionally requires an
/// explicit SHA-256 pin so the operator cannot accidentally hot-load
/// arbitrary JavaScript into an admin surface.
pub fn run_install_bundle(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut from_file: Option<PathBuf> = None;
    let mut expected_sha256: Option<String> = None;
    let mut json = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--from-file" => {
                i += 1;
                let Some(path) = args.get(i) else {
                    return Err(CliError::Usage(
                        "`dashboard install-bundle --from-file` requires a path".to_owned(),
                    ));
                };
                from_file = Some(PathBuf::from(path));
            }
            "--sha256" => {
                i += 1;
                let Some(sha) = args.get(i) else {
                    return Err(CliError::Usage(
                        "`dashboard install-bundle --sha256` requires a 64-char hex digest"
                            .to_owned(),
                    ));
                };
                expected_sha256 = Some(sha.to_owned());
            }
            "--json" => json = true,
            "--help" | "-h" => {
                print_install_bundle_help();
                return Ok(());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown flag for `dashboard install-bundle`: {other}"
                )));
            }
        }
        i += 1;
    }

    let from_file = from_file.ok_or_else(|| {
        CliError::Usage(
            "`dashboard install-bundle` requires --from-file <bundle.tar.gz>".to_owned(),
        )
    })?;
    let expected_sha256 = expected_sha256.ok_or_else(|| {
        CliError::Usage("`dashboard install-bundle` requires --sha256 <hex>".to_owned())
    })?;
    validate_sha256_hex(&expected_sha256)?;
    let expected_sha256 = expected_sha256.to_ascii_lowercase();

    let actual_sha256 = sha256_file(&from_file)?;
    if actual_sha256 != expected_sha256 {
        return Err(CliError::Key(format!(
            "dashboard bundle SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )));
    }

    let data_dir = flags.data_dir().clone();
    let dashboard_dir = data_dir.join("dashboard");
    let releases_dir = dashboard_dir.join("releases");
    let release_dir = releases_dir.join(&actual_sha256);
    let release_dist = release_dir.join("dist");
    let current = dashboard_dir.join("current");
    let temp_root = dashboard_dir.join(format!(
        ".install-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let extract_dir = temp_root.join("extract");
    let staged_dir = temp_root.join("release");
    fs::create_dir_all(&extract_dir).map_err(|source| CliError::Io {
        path: extract_dir.display().to_string(),
        source,
    })?;

    let result = (|| {
        extract_dashboard_bundle(&from_file, &extract_dir)?;
        let dist = locate_dashboard_dist(&extract_dir)?;

        if release_dir.exists() {
            fs::remove_dir_all(&release_dir).map_err(|source| CliError::Io {
                path: release_dir.display().to_string(),
                source,
            })?;
        }
        fs::create_dir_all(&staged_dir).map_err(|source| CliError::Io {
            path: staged_dir.display().to_string(),
            source,
        })?;
        copy_dir_recursively(&dist, &staged_dir.join("dist"))?;
        fs::create_dir_all(&releases_dir).map_err(|source| CliError::Io {
            path: releases_dir.display().to_string(),
            source,
        })?;
        fs::rename(&staged_dir, &release_dir).map_err(|source| CliError::Io {
            path: format!("{} -> {}", staged_dir.display(), release_dir.display()),
            source,
        })?;
        replace_current_link(&current, &release_dist)?;
        Ok::<(), CliError>(())
    })();

    let cleanup = fs::remove_dir_all(&temp_root);
    if let Err(err) = cleanup {
        if err.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "warning: could not remove temporary dashboard bundle directory {}: {}",
                temp_root.display(),
                err
            );
        }
    }
    result?;

    if json {
        let out = serde_json::json!({
            "ok": true,
            "sha256": actual_sha256,
            "release_dir": release_dir.display().to_string(),
            "current": current.display().to_string(),
            "served_after_restart": true,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("✓ installed dashboard bundle");
        println!("sha256:      {}", actual_sha256);
        println!("release:     {}", release_dir.display());
        println!("current:     {}", current.display());
        println!();
        println!(
            "Restart raxis-supervisor if the running kernel was not already \
             serving this data-dir dashboard override. New kernel starts prefer \
             <data_dir>/dashboard/current over the packaged static bundle."
        );
    }
    Ok(())
}

fn validate_sha256_hex(value: &str) -> Result<(), CliError> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(CliError::Usage(format!(
        "invalid --sha256 value {value:?}; expected 64 hexadecimal characters"
    )))
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let mut f = fs::File::open(path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|source| CliError::Io {
            path: path.display().to_string(),
            source,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn extract_dashboard_bundle(archive_path: &Path, dest: &Path) -> Result<(), CliError> {
    let file = fs::File::open(archive_path).map_err(|source| CliError::Io {
        path: archive_path.display().to_string(),
        source,
    })?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|source| CliError::Io {
        path: archive_path.display().to_string(),
        source,
    })?;

    for entry in entries {
        let mut entry = entry.map_err(|source| CliError::Io {
            path: archive_path.display().to_string(),
            source,
        })?;
        let ty = entry.header().entry_type();
        if ty == EntryType::Symlink || ty == EntryType::Link {
            return Err(CliError::Key(format!(
                "dashboard bundle contains a link entry, which is not allowed: {:?}",
                entry.path().ok()
            )));
        }
        if !(ty.is_file() || ty.is_dir()) {
            continue;
        }
        let rel = entry.path().map_err(|source| CliError::Io {
            path: archive_path.display().to_string(),
            source,
        })?;
        ensure_relative_archive_path(&rel)?;
        let out = dest.join(&rel);
        if ty.is_dir() {
            fs::create_dir_all(&out).map_err(|source| CliError::Io {
                path: out.display().to_string(),
                source,
            })?;
        } else {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent).map_err(|source| CliError::Io {
                    path: parent.display().to_string(),
                    source,
                })?;
            }
            entry.unpack(&out).map_err(|source| CliError::Io {
                path: out.display().to_string(),
                source,
            })?;
        }
    }
    Ok(())
}

fn ensure_relative_archive_path(path: &Path) -> Result<(), CliError> {
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CliError::Key(format!(
                    "dashboard bundle contains unsafe archive path: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn locate_dashboard_dist(extract_dir: &Path) -> Result<PathBuf, CliError> {
    let candidates = [
        extract_dir.join("dist"),
        extract_dir.to_path_buf(),
        extract_dir.join("dashboard").join("dist"),
    ];
    for candidate in candidates {
        if candidate.join("index.html").is_file() {
            return Ok(candidate);
        }
    }

    for entry in fs::read_dir(extract_dir).map_err(|source| CliError::Io {
        path: extract_dir.display().to_string(),
        source,
    })? {
        let entry = entry.map_err(|source| CliError::Io {
            path: extract_dir.display().to_string(),
            source,
        })?;
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        for candidate in [path.join("dist"), path] {
            if candidate.join("index.html").is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(CliError::Key(
        "dashboard bundle does not contain an index.html at dist/index.html".to_owned(),
    ))
}

fn copy_dir_recursively(src: &Path, dst: &Path) -> Result<(), CliError> {
    fs::create_dir_all(dst).map_err(|source| CliError::Io {
        path: dst.display().to_string(),
        source,
    })?;
    for entry in fs::read_dir(src).map_err(|source| CliError::Io {
        path: src.display().to_string(),
        source,
    })? {
        let entry = entry.map_err(|source| CliError::Io {
            path: src.display().to_string(),
            source,
        })?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ty = entry.file_type().map_err(|source| CliError::Io {
            path: from.display().to_string(),
            source,
        })?;
        if ty.is_symlink() {
            return Err(CliError::Key(format!(
                "dashboard bundle contains symlink after extraction: {}",
                from.display()
            )));
        }
        if ty.is_dir() {
            copy_dir_recursively(&from, &to)?;
        } else if ty.is_file() {
            fs::copy(&from, &to).map_err(|source| CliError::Io {
                path: format!("{} -> {}", from.display(), to.display()),
                source,
            })?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn replace_current_link(current: &Path, release_dist: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::symlink;

    if let Some(parent) = current.parent() {
        fs::create_dir_all(parent).map_err(|source| CliError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let tmp = current.with_file_name(format!(
        ".current.tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let _ = fs::remove_file(&tmp);
    symlink(release_dist, &tmp).map_err(|source| CliError::Io {
        path: format!("{} -> {}", tmp.display(), release_dist.display()),
        source,
    })?;
    if current.exists() || current.symlink_metadata().is_ok() {
        let meta = current.symlink_metadata().map_err(|source| CliError::Io {
            path: current.display().to_string(),
            source,
        })?;
        if meta.is_dir() && !meta.file_type().is_symlink() {
            fs::remove_dir_all(current).map_err(|source| CliError::Io {
                path: current.display().to_string(),
                source,
            })?;
        } else {
            fs::remove_file(current).map_err(|source| CliError::Io {
                path: current.display().to_string(),
                source,
            })?;
        }
    }
    fs::rename(&tmp, current).map_err(|source| CliError::Io {
        path: format!("{} -> {}", tmp.display(), current.display()),
        source,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn replace_current_link(current: &Path, release_dist: &Path) -> Result<(), CliError> {
    if current.exists() {
        fs::remove_dir_all(current).map_err(|source| CliError::Io {
            path: current.display().to_string(),
            source,
        })?;
    }
    copy_dir_recursively(release_dist, current)
}

fn print_help() {
    println!(
        r#"raxis dashboard rotate-jwt-secret — Rotate the dashboard's HS256 signing secret

USAGE:
    raxis [--data-dir <path>] dashboard rotate-jwt-secret [--json]

WHAT IT DOES:
    Bumps the secret_generation counter and mints a fresh 32-byte
    signing key at <data_dir>/auth/dashboard_jwt.secret. Every
    pre-rotation operator JWT immediately fails verification (the
    `gen` claim no longer matches the live signer's generation).

WHEN TO USE IT:
    * Suspected dashboard compromise — explicit "kick everyone out".
    * Periodic key hygiene (no schedule mandated; spec recommends
      after any operator-cert revocation event).

SAFETY:
    * Local file-system mutation only. Does not open operator.sock.
    * Does not require --operator-key.
    * Writes the file 0600 (auth dir 0700) on Unix.

NOTE:
    The running kernel keeps using its in-memory secret until it next
    restarts. To make rotation take effect immediately, restart the
    kernel after running this command (e.g. via
    `raxis-supervisor stop` followed by `raxis-supervisor start`).
"#
    );
}

fn print_install_bundle_help() {
    println!(
        r#"raxis dashboard install-bundle — Install a verified dashboard UI bundle

USAGE:
    raxis [--data-dir <path>] dashboard install-bundle \
      --from-file <dashboard.tar.gz> \
      --sha256 <64-hex> \
      [--json]

WHAT IT DOES:
    Verifies the tar.gz with SHA-256, extracts only regular files and
    directories, rejects unsafe archive paths and links, installs the
    dashboard at <data_dir>/dashboard/releases/<sha256>/dist, then
    points <data_dir>/dashboard/current at that release.

WHY SHA-256 IS REQUIRED:
    The dashboard is an operator admin surface. Fast UI-only patches
    are useful, but RAXIS still requires an explicit integrity pin
    before serving new JavaScript.

NOTE:
    Restart raxis-supervisor after install unless the running kernel
    was already serving <data_dir>/dashboard/current.
"#
    );
}
