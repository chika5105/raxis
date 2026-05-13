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

use std::path::PathBuf;

use raxis_dashboard::jwt_secret;

use crate::errors::CliError;
use crate::GlobalFlags;

/// `raxis dashboard rotate-jwt-secret [--json]`. Bumps the
/// persisted `secret_generation` counter at
/// `<data_dir>/auth/dashboard_jwt.secret` and mints a fresh
/// 32-byte HMAC-SHA-256 key. Writes the file `0600` (auth dir
/// `0700`) on Unix.
///
/// Side effects: invalidates every pre-rotation operator JWT.
pub fn run_rotate_jwt_secret(
    flags: &GlobalFlags,
    args: &[String],
) -> Result<(), CliError> {
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
