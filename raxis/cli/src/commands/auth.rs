// raxis-cli::commands::auth — Operator authentication helpers.
//
// Spec: raxis/specs/v2/v2_extended_gaps.md §4.2 — operator dashboard
// challenge-response auth. The dashboard's `Login` page asks the
// operator to run `raxis auth sign <challenge>` from their terminal,
// then paste the resulting signature + public key back into the
// browser. The private key NEVER enters the browser; this command is
// the bridge that lets the operator sign a kernel-issued challenge
// without uploading the key to a remote service.
//
// Wire shape:
//
//     $ raxis auth sign <challenge-hex>
//     # OR (when --json):
//     $ raxis auth sign --json <challenge-hex>
//
//     ✓ Signed challenge with operator key
//     challenge:   <64 hex chars>
//     public_key:  <64 hex chars>
//     signature:   <128 hex chars>
//
// JSON form is the same fields under one object so the operator can
// pipe through `jq` or feed the dashboard programmatically.
//
// Defence-in-depth:
//   * The challenge is decoded as 32-byte hex BEFORE signing — a
//     mistyped (odd-length, non-hex) input fails fast at the CLI
//     boundary instead of silently signing the wrong bytes.
//   * The signature output is the raw Ed25519 signature over the
//     challenge bytes (NOT a domain-separated wrapper). This matches
//     what `raxis_crypto::verify_ed25519` accepts on the kernel side
//     in `dashboard/src/routes/auth.rs::verify`.

use std::path::PathBuf;

use crate::errors::CliError;
use crate::signing::{load_operator_key, sign_bytes};
use crate::GlobalFlags;

/// Length of a hex-encoded 32-byte challenge.
const CHALLENGE_HEX_LEN: usize = 64;

/// `raxis auth sign [--json] <challenge-hex>`. The top-level
/// `auth` dispatcher in `main.rs` routes directly to this
/// function — we deliberately do NOT introduce a per-module
/// `pub fn run` shim, because every other `commands::*` module
/// uses the same per-subcommand dispatch and we want the
/// catalog tests to keep their single source of truth.
pub fn run_sign(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let mut json = false;
    let mut challenge_hex: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                print_sign_help();
                return Ok(());
            }
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag for `auth sign`: {other}"
                )));
            }
            other => {
                if challenge_hex.is_some() {
                    return Err(CliError::Usage(
                        "auth sign accepts a single positional <challenge-hex>".to_owned(),
                    ));
                }
                challenge_hex = Some(other.to_owned());
            }
        }
        i += 1;
    }

    let challenge_hex = challenge_hex.ok_or_else(|| {
        CliError::Usage(
            "auth sign <challenge-hex> is required (run `raxis auth sign --help`)".to_owned(),
        )
    })?;

    if challenge_hex.len() != CHALLENGE_HEX_LEN {
        return Err(CliError::Usage(format!(
            "challenge must be {CHALLENGE_HEX_LEN} hex characters (got {})",
            challenge_hex.len(),
        )));
    }
    let challenge_bytes = hex::decode(&challenge_hex).map_err(|e| {
        CliError::Usage(format!("challenge is not valid hex: {e}"))
    })?;

    let key_path: PathBuf = flags.operator_key_path.clone().ok_or_else(|| {
        CliError::Usage(
            "--operator-key <path> (or RAXIS_OPERATOR_KEY env) is required".to_owned(),
        )
    })?;

    let signing_key = load_operator_key(&key_path)?;
    let pubkey = signing_key.verifying_key().to_bytes();
    let signature_hex = sign_bytes(&signing_key, &challenge_bytes);
    let pubkey_hex = hex::encode(pubkey);

    if json {
        let body = serde_json::json!({
            "challenge":  challenge_hex,
            "public_key": pubkey_hex,
            "signature":  signature_hex,
        });
        println!("{body}");
    } else {
        println!("✓ Signed challenge with operator key");
        println!("  challenge:   {challenge_hex}");
        println!("  public_key:  {pubkey_hex}");
        println!("  signature:   {signature_hex}");
    }
    Ok(())
}

fn print_sign_help() {
    println!(
        "Usage: raxis auth sign [--json] <challenge-hex>\n\n\
         Sign a 32-byte hex challenge issued by the operator dashboard's\n\
         GET /api/auth/challenge endpoint. Output the operator's public\n\
         key + Ed25519 signature so the dashboard can complete the\n\
         POST /api/auth/verify call without ever seeing the private key.\n\n\
         Flags:\n  \
           --json       Emit JSON with `challenge`, `public_key`, `signature`.\n  \
           --help / -h  Print this help.\n\n\
         Required globals:\n  \
           --operator-key <path>   PKCS#8 PEM or 32-byte hex seed of the operator's Ed25519 key."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn temp_key() -> (tempfile::NamedTempFile, [u8; 32]) {
        // Deterministic seed so the test asserts on stable bytes.
        let seed = [0xCDu8; 32];
        let pem = format!("{}\n", hex::encode(seed));
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(f.path(), pem.as_bytes()).expect("write key");
        (f, seed)
    }

    #[test]
    fn rejects_short_challenge() {
        let (key_file, _) = temp_key();
        let flags = GlobalFlags {
            data_dir: PathBuf::from("/tmp"),
            socket_path: None,
            operator_key_path: Some(key_file.path().to_path_buf()),
        };
        let err = run_sign(&flags, &["abcd".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn rejects_non_hex_challenge() {
        let (key_file, _) = temp_key();
        let flags = GlobalFlags {
            data_dir: PathBuf::from("/tmp"),
            socket_path: None,
            operator_key_path: Some(key_file.path().to_path_buf()),
        };
        let err = run_sign(
            &flags,
            &["g".repeat(64)],
        ).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn signed_challenge_verifies_against_real_pubkey() {
        // Round-trip through the same `raxis_crypto::verify_ed25519`
        // path the dashboard's `routes::auth::verify` uses.
        let (key_file, seed) = temp_key();
        let flags = GlobalFlags {
            data_dir: PathBuf::from("/tmp"),
            socket_path: None,
            operator_key_path: Some(key_file.path().to_path_buf()),
        };
        let challenge_bytes = [0x42u8; 32];
        let challenge_hex = hex::encode(challenge_bytes);

        // Replicate the run_sign body so we can capture the signature
        // (the CLI prints to stdout; we don't capture stdout in
        // unit tests). Using the same load+sign primitives ensures
        // test parity.
        let signing_key = load_operator_key(&flags.operator_key_path.clone().unwrap()).unwrap();
        let sig_hex = sign_bytes(&signing_key, &challenge_bytes);

        // Sanity: the seed we wrote produces the same pubkey as the
        // dalek SigningKey loaded from the file.
        let pk_dalek = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(signing_key.verifying_key().to_bytes(), pk_dalek);

        // The CLI's signature must verify under the dashboard's
        // crypto helper.
        let sig_bytes = hex::decode(&sig_hex).unwrap();
        raxis_crypto::verify_ed25519(&pk_dalek, &challenge_bytes, &sig_bytes).expect("verify");

        // Also exercise the public CLI entry-point so we cover the
        // arg-parsing happy path.
        run_sign(&flags, &[challenge_hex]).expect("run_sign");
    }
}
