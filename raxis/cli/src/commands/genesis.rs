// raxis-cli::commands::genesis — Genesis key ceremony.
//
// Normative reference: cli-ceremony.md §4.1 `genesis`, §4.2 step-by-step.
//
// Generates all key families and writes initial policy.toml.
// Does NOT start the kernel.

use std::fs;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use raxis_crypto::token::try_random_array;

use crate::errors::CliError;
use crate::GlobalFlags;

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    // Parse genesis-specific flags.
    let mut force = false;
    let mut operator_pubkey_path: Option<PathBuf> = None;
    let mut rotate_family: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--force" => force = true,
            "--operator-pubkey" => {
                i += 1;
                operator_pubkey_path = Some(PathBuf::from(
                    args.get(i).ok_or_else(|| {
                        CliError::Usage("--operator-pubkey requires a path".to_owned())
                    })?,
                ));
            }
            "--rotate" => {
                i += 1;
                rotate_family = Some(
                    args.get(i)
                        .ok_or_else(|| CliError::Usage("--rotate requires a key family".to_owned()))?
                        .clone(),
                );
            }
            other => return Err(CliError::Usage(format!("unknown genesis flag: {other:?}"))),
        }
        i += 1;
    }

    if let Some(family) = rotate_family {
        return run_rotate(flags, &family);
    }

    run_genesis(flags, force, operator_pubkey_path)
}

// ---------------------------------------------------------------------------
// Full genesis ceremony
// ---------------------------------------------------------------------------

fn run_genesis(
    flags: &GlobalFlags,
    force: bool,
    operator_pubkey_path: Option<PathBuf>,
) -> Result<(), CliError> {
    let data_dir = flags.data_dir();
    let keys_dir = data_dir.join("keys");
    let policy_dir = data_dir.join("policy");

    // Step 1: Check for existing key files.
    let authority_key_path = keys_dir.join("authority_keypair.pem");
    if authority_key_path.exists() && !force {
        return Err(CliError::Usage(
            "ERR_ALREADY_INITIALIZED: data directory already contains key files. \
             Use --force to overwrite (WARNING: this destroys existing keys)."
                .to_owned(),
        ));
    }

    // Create directories.
    fs::create_dir_all(&keys_dir).map_err(|e| CliError::Io {
        path: keys_dir.display().to_string(),
        source: e,
    })?;
    fs::create_dir_all(&policy_dir).map_err(|e| CliError::Io {
        path: policy_dir.display().to_string(),
        source: e,
    })?;
    fs::create_dir_all(data_dir.join("sockets")).map_err(|e| CliError::Io {
        path: data_dir.join("sockets").display().to_string(),
        source: e,
    })?;
    fs::create_dir_all(data_dir.join("audit")).map_err(|e| CliError::Io {
        path: data_dir.join("audit").display().to_string(),
        source: e,
    })?;

    // Step 2: Generate authority_keypair (Ed25519). RNG failure aborts the
    // ceremony (cli-ceremony.md §4.2 step 2 — "fail closed").
    let authority_seed: [u8; 32] = try_random_array()?;
    let authority_key = SigningKey::from_bytes(&authority_seed);
    let authority_pubkey_hex = hex::encode(authority_key.verifying_key().to_bytes());
    write_key_pem(&authority_key_path, &authority_key)?;
    println!("✓ Generated authority_keypair → {}", authority_key_path.display());

    // Step 3: Generate quality_keypair (Ed25519).
    let quality_key_path = keys_dir.join("quality_keypair.pem");
    let quality_seed: [u8; 32] = try_random_array()?;
    let quality_key = SigningKey::from_bytes(&quality_seed);
    let quality_pubkey_hex = hex::encode(quality_key.verifying_key().to_bytes());
    write_key_pem(&quality_key_path, &quality_key)?;
    println!("✓ Generated quality_keypair → {}", quality_key_path.display());

    // Step 4: Generate verifier_token_key (32 CSPRNG bytes).
    let vtk_path = keys_dir.join("verifier_token_key.bin");
    let vtk: [u8; 32] = try_random_array()?;
    fs::write(&vtk_path, vtk).map_err(|e| CliError::Io {
        path: vtk_path.display().to_string(),
        source: e,
    })?;
    set_permissions_600(&vtk_path);
    println!("✓ Generated verifier_token_key → {}", vtk_path.display());

    // Step 5: Operator public key handling.
    let (operator_pubkey_hex, operator_fingerprint) = match operator_pubkey_path {
        Some(ref path) => load_operator_pubkey(path)?,
        None => prompt_operator_pubkey()?,
    };

    let operator_pub_path = keys_dir.join(format!("operator_{operator_fingerprint}.pub"));
    fs::write(&operator_pub_path, &operator_pubkey_hex).map_err(|e| CliError::Io {
        path: operator_pub_path.display().to_string(),
        source: e,
    })?;
    println!("✓ Registered operator pubkey → {}", operator_pub_path.display());

    // Step 6: Write initial policy.toml via the shared writer.
    //
    // All formatting decisions — the 13 permitted_ops, the four
    // canonical IntentKind budget keys, the default `[[lanes]]` entry,
    // and the operator-friendly comment header — live in
    // `raxis_genesis_tools::render_genesis_policy_toml`. The same emitter
    // is invoked by the kernel-side `bootstrap::write_genesis_policy`, so
    // the two paths cannot drift again. See
    // `crates/genesis-tools/src/lib.rs` for the drift history.
    //
    // The placeholder `allowed_worktree_roots` is `<data_dir>/worktrees`:
    //   - Non-empty (required — `raxis_policy::PolicyBundle::validate`
    //     rejects empty allowlists with `MalformedArtifact`).
    //   - Scoped to the operator's chosen data directory (no silent grant
    //     of access to `/home/operator/work` or any other path the
    //     operator did not opt into).
    // The shared emitter writes a TOML comment directing the operator to
    // replace this before creating sessions.
    let placeholder_worktree = data_dir.join("worktrees");
    let placeholder_worktree_str = placeholder_worktree.display().to_string();
    let allowed_worktree_roots: [&str; 1] = [placeholder_worktree_str.as_str()];

    let policy_path = policy_dir.join("policy.toml");
    let signed_at_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let policy_toml = raxis_genesis_tools::render_genesis_policy_toml(
        raxis_genesis_tools::GenesisPolicyInputs {
            authority_pubkey_hex:   &authority_pubkey_hex,
            quality_pubkey_hex:     &quality_pubkey_hex,
            operator_pubkey_hex:    &operator_pubkey_hex,
            operator_fingerprint:   &operator_fingerprint,
            signed_at_unix_secs,
            allowed_worktree_roots: &allowed_worktree_roots,
        },
    );
    fs::write(&policy_path, &policy_toml).map_err(|e| CliError::Io {
        path: policy_path.display().to_string(),
        source: e,
    })?;
    println!("✓ Wrote policy.toml → {}", policy_path.display());

    // Step 7: Remind operator to sign the policy.
    println!("\n=== CEREMONY NEXT STEPS ===");
    println!("Sign policy.toml with your private key:");
    println!("  raxis policy sign {} --key <your_private_key>", policy_path.display());
    println!("Then start the kernel:");
    println!("  RAXIS_DATA_DIR={} raxis-kernel", data_dir.display());

    Ok(())
}

// ---------------------------------------------------------------------------
// Key rotation ceremony
// ---------------------------------------------------------------------------

fn run_rotate(flags: &GlobalFlags, family: &str) -> Result<(), CliError> {
    let socket = flags.socket_path();

    // Refuse if kernel appears to be running.
    if socket.exists() {
        return Err(CliError::Usage(
            "kernel appears to be running (operator socket exists). \
             Stop the kernel before rotating keys.".to_owned(),
        ));
    }

    let keys_dir = flags.data_dir().join("keys");
    match family {
        "authority" => {
            let path = keys_dir.join("authority_keypair.pem");
            let seed: [u8; 32] = try_random_array()?;
            let key = SigningKey::from_bytes(&seed);
            write_key_pem(&path, &key)?;
            println!("✓ Rotated authority_keypair → {}", path.display());
        }
        "quality" => {
            let path = keys_dir.join("quality_keypair.pem");
            let seed: [u8; 32] = try_random_array()?;
            let key = SigningKey::from_bytes(&seed);
            write_key_pem(&path, &key)?;
            println!("✓ Rotated quality_keypair → {}", path.display());
        }
        "verifier-token" => {
            let path = keys_dir.join("verifier_token_key.bin");
            let vtk: [u8; 32] = try_random_array()?;
            std::fs::write(&path, vtk).map_err(|e| CliError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
            set_permissions_600(&path);
            println!("✓ Rotated verifier_token_key → {}", path.display());
        }
        "operator" => {
            println!("Paste new operator Ed25519 public key (64-char hex):");
            let (pubkey_hex, fingerprint) = prompt_operator_pubkey()?;

            // Remove old operator .pub files.
            let entries = fs::read_dir(&keys_dir).map_err(|e| CliError::Io {
                path: keys_dir.display().to_string(),
                source: e,
            })?;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("operator_") && name.ends_with(".pub") {
                    let _ = fs::remove_file(entry.path());
                }
            }

            let path = keys_dir.join(format!("operator_{fingerprint}.pub"));
            fs::write(&path, &pubkey_hex).map_err(|e| CliError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
            println!("✓ Rotated operator pubkey → {}", path.display());
        }
        other => {
            return Err(CliError::Usage(format!(
                "unknown key family: {other:?} (must be one of: authority, quality, verifier-token, operator)"
            )));
        }
    }

    println!("\nYou must advance the policy epoch before resuming work.");
    println!("After restarting the kernel, stage the new signed policy artifact under");
    println!("  <data_dir>/policy/");
    println!("and run:");
    println!("  raxis epoch advance --policy <path> --sig <path>");

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn load_operator_pubkey(path: &std::path::Path) -> Result<(String, String), CliError> {
    let content = fs::read_to_string(path).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let pubkey_bytes = crate::signing::parse_operator_public_key_material(&content)?;
    let pubkey_hex = hex::encode(pubkey_bytes);
    let fingerprint = crate::conn::pubkey_fingerprint(&pubkey_bytes);
    Ok((pubkey_hex, fingerprint))
}

fn prompt_operator_pubkey() -> Result<(String, String), CliError> {
    use std::io::BufRead;
    eprintln!("Paste operator Ed25519 public key as a single line — 64-character hex (preferred).");
    eprintln!("For `operator_public.pem`, use: raxis genesis --operator-pubkey /path/to/file.pem");
    let stdin = std::io::stdin();
    let line = stdin.lock().lines().next()
        .ok_or_else(|| CliError::Key("no input".to_owned()))?
        .map_err(|e| CliError::Io { path: "stdin".to_owned(), source: e })?;
    let pubkey_bytes = crate::signing::parse_operator_public_key_material(&line)?;
    let pubkey_hex = hex::encode(pubkey_bytes);
    let fingerprint = crate::conn::pubkey_fingerprint(&pubkey_bytes);
    Ok((pubkey_hex, fingerprint))
}

fn write_key_pem(path: &std::path::Path, key: &SigningKey) -> Result<(), CliError> {
    // Must match `kernel/bootstrap::generate_ed25519_keypair` and
    // `authority::keys::load_signing_key` — hex seed + pubkey in labelled blocks.
    let seed_hex = hex::encode(key.to_bytes());
    let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
    let pem = format!(
        "-----BEGIN ED25519 PRIVATE KEY-----\n\
{seed_hex}\n\
-----END ED25519 PRIVATE KEY-----\n\
-----BEGIN ED25519 PUBLIC KEY-----\n\
{pubkey_hex}\n\
-----END ED25519 PUBLIC KEY-----\n",
    );
    fs::write(path, pem.as_bytes()).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    set_permissions_600(path);
    Ok(())
}

// Policy.toml rendering used to live here as a 70-line `format!` block.
// It now delegates to `raxis_genesis_tools::render_genesis_policy_toml` so
// the kernel-side `bootstrap::write_genesis_policy` and this CLI command
// share one canonical implementation. See `crates/genesis-tools/src/lib.rs`
// for the drift history (P0 bugs eliminated by convergence).

// Random byte minting goes through `raxis_crypto::token::try_random_array`
// (see top of file). The CLI no longer carries a /dev/urandom shim because the
// previous implementation silently returned all-zeros on read failure, which
// was a catastrophic key-compromise risk; see the v1 review section "Catastrophic
// findings — fill_random_bytes silent failure".

#[cfg(unix)]
fn set_permissions_600(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_permissions_600(_path: &std::path::Path) {}

#[cfg(test)]
mod write_key_pem_tests {
    use super::write_key_pem;
    use ed25519_dalek::SigningKey;

    /// `raxis-kernel` `authority::keys::load_signing_key` only recognises this layout
    /// (`kernel/bootstrap::generate_ed25519_keypair`). Genesis must stay compatible.
    #[test]
    fn written_authority_pem_matches_kernel_parser_expectations() {
        let key = SigningKey::from_bytes(&[0x42u8; 32]);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("authority_keypair.pem");
        write_key_pem(&path, &key).expect("write pem");

        let pem = std::fs::read_to_string(&path).expect("read pem");
        assert!(
            pem.contains("BEGIN ED25519 PRIVATE KEY"),
            "kernel rejects GENERIC PRIVATE KEY label:\n{pem}"
        );
        assert!(
            pem.contains("BEGIN ED25519 PUBLIC KEY"),
            "bootstrap PEM bundles pubkey hex:\n{pem}"
        );

        let seed_line = pem
            .lines()
            .skip_while(|l| !l.contains("BEGIN ED25519 PRIVATE KEY"))
            .nth(1)
            .expect("line after BEGIN ED25519 PRIVATE KEY")
            .trim();
        assert_eq!(seed_line, hex::encode(key.to_bytes()));

        let pub_line = pem
            .lines()
            .skip_while(|l| !l.contains("BEGIN ED25519 PUBLIC KEY"))
            .nth(1)
            .expect("line after BEGIN ED25519 PUBLIC KEY")
            .trim();
        assert_eq!(pub_line, hex::encode(key.verifying_key().to_bytes()));
    }
}
