// raxis-cli::commands::genesis — Genesis key ceremony.
//
// Normative reference: cli-ceremony.md §4.1 `genesis`, §4.2 step-by-step.
//
// Generates all key families and writes initial policy.toml.
// Does NOT start the kernel.

use std::fs;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;

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

    // Step 2: Generate authority_keypair (Ed25519).
    let authority_key = SigningKey::from_bytes(&random_32_bytes());
    let authority_pubkey_hex = hex::encode(authority_key.verifying_key().to_bytes());
    write_key_pem(&authority_key_path, &authority_key)?;
    println!("✓ Generated authority_keypair → {}", authority_key_path.display());

    // Step 3: Generate quality_keypair (Ed25519).
    let quality_key_path = keys_dir.join("quality_keypair.pem");
    let quality_key = SigningKey::from_bytes(&random_32_bytes());
    let quality_pubkey_hex = hex::encode(quality_key.verifying_key().to_bytes());
    write_key_pem(&quality_key_path, &quality_key)?;
    println!("✓ Generated quality_keypair → {}", quality_key_path.display());

    // Step 4: Generate verifier_token_key (32 CSPRNG bytes).
    let vtk_path = keys_dir.join("verifier_token_key.bin");
    let vtk = random_32_bytes();
    fs::write(&vtk_path, &vtk).map_err(|e| CliError::Io {
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

    // Step 6: Write initial policy.toml.
    let policy_path = policy_dir.join("policy.toml");
    let policy_toml = render_initial_policy_toml(
        &authority_pubkey_hex,
        &quality_pubkey_hex,
        &operator_pubkey_hex,
        &operator_fingerprint,
    );
    fs::write(&policy_path, &policy_toml).map_err(|e| CliError::Io {
        path: policy_path.display().to_string(),
        source: e,
    })?;
    println!("✓ Wrote policy.toml → {}", policy_path.display());

    // Step 7: Remind operator to sign the policy.
    println!("\n=== CEREMONY NEXT STEPS ===");
    println!("Sign policy.toml with your private key:");
    println!("  raxis-cli policy sign {} --key <your_private_key>", policy_path.display());
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
            let key = SigningKey::from_bytes(&random_32_bytes());
            write_key_pem(&path, &key)?;
            println!("✓ Rotated authority_keypair → {}", path.display());
        }
        "quality" => {
            let path = keys_dir.join("quality_keypair.pem");
            let key = SigningKey::from_bytes(&random_32_bytes());
            write_key_pem(&path, &key)?;
            println!("✓ Rotated quality_keypair → {}", path.display());
        }
        "verifier-token" => {
            let path = keys_dir.join("verifier_token_key.bin");
            let vtk = random_32_bytes();
            std::fs::write(&path, &vtk).map_err(|e| CliError::Io {
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
    println!("  raxis-cli epoch advance --policy <path> --sig <path>");

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
    let pubkey_hex = content.trim().to_owned();
    let pubkey_bytes = hex::decode(&pubkey_hex)?;
    if pubkey_bytes.len() != 32 {
        return Err(CliError::Key(
            "operator pubkey must be 32 bytes (64 hex chars)".to_owned(),
        ));
    }
    let fingerprint = crate::conn::pubkey_fingerprint(&pubkey_bytes);
    Ok((pubkey_hex, fingerprint))
}

fn prompt_operator_pubkey() -> Result<(String, String), CliError> {
    use std::io::BufRead;
    eprintln!("Paste operator Ed25519 public key (64-char hex or PEM): ");
    let stdin = std::io::stdin();
    let line = stdin.lock().lines().next()
        .ok_or_else(|| CliError::Key("no input".to_owned()))?
        .map_err(|e| CliError::Io { path: "stdin".to_owned(), source: e })?;
    let pubkey_hex = line.trim().to_owned();
    let pubkey_bytes = hex::decode(&pubkey_hex)?;
    if pubkey_bytes.len() != 32 {
        return Err(CliError::Key("pubkey must be 32 bytes".to_owned()));
    }
    let fingerprint = crate::conn::pubkey_fingerprint(&pubkey_bytes);
    Ok((pubkey_hex, fingerprint))
}

fn write_key_pem(path: &std::path::Path, key: &SigningKey) -> Result<(), CliError> {
    // Write raw 32-byte seed as hex (simple format for v1).
    let seed_hex = hex::encode(key.to_bytes());
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{seed_hex}\n-----END PRIVATE KEY-----\n"
    );
    fs::write(path, pem.as_bytes()).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    set_permissions_600(path);
    Ok(())
}

fn render_initial_policy_toml(
    authority_pubkey_hex: &str,
    quality_pubkey_hex: &str,
    operator_pubkey_hex: &str,
    operator_fingerprint: &str,
) -> String {
    format!(
        r#"# RAXIS v1 policy artifact — generated by `raxis-cli genesis`
# Sign this file with: raxis-cli policy sign policy.toml --key <operator_key>

[meta]
epoch     = 1
signed_by = "{operator_fingerprint}"
signed_at = {signed_at}

[authority]
authority_pubkey = "{authority_pubkey_hex}"
quality_pubkey   = "{quality_pubkey_hex}"

[escalation_policy]
timeout_secs         = 3600
window_secs          = 300
max_per_window       = 5
quarantine_threshold = 3

[sessions]
default_ttl_secs       = 86400
max_ttl_secs           = 604800
allowed_worktree_roots = ["/home/operator/work"]

[delegations]
max_ttl_secs = 86400

[budget]
cost_per_touched_path = 1
max_cost_per_task     = 10000
[budget.base_cost_per_intent_kind]
SingleCommit       = 10
IntegrationMerge   = 50
CompleteTask       = 5
ReportFailure      = 1

[[operators.entries]]
pubkey_fingerprint = "{operator_fingerprint}"
display_name       = "Initial Operator"
pubkey_hex         = "{operator_pubkey_hex}"
permitted_ops = [
  "CreateInitiative",
  "ApprovePlan",
  "RejectPlan",
  "CreateSession",
  "RevokeSession",
  "GrantDelegation",
  "RetryTask",
  "ResumeTask",
  "AbortTask",
  "AbortInitiative",
  "ApproveEscalation",
  "DenyEscalation",
  "RotateEpoch",
]

[[lanes]]
lane_id              = "default"
max_concurrent_tasks = 4
max_cost_per_epoch   = 10000
priority             = 100
"#,
        signed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

fn random_32_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    fill_random_bytes(&mut b);
    b
}


/// Fill `dest` with OS-random bytes via /dev/urandom.
pub fn fill_random_bytes(dest: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(dest);
    }
}

#[cfg(unix)]
fn set_permissions_600(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_permissions_600(_path: &std::path::Path) {}
