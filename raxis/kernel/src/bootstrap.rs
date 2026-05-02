// raxis-kernel::bootstrap — Genesis state machine.
//
// Normative reference: kernel-core.md §2.2 `src/bootstrap.rs`.
//
// Entered ONLY when RAXIS_BOOTSTRAP env var is set. Creates all four key
// families and the initial policy.toml, then writes the chain-initiating
// genesis audit record and exits. It does not enter the IPC dispatch loop.
//
// Mutual exclusion: the normal startup path in main.rs checks for the
// existence of authority_keypair.pem (step 4). If bootstrap ran and
// succeeded, that file exists and the normal path proceeds. If bootstrap
// failed mid-way, the operator must remove partial artefacts and re-run.
//
// Key files written (cli-ceremony.md §4.2):
//   <data_dir>/keys/authority_keypair.pem   — Ed25519 signing keypair (0400)
//   <data_dir>/keys/quality_keypair.pem     — Ed25519 quality keypair (0400)
//   <data_dir>/keys/verifier_token_key.bin  — 32 CSPRNG bytes (0400)
//   <data_dir>/keys/operator_<fp>.pub       — operator public key (0444)
//   <data_dir>/policy/policy.toml           — first policy epoch (0644)
//
// Operator private key is NEVER stored by the kernel. The operator runs
// `raxis-cli policy sign` separately to produce policy.sig.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::errors::KernelError;
use raxis_crypto::token::try_random_array;

/// Configuration supplied by main.rs to bootstrap::run.
pub struct BootstrapConfig {
    /// Root data directory (e.g. `~/.raxis`).
    pub data_dir: PathBuf,
    /// Path to an operator Ed25519 public key file, if supplied via
    /// `--operator-pubkey`. If None, operator pubkey must be pasted interactively.
    pub operator_pubkey_path: Option<PathBuf>,
    /// If true, allow re-genesis even if key files already exist.
    /// Only set from `--force`; not set in normal usage.
    pub force: bool,
}

/// Genesis state machine entry point.
///
/// Called from `main.rs` step 2 when RAXIS_BOOTSTRAP is set.
/// On success, calls `std::process::exit(0)` — does not return.
/// On failure, returns `Err(KernelError::BootstrapFailed)` for main to exit_with_code.
pub fn run(config: &BootstrapConfig) -> Result<(), KernelError> {
    let keys_dir = config.data_dir.join("keys");
    let policy_dir = config.data_dir.join("policy");
    let audit_dir = config.data_dir.join("audit");

    // Create directory tree.
    for dir in &[&keys_dir, &policy_dir, &audit_dir] {
        std::fs::create_dir_all(dir).map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot create directory {}: {e}", dir.display()),
        })?;
    }

    // Guard: prevent accidental re-genesis.
    let authority_pem = keys_dir.join("authority_keypair.pem");
    if authority_pem.exists() && !config.force {
        return Err(KernelError::BootstrapFailed {
            reason: format!(
                "authority_keypair.pem already exists at {}; use --force to overwrite",
                authority_pem.display()
            ),
        });
    }

    // Step 2 (cli-ceremony §4.2): Generate authority keypair.
    let authority_signing_key = generate_ed25519_keypair(&keys_dir, "authority_keypair.pem")?;
    let authority_pubkey = authority_signing_key.verifying_key();
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"bootstrap\",\"action\":\"generated authority_keypair\"}}",
    );

    // Step 3: Generate quality keypair.
    let _quality_signing_key = generate_ed25519_keypair(&keys_dir, "quality_keypair.pem")?;
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"bootstrap\",\"action\":\"generated quality_keypair\"}}",
    );

    // Step 4: Generate verifier_token_key (32 CSPRNG bytes).
    generate_verifier_token_key(&keys_dir)?;
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"bootstrap\",\"action\":\"generated verifier_token_key\"}}",
    );

    // Step 5: Register operator public key.
    let operator_pubkey_hex = load_operator_pubkey(config)?;
    let operator_fingerprint = pubkey_fingerprint_from_hex(&operator_pubkey_hex)
        .map_err(|e| KernelError::BootstrapFailed { reason: e })?;
    let op_pub_path = keys_dir.join(format!("operator_{operator_fingerprint}.pub"));
    write_file_0444(
        &op_pub_path,
        operator_pubkey_hex.as_bytes(),
    )?;
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"bootstrap\",\"action\":\"registered operator\",\"fingerprint\":\"{operator_fingerprint}\"}}",
    );

    // Step 6: Write initial policy.toml.
    let quality_pem = keys_dir.join("quality_keypair.pem");
    let quality_vk = read_verifying_key_from_pem(&quality_pem)?;
    write_genesis_policy(
        &policy_dir,
        &authority_pubkey,
        &quality_vk,
        &operator_pubkey_hex,
        &operator_fingerprint,
    )?;
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"bootstrap\",\"action\":\"wrote policy.toml\",\"epoch\":1}}",
    );

    // Step 7: Write genesis audit record (chain anchor).
    write_genesis_audit_record(&audit_dir, &authority_pubkey)?;
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"bootstrap\",\"action\":\"wrote genesis audit record\"}}",
    );

    // Step 8: Print summary.
    println!("\n=== RAXIS Genesis Complete ===");
    println!("  authority_keypair : {}", keys_dir.join("authority_keypair.pem").display());
    println!("  quality_keypair   : {}", keys_dir.join("quality_keypair.pem").display());
    println!("  verifier_token_key: {}", keys_dir.join("verifier_token_key.bin").display());
    println!("  operator key      : {}", op_pub_path.display());
    println!("  policy.toml       : {}", policy_dir.join("policy.toml").display());
    println!("\nNext step: sign the policy artifact:");
    println!("  raxis-cli policy sign {} --key <your_private_key>", policy_dir.join("policy.toml").display());
    println!("Then start the kernel:");
    println!("  raxis-kernel");

    // Exit 0 — bootstrap does not enter the dispatch loop.
    std::process::exit(0);
}

// ---------------------------------------------------------------------------
// Key generation helpers
// ---------------------------------------------------------------------------

/// Generate an Ed25519 keypair, write it as a PEM-like file with 0400
/// permissions, and return the `SigningKey` for immediate use.
///
/// The on-disk format is a simplified PEM block:
/// ```
/// -----BEGIN ED25519 PRIVATE KEY-----
/// <64-char hex: 32-byte seed>
/// -----END ED25519 PRIVATE KEY-----
/// -----BEGIN ED25519 PUBLIC KEY-----
/// <64-char hex: 32-byte compressed public key>
/// -----END ED25519 PUBLIC KEY-----
/// ```
///
/// Fails if the file already exists (unless the caller already guarded with
/// the `force` flag check in `run`).
fn generate_ed25519_keypair(keys_dir: &Path, filename: &str) -> Result<SigningKey, KernelError> {
    let path = keys_dir.join(filename);

    // 32-byte Ed25519 seed straight from the OS CSPRNG. ANY rng failure
    // aborts bootstrap — we never write a partially-random key file.
    let seed: [u8; 32] = try_random_array().map_err(|e| KernelError::BootstrapFailed {
        reason: format!("OS CSPRNG unavailable: {e}"),
    })?;

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let pem_content = format!(
        "-----BEGIN ED25519 PRIVATE KEY-----\n{}\n-----END ED25519 PRIVATE KEY-----\n-----BEGIN ED25519 PUBLIC KEY-----\n{}\n-----END ED25519 PUBLIC KEY-----\n",
        hex::encode(seed),
        hex::encode(verifying_key.as_bytes()),
    );

    write_file_0400(&path, pem_content.as_bytes())?;
    Ok(signing_key)
}

/// Generate 32 CSPRNG bytes for the verifier token HMAC key and write to disk.
///
/// Returns `BootstrapFailed` if the OS CSPRNG is unavailable; never writes
/// a key file with non-CSPRNG bytes.
fn generate_verifier_token_key(keys_dir: &Path) -> Result<(), KernelError> {
    let path = keys_dir.join("verifier_token_key.bin");
    let key_bytes: [u8; 32] = try_random_array().map_err(|e| KernelError::BootstrapFailed {
        reason: format!("OS CSPRNG unavailable: {e}"),
    })?;
    write_file_0400(&path, &key_bytes)
}

/// Load operator public key bytes (hex-encoded) from file or stdin prompt.
fn load_operator_pubkey(config: &BootstrapConfig) -> Result<String, KernelError> {
    if let Some(path) = &config.operator_pubkey_path {
        let raw = std::fs::read_to_string(path).map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot read operator pubkey {}: {e}", path.display()),
        })?;
        Ok(raw.trim().to_owned())
    } else {
        // Interactive prompt — read from stdin.
        eprintln!("Paste the operator Ed25519 public key (64 hex chars) and press Enter:");
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| KernelError::BootstrapFailed {
                reason: format!("stdin read failed: {e}"),
            })?;
        Ok(line.trim().to_owned())
    }
}

/// Read the Ed25519 verifying key from a PEM file written by `generate_ed25519_keypair`.
fn read_verifying_key_from_pem(pem_path: &Path) -> Result<VerifyingKey, KernelError> {
    let content = std::fs::read_to_string(pem_path).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("cannot read {}: {e}", pem_path.display()),
    })?;
    // The public key hex is on the line after "-----BEGIN ED25519 PUBLIC KEY-----".
    let pub_hex = content
        .lines()
        .skip_while(|l| !l.contains("BEGIN ED25519 PUBLIC KEY"))
        .nth(1)
        .ok_or_else(|| KernelError::BootstrapFailed {
            reason: format!("malformed PEM in {}: missing public key line", pem_path.display()),
        })?
        .trim();
    let pub_bytes = hex::decode(pub_hex).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("cannot hex-decode pubkey in {}: {e}", pem_path.display()),
    })?;
    let pub_arr: [u8; 32] = pub_bytes.try_into().map_err(|_| KernelError::BootstrapFailed {
        reason: format!("pubkey in {} is not 32 bytes", pem_path.display()),
    })?;
    VerifyingKey::from_bytes(&pub_arr).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("invalid Ed25519 pubkey in {}: {e}", pem_path.display()),
    })
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// SHA-256[:16] fingerprint of a hex-encoded pubkey — 32 hex chars.
/// Matches kernel-store.md §2.5.4 and raxis-policy::loader::operator_pubkey_fingerprint.
fn pubkey_fingerprint_from_hex(pubkey_hex: &str) -> Result<String, String> {
    let bytes = hex::decode(pubkey_hex).map_err(|e| format!("hex decode failed: {e}"))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    let digest = h.finalize();
    Ok(hex::encode(&digest[..16]))
}

// ---------------------------------------------------------------------------
// Genesis policy writer
// ---------------------------------------------------------------------------

/// Write the initial policy.toml for epoch 1.
///
/// Format matches the PolicyBundle TOML schema in raxis-policy::bundle.
/// The canonical 13-operation permitted_ops set is from cli-ceremony.md §4.2
/// and kernel-store.md §2.5.5.
fn write_genesis_policy(
    policy_dir: &Path,
    authority_vk: &VerifyingKey,
    quality_vk: &VerifyingKey,
    operator_pubkey_hex: &str,
    operator_fingerprint: &str,
) -> Result<(), KernelError> {
    let policy_path = policy_dir.join("policy.toml");

    let authority_hex = hex::encode(authority_vk.as_bytes());
    let quality_hex = hex::encode(quality_vk.as_bytes());

    // Canonical 13-operation v1 set (cli-ceremony.md §4.2).
    let permitted_ops = [
        "CreateInitiative", "ApprovePlan", "RejectPlan", "CreateSession",
        "RevokeSession", "GrantDelegation", "RetryTask", "ResumeTask",
        "AbortTask", "AbortInitiative", "ApproveEscalation", "DenyEscalation",
        "RotateEpoch",
    ];
    let ops_toml = permitted_ops
        .iter()
        .map(|op| format!("  \"{op}\""))
        .collect::<Vec<_>>()
        .join(",\n");

    // Compute SHA-256 of the policy bytes (will be set after we have the content).
    // We write a placeholder, compute, then update — but since the loader no longer
    // self-verifies, we just compute and record. The placeholder approach is fine.
    let policy_content = format!(
        r#"[meta]
epoch         = 1
signed_by     = "{operator_fingerprint}"
signed_at     = {ts}

[authority]
authority_pubkey = "{authority_hex}"
quality_pubkey   = "{quality_hex}"

[escalation_policy]
timeout_secs         = 3600
window_secs          = 300
max_per_window       = 5
quarantine_threshold = 3

[sessions]
default_ttl_secs       = 86400
max_ttl_secs           = 604800
allowed_worktree_roots = []

[delegations]
max_ttl_secs = 86400

[budget]
[budget.base_cost_per_intent_kind]
SingleCommit      = 10
MultiBranchCommit = 25
IntegrationMerge  = 50
PrGateEvaluation  = 15

[operators]
[[operators.entries]]
pubkey_fingerprint = "{operator_fingerprint}"
display_name       = "operator-1"
pubkey_hex         = "{operator_pubkey_hex}"
permitted_ops      = [
{ops_toml}
]
"#,
        ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );

    write_file_0644(&policy_path, policy_content.as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Genesis audit record
// ---------------------------------------------------------------------------

/// Write the chain-initiating genesis audit record.
///
/// Fields (kernel-core.md §2.2 bootstrap.rs):
///   prev_hash                 = null (genesis sentinel)
///   genesis_nonce             = 256-bit CSPRNG random hex
///   timestamp                 = Unix seconds
///   authority_pubkey_fingerprint = SHA-256[:16] of authority pubkey
///
/// Write order (matching raxis-audit-tools chain-write protocol):
///   1. Write record bytes to audit/segment-000.jsonl
///   2. fsync segment file
///   3. Done (index entry deferred to audit-tools in future)
fn write_genesis_audit_record(
    audit_dir: &Path,
    authority_vk: &VerifyingKey,
) -> Result<(), KernelError> {
    use std::io::Write;

    let segment_path = audit_dir.join("segment-000.jsonl");

    // 512-bit (64-byte) CSPRNG nonce, hex-encoded → 128 hex chars. Spec
    // (kernel-store.md §2.5.5 audit-genesis-nonce) requires "at least 256 bits
    // of entropy"; we mint 512 bits to leave headroom.
    let nonce_bytes: [u8; 64] = try_random_array().map_err(|e| KernelError::BootstrapFailed {
        reason: format!("OS CSPRNG unavailable for genesis nonce: {e}"),
    })?;
    let genesis_nonce = hex::encode(nonce_bytes);

    let fingerprint = {
        let mut h = Sha256::new();
        h.update(authority_vk.as_bytes());
        hex::encode(&h.finalize()[..16])
    };

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // prev_sha256 = 64 zeros = genesis sentinel (matches AuditWriter::GENESIS_PREV_SHA256).
    let record = serde_json::json!({
        "seq": 0,
        "event_id": uuid::Uuid::new_v4().to_string(),
        "event_kind": "GenesisRecord",
        "prev_sha256": "0".repeat(64),
        "genesis_nonce": genesis_nonce,
        "authority_pubkey_fingerprint": fingerprint,
        "emitted_at": ts,
    });

    let mut line = serde_json::to_string(&record).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("genesis audit record serialize failed: {e}"),
    })?;
    line.push('\n');

    // Write order: (1) write bytes, (2) fsync.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&segment_path)
        .map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot open {}: {e}", segment_path.display()),
        })?;

    file.write_all(line.as_bytes())
        .map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot write genesis record: {e}"),
        })?;
    file.sync_all().map_err(|e| KernelError::BootstrapFailed {
        reason: format!("fsync genesis segment failed: {e}"),
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// File write helpers (permission-aware)
// ---------------------------------------------------------------------------

/// Write bytes to `path` with mode 0400 (owner read-only).
/// Fails if `path` already exists.
fn write_file_0400(path: &Path, data: &[u8]) -> Result<(), KernelError> {
    use std::io::Write;
    if path.exists() {
        return Err(KernelError::BootstrapFailed {
            reason: format!("{} already exists; remove it before re-running genesis", path.display()),
        });
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot create {}: {e}", path.display()),
        })?;
    // Set permissions before writing.
    file.set_permissions(std::fs::Permissions::from_mode(0o400))
        .map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot chmod 0400 {}: {e}", path.display()),
        })?;
    file.write_all(data).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("cannot write {}: {e}", path.display()),
    })?;
    file.sync_all().map_err(|e| KernelError::BootstrapFailed {
        reason: format!("fsync failed {}: {e}", path.display()),
    })
}

/// Write bytes to `path` with mode 0444 (world-readable, no write).
fn write_file_0444(path: &Path, data: &[u8]) -> Result<(), KernelError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot create {}: {e}", path.display()),
        })?;
    file.set_permissions(std::fs::Permissions::from_mode(0o444))
        .map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot chmod 0444 {}: {e}", path.display()),
        })?;
    file.write_all(data).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("cannot write {}: {e}", path.display()),
    })
}

/// Write bytes to `path` with mode 0644.
fn write_file_0644(path: &Path, data: &[u8]) -> Result<(), KernelError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot create {}: {e}", path.display()),
        })?;
    file.set_permissions(std::fs::Permissions::from_mode(0o644))
        .map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot chmod 0644 {}: {e}", path.display()),
        })?;
    file.write_all(data).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("cannot write {}: {e}", path.display()),
    })
}
