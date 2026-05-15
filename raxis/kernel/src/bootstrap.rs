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
//   <data_dir>/keys/operator_<fp>.cert.toml — operator self-signed cert (0444)
//   <data_dir>/policy/policy.toml           — first policy epoch (0644)
//
// Operator private key is NEVER stored or seen by the kernel. The kernel
// bootstrap takes a pre-minted self-signed cert (produced by `raxis cert
// mint` on an air-gapped operator workstation) and embeds it into the
// genesis policy.toml. Cert is mandatory (INV-CERT-01); there is no
// pubkey-only path.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::errors::KernelError;
use raxis_crypto::cert::{validate_cert_structurally, verify_cert_self_signature};
use raxis_crypto::token::try_random_array;
use raxis_types::operator_cert::OperatorCert;
use raxis_types::unix_now_secs;

// INV-STORE-03 (kernel-store.md §2.5.1): no raw SQL table-name literals
// in `kernel/src`. The only table this module reads is
// `policy_epoch_history`, surfaced via the typed `Table` enum.
#[cfg(test)]
const POLICY_EPOCH_HISTORY: &str = raxis_store::Table::PolicyEpochHistory.as_str();

/// Configuration supplied by main.rs to bootstrap::run.
pub struct BootstrapConfig {
    /// Root data directory (e.g. `~/.raxis`).
    pub data_dir: PathBuf,
    /// Path to a pre-minted operator certificate file (`*.cert.toml` shape;
    /// produced by `raxis cert mint`). The cert MUST be self-signed and
    /// structurally valid; bootstrap fails closed otherwise.
    ///
    /// Cert-mandatory (INV-CERT-01): there is no pubkey-only path. Operators
    /// must mint their cert offline (typically on an air-gapped workstation
    /// holding the operator private key) and pass the resulting `*.cert.toml`
    /// here. The kernel never sees the operator private key.
    ///
    /// If `None`, the kernel reads the cert TOML body from stdin in bootstrap
    /// mode (used by `RAXIS_BOOTSTRAP=1 raxis-kernel < cert.toml`).
    pub operator_cert_path: Option<PathBuf>,
    /// If true, allow re-genesis even if key files already exist.
    /// Only set from `--force`; not set in normal usage.
    pub force: bool,
}

/// Genesis state machine entry point.
///
/// Called from `main.rs` step 2 when RAXIS_BOOTSTRAP is set.
/// On success, calls `std::process::exit(0)` — does not return.
/// On failure, returns `Err(KernelError::BootstrapFailed)` for main to exit_with_code.
///
/// This is a thin wrapper: every side effect (key generation, policy emission,
/// genesis audit record write, summary print) lives in [`run_inner`], which
/// returns normally so integration tests can drive bootstrap end-to-end and
/// then assert against the resulting filesystem state. `run` exists solely to
/// preserve the long-standing "bootstrap exits the process; main never falls
/// through into the dispatch loop" invariant declared by kernel-core.md §2.2
/// `bootstrap.rs` ("Exits the process after completion; does not return to
/// `main`"). If a future contributor needs to inspect bootstrap's outputs
/// in-process, they MUST call `run_inner` directly — never weaken the exit
/// here.
pub fn run(config: &BootstrapConfig) -> Result<(), KernelError> {
    run_inner(config)?;
    // SAFETY: kernel-core.md §2.2 mandates that the bootstrap binary not
    // proceed to the IPC dispatch loop. The `?` above propagates failures
    // to `main::exit_with_code`; the only way to reach this line is a
    // successful genesis, in which case we exit 0 here so `main.rs` falls
    // straight into its `unreachable!` guard rather than into step 3.
    std::process::exit(0);
}

/// The testable inner implementation of bootstrap.
///
/// Identical to [`run`] in every observable side effect except that on
/// success it returns `Ok(())` instead of calling `std::process::exit(0)`.
/// Exposed `pub(crate)` so the integration tests at the bottom of this
/// file can run bootstrap against a [`tempfile::TempDir`] and then assert:
///
///   - Every output file exists with the spec-mandated permission mode.
///   - `policy.toml` round-trips through `raxis_policy::load_policy`.
///   - `keys/*.pem` and `verifier_token_key.bin` round-trip through
///     `authority::load_key_registry`.
///   - The genesis audit record is accepted by
///     `recovery::verify_audit_chain`.
///   - `policy.toml`'s `meta.signed_by` fingerprint matches the SHA-256[:16]
///     of the operator pubkey on disk.
///
/// Production callers MUST go through [`run`]; they MUST NOT call
/// `run_inner` directly, because doing so would skip the spec-mandated
/// process exit and let `main.rs` accidentally fall through into the IPC
/// dispatch loop with a freshly-minted authority key.
pub(crate) fn run_inner(config: &BootstrapConfig) -> Result<(), KernelError> {
    let keys_dir = config.data_dir.join("keys");
    let policy_dir = config.data_dir.join("policy");
    let audit_dir = config.data_dir.join("audit");
    // `providers/` holds per-provider credential files (e.g. Anthropic API
    // keys). Created at genesis time even though no provider is configured
    // in the genesis policy.toml — operators dropping a credentials file
    // post-bootstrap should not have to mkdir first. Mode 0700 (kernel uid
    // only); the credential files themselves are 0600 once written.
    // peripherals.md §3.2 "Provider credential storage".
    let providers_dir = config.data_dir.join("providers");
    // `runtime/` holds the kernel's heartbeat file (`heartbeat.json`)
    // — the CLI-visible liveness hint defined in cli-readonly.md §5.2.
    // Created at genesis so the very first kernel boot can write into
    // an existing directory without racing `create_dir_all` against
    // `tempfile + rename`. Mode is the default 0755 (the heartbeat
    // itself is 0644 — readable by any local operator process); the
    // file contains no secrets, only public liveness counters.
    let runtime_dir = config.data_dir.join("runtime");
    // `sockets/` holds the three UDS endpoints (operator/planner/gateway)
    // bound by `ipc::server::start` (see kernel-store.md §2.5.5). The
    // server bind path also calls `create_dir_all` so the kernel can
    // boot on a non-genesis'd data dir, but we mkdir here so:
    //   1. `raxis doctor` run between genesis and the first kernel
    //      start does NOT report `[FAIL] sockets.exists missing: …`
    //      (the operator's observable symptom that motivated this fix);
    //   2. the directory inherits genesis-time mode 0755 deterministically
    //      rather than depending on whichever umask `raxis-kernel`
    //      happens to inherit on first boot.
    // Mode is plain 0755 — the socket *files* themselves carry the
    // sensitive bits (operator.sock is 0600 per kernel-store.md §2.5.5).
    let sockets_dir = config.data_dir.join("sockets");
    // `notifications/` holds `inbox.jsonl` produced by the Shell
    // notification channel handler (kernel-core.md §2.3 + cli-readonly.md
    // §5.6). Without this directory, a freshly-bootstrapped kernel that
    // ever fires a notification would crash the writer thread. Doctor
    // tolerates a missing `notifications/` as WARN, but creating it at
    // genesis is the cleaner contract: every directory `raxis doctor`
    // checks should be present immediately after the ceremony.
    let notifications_dir = config.data_dir.join("notifications");

    // Create directory tree.
    for dir in &[
        &keys_dir,
        &policy_dir,
        &audit_dir,
        &providers_dir,
        &runtime_dir,
        &sockets_dir,
        &notifications_dir,
    ] {
        std::fs::create_dir_all(dir).map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot create directory {}: {e}", dir.display()),
        })?;
    }
    // Tighten permissions on the new keys/ and providers/ dirs.
    //
    // Why both — `create_dir_all` honours the process umask (typically
    // 0022), which leaves the directory at 0o755. The kernel-store.md
    // §2.5.1 contract demands keys/ at 0o700 (the four key-material
    // files inside are 0o400) and peripherals.md §3.2 demands
    // providers/ at 0o700 (per-provider credential files are 0o600).
    // `raxis doctor` flags any other mode for these two dirs as FAIL
    // (`commands/doctor.rs::check_subdir`), so a kernel that genesis'd
    // its own data dir was reporting `[FAIL] keys.mode mode is 0755`
    // until this chmod was added — the exact symptom this fix repairs.
    for dir in &[&keys_dir, &providers_dir] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            KernelError::BootstrapFailed {
                reason: format!("cannot chmod 0700 {}: {e}", dir.display()),
            }
        })?;
    }

    // Guard: prevent accidental re-genesis.
    //
    // The check below establishes intent (operator did/did-not pass --force).
    // The actual file-system cleanup, when force is set, is done by
    // `purge_existing_keys_if_force` below — without that step, the per-file
    // `write_file_0400` exists-check would fire mid-ceremony and the --force
    // escape hatch would be a lie. (This is a P0 fix surfaced by
    // `bootstrap::edge_cases::second_run_with_force_succeeds_and_overwrites`;
    // until that test was added, every "I need to re-genesis my data dir"
    // operator path was silently broken.)
    let authority_pem = keys_dir.join("authority_keypair.pem");
    if authority_pem.exists() && !config.force {
        return Err(KernelError::BootstrapFailed {
            reason: format!(
                "authority_keypair.pem already exists at {}; use --force to overwrite",
                authority_pem.display()
            ),
        });
    }
    if config.force {
        purge_existing_genesis_artifacts(&keys_dir, &audit_dir)?;
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

    // Step 5: Load and validate the operator's pre-minted cert.
    //
    // Cert-mandatory (INV-CERT-01). The kernel never sees the operator
    // private key — the cert is produced offline on an air-gapped
    // operator workstation and supplied here as a `*.cert.toml` file.
    // Bootstrap fails closed if the cert is structurally invalid or
    // its self-signature does not verify under its declared pubkey.
    let operator_cert = load_operator_cert(config)?;
    let operator_pubkey_hex = operator_cert.pubkey_hex.clone();
    let operator_fingerprint = pubkey_fingerprint_from_hex(&operator_pubkey_hex)
        .map_err(|e| KernelError::BootstrapFailed { reason: e })?;
    let op_pub_path = keys_dir.join(format!("operator_{operator_fingerprint}.pub"));
    write_file_0444(&op_pub_path, operator_pubkey_hex.as_bytes())?;
    // Persist the supplied cert into <keys_dir>/operator_<fp>.cert.toml so
    // a future `raxis cert show` / `raxis cert verify` against the data
    // dir can find the genesis cert without the operator having to retain
    // their original cert artefact.
    let op_cert_path = keys_dir.join(format!("operator_{operator_fingerprint}.cert.toml"));
    let cert_toml = toml::to_string(&operator_cert).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("cannot serialise cert for {}: {e}", op_cert_path.display()),
    })?;
    write_file_0444(&op_cert_path, cert_toml.as_bytes())?;
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"bootstrap\",\"action\":\"registered operator\",\"fingerprint\":\"{operator_fingerprint}\",\"cert_kind\":\"{kind}\"}}",
        kind = operator_cert.kind.as_str(),
    );

    // Step 6: Write initial policy.toml.
    let quality_pem = keys_dir.join("quality_keypair.pem");
    let quality_vk = read_verifying_key_from_pem(&quality_pem)?;
    write_genesis_policy(
        config,
        &policy_dir,
        &authority_pubkey,
        &quality_vk,
        &operator_pubkey_hex,
        &operator_fingerprint,
        &operator_cert,
    )?;
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"bootstrap\",\"action\":\"wrote policy.toml\",\"epoch\":1}}",
    );

    // Step 6.5: Install the canonical `epoch_id = 1` row into
    // `policy_epoch_history`. Per kernel-core.md §`policy_manager.rs`
    // the genesis bootstrap is one of the two writers to this table;
    // without this row the kernel would boot with `current_epoch = 0`,
    // and the first `RotateEpoch` would record `epoch_id = 1` instead
    // of `epoch_id = 2`, leaving the genesis artifact unrecorded in
    // the policy history audit trail. The store is opened (which
    // applies the schema migration), the row inserted via
    // `policy_manager::install_genesis_policy_epoch` (idempotent
    // INSERT OR IGNORE), and the connection dropped immediately so
    // the kernel's main `Store::open` at startup gets exclusive WAL
    // access.
    install_genesis_policy_epoch_row(&config.data_dir, &policy_dir, &authority_pubkey)?;
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"bootstrap\",\"action\":\"installed genesis policy_epoch_history row\",\"epoch\":1}}",
    );

    // Step 7: Write genesis audit record (chain anchor).
    write_genesis_audit_record(&audit_dir, &authority_pubkey)?;
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"bootstrap\",\"action\":\"wrote genesis audit record\"}}",
    );

    // Step 8: Print summary.
    println!("\n=== RAXIS Genesis Complete ===");
    println!(
        "  authority_keypair : {}",
        keys_dir.join("authority_keypair.pem").display()
    );
    println!(
        "  quality_keypair   : {}",
        keys_dir.join("quality_keypair.pem").display()
    );
    println!(
        "  verifier_token_key: {}",
        keys_dir.join("verifier_token_key.bin").display()
    );
    println!("  operator key      : {}", op_pub_path.display());
    println!(
        "  operator cert     : {} (kind={})",
        op_cert_path.display(),
        operator_cert.kind.as_str()
    );
    println!(
        "  policy.toml       : {}",
        policy_dir.join("policy.toml").display()
    );
    println!("\nNext step: sign the policy artifact:");
    println!(
        "  raxis-cli policy sign {} --key <your_private_key>",
        policy_dir.join("policy.toml").display()
    );
    println!("Then start the kernel:");
    println!("  raxis-kernel");

    Ok(())
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

/// Load the operator's pre-minted self-signed cert from file or stdin and
/// return the parsed [`OperatorCert`] (cert-mandatory: INV-CERT-01).
///
/// The cert is supplied as a TOML document matching `OperatorCert`'s serde
/// shape (the same shape `raxis cert mint` writes and `policy.toml` embeds
/// under `[operators.entries.cert]`).
///
/// Bootstrap fails closed if any of the following hold:
///   * file/stdin I/O fails;
///   * the bytes do not parse as TOML / `OperatorCert`;
///   * `validate_cert_structurally` returns any errors (malformed pubkey,
///     bad expiry positions for `Standard`, etc.); or
///   * `verify_cert_self_signature` fails (the cert was not signed by the
///     private key matching `cert.pubkey_hex`).
///
/// **Why fail closed at this layer (not just at next-boot loader read):**
/// the kernel will write `policy.toml` before the loader runs again. If we
/// accepted an invalid cert here, we would emit a policy.toml the loader
/// rejects on the very next boot — leaving the operator with a "successful"
/// genesis that cannot start. Failing closed in `load_operator_cert` keeps
/// the on-disk artefact set internally consistent: either every file is
/// valid, or no policy.toml exists at all.
fn load_operator_cert(config: &BootstrapConfig) -> Result<OperatorCert, KernelError> {
    let raw = if let Some(path) = &config.operator_cert_path {
        std::fs::read_to_string(path).map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot read operator cert {}: {e}", path.display()),
        })?
    } else {
        eprintln!(
            "Paste the operator cert (TOML body produced by `raxis cert mint`) and press Ctrl-D:",
        );
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).map_err(|e| {
            KernelError::BootstrapFailed {
                reason: format!("stdin read failed: {e}"),
            }
        })?;
        buf
    };

    let cert: OperatorCert = toml::from_str(&raw).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("operator cert parse failed: {e}"),
    })?;

    let structural = validate_cert_structurally(&cert);
    if !structural.is_empty() {
        return Err(KernelError::BootstrapFailed {
            reason: format!(
                "operator cert structural validation failed: {}",
                structural
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        });
    }

    verify_cert_self_signature(&cert).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("operator cert self-signature verification failed: {e}"),
    })?;

    Ok(cert)
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
            reason: format!(
                "malformed PEM in {}: missing public key line",
                pem_path.display()
            ),
        })?
        .trim();
    let pub_bytes = hex::decode(pub_hex).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("cannot hex-decode pubkey in {}: {e}", pem_path.display()),
    })?;
    let pub_arr: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| KernelError::BootstrapFailed {
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
///
/// Thin adaptor over `raxis_genesis_tools::pubkey_fingerprint`, which takes
/// raw bytes; the hex-decode step lives here because the operator pubkey
/// arrives as hex on stdin / `--operator-pubkey`. The actual SHA-256[:16]
/// computation lives in the shared crate so every fingerprint site
/// (kernel bootstrap, CLI genesis, AuditDir test fixture, planner client)
/// shares one implementation.
fn pubkey_fingerprint_from_hex(pubkey_hex: &str) -> Result<String, String> {
    let bytes = hex::decode(pubkey_hex).map_err(|e| format!("hex decode failed: {e}"))?;
    Ok(raxis_genesis_tools::pubkey_fingerprint(&bytes))
}

// ---------------------------------------------------------------------------
// Genesis policy writer
// ---------------------------------------------------------------------------

/// Write the initial policy.toml for epoch 1.
///
/// All formatting decisions live in `raxis_genesis_tools::render_genesis_policy_toml`;
/// this function is a thin wrapper that
///   1. plumbs config inputs into [`raxis_genesis_tools::GenesisPolicyInputs`],
///   2. invokes the shared emitter to render the TOML body, and
///   3. writes the bytes to disk with the spec-mandated `0644` mode.
///
/// The shared emitter is the single source of truth for both this kernel-side
/// genesis path and the operator-facing `raxis genesis` CLI command. See
/// `crates/genesis-tools/src/lib.rs` for the drift history that motivated the
/// extraction (the kernel-side emitter previously shipped an empty
/// `allowed_worktree_roots`, dead `MultiBranchCommit`/`PrGateEvaluation`
/// budget keys, and no `[[lanes]]` section — three latent bugs the shared
/// emitter eliminates).
fn write_genesis_policy(
    config: &BootstrapConfig,
    policy_dir: &Path,
    authority_vk: &VerifyingKey,
    quality_vk: &VerifyingKey,
    operator_pubkey_hex: &str,
    operator_fingerprint: &str,
    operator_cert: &OperatorCert,
) -> Result<(), KernelError> {
    let policy_path = policy_dir.join("policy.toml");

    let authority_hex = hex::encode(authority_vk.as_bytes());
    let quality_hex = hex::encode(quality_vk.as_bytes());

    // Default placeholder worktree root, scoped under data_dir so the
    // genesis artifact does not silently grant access to anything outside
    // the kernel's own state directory. Operators MUST replace this in
    // their first epoch advance; the shared emitter writes a TOML comment
    // directing them to do so.
    let default_worktree_root = config.data_dir.join("worktrees");
    let default_worktree_root_str = default_worktree_root.display().to_string();
    let allowed_worktree_roots: [&str; 1] = [default_worktree_root_str.as_str()];

    let policy_content =
        raxis_genesis_tools::render_genesis_policy_toml(raxis_genesis_tools::GenesisPolicyInputs {
            authority_pubkey_hex: &authority_hex,
            quality_pubkey_hex: &quality_hex,
            operator_pubkey_hex,
            operator_fingerprint,
            // Caller-injected timestamp — kernel uses the same wall-clock
            // helper every other audit emit site uses, so the genesis
            // record's `signed_at` and the audit record's `emitted_at` are
            // taken from the same monotonic baseline.
            // `raxis_types::unix_now_secs()` already returns i64.
            signed_at_unix_secs: unix_now_secs(),
            allowed_worktree_roots: &allowed_worktree_roots,
            operator_cert,
        });

    write_file_0644(&policy_path, policy_content.as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Genesis policy_epoch_history row
// ---------------------------------------------------------------------------

/// Open the kernel.db, run schema migrations, and INSERT the canonical
/// `epoch_id = 1, triggered_by_operator = "genesis"` row into
/// `policy_epoch_history`. Idempotent: a re-bootstrap that crashed
/// after this row was written is treated as a no-op via INSERT OR IGNORE.
///
/// We re-load the just-written `policy.toml` here (instead of plumbing
/// the bytes from `write_genesis_policy`) so the SHA-256 we record is
/// guaranteed to match what the kernel will read at next boot — there
/// is no in-memory short-circuit that could drift from the on-disk
/// artifact.
///
/// The store handle is dropped at the end of this function so the
/// kernel's main `Store::open` at startup gets exclusive access to
/// the WAL file.
fn install_genesis_policy_epoch_row(
    data_dir: &Path,
    policy_dir: &Path,
    authority_vk: &VerifyingKey,
) -> Result<(), KernelError> {
    let policy_path = policy_dir.join("policy.toml");
    let (bundle, _raw_bytes, sha256_hex) =
        raxis_policy::load_policy(&policy_path).map_err(|e| KernelError::BootstrapFailed {
            reason: format!(
                "cannot re-load just-written policy artifact {}: {e}",
                policy_path.display(),
            ),
        })?;
    let signed_by_authority = raxis_genesis_tools::pubkey_fingerprint(authority_vk.as_bytes());

    let db_path = data_dir.join("kernel.db");
    let store = raxis_store::Store::open(&db_path).map_err(|e| KernelError::BootstrapFailed {
        reason: format!("cannot open kernel.db at {}: {e}", db_path.display()),
    })?;

    // Pass the bundle through so the operator entries get mirrored
    // into `operator_certificates` atomically with the
    // `policy_epoch_history` row INSERT. Cert is mandatory
    // (INV-CERT-01), so the bundle's `operators` is non-empty and
    // every entry carries a cert; the cert table and the
    // policy_epoch_history table cannot disagree about which
    // operators exist at epoch 1.
    crate::policy_manager::install_genesis_policy_epoch(
        &store,
        &sha256_hex,
        &signed_by_authority,
        unix_now_secs() as i64,
        &bundle,
    )
    .map_err(|e| KernelError::BootstrapFailed {
        reason: format!("install_genesis_policy_epoch failed: {e}"),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Genesis audit record
// ---------------------------------------------------------------------------

/// Write the chain-initiating genesis audit record.
///
/// Mints the genesis nonce via the workspace CSPRNG shim (any RNG failure
/// aborts bootstrap before we touch the disk) and delegates the byte-level
/// rendering + file I/O to `raxis_audit_tools::write_genesis_segment`.
/// Both the kernel-side `RAXIS_BOOTSTRAP=1` path and the operator-facing
/// `raxis genesis` CLI command call the same writer so the chain-anchor
/// shape cannot drift between the two genesis entry points.
fn write_genesis_audit_record(
    audit_dir: &Path,
    authority_vk: &VerifyingKey,
) -> Result<(), KernelError> {
    let nonce_bytes: [u8; 64] = try_random_array().map_err(|e| KernelError::BootstrapFailed {
        reason: format!("OS CSPRNG unavailable for genesis nonce: {e}"),
    })?;

    raxis_audit_tools::write_genesis_segment(
        audit_dir,
        authority_vk.as_bytes(),
        &nonce_bytes,
        unix_now_secs() as u64,
    )
    .map_err(|e| KernelError::BootstrapFailed {
        reason: format!("write genesis audit segment failed: {e}"),
    })
}

// ---------------------------------------------------------------------------
// --force support: deterministic cleanup of prior-genesis artifacts
// ---------------------------------------------------------------------------

/// Remove every file `run_inner` will subsequently try to write that
/// `write_file_0400` would refuse to overwrite.
///
/// Called only when `config.force == true`. The per-file exists-checks
/// inside `write_file_0400` are intentionally preserved as a defense-in-depth
/// layer: they catch any future genesis-emitting code path that forgets to
/// route through `purge_existing_genesis_artifacts`. The re-genesis flow
/// here MUST list every file the helpers below would create — adding a new
/// keys/* artifact without listing it here will silently break --force.
///
/// Operator pubkey files (`operator_<fp>.pub`) are written via
/// `write_file_0444`, which already truncates+overwrites, so they are not
/// listed here. The audit segment is similarly opened with `create+append`,
/// not `create_new`, so we only remove it to avoid appending a second
/// genesis record on top of the prior one (which would produce a
/// two-record segment-000 the chain verifier would reject).
fn purge_existing_genesis_artifacts(keys_dir: &Path, audit_dir: &Path) -> Result<(), KernelError> {
    let create_new_targets = [
        keys_dir.join("authority_keypair.pem"),
        keys_dir.join("quality_keypair.pem"),
        keys_dir.join("verifier_token_key.bin"),
    ];
    for path in &create_new_targets {
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| KernelError::BootstrapFailed {
                reason: format!("--force cleanup: cannot remove {}: {e}", path.display()),
            })?;
        }
    }

    // Stale operator pubkey files (`operator_<fp>.pub`) and stale
    // operator cert artefacts (`operator_<fp>.cert.toml`) from a
    // previous genesis must also go: a fresh genesis may register a
    // different operator, leaving the old fingerprint orphaned in
    // the keys dir would let a stale entry shadow lookups. The cert
    // file is now part of the canonical genesis output set
    // (cert-mandatory per INV-CERT-01) and is written with mode 0444
    // — without removing it, the second genesis attempt would fail
    // with EACCES on `write_file_0444`. We pattern-match by filename
    // to avoid removing unrelated files in keys/.
    if let Ok(entries) = std::fs::read_dir(keys_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("operator_")
                && (name.ends_with(".pub") || name.ends_with(".cert.toml"))
            {
                let p = entry.path();
                std::fs::remove_file(&p).map_err(|e| KernelError::BootstrapFailed {
                    reason: format!("--force cleanup: cannot remove {}: {e}", p.display()),
                })?;
            }
        }
    }

    // segment-000.jsonl is opened with create+append, so a second --force
    // run would tack a second genesis record onto the end of the existing
    // file — which the chain verifier would reject as "seq != 0 on first
    // record". Remove the prior segment so the next run writes a clean one.
    let segment0 = audit_dir.join("segment-000.jsonl");
    if segment0.exists() {
        std::fs::remove_file(&segment0).map_err(|e| KernelError::BootstrapFailed {
            reason: format!("--force cleanup: cannot remove {}: {e}", segment0.display()),
        })?;
    }

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
            reason: format!(
                "{} already exists; remove it before re-running genesis",
                path.display()
            ),
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
    file.write_all(data)
        .map_err(|e| KernelError::BootstrapFailed {
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
    file.write_all(data)
        .map_err(|e| KernelError::BootstrapFailed {
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
    file.write_all(data)
        .map_err(|e| KernelError::BootstrapFailed {
            reason: format!("cannot write {}: {e}", path.display()),
        })
}

// ---------------------------------------------------------------------------
// Integration tests — run_inner end-to-end against a TempDir.
//
// These tests close every "two halves of a contract" gap that bootstrap is
// the producer half of: the policy loader, the key registry, the audit-chain
// verifier, the SHA-256[:16] fingerprint convention, and the AuditDir test
// fixture (which until now was a hand-copied replica of bootstrap's genesis
// emitter — these tests pin the two emitters to the same byte shape).
//
// Why here (in `src/bootstrap.rs`) rather than in `kernel/tests/`:
//   - `run_inner` is `pub(crate)` — only an in-crate test can call it.
//   - Keeping the tests next to the production code makes drift visible at
//     review time. A spec-level reviewer who changes `write_genesis_policy`
//     sees the integration test's assertions in the same diff.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;

    // ── Test fixtures ───────────────────────────────────────────────────────

    /// A deterministic operator Ed25519 keypair derived from a fixed seed.
    /// Avoids `getrandom` so tests are reproducible across runs.
    ///
    /// Returns `(signing_key, hex-encoded public key)` because every caller
    /// needs the hex form (that's what we embed inside the cert that
    /// bootstrap reads from the on-disk `--operator-cert` file).
    fn fixed_operator_key() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[0xC1u8; 32]);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        (sk, pk_hex)
    }

    /// Mint a self-signed `Standard` cert from the fixed test key so
    /// bootstrap can be exercised end-to-end without going through the
    /// CLI's `raxis cert mint`. We sign at fixture-time rather than at
    /// suite-time so every cert byte (including the signature) is
    /// deterministic.
    fn fixed_operator_cert() -> OperatorCert {
        // Seed deliberately differs from the prod default `[42u8;32]` of
        // `raxis_test_support::ephemeral_cert` so a leak between this
        // fixture and any other surfaces immediately.
        let seed = [0xC1u8; 32];
        // Fixed `now` so the cert's [not_before, not_after] window is
        // byte-stable across runs.
        let now = 1_700_000_000;
        raxis_test_support::ephemeral_cert(seed, now)
    }

    /// Build a `BootstrapConfig` pointing at a fresh `TempDir` with a
    /// pre-written operator **cert** file (`*.cert.toml`). Returns the
    /// `TempDir` (held by the caller for the test's duration so it isn't
    /// dropped), the corresponding `BootstrapConfig`, and the operator
    /// pubkey hex (extracted from the cert) so tests can assert against
    /// the exact bytes that bootstrap wrote.
    fn fresh_bootstrap_env() -> (TempDir, BootstrapConfig, String) {
        let tmp = TempDir::new().expect("TempDir::new");
        let data_dir = tmp.path().to_path_buf();

        let cert = fixed_operator_cert();
        let op_pk_hex = cert.pubkey_hex.clone();
        let cert_path = data_dir.join("operator.cert.toml");
        // The data_dir doesn't exist yet — bootstrap creates the subdirs,
        // not the root — but we need a place to put the cert file so
        // bootstrap can read it. Stash it in the root data_dir, which is
        // the TempDir itself (always exists).
        let cert_toml = toml::to_string(&cert).expect("serialise cert");
        std::fs::write(&cert_path, cert_toml.as_bytes()).expect("write operator cert");

        let config = BootstrapConfig {
            data_dir,
            operator_cert_path: Some(cert_path),
            force: false,
        };

        (tmp, config, op_pk_hex)
    }

    /// Read a file's mode bits (the low 12 bits — owner/group/world rwx +
    /// setuid/setgid/sticky). Strips the file-type bits that `st_mode`
    /// also encodes so callers can compare directly against `0o400` etc.
    fn mode_bits(path: &Path) -> u32 {
        std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("metadata({}) failed: {e}", path.display()))
            .mode()
            & 0o7777
    }

    // ── Happy-path tests — every "producer / reader" round trip ─────────────

    #[test]
    fn run_inner_returns_ok_and_creates_every_required_artifact() {
        let (_tmp, config, _) = fresh_bootstrap_env();
        run_inner(&config).expect("run_inner must succeed on a fresh data_dir");

        let keys = config.data_dir.join("keys");
        let policy = config.data_dir.join("policy");
        let audit = config.data_dir.join("audit");

        for p in &[
            keys.join("authority_keypair.pem"),
            keys.join("quality_keypair.pem"),
            keys.join("verifier_token_key.bin"),
            policy.join("policy.toml"),
            audit.join("segment-000.jsonl"),
        ] {
            assert!(p.exists(), "missing artifact: {}", p.display());
        }

        // The operator pubkey file is named operator_<fingerprint>.pub. We
        // compute the expected fingerprint from the on-disk pubkey hex.
        let (_, op_pk_hex) = fixed_operator_key();
        let fp = pubkey_fingerprint_from_hex(&op_pk_hex).unwrap();
        let op_path = keys.join(format!("operator_{fp}.pub"));
        assert!(
            op_path.exists(),
            "operator pubkey file missing: {}",
            op_path.display()
        );
    }

    #[test]
    fn every_artifact_has_the_spec_mandated_permission_mode() {
        let (_tmp, config, _) = fresh_bootstrap_env();
        run_inner(&config).expect("run_inner");

        let keys = config.data_dir.join("keys");
        let policy = config.data_dir.join("policy");

        // cli-ceremony.md §4.2 fixes the modes for every output:
        //   keys/*.pem            → 0400 (owner read-only — private key material)
        //   keys/verifier_token*  → 0400 (owner read-only — HMAC secret)
        //   keys/operator_<fp>.pub→ 0444 (world-readable — public key)
        //   policy/policy.toml    → 0644 (world-readable, owner-writable)
        //
        // Note: the audit segment is created by the genesis-record writer
        // via `OpenOptions::open(...)` without an explicit mode call, so
        // its bits are governed by the process umask; we don't pin them.
        assert_eq!(mode_bits(&keys.join("authority_keypair.pem")), 0o400);
        assert_eq!(mode_bits(&keys.join("quality_keypair.pem")), 0o400);
        assert_eq!(mode_bits(&keys.join("verifier_token_key.bin")), 0o400);
        assert_eq!(mode_bits(&policy.join("policy.toml")), 0o644);

        let (_, op_pk_hex) = fixed_operator_key();
        let fp = pubkey_fingerprint_from_hex(&op_pk_hex).unwrap();
        assert_eq!(mode_bits(&keys.join(format!("operator_{fp}.pub"))), 0o444);
    }

    #[test]
    fn policy_toml_round_trips_through_raxis_policy_load_policy() {
        // The single most important "two halves" test in the file.
        // Bootstrap writes policy.toml; the kernel's own `load_policy`
        // (in raxis-policy::loader) parses it on every boot. A drift in
        // the schema (renamed field, missing required section) would
        // surface for operators only after they tried to boot the kernel
        // they just genesis'd.
        let (_tmp, config, op_pk_hex) = fresh_bootstrap_env();
        run_inner(&config).expect("run_inner");

        let policy_path = config.data_dir.join("policy").join("policy.toml");
        let (bundle, raw_bytes, sha) = raxis_policy::load_policy(&policy_path)
            .expect("load_policy must accept what bootstrap wrote");

        assert_eq!(bundle.epoch(), 1, "genesis epoch is always 1");
        assert!(!raw_bytes.is_empty(), "raw bytes must be non-empty");
        assert_eq!(sha.len(), 64, "sha256 hex is 64 chars");

        // The SHA the loader computed must match what we'd compute on the
        // file independently — cheap belt-and-braces against the loader
        // accidentally hashing something other than the file bytes.
        let mut h = Sha256::new();
        h.update(&raw_bytes);
        let direct = hex::encode(h.finalize());
        assert_eq!(direct, sha);

        // The exactly-one operator entry must carry the on-disk pubkey hex.
        let ops = bundle.operators();
        assert_eq!(ops.len(), 1, "bootstrap registers exactly one operator");
        assert_eq!(ops[0].pubkey_hex, op_pk_hex);
    }

    #[test]
    fn genesis_writes_epoch_one_into_policy_epoch_history() {
        // Pins the bootstrap ↔ policy_manager::install_genesis_policy_epoch
        // contract: after a successful run, the on-disk kernel.db carries
        // exactly one row in `policy_epoch_history` with epoch_id = 1,
        // triggered_by_operator = "genesis", and policy_sha256 equal to
        // the hash of the genesis policy.toml on disk. Without this row
        // the first RotateEpoch would record epoch_id = 1 instead of 2,
        // leaving the genesis artifact unrecorded in the policy history
        // (kernel-core.md §`policy_manager.rs` "two writers" contract).
        let (_tmp, config, _) = fresh_bootstrap_env();
        run_inner(&config).expect("run_inner");

        let policy_path = config.data_dir.join("policy").join("policy.toml");
        let (_b, _bytes, expected_sha) =
            raxis_policy::load_policy(&policy_path).expect("load policy");

        let store = raxis_store::Store::open(&config.data_dir.join("kernel.db"))
            .expect("re-open kernel.db");
        let conn = store.lock_sync();
        let (epoch_id, sha, triggered): (i64, String, String) = conn
            .query_row(
                &format!(
                    "SELECT epoch_id, policy_sha256, triggered_by_operator
                       FROM {POLICY_EPOCH_HISTORY}
                      ORDER BY epoch_id DESC LIMIT 1"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("policy_epoch_history must contain the genesis row");
        assert_eq!(epoch_id, 1);
        assert_eq!(sha, expected_sha);
        assert_eq!(triggered, "genesis");
    }

    #[test]
    fn genesis_install_is_idempotent_under_force_re_run() {
        // A `--force` re-bootstrap rewrites every key + policy artifact
        // and must NOT trip the UNIQUE(policy_sha256) constraint on the
        // genesis row written by the previous run. The deterministic
        // fixture key + clock means the second policy.toml hashes to the
        // same value as the first; INSERT OR IGNORE keeps the run
        // idempotent.
        let (tmp, mut config, _) = fresh_bootstrap_env();
        run_inner(&config).expect("first run");

        config.force = true;
        run_inner(&config).expect("force re-run must succeed");

        let store =
            raxis_store::Store::open(&tmp.path().join("kernel.db")).expect("re-open kernel.db");
        let conn = store.lock_sync();
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {POLICY_EPOCH_HISTORY}"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "genesis row must remain unique after re-run");
    }

    #[test]
    fn keys_round_trip_through_authority_load_key_registry() {
        // Pins the bootstrap ↔ authority::load_key_registry contract: the
        // PEM-like format bootstrap writes for authority/quality keys, and
        // the raw 32-byte format for verifier_token_key.bin, must be
        // exactly what the production loader expects to parse.
        let (_tmp, config, _) = fresh_bootstrap_env();
        run_inner(&config).expect("run_inner");

        let registry = crate::authority::load_key_registry(&config.data_dir)
            .expect("load_key_registry must accept what bootstrap wrote");

        // Round-trip a signature: signing then verifying with the loaded
        // registry MUST succeed. A bug that loaded a 31-byte seed (one
        // hex char short) would silently produce a different keypair —
        // signing would still work but the public key would be wrong.
        // The audit-record signer is the production code that exercises
        // this path; we just confirm the API works end-to-end.
        let _fp = crate::authority::authority_pubkey_fingerprint(&registry);
        // Sign a sample byte string and confirm the signature verifies.
        let sample = b"bootstrap integration test sample";
        let sig = crate::authority::sign_audit_record(sample, &registry);
        // ed25519-dalek::Signature → bytes, then back through the
        // verifier API the kernel uses (raxis_crypto::verify_ed25519).
        let pk = crate::authority::keys::authority_verifying_key(&registry);
        raxis_crypto::verify_ed25519(&pk.to_bytes(), sample, &sig.to_bytes())
            .expect("authority round-trip signature must verify");
    }

    #[test]
    fn genesis_audit_record_is_accepted_by_recovery_verify_audit_chain() {
        // Pins the bootstrap ↔ recovery::verify_audit_chain contract.
        // Until now `AuditDir::write_genesis_record` (the test fixture)
        // was a hand-copied replica of bootstrap's genesis emitter; this
        // test runs the REAL bootstrap and the REAL verifier against the
        // same artifact, so any drift is caught immediately.
        let (_tmp, config, _) = fresh_bootstrap_env();
        run_inner(&config).expect("run_inner");

        let audit_dir = config.data_dir.join("audit");
        // verify_audit_chain is module-private to recovery.rs but we can
        // hit it indirectly through the recovery::reconcile entry point,
        // which calls verify_audit_chain first and propagates its error.
        // The return value carries swept_tasks=0 on a clean chain.
        let result = crate::recovery::reconcile(&raxis_test_support::mem_store(), &audit_dir);
        let report =
            result.expect("recovery::reconcile must accept the genesis chain bootstrap wrote");
        assert_eq!(
            report.swept_tasks, 0,
            "fresh genesis has no in-flight tasks"
        );
        assert_eq!(report.expired_tokens, 0, "fresh genesis has no live tokens");
        assert_eq!(
            report.folded_integration_merge_attempts, 0,
            "fresh genesis has no in-flight integration_merge_attempts rows",
        );
    }

    #[test]
    fn policy_meta_signed_by_matches_sha256_16_of_pubkey_on_disk() {
        // Cross-file consistency invariant: `policy.toml.meta.signed_by`
        // is the SHA-256[:16] of the operator pubkey, AND the pubkey file
        // is named `operator_<that fingerprint>.pub`. A bug that computed
        // the fingerprint over the wrong byte slice (e.g. the hex string
        // instead of the raw key bytes — the kernel's other halves
        // disagree about which) would surface here.
        let (_tmp, config, op_pk_hex) = fresh_bootstrap_env();
        run_inner(&config).expect("run_inner");

        // (a) Loader's view of the operator entry.
        let policy_path = config.data_dir.join("policy").join("policy.toml");
        let (bundle, _, _) = raxis_policy::load_policy(&policy_path).unwrap();
        let signed_by = bundle.signed_by().to_owned();

        // (b) raxis-policy's canonical fingerprint function over the same hex.
        let fp_via_loader = raxis_policy::loader::operator_pubkey_fingerprint(&op_pk_hex)
            .expect("operator_pubkey_fingerprint must accept canonical hex");

        // (c) The fingerprint embedded in the operator pubkey file's name
        //     on disk.
        let entries: Vec<_> = std::fs::read_dir(config.data_dir.join("keys"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("operator_") && n.ends_with(".pub"))
            .collect();
        assert_eq!(entries.len(), 1, "exactly one operator pubkey file");
        let on_disk_fp = entries[0]
            .strip_prefix("operator_")
            .and_then(|s| s.strip_suffix(".pub"))
            .unwrap();

        // All three views MUST agree on the same 32-char fingerprint.
        assert_eq!(
            signed_by, fp_via_loader,
            "policy.meta.signed_by != raxis_policy::operator_pubkey_fingerprint"
        );
        assert_eq!(
            signed_by, on_disk_fp,
            "policy.meta.signed_by != filename fingerprint"
        );
        assert_eq!(
            signed_by.len(),
            32,
            "fingerprint must be SHA-256[:16] = 32 hex chars"
        );
    }

    #[test]
    fn bootstrap_genesis_line_shape_matches_audit_dir_fixture() {
        // Pins the AuditDir test fixture to bootstrap forever. Until this
        // test, `AuditDir::write_genesis_record` was a hand-copied replica
        // — if bootstrap added a field to its genesis emitter, the fixture
        // would silently drift and the audit-chain integration tests would
        // continue to pass against the wrong shape.
        //
        // The two emitters cannot byte-for-byte match (UUIDs, timestamps,
        // and the genesis_nonce are CSPRNG-minted), so we compare the
        // structural shape: the EXACT set of top-level field names AND
        // the type each carries.
        let (_tmp, config, _) = fresh_bootstrap_env();
        run_inner(&config).expect("run_inner");

        let bootstrap_audit = config.data_dir.join("audit");
        let bootstrap_line =
            std::fs::read_to_string(bootstrap_audit.join("segment-000.jsonl")).unwrap();
        let bootstrap_rec: serde_json::Value =
            serde_json::from_str(bootstrap_line.lines().next().unwrap()).unwrap();

        let fixture = raxis_test_support::AuditDir::new();
        fixture.write_genesis_record();
        let fixture_recs = fixture.read_records();
        let fixture_rec = &fixture_recs[0];

        // Same set of keys, same type for each.
        let bootstrap_keys: std::collections::BTreeSet<&str> = bootstrap_rec
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let fixture_keys: std::collections::BTreeSet<&str> = fixture_rec
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            bootstrap_keys, fixture_keys,
            "AuditDir::write_genesis_record key set has drifted from bootstrap's emitter",
        );

        // Per-field type pinning — fixture's value for each key MUST be
        // the same JSON type as bootstrap's. This catches e.g. one side
        // emitting `seq: 0` (number) while the other emits `seq: "0"`
        // (string), which would round-trip through serde but break the
        // verifier's structural checks.
        for k in &bootstrap_keys {
            let b = &bootstrap_rec[k];
            let f = &fixture_rec[k];
            let same_kind = (b.is_string() && f.is_string())
                || (b.is_number() && f.is_number())
                || (b.is_boolean() && f.is_boolean())
                || (b.is_null() && f.is_null())
                || (b.is_array() && f.is_array())
                || (b.is_object() && f.is_object());
            assert!(
                same_kind,
                "field {k:?}: bootstrap is {b:?}, fixture is {f:?} — JSON kinds differ"
            );
        }

        // Spot-pin the values that MUST be byte-identical regardless of
        // CSPRNG state: prev_sha256 (genesis sentinel), seq, event_kind.
        assert_eq!(bootstrap_rec["prev_sha256"], fixture_rec["prev_sha256"]);
        assert_eq!(bootstrap_rec["seq"], fixture_rec["seq"]);
        assert_eq!(bootstrap_rec["event_kind"], fixture_rec["event_kind"]);

        // String fields MUST match the spec's lengths: nonce ≥ 256 bits
        // (we mint 512 → 128 hex chars), fingerprint = SHA-256[:16] = 32 hex.
        assert_eq!(bootstrap_rec["genesis_nonce"].as_str().unwrap().len(), 128);
        assert_eq!(
            bootstrap_rec["authority_pubkey_fingerprint"]
                .as_str()
                .unwrap()
                .len(),
            32,
        );
        assert_eq!(
            bootstrap_rec["prev_sha256"].as_str().unwrap(),
            "0".repeat(64),
            "genesis prev_sha256 sentinel is 64 zeroes",
        );
    }

    #[test]
    fn genesis_record_authority_fingerprint_matches_authority_pubkey_on_disk() {
        // Cross-file invariant: the genesis record's
        // `authority_pubkey_fingerprint` is SHA-256[:16] of the SAME
        // authority pubkey that gets written into policy.toml's
        // `[authority]` section. If bootstrap ever wrote DIFFERENT keys
        // into the two files, every audit verifier would compute a
        // mismatch.
        let (_tmp, config, _) = fresh_bootstrap_env();
        run_inner(&config).expect("run_inner");

        // (a) Authority pubkey from the on-disk PEM.
        let registry = crate::authority::load_key_registry(&config.data_dir).unwrap();
        let registry_fp = crate::authority::authority_pubkey_fingerprint(&registry);

        // (b) Authority pubkey echoed inside the policy.toml.
        let (bundle, _, _) =
            raxis_policy::load_policy(&config.data_dir.join("policy").join("policy.toml")).unwrap();
        let policy_pk_bytes = bundle.authority_pubkey_bytes().unwrap();
        let mut h = Sha256::new();
        h.update(&policy_pk_bytes);
        let policy_fp = hex::encode(&h.finalize()[..16]);

        // (c) Fingerprint embedded in the genesis audit record.
        let line = std::fs::read_to_string(config.data_dir.join("audit").join("segment-000.jsonl"))
            .unwrap();
        let rec: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
        let audit_fp = rec["authority_pubkey_fingerprint"].as_str().unwrap();

        assert_eq!(
            registry_fp, policy_fp,
            "registry-derived fingerprint must equal policy-file fingerprint"
        );
        assert_eq!(
            registry_fp, audit_fp,
            "registry-derived fingerprint must equal audit-record fingerprint"
        );
    }
}

// ---------------------------------------------------------------------------
// Edge-case tests — guards, error paths, idempotence semantics.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod edge_cases {
    use super::*;
    use ed25519_dalek::SigningKey;
    use raxis_test_support::{ephemeral_cert_with_key, CertOpts};
    use tempfile::TempDir;

    /// Build a fresh `(TempDir, BootstrapConfig)` pair that points at a
    /// pre-written, structurally-valid cert TOML on disk. The cert is
    /// deterministic (fixed seed) so failures reproduce byte-identically.
    fn fresh_env_with_good_cert() -> (TempDir, BootstrapConfig) {
        let tmp = TempDir::new().unwrap();
        let cert = good_cert();
        let cert_path = tmp.path().join("operator.cert.toml");
        std::fs::write(
            &cert_path,
            toml::to_string(&cert).expect("serialise cert").as_bytes(),
        )
        .unwrap();
        let config = BootstrapConfig {
            data_dir: tmp.path().to_path_buf(),
            operator_cert_path: Some(cert_path),
            force: false,
        };
        (tmp, config)
    }

    /// Variant of [`fresh_env_with_good_cert`] that lets the caller supply
    /// raw cert-file bytes (used by malformed-input tests).
    fn fresh_env_with_cert_bytes(cert_bytes: &[u8]) -> (TempDir, BootstrapConfig) {
        let tmp = TempDir::new().unwrap();
        let cert_path = tmp.path().join("operator.cert.toml");
        std::fs::write(&cert_path, cert_bytes).unwrap();
        let config = BootstrapConfig {
            data_dir: tmp.path().to_path_buf(),
            operator_cert_path: Some(cert_path),
            force: false,
        };
        (tmp, config)
    }

    /// Mint a deterministic, structurally-valid, self-signed `Standard`
    /// cert from a fixed seed. Used by every happy-path edge-case test in
    /// this module.
    fn good_cert() -> OperatorCert {
        let key = SigningKey::from_bytes(&[0xD1u8; 32]);
        ephemeral_cert_with_key(
            &key,
            CertOpts {
                // Anchor `now` to a value that places the cert squarely in
                // the Active zone — no warn / grace overlap inside any
                // edge-case test.
                now_unix_secs: 1_700_000_000,
                ..CertOpts::default()
            },
        )
    }

    // ── Re-genesis guard ────────────────────────────────────────────────────

    #[test]
    fn second_run_without_force_fails_with_already_exists_message() {
        // The whole point of the re-genesis guard: an operator must not
        // accidentally regenerate keys (which would invalidate every
        // existing session, plan signature, and witness blob — the kernel
        // has no migration path for that).
        let (_tmp, config) = fresh_env_with_good_cert();
        run_inner(&config).expect("first run");

        let err = run_inner(&config).expect_err("second run must fail");
        match err {
            KernelError::BootstrapFailed { reason } => {
                assert!(
                    reason.contains("already exists") && reason.contains("--force"),
                    "expected already-exists+force message, got {reason:?}",
                );
            }
            other => panic!("expected BootstrapFailed, got {other:?}"),
        }
    }

    // ── providers/ directory (Phase A.3 / T0.3) ─────────────────────────────

    #[test]
    fn bootstrap_creates_providers_directory_with_0700_permissions() {
        // Per peripherals.md §3.2 "Provider credential storage": credential
        // files live under <data_dir>/providers/ and are readable only by
        // the kernel uid. The bootstrap MUST create the directory (so an
        // operator dropping a credentials file does not have to mkdir
        // first) AND chmod 0700 (so a careless umask does not leak the
        // directory listing to other users on the host).
        let (tmp, config) = fresh_env_with_good_cert();
        run_inner(&config).expect("bootstrap");

        let providers_dir = tmp.path().join("providers");
        let meta =
            std::fs::metadata(&providers_dir).expect("providers/ must exist after bootstrap");
        assert!(meta.is_dir(), "providers/ must be a directory");

        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "providers/ must be chmod 0700; got 0{mode:o}");
    }

    // ── keys/ directory mode (raxis doctor FAIL fix) ───────────────────────

    #[test]
    fn bootstrap_chmods_keys_directory_to_0700() {
        // `raxis doctor` (cli/src/commands/doctor.rs::EXPECTED_MODES)
        // pins keys/ at 0o700 and treats any other mode as FAIL — the
        // operator's observable symptom was
        //
        //     [FAIL] keys.mode  mode is 0755, expected 0700
        //
        // immediately after `RAXIS_BOOTSTRAP=1 raxis-kernel`, because
        // the previous bootstrap ran `create_dir_all` and trusted the
        // umask. Pin the chmod here so a future "simplify the dir-
        // creation loop" PR can't quietly re-introduce the bug.
        let (tmp, config) = fresh_env_with_good_cert();
        run_inner(&config).expect("bootstrap");

        let keys_dir = tmp.path().join("keys");
        let meta = std::fs::metadata(&keys_dir).expect("keys/ must exist");
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "keys/ must be chmod 0700 after bootstrap (raxis doctor flags any other mode as FAIL); got 0{mode:o}",
        );
    }

    // ── sockets/ + notifications/ existence (raxis doctor FAIL fix) ─────────

    #[test]
    fn bootstrap_creates_sockets_directory_so_doctor_does_not_flag_it() {
        // Before this fix, `<data_dir>/sockets/` was created lazily by
        // `ipc::server::start` only on first kernel boot — meaning an
        // operator running `raxis doctor` between `RAXIS_BOOTSTRAP=1
        // raxis-kernel` and the next start saw
        //
        //     [FAIL] sockets.exists  missing: <data_dir>/sockets
        //
        // Pin that bootstrap creates the directory eagerly. Mode is
        // intentionally 0755 (the socket *files* themselves are mode-
        // hardened individually per kernel-store.md §2.5.5).
        let (tmp, config) = fresh_env_with_good_cert();
        run_inner(&config).expect("bootstrap");

        let sockets_dir = tmp.path().join("sockets");
        let meta = std::fs::metadata(&sockets_dir)
            .expect("sockets/ must exist after bootstrap so `raxis doctor` does not FAIL");
        assert!(meta.is_dir(), "sockets/ must be a directory");
    }

    #[test]
    fn bootstrap_creates_notifications_directory_so_doctor_reports_ok() {
        // Doctor degrades a missing `notifications/` to WARN (not FAIL),
        // because the Shell notification channel creates it lazily on
        // first delivery. But operators reading the doctor report after
        // a fresh genesis shouldn't see WARN rows for things genesis
        // could have trivially set up. Pin that bootstrap creates the
        // directory so `raxis doctor` is fully green right after the
        // ceremony.
        let (tmp, config) = fresh_env_with_good_cert();
        run_inner(&config).expect("bootstrap");

        let notifications_dir = tmp.path().join("notifications");
        let meta = std::fs::metadata(&notifications_dir)
            .expect("notifications/ must exist after bootstrap");
        assert!(meta.is_dir(), "notifications/ must be a directory");
    }

    // ── runtime/ directory (Phase A1 / T2.1) ────────────────────────────────

    #[test]
    fn bootstrap_creates_runtime_directory() {
        // Per cli-readonly.md §5.2.1, the kernel writes
        // `<data_dir>/runtime/heartbeat.json` once at startup and every
        // 5s thereafter. The directory MUST already exist when the
        // first heartbeat write happens — the writer uses
        // `tempfile + atomic rename` and would crash on a missing
        // parent. Genesis is the natural place to mkdir it.
        let (tmp, config) = fresh_env_with_good_cert();
        run_inner(&config).expect("bootstrap");

        let runtime_dir = tmp.path().join("runtime");
        let meta = std::fs::metadata(&runtime_dir).expect("runtime/ must exist after bootstrap");
        assert!(meta.is_dir(), "runtime/ must be a directory");
        // No chmod 0700 contract here: heartbeat.json carries no
        // secrets and is intended to be readable by the operator's
        // CLI process running under the same uid.
    }

    #[test]
    fn bootstrapped_policy_loads_with_no_gateway_section() {
        // The genesis policy template emits `[gateway]` and `[[providers]]`
        // as commented blocks. A freshly-bootstrapped kernel must therefore
        // load policy.toml with `gateway() == None` and `providers() == &[]`
        // — the no-LLM degraded mode mentioned in the spec.
        let (tmp, config) = fresh_env_with_good_cert();
        run_inner(&config).expect("bootstrap");

        let (bundle, _, _) = raxis_policy::load_policy(&tmp.path().join("policy/policy.toml"))
            .expect("genesis policy must load");
        assert!(
            bundle.gateway().is_none(),
            "genesis template must NOT activate [gateway]; operator must opt in"
        );
        assert!(
            bundle.providers().is_empty(),
            "genesis template must NOT activate [[providers]]; operator must opt in"
        );
    }

    #[test]
    fn second_run_with_force_succeeds_and_overwrites() {
        // The escape hatch: --force lets an operator deliberately re-run
        // genesis (e.g. to recover from a torn first run). The new
        // authority key MUST replace the old one byte-for-byte.
        let (_tmp, mut config) = fresh_env_with_good_cert();
        run_inner(&config).expect("first run");

        // Capture the authority pubkey from run #1.
        let pk1 = crate::authority::authority_pubkey_fingerprint(
            &crate::authority::load_key_registry(&config.data_dir).unwrap(),
        );

        config.force = true;
        run_inner(&config).expect("force run must succeed");

        let pk2 = crate::authority::authority_pubkey_fingerprint(
            &crate::authority::load_key_registry(&config.data_dir).unwrap(),
        );
        assert_ne!(
            pk1, pk2,
            "force re-genesis must mint a new authority keypair"
        );
    }

    // ── Operator cert input validation ──────────────────────────────────────

    #[test]
    fn missing_operator_cert_file_fails_with_path_in_message() {
        let tmp = TempDir::new().unwrap();
        let config = BootstrapConfig {
            data_dir: tmp.path().to_path_buf(),
            operator_cert_path: Some(tmp.path().join("does/not/exist.cert.toml")),
            force: false,
        };
        let err = run_inner(&config).expect_err("missing cert file must error");
        match err {
            KernelError::BootstrapFailed { reason } => {
                assert!(
                    reason.contains("operator cert") && reason.contains("does/not/exist.cert.toml"),
                    "error message should name the missing path: {reason:?}",
                );
            }
            other => panic!("expected BootstrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn malformed_operator_cert_input_fails_with_parse_message() {
        // The cert is supplied as a TOML document. Anything that is not
        // a valid TOML body (or that parses but is missing a required
        // `OperatorCert` field) MUST surface a `cert parse failed`
        // diagnostic rather than panicking deeper inside the policy
        // emitter — operators need to know the symptom.
        let (_tmp, config) = fresh_env_with_cert_bytes(b"not a TOML cert");
        let err = run_inner(&config).expect_err("malformed cert must error");
        match err {
            KernelError::BootstrapFailed { reason } => {
                assert!(
                    reason.contains("operator cert parse failed"),
                    "expected parse-failed error, got {reason:?}",
                );
            }
            other => panic!("expected BootstrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn structurally_invalid_operator_cert_fails_closed_at_bootstrap() {
        // A cert whose `pubkey_hex` is the wrong length must be rejected
        // by `validate_cert_structurally` BEFORE we touch policy.toml.
        // Otherwise the round-trip read at next boot would fail and the
        // operator would see a "successful" genesis they cannot start.
        let mut cert = good_cert();
        cert.pubkey_hex = "deadbeef".to_owned(); // 8 chars, not 64
        let (_tmp, config) = fresh_env_with_cert_bytes(toml::to_string(&cert).unwrap().as_bytes());
        let err = run_inner(&config).expect_err("structurally-invalid cert must error");
        match err {
            KernelError::BootstrapFailed { reason } => {
                assert!(
                    reason.contains("structural validation failed"),
                    "expected structural-validation error, got {reason:?}",
                );
            }
            other => panic!("expected BootstrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn operator_cert_with_invalid_self_signature_fails_closed_at_bootstrap() {
        // A cert that parses + structurally validates but whose
        // `self_sig_hex` does not actually verify under `pubkey_hex`
        // (e.g. an operator hand-edited their cert.toml after minting)
        // must fail closed at bootstrap rather than be rubber-stamped
        // into policy.toml.
        let mut cert = good_cert();
        // Flip the last byte of the signature — still 128 hex chars,
        // still parses, but no longer a valid Ed25519 signature.
        let mut sig_bytes = hex::decode(&cert.self_sig_hex).unwrap();
        sig_bytes[63] ^= 0x01;
        cert.self_sig_hex = hex::encode(&sig_bytes);
        let (_tmp, config) = fresh_env_with_cert_bytes(toml::to_string(&cert).unwrap().as_bytes());
        let err = run_inner(&config).expect_err("tampered self-sig must error");
        match err {
            KernelError::BootstrapFailed { reason } => {
                assert!(
                    reason.contains("self-signature verification failed"),
                    "expected self-sig-verification error, got {reason:?}",
                );
            }
            other => panic!("expected BootstrapFailed, got {other:?}"),
        }
    }

    #[test]
    fn operator_cert_is_persisted_to_keys_dir_after_bootstrap() {
        // The kernel must persist the supplied cert to
        // `keys/operator_<fp>.cert.toml` so a future `raxis cert show`
        // / `raxis cert verify` against the data dir can find it
        // without the operator having to retain their original cert
        // artefact. The on-disk bytes MUST round-trip back to the
        // same `OperatorCert` we passed in.
        let (tmp, config) = fresh_env_with_good_cert();
        run_inner(&config).expect("bootstrap");

        let keys_dir = tmp.path().join("keys");
        let mut cert_file = None;
        for entry in std::fs::read_dir(&keys_dir).expect("keys dir readable") {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name = name.to_string_lossy().to_string();
            if name.starts_with("operator_") && name.ends_with(".cert.toml") {
                cert_file = Some(entry.path());
                break;
            }
        }
        let cert_path =
            cert_file.expect("bootstrap must write operator_<fp>.cert.toml under keys/");
        let raw = std::fs::read_to_string(&cert_path).unwrap();
        let parsed: OperatorCert = toml::from_str(&raw).expect("persisted cert must round-trip");
        assert_eq!(
            parsed,
            good_cert(),
            "persisted cert must equal the cert bootstrap was supplied"
        );

        // Mode bits: the cert is public material (it embeds only the
        // pubkey, never the private key) and must be world-readable
        // (0o444) so that `raxis cert show` running as a different uid
        // can inspect it.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o444,
            "operator_<fp>.cert.toml must be chmod 0444 (public material); got 0{mode:o}"
        );
    }

    // ── Authority and quality keys must be DISTINCT ─────────────────────────

    #[test]
    fn authority_and_quality_keypairs_are_distinct() {
        // Both keypairs are CSPRNG-minted. The probability of collision
        // is 2^-256, but a bug that accidentally re-used the same RNG
        // state for both would silently produce identical keys, and v2's
        // witness attestation (which uses quality_keypair) would then be
        // signing under the authority key — a trust-boundary violation.
        let (_tmp, config) = fresh_env_with_good_cert();
        run_inner(&config).unwrap();

        let auth_path = config.data_dir.join("keys").join("authority_keypair.pem");
        let qual_path = config.data_dir.join("keys").join("quality_keypair.pem");
        let auth_pem = std::fs::read_to_string(&auth_path).unwrap();
        let qual_pem = std::fs::read_to_string(&qual_path).unwrap();
        assert_ne!(
            auth_pem, qual_pem,
            "authority_keypair.pem and quality_keypair.pem MUST contain distinct key material"
        );
    }

    // ── Verifier token key bytes are 32 bytes exactly ───────────────────────

    #[test]
    fn verifier_token_key_is_exactly_32_bytes() {
        let (_tmp, config) = fresh_env_with_good_cert();
        run_inner(&config).unwrap();
        let key =
            std::fs::read(config.data_dir.join("keys").join("verifier_token_key.bin")).unwrap();
        assert_eq!(
            key.len(),
            32,
            "verifier_token_key.bin MUST be 32 bytes (HMAC-SHA256 key size)"
        );
    }

    // ── Genesis nonce uniqueness across invocations ─────────────────────────

    #[test]
    fn two_force_runs_mint_distinct_genesis_nonces() {
        // The genesis nonce is the chain-anchor entropy; two genesis runs
        // on the same machine MUST produce different nonces or operators
        // could not distinguish two distinct kernel installs from one.
        let (_tmp, mut config) = fresh_env_with_good_cert();
        run_inner(&config).unwrap();
        let line1 =
            std::fs::read_to_string(config.data_dir.join("audit").join("segment-000.jsonl"))
                .unwrap();

        // Wipe ONLY the audit segment (so the next run will append fresh)
        // and rerun with --force so the key files get overwritten too.
        std::fs::remove_file(config.data_dir.join("audit").join("segment-000.jsonl")).unwrap();
        config.force = true;
        run_inner(&config).unwrap();

        let line2 =
            std::fs::read_to_string(config.data_dir.join("audit").join("segment-000.jsonl"))
                .unwrap();
        let rec1: serde_json::Value = serde_json::from_str(line1.lines().next().unwrap()).unwrap();
        let rec2: serde_json::Value = serde_json::from_str(line2.lines().next().unwrap()).unwrap();
        assert_ne!(
            rec1["genesis_nonce"], rec2["genesis_nonce"],
            "two genesis runs must mint distinct nonces",
        );
    }
}
