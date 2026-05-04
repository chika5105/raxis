// raxis-cli::commands::genesis — Genesis key ceremony.
//
// Normative reference: cli-ceremony.md §4.1 `genesis`, §4.2 step-by-step.
//
// Generates all key families, writes initial policy.toml, installs the
// genesis row in `policy_epoch_history`, and writes the chain-anchor
// `audit/segment-000.jsonl`. After this command returns Ok, the operator
// signs `policy.toml` and starts the kernel — the kernel will boot
// without ever touching `RAXIS_BOOTSTRAP=1` (the kernel-side bootstrap
// path is reserved for non-CLI deployments / recovery).
//
// Why every step matters
// ──────────────────────
// All four trusted stores must exist *and* be at their spec'd modes
// before the kernel's startup pipeline (kernel-core.md §2.1) succeeds:
//
//   * keys/ at 0700, files at 0400/0444 — `authority::load_key_registry`
//     reads them at boot step 4 (BOOT_ERR_KEY_REGISTRY).
//   * providers/ at 0700 — `gateway` subprocess reads from this dir at
//     step 9; missing dir = no provider can be configured.
//   * runtime/ — `<runtime>/heartbeat.json` lives here; missing dir would
//     race `tempfile + rename` during the first heartbeat write.
//   * policy/policy.toml + policy.sig — boot step 3 (BOOT_ERR_POLICY_INVALID).
//   * kernel.db with the epoch-1 row in `policy_epoch_history` — without
//     this row the first `RotateEpoch` would record `epoch_id = 1` instead
//     of `2`, orphaning the genesis artifact in the policy-history audit
//     trail (kernel-core.md §`policy_manager.rs` "two writers" contract).
//   * audit/segment-000.jsonl — boot step 6-chain (BOOT_ERR_AUDIT_CHAIN).
//     This is the chain anchor every subsequent record links back to.
//
// The kernel's `bootstrap::run_inner` produces the same set of artifacts.
// Both paths share the same writers (`raxis_store::install_genesis_policy_epoch_row`,
// `raxis_audit_tools::write_genesis_segment`) so the byte-level shape
// cannot drift between them.

use std::fs;
use std::path::{Path, PathBuf};

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
    let audit_dir = data_dir.join("audit");
    // `providers/` holds per-provider credential files (peripherals.md §3.2);
    // `runtime/` holds the kernel's `heartbeat.json`. Both are required by
    // `raxis doctor` and by the kernel's own first-boot writes.
    let providers_dir = data_dir.join("providers");
    let runtime_dir = data_dir.join("runtime");

    // Step 1: Check for existing key files.
    let authority_key_path = keys_dir.join("authority_keypair.pem");
    if authority_key_path.exists() && !force {
        return Err(CliError::Usage(
            "ERR_ALREADY_INITIALIZED: data directory already contains key files. \
             Use --force to overwrite (WARNING: this destroys existing keys)."
                .to_owned(),
        ));
    }

    // Create directories. Mode-tightening happens after `create_dir_all`
    // because that function honours the process umask (typically 0022),
    // which would leave keys/ at 0o755 — failing `raxis doctor`.
    //
    // `sockets/` and `notifications/` are created here so `raxis doctor`
    // run between `raxis genesis` and the first `raxis-kernel` start
    // does not report `[FAIL] sockets.exists` or `[WARN] notifications.exists`.
    // Both directories are eventually created lazily by their respective
    // kernel subsystems (`ipc::server::start` and the Shell notification
    // channel handler), but waiting for first kernel boot to do so leaves
    // the doctor report dirty in the meantime.
    let dirs_to_create = [
        ("keys", &keys_dir),
        ("policy", &policy_dir),
        ("audit", &audit_dir),
        ("providers", &providers_dir),
        ("runtime", &runtime_dir),
        ("sockets", &data_dir.join("sockets")),
        ("notifications", &data_dir.join("notifications")),
    ];
    for (_label, dir) in dirs_to_create {
        fs::create_dir_all(dir).map_err(|e| CliError::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
    }
    // `keys/` and `providers/` carry secret material — the kernel-side
    // bootstrap (kernel/src/bootstrap.rs) chmods both to 0700 so a
    // sibling user-process cannot read them. `raxis doctor` flags 0755
    // as FAIL for these dirs (`commands/doctor.rs::EXPECTED_MODES`).
    //
    // The chmod helpers were previously fire-and-forget (`let _ = …`)
    // which silently swallowed failures — exactly the failure mode that
    // produced the operator-visible `[FAIL] keys.mode mode is 0755`. They
    // now return `Result` and we `?` here, so any chmod EPERM/EROFS
    // surfaces at genesis time instead of as a silent unsafe-perms drift.
    set_permissions_700(&keys_dir)?;
    set_permissions_700(&providers_dir)?;

    // --force handling: remove the artifacts that the per-file `0400`
    // writes below would refuse to overwrite. The kernel-side bootstrap
    // does the equivalent in `purge_existing_genesis_artifacts`; we
    // mirror that list here so re-running `raxis genesis --force` is a
    // clean idempotent operation.
    if force {
        purge_existing_artifacts(&keys_dir, &audit_dir)?;
    }

    // Step 2: Generate authority_keypair (Ed25519). RNG failure aborts the
    // ceremony (cli-ceremony.md §4.2 step 2 — "fail closed").
    let authority_seed: [u8; 32] = try_random_array()?;
    let authority_key = SigningKey::from_bytes(&authority_seed);
    let authority_pubkey_bytes = authority_key.verifying_key().to_bytes();
    let authority_pubkey_hex = hex::encode(authority_pubkey_bytes);
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
    set_permissions_400(&vtk_path)?;
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
    set_permissions_444(&operator_pub_path)?;
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
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let signed_at_unix_secs = now_unix_secs as i64;
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

    // Step 6.5: Install the canonical `epoch_id = 1` row in
    // `policy_epoch_history`. We re-load policy.toml from disk (rather
    // than re-using the in-memory `policy_toml` we just wrote) so the
    // SHA-256 we record matches what the kernel will read at next boot
    // — there is no in-memory short-circuit that could drift from the
    // on-disk artifact. The store handle is dropped before step 7 so
    // the kernel's main `Store::open` at startup gets exclusive WAL
    // access. (See `kernel/src/bootstrap.rs::install_genesis_policy_epoch_row`
    // for the kernel-side mirror of this exact pattern.)
    install_genesis_epoch_row(
        data_dir,
        &policy_path,
        &authority_pubkey_bytes,
        signed_at_unix_secs,
    )?;
    println!("✓ Installed genesis policy_epoch_history row (epoch=1)");

    // Step 7: Write the chain-anchor genesis audit record. Without this
    // file the kernel exits BOOT_ERR_AUDIT_CHAIN at startup
    // (kernel-core.md §2.1 step 6-chain). We mint the 64-byte CSPRNG
    // nonce here — `raxis_audit_tools::write_genesis_segment` is pure
    // I/O so a partial RNG failure aborts the ceremony before we touch
    // the audit segment.
    let nonce_bytes: [u8; 64] = try_random_array()?;
    raxis_audit_tools::write_genesis_segment(
        &audit_dir,
        &authority_pubkey_bytes,
        &nonce_bytes,
        now_unix_secs,
    )
    .map_err(|e| CliError::Policy(format!("write genesis audit segment failed: {e}")))?;
    println!(
        "✓ Wrote genesis audit segment → {}",
        audit_dir.join("segment-000.jsonl").display(),
    );

    // Step 8: Remind operator to sign the policy.
    println!("\n=== CEREMONY NEXT STEPS ===");
    println!("Sign policy.toml with your private key:");
    println!("  raxis policy sign {} --key <your_private_key>", policy_path.display());
    println!("Then start the kernel:");
    println!("  RAXIS_DATA_DIR={} raxis-kernel", data_dir.display());

    Ok(())
}

/// Open the kernel.db (creating + migrating on first run), insert the
/// genesis row, and drop the handle. Centralised here so the
/// short-lived store handle's lifetime is obvious to a reviewer.
fn install_genesis_epoch_row(
    data_dir: &Path,
    policy_path: &Path,
    authority_pubkey_bytes: &[u8; 32],
    advanced_at_unix_secs: i64,
) -> Result<(), CliError> {
    let (_bundle, _raw_bytes, sha256_hex) = raxis_policy::load_policy(policy_path)
        .map_err(|e| {
            CliError::Policy(format!(
                "cannot re-load just-written policy artifact {}: {e}",
                policy_path.display(),
            ))
        })?;
    let signed_by_authority = raxis_genesis_tools::pubkey_fingerprint(authority_pubkey_bytes);

    let db_path = data_dir.join("kernel.db");
    let store = raxis_store::Store::open(&db_path).map_err(|e| {
        CliError::Policy(format!(
            "cannot open kernel.db at {}: {e}",
            db_path.display(),
        ))
    })?;
    raxis_store::install_genesis_policy_epoch_row(
        &store,
        &sha256_hex,
        &signed_by_authority,
        advanced_at_unix_secs,
    )
    .map_err(|e| CliError::Policy(format!("install_genesis_policy_epoch_row failed: {e}")))?;
    // Explicit drop so it is visible at review time that the WAL
    // file is closed before this function returns.
    drop(store);
    Ok(())
}

/// Best-effort cleanup of the artifacts that a `--force` re-run would
/// otherwise refuse to overwrite. Mirrors
/// `kernel/src/bootstrap.rs::purge_existing_genesis_artifacts` exactly.
fn purge_existing_artifacts(
    keys_dir: &Path,
    audit_dir: &Path,
) -> Result<(), CliError> {
    let create_targets = [
        keys_dir.join("authority_keypair.pem"),
        keys_dir.join("quality_keypair.pem"),
        keys_dir.join("verifier_token_key.bin"),
    ];
    for path in &create_targets {
        if path.exists() {
            fs::remove_file(path).map_err(|e| CliError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
        }
    }

    // Stale operator pubkey files (`operator_<fp>.pub`) from a prior
    // genesis must be cleaned out — a fresh genesis may register a
    // different operator and we must not leave the old fingerprint
    // shadowing lookups.
    if let Ok(entries) = fs::read_dir(keys_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("operator_") && name.ends_with(".pub") {
                let p = entry.path();
                fs::remove_file(&p).map_err(|e| CliError::Io {
                    path: p.display().to_string(),
                    source: e,
                })?;
            }
        }
    }

    // segment-000.jsonl is opened with create+append by the genesis
    // segment writer, so a second --force run would tack a second
    // genesis record onto the existing file — which the chain verifier
    // would reject (`seq != 0` on the second record). Remove the prior
    // segment so the next run writes a clean one.
    let segment0 = audit_dir.join("segment-000.jsonl");
    if segment0.exists() {
        fs::remove_file(&segment0).map_err(|e| CliError::Io {
            path: segment0.display().to_string(),
            source: e,
        })?;
    }

    // Remove the prior kernel.db too — the genesis row insert is
    // INSERT OR IGNORE so it would no-op against an existing row, but
    // a stale schema from a previous version would silently skip
    // migrations and confuse the kernel at boot. Forcing a fresh DB
    // is the safe default for `--force`.
    let kernel_db = keys_dir.parent().map(|p| p.join("kernel.db"));
    if let Some(db) = kernel_db {
        if db.exists() {
            fs::remove_file(&db).map_err(|e| CliError::Io {
                path: db.display().to_string(),
                source: e,
            })?;
        }
        // SQLite WAL sidecar files — cleaned up alongside the main DB.
        for sidecar in &["kernel.db-wal", "kernel.db-shm"] {
            if let Some(parent) = keys_dir.parent() {
                let p = parent.join(sidecar);
                if p.exists() {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }

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
            set_permissions_400(&path)?;
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
            set_permissions_444(&path)?;
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
    // 0400 — owner read-only. Matches `kernel/bootstrap::write_file_0400`
    // and `cli-ceremony.md §4.2` ("private key material is owner-only").
    set_permissions_400(path)?;
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

// On non-unix targets, mode bits are not meaningful; the helpers degrade
// to no-ops. We keep one helper per spec'd mode (0400 / 0444 / 0700) so a
// reviewer reading `run_genesis` can match each call site to the
// cli-ceremony.md §4.2 row that prescribes that mode.
//
// Why these return `Result<(), CliError>` (and not `()`):
// The previous fire-and-forget signature (`let _ = set_permissions(...)`)
// silently swallowed chmod failures. The operator-visible symptom was
// `raxis doctor` reporting `[FAIL] keys.mode mode is 0755, expected 0700`
// after a successful `raxis genesis` — because chmod had failed (or never
// run) and nobody told the operator. Propagating the Result means a chmod
// EPERM/EROFS/ENOENT now fails the genesis ceremony loudly at the call
// site, rather than producing an unsafe data dir that doctor catches
// after the fact.

#[cfg(unix)]
fn set_permissions_400(path: &std::path::Path) -> Result<(), CliError> {
    chmod(path, 0o400)
}

#[cfg(not(unix))]
fn set_permissions_400(_path: &std::path::Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn set_permissions_444(path: &std::path::Path) -> Result<(), CliError> {
    chmod(path, 0o444)
}

#[cfg(not(unix))]
fn set_permissions_444(_path: &std::path::Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn set_permissions_700(path: &std::path::Path) -> Result<(), CliError> {
    chmod(path, 0o700)
}

#[cfg(not(unix))]
fn set_permissions_700(_path: &std::path::Path) -> Result<(), CliError> {
    Ok(())
}

/// Apply `mode` to `path`. Failures are wrapped in [`CliError::Io`] so
/// the genesis flow's existing `?` error-propagation pattern surfaces
/// chmod errors at the same fidelity as `fs::write` errors.
#[cfg(unix)]
fn chmod(path: &std::path::Path, mode: u32) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        CliError::Io {
            path: format!("{} (chmod 0{:o})", path.display(), mode),
            source: e,
        }
    })
}

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

// ---------------------------------------------------------------------------
// End-to-end tests — exercise `run_genesis` against a tempdir and confirm the
// resulting data dir is what the kernel boot pipeline expects.
//
// These tests are the "two halves" pin between `cli/src/commands/genesis.rs`
// and the kernel's own startup checks. Until the genesis CLI command was
// completed, an operator running `raxis genesis` would silently produce a
// data dir missing `audit/segment-000.jsonl` and the genesis row in
// `policy_epoch_history`, and the kernel would only fail at the *next* boot
// with `BOOT_ERR_AUDIT_CHAIN`. Pinning the post-conditions here surfaces
// any regression at compile/test time rather than at first deployment.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod run_genesis_e2e {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::MetadataExt;

    /// Deterministic operator key — same fixture pattern the kernel-side
    /// `bootstrap::integration` tests use, so failures reproduce across
    /// runs without depending on `getrandom`.
    fn fixed_operator() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[0xC1u8; 32]);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        (sk, pk_hex)
    }

    fn fresh_flags() -> (tempfile::TempDir, GlobalFlags) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flags = GlobalFlags {
            data_dir: tmp.path().to_path_buf(),
            socket_path: None,
            operator_key_path: None,
        };
        (tmp, flags)
    }

    /// Write `pubkey_hex` to a sibling `operator.pub` file inside `dir`
    /// and return the path — what `--operator-pubkey` would point to.
    fn stage_operator_pubkey(dir: &Path, pubkey_hex: &str) -> PathBuf {
        let p = dir.join("operator.pub");
        std::fs::write(&p, pubkey_hex.as_bytes()).expect("write operator pubkey");
        p
    }

    fn mode_bits(path: &Path) -> u32 {
        std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("metadata({}) failed: {e}", path.display()))
            .mode()
            & 0o7777
    }

    #[test]
    fn run_genesis_creates_every_artifact_the_kernel_needs_at_boot() {
        let (tmp, flags) = fresh_flags();
        let (_sk, pk_hex) = fixed_operator();
        let pk_path = stage_operator_pubkey(tmp.path(), &pk_hex);

        run_genesis(&flags, false, Some(pk_path)).expect("run_genesis must succeed");

        let data_dir = tmp.path();
        // Every directory `raxis doctor` checks (commands/doctor.rs
        // ::EXPECTED_MODES). Missing `sockets/` and `notifications/`
        // were the operator-visible `raxis doctor` regressions: the
        // former produced `[FAIL] sockets.exists` (the kernel created
        // the dir lazily on first `ipc::server::start`); the latter
        // a `[WARN] notifications.exists` (created lazily by the Shell
        // notification channel handler on first delivery). Genesis
        // now creates both eagerly so a freshly-bootstrapped data dir
        // produces a fully-green doctor report.
        for d in &[
            "keys",
            "policy",
            "audit",
            "providers",
            "runtime",
            "sockets",
            "notifications",
        ] {
            assert!(data_dir.join(d).is_dir(), "missing dir: {d}");
        }
        // The four key-material files the kernel's `authority::load_key_registry`
        // opens at boot step 4 (BOOT_ERR_KEY_REGISTRY).
        let keys = data_dir.join("keys");
        assert!(keys.join("authority_keypair.pem").exists());
        assert!(keys.join("quality_keypair.pem").exists());
        assert!(keys.join("verifier_token_key.bin").exists());
        // The operator pubkey filename is operator_<fingerprint>.pub.
        let fp = raxis_genesis_tools::pubkey_fingerprint(
            &hex::decode(&pk_hex).expect("hex"),
        );
        assert!(keys.join(format!("operator_{fp}.pub")).exists());
        // The signed-policy file the kernel re-loads at boot step 3.
        assert!(data_dir.join("policy/policy.toml").exists());
        // The audit chain anchor — without this, the kernel exits
        // BOOT_ERR_AUDIT_CHAIN at step 6-chain. Pre-completion of the
        // CLI genesis command, this file was *missing* and operators
        // saw the kernel fail to boot after a successful `raxis genesis`.
        assert!(data_dir.join("audit/segment-000.jsonl").exists());
        // The kernel.db with the genesis row in policy_epoch_history.
        // Pre-completion, this DB did not exist either.
        assert!(data_dir.join("kernel.db").exists());
    }

    #[test]
    #[cfg(unix)]
    fn keys_and_providers_dirs_are_zero_seven_zero_zero() {
        let (tmp, flags) = fresh_flags();
        let (_sk, pk_hex) = fixed_operator();
        let pk_path = stage_operator_pubkey(tmp.path(), &pk_hex);

        run_genesis(&flags, false, Some(pk_path)).expect("run_genesis");

        // `raxis doctor` flags any other mode for these dirs as FAIL.
        assert_eq!(mode_bits(&tmp.path().join("keys")), 0o700);
        assert_eq!(mode_bits(&tmp.path().join("providers")), 0o700);
    }

    #[test]
    #[cfg(unix)]
    fn key_files_match_cli_ceremony_spec_modes() {
        let (tmp, flags) = fresh_flags();
        let (_sk, pk_hex) = fixed_operator();
        let pk_path = stage_operator_pubkey(tmp.path(), &pk_hex);

        run_genesis(&flags, false, Some(pk_path)).expect("run_genesis");

        // cli-ceremony.md §4.2 — these modes match what
        // `kernel/bootstrap::write_file_0400` and `_0444` produce.
        let keys = tmp.path().join("keys");
        assert_eq!(mode_bits(&keys.join("authority_keypair.pem")), 0o400);
        assert_eq!(mode_bits(&keys.join("quality_keypair.pem")), 0o400);
        assert_eq!(mode_bits(&keys.join("verifier_token_key.bin")), 0o400);

        let fp = raxis_genesis_tools::pubkey_fingerprint(
            &hex::decode(&pk_hex).expect("hex"),
        );
        assert_eq!(mode_bits(&keys.join(format!("operator_{fp}.pub"))), 0o444);
    }

    #[test]
    fn policy_epoch_history_carries_the_genesis_row() {
        let (tmp, flags) = fresh_flags();
        let (_sk, pk_hex) = fixed_operator();
        let pk_path = stage_operator_pubkey(tmp.path(), &pk_hex);

        run_genesis(&flags, false, Some(pk_path)).expect("run_genesis");

        // Independently re-load policy.toml so the SHA we expect in the
        // row is the kernel's SHA, not whatever genesis happens to print.
        let (_b, _bytes, expected_sha) =
            raxis_policy::load_policy(&tmp.path().join("policy/policy.toml"))
                .expect("load policy");

        let conn = raxis_store::open_ro(tmp.path()).expect("open_ro");
        let (epoch, sha, triggered): (i64, String, String) = conn
            .query_row(
                "SELECT epoch_id, policy_sha256, triggered_by_operator \
                   FROM policy_epoch_history",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("genesis row must be present");
        assert_eq!(epoch, 1);
        assert_eq!(sha, expected_sha);
        assert_eq!(triggered, "genesis");
    }

    #[test]
    fn audit_segment_passes_the_kernel_quick_chain_check() {
        // The single most important post-condition: what the CLI wrote
        // MUST be accepted by the production chain reader. Before the
        // genesis CLI was completed, the kernel's `quick_chain_check`
        // returned `Err(SegmentMissing)` and boot failed with
        // BOOT_ERR_AUDIT_CHAIN. Pinning this round-trip keeps the
        // post-condition load-bearing for every future change to the
        // genesis writer or the chain reader.
        let (tmp, flags) = fresh_flags();
        let (_sk, pk_hex) = fixed_operator();
        let pk_path = stage_operator_pubkey(tmp.path(), &pk_hex);

        run_genesis(&flags, false, Some(pk_path)).expect("run_genesis");

        match raxis_audit_tools::quick_chain_check(&tmp.path().join("audit")) {
            raxis_audit_tools::ChainQuickCheck::Ok { last_seq, segment_count } => {
                assert_eq!(last_seq, 0);
                assert_eq!(segment_count, 1);
            }
            other => panic!(
                "genesis segment must pass the kernel's quick chain check, got: {other:?}"
            ),
        }
    }

    #[test]
    #[cfg(unix)]
    fn sockets_and_notifications_dirs_have_default_0755_mode() {
        // `raxis doctor` (commands/doctor.rs::EXPECTED_MODES) pins both
        // `sockets/` and `notifications/` to 0o755. Genesis used to skip
        // creating both, leaving doctor at `[FAIL] sockets.exists` and
        // `[WARN] notifications.exists`. Pin the modes here so a future
        // "tighten everything to 0700" PR has to deliberately update
        // both this test AND the doctor's expected-modes table.
        let (tmp, flags) = fresh_flags();
        let (_sk, pk_hex) = fixed_operator();
        let pk_path = stage_operator_pubkey(tmp.path(), &pk_hex);

        run_genesis(&flags, false, Some(pk_path)).expect("run_genesis");

        // 0o755 is what `mkdir(2)` produces under the standard 0o022
        // umask. We do NOT chmod these dirs — the spec doesn't require
        // tightening, and the umask-derived value is what doctor checks.
        let sockets_mode = mode_bits(&tmp.path().join("sockets"));
        let notifications_mode = mode_bits(&tmp.path().join("notifications"));
        assert_eq!(
            sockets_mode, 0o755,
            "sockets/ should be 0o755 (raxis doctor expectation); got 0{sockets_mode:o}",
        );
        assert_eq!(
            notifications_mode, 0o755,
            "notifications/ should be 0o755 (raxis doctor expectation); got 0{notifications_mode:o}",
        );
    }

    #[test]
    #[cfg(unix)]
    fn chmod_helper_propagates_io_errors_instead_of_swallowing_them() {
        // The original `set_permissions_700` was `let _ = …` — a chmod
        // failure (EPERM, EROFS, ENOENT) silently produced an unsafe
        // data dir that `raxis doctor` flagged after the fact with
        // `[FAIL] keys.mode mode is 0755, expected 0700`. Pin that the
        // helpers now return Err so the genesis ceremony fails loudly
        // at the call site instead.
        //
        // We trigger an error by chmodding a path that doesn't exist;
        // this avoids needing root (which a chmod-on-RO-mount test
        // would require) and is portable across CI runners.
        let tmp = tempfile::tempdir().expect("tempdir");
        let nonexistent = tmp.path().join("does/not/exist");

        let err700 = set_permissions_700(&nonexistent)
            .expect_err("chmod of a nonexistent path must Err");
        let err400 = set_permissions_400(&nonexistent)
            .expect_err("chmod of a nonexistent path must Err");
        let err444 = set_permissions_444(&nonexistent)
            .expect_err("chmod of a nonexistent path must Err");

        for (mode, err) in [(0o700u32, err700), (0o400, err400), (0o444, err444)] {
            let msg = err.to_string();
            assert!(
                msg.contains(&format!("0{mode:o}")) || msg.contains("does/not/exist"),
                "chmod error must name the mode and/or path so operators can debug; \
                 got: {msg}",
            );
        }
    }

    #[test]
    fn force_re_run_against_the_same_data_dir_succeeds() {
        let (tmp, flags) = fresh_flags();
        let (_sk, pk_hex) = fixed_operator();
        let pk_path = stage_operator_pubkey(tmp.path(), &pk_hex);

        run_genesis(&flags, false, Some(pk_path.clone())).expect("first run");
        // A second run without --force MUST be rejected — operators must
        // see ERR_ALREADY_INITIALIZED, not silent overwrite.
        let err = run_genesis(&flags, false, Some(pk_path.clone()))
            .expect_err("second run without --force must fail");
        assert!(
            err.to_string().contains("ERR_ALREADY_INITIALIZED"),
            "expected ERR_ALREADY_INITIALIZED, got: {err}",
        );
        // A third run with --force MUST succeed — the cleanup removes
        // every artifact the per-file 0400 writes would refuse to
        // overwrite (mirrors `bootstrap::purge_existing_genesis_artifacts`).
        run_genesis(&flags, true, Some(pk_path)).expect("--force re-run");

        // After the --force re-run, all post-conditions still hold.
        assert!(tmp.path().join("audit/segment-000.jsonl").exists());
        assert!(tmp.path().join("kernel.db").exists());
        let conn = raxis_store::open_ro(tmp.path()).expect("open_ro");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM policy_epoch_history",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "exactly one genesis row even after --force; --force purges the prior DB",
        );
    }
}
