//! Generic kernel-driver helpers for `RAXIS_LIVE_E2E=1` tests.
//!
//! Mirrors the inline helpers in
//! `extended_e2e_concurrent_lifecycle.rs` but parametrised over
//! the plan-toml builder so multiple `live-e2e` tests can share
//! the same bootstrap / IPC / polling pipeline without
//! duplicating ~700 lines of infrastructure.
//!
//! The existing extended-scenario test continues to use its own
//! inline helpers (deliberately — refactoring them in lockstep
//! would couple two unrelated tests together). New tests
//! (`extended_e2e_realistic_scenario.rs`, future realism
//! follow-ups) call into THIS module instead.
//!
//! Every function panics on failure rather than returning a
//! `Result` — the call sites are test-only and a panic surfaces
//! more cleanly through `cargo test` than a `Result<()>` rip-tide.

#![allow(dead_code)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use raxis_audit_tools::{verify_chain_full, AuditEvent, AuditEventKind, ChainReader};
use raxis_crypto::{
    bundle_sha256 as crypto_bundle_sha256, canonical_encode, mint_bundle_nonce,
    sha256_of_artifact_bytes, signing_input,
};
use raxis_ipc::{read_json_frame_raw, write_json_frame};
use raxis_test_support::{ephemeral_cert_with_key, CertOpts};
use raxis_types::{BundleArtifact, OperatorFingerprint, PlanBundle};
use serde_json::Value;
use sha2::{Digest, Sha256};

// `crate::common` is the sibling `mod common;` each test binary
// (`extended_e2e_concurrent_lifecycle.rs`,
// `extended_e2e_realistic_scenario.rs`, …) declares at its root.
// Both test binaries that pull this module in must `mod common;`
// alongside `mod extended_e2e_support;`.
use crate::common::kernel_harness::{build_and_locate_kernel, KernelInstance};
use super::witnesses::typed;

pub const LIVE_E2E_GATE:    &str     = "RAXIS_LIVE_E2E";
pub const READY_DEADLINE:   Duration = Duration::from_secs(15);
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(60);

/// Distinct seed from the extended scenario's `[0xCE; 32]` so
/// the two live-e2e tests can be run back-to-back without
/// cross-contaminating operator identity in audit attribution.
pub const REALISTIC_OPERATOR_SEED: [u8; 32] = [0xD0; 32];

// ---------------------------------------------------------------------------
// Preflight — every external dependency reachable before we
// bother bootstrapping a kernel.
// ---------------------------------------------------------------------------

pub fn require_tcp_reachable(host_port: &str, what: &str) {
    if std::net::TcpStream::connect_timeout(
        &host_port.parse().expect("static literal parses"),
        Duration::from_millis(500),
    ).is_err() {
        panic!(
            "{what} not reachable at {host_port}. Run:\n  \
             docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait",
        );
    }
}

pub fn require_anthropic_dev_key() {
    let env_path = workspace_dotenv_path();
    let body = std::fs::read_to_string(&env_path).unwrap_or_else(|e| panic!(
        "{} is required for the live LLM round-trip but read failed: {e}\n\
         Create it with one line:\n  ANTHROPIC-API-DEV-KEY=sk-ant-...",
        env_path.display(),
    ));
    let has_key = body
        .lines()
        .any(|l| l.starts_with("ANTHROPIC-API-DEV-KEY=")
            && l.len() > "ANTHROPIC-API-DEV-KEY=".len());
    assert!(
        has_key,
        "{} must contain a non-empty ANTHROPIC-API-DEV-KEY=... line",
        env_path.display(),
    );
}

pub fn require_gcp_adc() {
    let adc = match dirs_home() {
        Some(h) => h.join(".config/gcloud/application_default_credentials.json"),
        None    => panic!("HOME is unset; cannot locate gcloud ADC"),
    };
    assert!(
        adc.exists(),
        "GCP application default credentials not found at {}.\n\
         Run: gcloud auth application-default login",
        adc.display(),
    );
}

pub fn require_gateway_binary() -> PathBuf {
    let raw = std::env::var("RAXIS_GATEWAY_BINARY").unwrap_or_else(|_| panic!(
        "RAXIS_GATEWAY_BINARY env var is required; build the gateway and \
         export the path:\n  cargo build -p raxis-gateway --release\n  \
         export RAXIS_GATEWAY_BINARY=$(pwd)/target/release/raxis-gateway",
    ));
    let p = PathBuf::from(&raw);
    assert!(p.is_absolute(), "RAXIS_GATEWAY_BINARY must be absolute; got {raw:?}");
    assert!(p.exists(), "RAXIS_GATEWAY_BINARY={raw:?} does not exist");
    p
}

pub fn require_canonical_images() {
    let install_dir_raw = std::env::var("RAXIS_INSTALL_DIR").unwrap_or_else(|_| panic!(
        "RAXIS_INSTALL_DIR env var is required",
    ));
    let install_dir = PathBuf::from(&install_dir_raw);
    let kernel_version = env!("CARGO_PKG_VERSION");
    for role in &["orchestrator-core", "executor-starter", "reviewer-core"] {
        let img = install_dir.join("images")
            .join(format!("raxis-{role}-{kernel_version}.img"));
        let manifest = install_dir.join("images")
            .join(format!("raxis-{role}-{kernel_version}.manifest.toml"));
        assert!(img.exists(), "missing canonical image {}", img.display());
        assert!(manifest.exists(), "missing canonical manifest {}", manifest.display());
    }
}

// ---------------------------------------------------------------------------
// Bootstrap + spawn.
// ---------------------------------------------------------------------------

/// Build a fresh operator signing key from `seed`. Returns the
/// key + its 8-byte fingerprint (the kernel's stable operator id
/// in audit rows).
pub fn build_operator_key(seed: &[u8; 32]) -> (SigningKey, OperatorFingerprint) {
    let key = SigningKey::from_bytes(seed);
    let pubkey = key.verifying_key().to_bytes();
    (key, fingerprint_8(&pubkey))
}

/// Bootstrap a fresh kernel under a tempdir-data-dir with a
/// custom operator cert that grants the full lifecycle ops.
pub fn bootstrap_with_custom_cert(
    signing_key: &SigningKey,
) -> (PathBuf, PathBuf) {
    let kernel_bin = build_and_locate_kernel();

    #[cfg(target_os = "macos")]
    codesign_kernel_for_avf(&kernel_bin);

    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is post-epoch")
        .as_secs() as i64;
    let cert = ephemeral_cert_with_key(signing_key, CertOpts {
        now_unix_secs,
        permitted_ops: vec![
            "CreateInitiative".to_owned(),
            "CreateInitiativeV2".to_owned(),
            "ApprovePlan".to_owned(),
            "AbortInitiative".to_owned(),
        ],
        display_name: "realism-e2e-operator".to_owned(),
        ..CertOpts::default()
    });

    let data_dir: PathBuf = tempfile::tempdir()
        .expect("tempdir for kernel data dir")
        .keep();
    let cert_path = data_dir.join("operator.cert.toml");
    let toml_body = toml::to_string(&cert).expect("serialise realism-e2e cert");
    std::fs::write(&cert_path, toml_body).expect("write operator cert");

    let bootstrap_output = Command::new(&kernel_bin)
        .env("RAXIS_BOOTSTRAP", "1")
        .env("RAXIS_DATA_DIR", &data_dir)
        .env("RAXIS_OPERATOR_CERT", &cert_path)
        .output()
        .expect("spawn kernel in bootstrap mode");
    assert!(
        bootstrap_output.status.success(),
        "kernel bootstrap failed (exit {:?}):\n--- stderr ---\n{}",
        bootstrap_output.status.code(),
        String::from_utf8_lossy(&bootstrap_output.stderr),
    );

    (kernel_bin, data_dir)
}

pub fn spawn_kernel_normal(
    kernel_bin: &Path,
    data_dir: PathBuf,
    install_dir: &Path,
) -> KernelInstance {
    use std::io::{BufRead, BufReader};
    use std::process::{Command as ProcCommand, Stdio};
    use std::sync::{Arc, Mutex};

    let mut child = ProcCommand::new(kernel_bin)
        .env("RAXIS_DATA_DIR", &data_dir)
        .env("RAXIS_INSTALL_DIR", install_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kernel in normal mode");

    let stderr = child.stderr.take().expect("kernel stderr captured");
    let stderr_lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let log_path = data_dir.join("kernel.stderr.log");
    let log_handle = std::fs::File::create(&log_path).ok().map(|f| Arc::new(Mutex::new(f)));
    {
        let lines = Arc::clone(&stderr_lines);
        let log_handle = log_handle.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if let Some(h) = &log_handle {
                    if let Ok(mut g) = h.lock() {
                        use std::io::Write as _;
                        let _ = writeln!(g, "{line}");
                    }
                }
                lines.lock().unwrap().push(line);
            }
        });
    }

    KernelInstance::from_parts(child, stderr_lines, data_dir)
}

pub fn enable_gateway_in_policy(data_dir: &Path, gateway_binary: &Path) {
    let policy_path = data_dir.join("policy").join("policy.toml");
    let mut body = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", policy_path.display()));
    assert!(
        !body.contains("\n[gateway]\n"),
        "policy.toml already has a [gateway] block; bootstrap template changed",
    );
    let injected = format!(
        "\n# ── [gateway] + [[providers]] + [egress] (realism-e2e) ──\n\
         [gateway]\n\
         binary_path              = \"{gw}\"\n\
         spawn_timeout_secs       = 30\n\
         respawn_backoff_ms       = 1000\n\
         max_consecutive_respawns = 5\n\
         \n\
         [egress]\n\
         domains = [\"api.anthropic.com\"]\n\
         patterns = []\n\
         \n\
         [[providers]]\n\
         provider_id           = \"anthropic-realism-e2e\"\n\
         kind                  = \"Anthropic\"\n\
         credentials_file      = \"anthropic-realism-e2e.toml\"\n\
         inference_timeout_ms  = 120000\n\
         data_fetch_timeout_ms = 30000\n\
         pricing.input_tokens_per_dollar      = 200000\n\
         pricing.output_tokens_per_dollar     = 50000\n\
         pricing.cache_read_tokens_per_dollar = 2000000\n",
        gw = gateway_binary.display(),
    );
    body.push_str(&injected);
    std::fs::write(&policy_path, body)
        .unwrap_or_else(|e| panic!("rewrite {}: {e}", policy_path.display()));
}

pub fn write_credentials(data_dir: &Path) {
    let cred_dir = data_dir.join("credentials");
    std::fs::create_dir_all(&cred_dir).expect("mkdir credentials");

    write_with_mode_0600(
        &cred_dir.join("test-pg-dev.env"),
        b"PGHOST=127.0.0.1\n\
          PGPORT=54399\n\
          PGUSER=raxis_test\n\
          PGPASSWORD=raxis_test_pass\n\
          PGDATABASE=raxis_e2e_pg\n\
          PGSSLMODE=disable\n",
    );

    write_with_mode_0600(
        &cred_dir.join("test-mongo-dev.env"),
        b"MONGO_HOST=127.0.0.1\n\
          MONGO_PORT=27399\n\
          MONGO_USER=raxis_test\n\
          MONGO_PASSWORD=raxis_test_pass\n\
          MONGO_AUTH_DB=admin\n\
          MONGO_DATABASE=raxis_e2e_mongo\n",
    );
}

pub fn write_provider_credentials(data_dir: &Path) {
    let providers_dir = data_dir.join("providers");
    std::fs::create_dir_all(&providers_dir).expect("mkdir providers");

    let env_path = workspace_dotenv_path();
    let body = std::fs::read_to_string(&env_path).expect("preflight verified .env");
    let api_key = body
        .lines()
        .find_map(|l| l.strip_prefix("ANTHROPIC-API-DEV-KEY="))
        .map(str::trim)
        .expect("preflight verified ANTHROPIC-API-DEV-KEY=...")
        .to_owned();

    let provider_toml = format!(
        "api_key     = \"{api_key}\"\n\
         auth_header = \"x-api-key\"\n\
         auth_prefix = \"\"\n",
    );
    write_with_mode_0600(
        &providers_dir.join("anthropic-realism-e2e.toml"),
        provider_toml.as_bytes(),
    );
}

fn write_with_mode_0600(path: &Path, body: &[u8]) {
    std::fs::write(path, body)
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| panic!("chmod 0600 {}: {e}", path.display()));
}

// ---------------------------------------------------------------------------
// Operator IPC — generic over plan TOML body.
// ---------------------------------------------------------------------------

pub struct OperatorIpc {
    pub stream: UnixStream,
    /// Operator signing key, used by `submit_plan` and
    /// `approve_plan`. Captured at connect time so callers don't
    /// need to thread it through every call site.
    seed: [u8; 32],
}

impl OperatorIpc {
    pub fn connect(
        socket_path: &Path,
        signing_key: &SigningKey,
        seed: [u8; 32],
        _fingerprint: &OperatorFingerprint,
    ) -> Self {
        let mut stream = UnixStream::connect(socket_path)
            .unwrap_or_else(|e| panic!("connect {}: {e}", socket_path.display()));

        let challenge = read_json_blocking(&mut stream);
        let challenge_hex = challenge["challenge_hex"]
            .as_str()
            .expect("kernel sends challenge_hex");
        let challenge_bytes = hex::decode(challenge_hex).expect("challenge_hex is hex");
        assert_eq!(challenge_bytes.len(), 32, "challenge is 32 bytes");

        let sig = signing_key.sign(&challenge_bytes);
        let pubkey = signing_key.verifying_key().to_bytes();
        let policy_fingerprint_hex = policy_fingerprint_32(&pubkey);
        let response = serde_json::json!({
            "fingerprint":          policy_fingerprint_hex,
            "signed_challenge_hex": hex::encode(sig.to_bytes()),
        });
        write_json_frame(&mut stream, &response).expect("write auth response");

        let ack = read_json_blocking(&mut stream);
        assert_eq!(
            ack["status"].as_str(), Some("Ok"),
            "kernel rejected auth: {ack:#}",
        );

        Self { stream, seed }
    }

    /// Submit `plan_toml` verbatim as the plan bundle for
    /// `initiative_id`. Caller chose the plan body — this method
    /// only handles signing + framing.
    pub fn submit_plan(&mut self, initiative_id: &str, plan_toml: &str) {
        let bundle = build_plan_bundle(plan_toml);
        let canonical = canonical_encode(&bundle).expect("canonical_encode");
        let bundle_sha = crypto_bundle_sha256(&canonical);
        let signing_key = SigningKey::from_bytes(&self.seed);
        let sig_input = signing_input(&bundle_sha);
        let signature = signing_key.sign(&sig_input);
        let pubkey = signing_key.verifying_key().to_bytes();
        let fingerprint = fingerprint_8(&pubkey);

        let req = serde_json::json!({
            "op": "CreateInitiativeV2",
            "payload": {
                "initiative_id":     initiative_id,
                "plan_bundle_hex":   hex::encode(&canonical),
                "bundle_sha256_hex": hex::encode(bundle_sha.as_bytes()),
                "signature_hex":     hex::encode(signature.to_bytes()),
                "signed_by_hex":     hex::encode(fingerprint.as_bytes()),
            },
        });
        write_json_frame(&mut self.stream, &req).expect("write CreateInitiativeV2");
        let resp = read_json_blocking(&mut self.stream);
        assert_eq!(
            resp["status"].as_str(), Some("InitiativeCreated"),
            "CreateInitiativeV2 must succeed; got: {resp:#}",
        );
        let returned_id = resp["payload"]["initiative_id"]
            .as_str()
            .expect("InitiativeCreated carries payload.initiative_id");
        assert_eq!(returned_id, initiative_id, "initiative id roundtrip");
    }

    pub fn approve_plan(
        &mut self,
        initiative_id: &str,
        _fingerprint: &OperatorFingerprint,
    ) {
        let signing_key = SigningKey::from_bytes(&self.seed);
        let pubkey = signing_key.verifying_key().to_bytes();
        let approving_operator_32 = policy_fingerprint_32(&pubkey);
        let req = serde_json::json!({
            "op": "ApprovePlan",
            "payload": {
                "initiative_id":      initiative_id,
                "approving_operator": approving_operator_32,
            },
        });
        write_json_frame(&mut self.stream, &req).expect("write ApprovePlan");
        let resp = read_json_blocking(&mut self.stream);
        assert_eq!(
            resp["status"].as_str(), Some("PlanApproved"),
            "ApprovePlan must succeed; got: {resp:#}",
        );
    }
}

fn read_json_blocking(stream: &mut UnixStream) -> Value {
    let body = read_json_frame_raw(stream).expect("read kernel frame");
    serde_json::from_str(&body).expect("kernel frame is JSON")
}

fn build_plan_bundle(plan_toml: &str) -> PlanBundle {
    let plan_bytes = plan_toml.as_bytes().to_vec();
    let plan_sha = sha256_of_artifact_bytes(&plan_bytes);
    let artifacts = vec![BundleArtifact {
        name:   "plan.toml".to_owned(),
        bytes:  plan_bytes,
        sha256: plan_sha,
    }];
    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let nonce = mint_bundle_nonce().expect("mint_bundle_nonce");
    PlanBundle::new_v2_1(
        signed_at,
        signed_at,
        nonce,
        "/raxis/realism-e2e".to_owned(),
        artifacts,
    )
}

#[cfg(target_os = "macos")]
fn codesign_kernel_for_avf(kernel_bin: &Path) {
    let mut anchor = kernel_bin
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    loop {
        let manifest = anchor.join("Cargo.toml");
        if manifest.exists() {
            if let Ok(s) = std::fs::read_to_string(&manifest) {
                if s.contains("[workspace]") { break; }
            }
        }
        if !anchor.pop() {
            eprintln!("[realism-e2e] codesign: workspace root not found from {}",
                kernel_bin.display());
            return;
        }
    }
    let entitlements = anchor.join("release/raxis.entitlements");
    if !entitlements.exists() {
        eprintln!("[realism-e2e] codesign: entitlements missing at {}",
            entitlements.display());
        return;
    }
    let status = Command::new("codesign")
        .arg("--sign").arg("-")
        .arg("--entitlements").arg(&entitlements)
        .arg("--options").arg("runtime")
        .arg("--force")
        .arg(kernel_bin)
        .status()
        .expect("codesign required for AVF on macOS");
    if !status.success() {
        panic!("codesign failed (exit {:?}) for {}",
            status.code(), kernel_bin.display());
    }
}

fn fingerprint_8(pubkey: &[u8; 32]) -> OperatorFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    OperatorFingerprint::new(out)
}

fn policy_fingerprint_32(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

// ---------------------------------------------------------------------------
// Audit-chain polling + post-mortem.
// ---------------------------------------------------------------------------

/// Default deadline for the realistic scenario lifecycle. Larger
/// than the extended scenario's 15 min because the realistic plan
/// carries materializer + cross-file refactor + lint-defect +
/// path-allowlist + secrets + reviewer-substantive + sibling
/// initiative — three executor re-spawns and two review rounds
/// across two initiatives.
pub fn realistic_lifecycle_deadline() -> Duration {
    let secs = std::env::var("RAXIS_E2E_REALISTIC_DEADLINE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1800); // 30 min
    Duration::from_secs(secs)
}

/// Poll the audit chain until BOTH `initiative_ids` emit
/// `IntegrationMergeCompleted`. Surfaces `SecurityViolation`
/// instantly. Returns the merged chain at completion.
pub fn poll_for_dual_lifecycle_completion(
    data_dir: &Path,
    initiative_ids: [&str; 2],
    deadline: Duration,
) -> Vec<AuditEvent> {
    let audit_dir = data_dir.join("audit");
    let start = Instant::now();
    let mut last_len = 0usize;
    loop {
        if start.elapsed() > deadline {
            let stderr_path = audit_dir.parent().map(|p| p.join("kernel.stderr.log"));
            let stderr_tail = stderr_path
                .as_ref()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|s| {
                    let lines: Vec<&str> = s.lines().collect();
                    let n = lines.len();
                    let take = n.min(60);
                    lines[n.saturating_sub(take)..].join("\n")
                })
                .unwrap_or_else(|| "<no kernel.stderr.log on disk>".to_owned());
            panic!(
                "realistic dual-lifecycle deadline of {deadline:?} exceeded \
                 without IntegrationMergeCompleted for both {} and {}; \
                 audit chain at exit ({} events):\n{}\n\n\
                 ── kernel.stderr (tail) ──\n{}",
                initiative_ids[0],
                initiative_ids[1],
                last_len,
                summarize_chain_for_panic(&audit_dir),
                stderr_tail,
            );
        }

        let events = match read_audit_chain(&audit_dir) {
            Ok(e) => e,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
        };
        last_len = events.len();

        for e in &events {
            if e.event_kind == "SecurityViolation"
                || e.event_kind == "SecurityViolationDetected"
            {
                panic!(
                    "SecurityViolation fired during realistic lifecycle: \
                     event_kind={}, payload={:#}",
                    e.event_kind, e.payload,
                );
            }
        }

        let merged_a = events.iter().any(|e| {
            e.event_kind == "IntegrationMergeCompleted"
                && e.initiative_id.as_deref() == Some(initiative_ids[0])
        });
        let merged_b = events.iter().any(|e| {
            e.event_kind == "IntegrationMergeCompleted"
                && e.initiative_id.as_deref() == Some(initiative_ids[1])
        });
        if merged_a && merged_b {
            return events;
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

pub fn read_audit_chain(audit_dir: &Path) -> Result<Vec<AuditEvent>, ()> {
    if !audit_dir.exists() { return Err(()); }
    let mut events = Vec::new();
    for entry in std::fs::read_dir(audit_dir).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        if entry.file_name().to_string_lossy().ends_with(".jsonl") {
            let bytes = std::fs::read(entry.path()).map_err(|_| ())?;
            for line in bytes.split(|&b| b == b'\n') {
                if line.is_empty() { continue; }
                if let Ok(ev) = serde_json::from_slice::<AuditEvent>(line) {
                    events.push(ev);
                }
            }
        }
    }
    events.sort_by_key(|e| e.seq);
    Ok(events)
}

pub fn summarize_chain_for_panic(audit_dir: &Path) -> String {
    match read_audit_chain(audit_dir) {
        Ok(events) => {
            let kinds: Vec<&str> = events.iter().map(|e| e.event_kind.as_str()).collect();
            format!("seqs={}…{}, kinds={kinds:#?}",
                events.first().map(|e| e.seq).unwrap_or(0),
                events.last().map(|e| e.seq).unwrap_or(0),
            )
        }
        Err(_) => "(audit dir not yet present)".to_owned(),
    }
}

pub fn walk_chain_or_panic(data_dir: &Path) -> Vec<AuditEvent> {
    let audit_dir = data_dir.join("audit");
    verify_chain_full(&audit_dir)
        .unwrap_or_else(|e| panic!("verify_chain_full({audit_dir:?}) failed: {e:?}"));
    let reader = ChainReader::open(&audit_dir).unwrap_or_else(|e| {
        panic!("ChainReader::open({audit_dir:?}) failed: {e:?}")
    });
    reader
        .records()
        .map(|r| {
            let row = r.unwrap_or_else(|e| panic!("chain record decode failed: {e:?}"));
            let value = row.parsed_value.unwrap_or_else(|| panic!(
                "chain row seq={} has no parsed_value", row.seq,
            ));
            serde_json::from_value::<AuditEvent>(value).unwrap_or_else(|e| {
                panic!("decode AuditEvent from chain row {}: {e}", row.seq)
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Worktree locator.
// ---------------------------------------------------------------------------

pub fn locate_executor_worktree(
    data_dir: &Path,
    initiative_id: &str,
    task_id: &str,
) -> PathBuf {
    let candidates = [
        data_dir.join("worktrees").join(initiative_id).join(task_id),
        data_dir.join("workspaces").join(initiative_id).join(task_id),
        data_dir.join("sessions").join(initiative_id).join(task_id),
    ];
    for c in &candidates {
        if c.exists() && c.join(".git").exists() {
            return c.clone();
        }
    }
    panic!(
        "could not locate executor worktree for initiative={initiative_id} \
         task={task_id}; tried {:?}",
        candidates,
    );
}

// ---------------------------------------------------------------------------
// Misc helpers.
// ---------------------------------------------------------------------------

pub fn workspace_dotenv_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join(".env"))
        .unwrap_or_else(|| PathBuf::from("raxis/.env"))
}

pub fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// First `SessionVmSpawned.session_id` for `task_id` (used to
/// thread per-task session ids into witnesses that key on them).
pub fn locate_session_id_for_task(
    chain: &[AuditEvent],
    task_id: &str,
) -> Option<String> {
    chain.iter().find_map(|ev| match typed(ev) {
        Some(AuditEventKind::SessionVmSpawned {
            session_id, task_id: Some(t), ..
        }) if t == task_id => Some(session_id),
        _ => None,
    })
}

/// Earliest `seq` of any `SessionVmSpawned{task_id}`. Used by
/// the crash-recovery driver to mark the moment "this task is
/// in-flight" just before delivering SIGTERM.
pub fn first_spawn_seq(chain: &[AuditEvent], task_id: &str) -> Option<u64> {
    chain
        .iter()
        .filter_map(|ev| match typed(ev) {
            Some(AuditEventKind::SessionVmSpawned {
                task_id: Some(t), ..
            }) if t == task_id => Some(ev.seq),
            _ => None,
        })
        .min()
}
