//! End-to-end gateway round-trip test (in-process).
//!
//! Drives `run_gateway_with_backend` directly with
//! `raxis_test_support::MockBackend`, against a fake-kernel
//! `UnixListener` bound under a tempdir. Asserts the IPC contract
//! pinned by `peripherals.md` §3.2:
//!
//!   1. The gateway sends `GatewayMessage::GatewayReady { gateway_token }`
//!      with the env-supplied token within a 5 s deadline.
//!   2. After a `FetchRequest` to an allowed URL, the gateway returns a
//!      `FetchResponse` whose `status_code = 200` (the `MockBackend`
//!      default).
//!   3. After a `FetchRequest` to a URL outside the egress allowlist,
//!      the gateway returns `error: "DomainNotAllowed"`.
//!   4. After a `FetchRequest` with a bad gateway token, the gateway
//!      returns `error: "InvalidToken"`.
//!   5. The kernel-side close (drop the listener) does not crash the
//!      gateway — the run-future returns `Ok(())`.
//!
//! Why in-process and not "spawn the binary":
//!   The earlier revision spawned `raxis-gateway` with
//!   `RAXIS_GATEWAY_BACKEND=mock`. That env knob is gone (production
//!   gateways always use `HttpBackend`; the mock is dev-dep-only and
//!   lives in `raxis-test-support`). The IPC contract is what these
//!   tests actually verify — running it in-process via
//!   `run_gateway_with_backend` exercises the same dispatch path
//!   without conflating it with subprocess lifecycle. Subprocess
//!   bring-up is covered separately by the kernel supervisor's
//!   spawn-on-boot smoke (`kernel/tests/...`).

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use raxis_gateway::{parse_gateway_env, run_gateway_with_backend, Backend};
use raxis_ipc::message::{FetchKind, GatewayMessage};
use raxis_ipc::{read_frame, write_frame};
use raxis_test_support::MockBackend;
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

const GATEWAY_TOKEN: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

// ---------------------------------------------------------------------------
// Fixture: build a `<data_dir>` with policy.toml + providers/anthropic.toml.
// ---------------------------------------------------------------------------

fn build_data_dir() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("data dir tempdir");
    let dd = tmp.path();
    std::fs::create_dir_all(dd.join("policy")).unwrap();
    std::fs::create_dir_all(dd.join("providers")).unwrap();

    // Cert-mandatory (INV-CERT-01): the policy loader (which the
    // gateway calls into via `raxis_policy::load_policy`) rejects any
    // `[[operators.entries]]` block missing a self-signed cert whose
    // `pubkey_hex` matches the entry's. Mint that cert here from a
    // deterministic operator key so the gateway accepts the fixture.
    let op_key = raxis_test_support::ephemeral_signing_key([0xCCu8; 32]);
    let op_pk_hex = raxis_test_support::pubkey_hex(&op_key);
    let op_fp = raxis_genesis_tools::pubkey_fingerprint(&hex::decode(&op_pk_hex).unwrap());
    let op_cert = raxis_test_support::ephemeral_cert_with_key(
        &op_key,
        raxis_test_support::CertOpts {
            display_name: "operator-1".to_owned(),
            permitted_ops: vec!["CreateInitiative".into()],
            ..raxis_test_support::CertOpts::default()
        },
    );
    let cert_subtable = toml::to_string(&op_cert).unwrap();
    let policy = format!(
        r#"[meta]
epoch     = 1
signed_by = "{op_fp}"
signed_at = 1700000000

[authority]
authority_pubkey = "{a}"
quality_pubkey   = "{b}"

[escalation_policy]
timeout_secs         = 3600
window_secs          = 300
max_per_window       = 5
quarantine_threshold = 3

[sessions]
default_ttl_secs       = 86400
max_ttl_secs           = 604800
allowed_worktree_roots = ["/tmp/raxis-gw-test"]

[delegations]
max_ttl_secs = 86400

[budget]
cost_per_touched_path = 1
max_cost_per_task     = 10000

[budget.base_cost_per_intent_kind]
SingleCommit     = 10
IntegrationMerge = 50
CompleteTask     = 5
ReportFailure    = 1

[[operators.entries]]
pubkey_fingerprint = "{op_fp}"
display_name       = "operator-1"
pubkey_hex         = "{op_pk_hex}"
permitted_ops      = ["CreateInitiative"]

[operators.entries.cert]
{cert_subtable}

[[lanes]]
lane_id              = "default"
max_concurrent_tasks = 4
max_cost_per_epoch   = 10000
priority             = 100

[egress]
domains  = []
patterns = ["*.anthropic.com"]
max_fetches_per_window = 100

[[providers]]
provider_id      = "anthropic-prod"
kind             = "Anthropic"
credentials_file = "anthropic-prod.toml"
  pricing.input_tokens_per_dollar  = 200000
  pricing.output_tokens_per_dollar = 50000
"#,
        a = "a".repeat(64),
        b = "b".repeat(64),
    );
    std::fs::write(dd.join("policy/policy.toml"), policy).unwrap();
    let creds_path = dd.join("providers/anthropic-prod.toml");
    std::fs::write(
        &creds_path,
        "api_key = \"sk-ant-test\"\nauth_header = \"x-api-key\"\nauth_prefix = \"\"\n",
    )
    .unwrap();
    // The V2 `FileCredentialBackend` validates `chmod 0600` at every
    // resolve (production invariant — operators copy credential files
    // in with `install -m 0600`). Make the test fixture honour the
    // same invariant rather than relying on the umask default (which
    // is 0644 on macOS).
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&creds_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&creds_path, perms).unwrap();
    }
    tmp
}

// ---------------------------------------------------------------------------
// Fake kernel: binds gateway.sock under a tempdir, accepts ONE connection.
// ---------------------------------------------------------------------------

struct FakeKernel {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl FakeKernel {
    fn bind() -> Self {
        // UDS path length cap (~104 chars on macOS); use std::env::temp_dir
        // + uuid suffix to stay short. Same trick as the verifier-stub
        // round-trip test.
        let socket_path = std::env::temp_dir().join(format!("rxgw-{}.sock", Uuid::new_v4()));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)
            .unwrap_or_else(|e| panic!("bind UDS at {socket_path:?}: {e}"));
        Self {
            listener,
            socket_path,
        }
    }
}

impl Drop for FakeKernel {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

// ---------------------------------------------------------------------------
// Test utilities
// ---------------------------------------------------------------------------

fn ok_request(url: &str) -> GatewayMessage {
    ok_request_with_token(url, GATEWAY_TOKEN.to_owned())
}

fn ok_request_with_token(url: &str, token: String) -> GatewayMessage {
    GatewayMessage::FetchRequest {
        gateway_token: token,
        fetch_id: Uuid::new_v4(),
        fetch_kind: FetchKind::Inference,
        url: url.to_owned(),
        method: "POST".to_owned(),
        headers: vec![],
        body_bytes: b"{}".to_vec(),
        timeout_ms: 5_000,
        session_id: None,
        task_id: None,
    }
}

async fn drain_handshake(stream: &mut UnixStream) {
    let ready = tokio::time::timeout(
        Duration::from_secs(5),
        read_frame::<_, GatewayMessage>(stream),
    )
    .await
    .expect("gateway handshake within 5s")
    .expect("read handshake frame");
    match ready {
        GatewayMessage::GatewayReady { gateway_token } => {
            assert_eq!(
                gateway_token, GATEWAY_TOKEN,
                "handshake token MUST echo RAXIS_GATEWAY_TOKEN byte-for-byte"
            );
        }
        other => panic!("first frame must be GatewayReady, got {other:?}"),
    }
}

/// Spawn `run_gateway_with_backend` on a tokio task, returning the
/// JoinHandle. The caller awaits `.await?` (Result<Result<(), _>, _>)
/// to assert clean termination after dropping the listener.
fn spawn_gateway(
    socket: PathBuf,
    data_dir: PathBuf,
    backend: Arc<dyn Backend>,
) -> tokio::task::JoinHandle<Result<(), raxis_gateway::runtime::GatewayRunError>> {
    let env = parse_gateway_env(
        GATEWAY_TOKEN,
        &socket.display().to_string(),
        &data_dir.display().to_string(),
    )
    .expect("parse_gateway_env in test");
    tokio::spawn(async move { run_gateway_with_backend(env, backend).await })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_handshakes_then_returns_mock_response_for_allowed_url() {
    let data_dir = build_data_dir();
    let kernel = FakeKernel::bind();

    let backend: Arc<dyn Backend> = Arc::new(MockBackend::default());
    let task = spawn_gateway(
        kernel.socket_path.clone(),
        data_dir.path().to_owned(),
        backend,
    );

    let (mut stream, _addr) = kernel.listener.accept().await.expect("accept");
    drain_handshake(&mut stream).await;

    let req = ok_request("https://api.anthropic.com/v1/messages");
    let req_id = match &req {
        GatewayMessage::FetchRequest { fetch_id, .. } => *fetch_id,
        _ => unreachable!(),
    };
    write_frame(&mut stream, &req).await.unwrap();
    let resp: GatewayMessage = read_frame(&mut stream).await.unwrap();
    match resp {
        GatewayMessage::FetchResponse {
            fetch_id,
            status_code,
            body_bytes,
            error,
            ..
        } => {
            assert_eq!(fetch_id, req_id, "fetch_id MUST round-trip unchanged");
            assert_eq!(status_code, Some(200));
            assert!(body_bytes.is_some());
            assert!(error.is_none(), "expected success, got error={error:?}");
        }
        other => panic!("expected FetchResponse, got {other:?}"),
    }

    // Drop the kernel side to signal EOF; gateway run-future should
    // resolve `Ok(())` cleanly.
    drop(stream);
    drop(kernel);
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("gateway exited within 5s")
        .expect("gateway task did not panic");
    result.expect("run_gateway returned Ok on clean disconnect");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_returns_domain_not_allowed_for_url_outside_egress_allowlist() {
    let data_dir = build_data_dir();
    let kernel = FakeKernel::bind();

    let backend: Arc<dyn Backend> = Arc::new(MockBackend::default());
    let task = spawn_gateway(
        kernel.socket_path.clone(),
        data_dir.path().to_owned(),
        backend,
    );

    let (mut stream, _addr) = kernel.listener.accept().await.expect("accept");
    drain_handshake(&mut stream).await;

    let req = ok_request("https://evil.example.com/v1/messages");
    write_frame(&mut stream, &req).await.unwrap();
    let resp: GatewayMessage = read_frame(&mut stream).await.unwrap();
    match resp {
        GatewayMessage::FetchResponse {
            error, status_code, ..
        } => {
            assert_eq!(status_code, None);
            assert_eq!(error.as_deref(), Some("DomainNotAllowed"));
        }
        other => panic!("expected FetchResponse, got {other:?}"),
    }

    drop(stream);
    drop(kernel);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// Binary-level smoke: missing required env vars must surface as exit
/// code 64 (EX_USAGE) so the kernel supervisor's spawn-on-boot path
/// produces a clear log entry.
#[test]
fn gateway_binary_exits_with_code_64_when_required_env_var_missing() {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_raxis-gateway"));
    let out = Command::new(&bin)
        .env_clear()
        // Deliberately omit RAXIS_GATEWAY_TOKEN / SOCKET / DATA_DIR.
        // Keep PATH+HOME so the loader doesn't fail for an unrelated
        // reason on platforms that need them for libc.
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn raxis-gateway");
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        64,
        "missing env must produce EX_USAGE=64; got {code}, stderr=\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_returns_invalid_token_when_token_does_not_match_env() {
    let data_dir = build_data_dir();
    let kernel = FakeKernel::bind();

    let backend: Arc<dyn Backend> = Arc::new(MockBackend::default());
    let task = spawn_gateway(
        kernel.socket_path.clone(),
        data_dir.path().to_owned(),
        backend,
    );

    let (mut stream, _addr) = kernel.listener.accept().await.expect("accept");
    drain_handshake(&mut stream).await;

    // Token differs from GATEWAY_TOKEN by exactly one byte at the end.
    let bad_token = format!("{}1", &GATEWAY_TOKEN[..63]);
    let req = ok_request_with_token("https://api.anthropic.com/v1/messages", bad_token);
    write_frame(&mut stream, &req).await.unwrap();
    let resp: GatewayMessage = read_frame(&mut stream).await.unwrap();
    match resp {
        GatewayMessage::FetchResponse {
            error, status_code, ..
        } => {
            assert_eq!(status_code, None);
            assert_eq!(error.as_deref(), Some("InvalidToken"));
        }
        other => panic!("expected FetchResponse, got {other:?}"),
    }

    drop(stream);
    drop(kernel);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}
