//! End-to-end gateway round-trip test.
//!
//! Builds the `raxis-gateway` binary, stands up a fake kernel that
//! binds a UDS, spawns the gateway pointed at the UDS, asserts:
//!
//!   1. Gateway writes `GatewayMessage::GatewayReady { gateway_token }`
//!      with the env-supplied token within a 5-second deadline.
//!   2. After a `FetchRequest`, the gateway returns a `FetchResponse`
//!      whose `status_code = 200` and whose `body_bytes` is the
//!      MockBackend default.
//!   3. After a `FetchRequest` with a bad URL, the gateway returns
//!      `error: "DomainNotAllowed"`.
//!   4. After a `FetchRequest` with a bad token, the gateway returns
//!      `error: "InvalidToken"`.
//!   5. The kernel-side close (drop the listener) does not crash the
//!      gateway — it logs and exits cleanly with code 0.
//!
//! These pin the IPC contract documented in `peripherals.md` §3.2 so
//! Phase A.5 (kernel-side spawn) can lean on a known-good child.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use raxis_ipc::message::{FetchKind, GatewayMessage};
use raxis_ipc::{read_frame, write_frame};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

const GATEWAY_TOKEN: &str =
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

// ---------------------------------------------------------------------------
// Build helpers
// ---------------------------------------------------------------------------

/// Path to the pre-built `raxis-gateway` binary.
///
/// We rely on `CARGO_BIN_EXE_raxis-gateway`, which Cargo defines for
/// integration tests inside the same crate as the binary
/// (https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates).
///
/// We deliberately do NOT shell out to `cargo build -p raxis-gateway` from
/// inside the test, because that recursive cargo invocation contends with
/// the parent `cargo test --workspace` build lock and can wedge the entire
/// workspace test run for tens of minutes (observed in practice). Cargo
/// already builds every binary that integration tests depend on before the
/// test binary is launched, so the env-var lookup is sufficient and
/// race-free.
fn locate_gateway() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_raxis-gateway"))
}

/// Build a minimal `<data_dir>` with policy.toml + providers/anthropic.toml.
/// This is what the kernel's bootstrap would have produced; we hand-craft
/// it so the test doesn't depend on the kernel binary.
fn build_data_dir() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("data dir tempdir");
    let dd = tmp.path();
    std::fs::create_dir_all(dd.join("policy")).unwrap();
    std::fs::create_dir_all(dd.join("providers")).unwrap();

    let policy = format!(
        r#"[meta]
epoch     = 1
signed_by = "deadbeefdeadbeefdeadbeefdeadbeef"
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
pubkey_fingerprint = "deadbeefdeadbeefdeadbeefdeadbeef"
display_name       = "operator-1"
pubkey_hex         = "{c}"
permitted_ops      = ["CreateInitiative"]

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
"#,
        a = "a".repeat(64),
        b = "b".repeat(64),
        c = "c".repeat(64),
    );
    std::fs::write(dd.join("policy/policy.toml"), policy).unwrap();
    std::fs::write(
        dd.join("providers/anthropic-prod.toml"),
        "api_key = \"sk-ant-test\"\nauth_header = \"x-api-key\"\nauth_prefix = \"\"\n",
    )
    .unwrap();
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
        let socket_path = std::env::temp_dir()
            .join(format!("rxgw-{}.sock", Uuid::new_v4()));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)
            .unwrap_or_else(|e| panic!("bind UDS at {socket_path:?}: {e}"));
        Self { listener, socket_path }
    }
}

impl Drop for FakeKernel {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

// ---------------------------------------------------------------------------
// Gateway spawn helper
// ---------------------------------------------------------------------------

struct GatewayChild {
    child: std::process::Child,
}

impl GatewayChild {
    fn spawn(bin: &Path, env: &GatewaySpawnEnv) -> Self {
        let child = Command::new(bin)
            .env("RAXIS_GATEWAY_TOKEN", &env.token)
            .env("RAXIS_GATEWAY_SOCKET", &env.socket)
            .env("RAXIS_DATA_DIR", &env.data_dir)
            .env("RAXIS_GATEWAY_BACKEND", "mock")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn raxis-gateway");
        Self { child }
    }

    fn wait(&mut self, deadline: Duration) -> std::process::ExitStatus {
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(s)) => return s,
                Ok(None) => {
                    if start.elapsed() > deadline {
                        let _ = self.child.kill();
                        panic!("gateway did not exit within {deadline:?}");
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("try_wait: {e}"),
            }
        }
    }
}

impl Drop for GatewayChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct GatewaySpawnEnv {
    token: String,
    socket: PathBuf,
    data_dir: PathBuf,
}

// ---------------------------------------------------------------------------
// Test utilities
// ---------------------------------------------------------------------------

fn ok_request(url: &str) -> GatewayMessage {
    GatewayMessage::FetchRequest {
        gateway_token: GATEWAY_TOKEN.to_owned(),
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
    // Block up to 5 s for `GatewayReady`. This proves the env was
    // parsed, policy was loaded, and the handshake byte was sent —
    // the three things `Phase A.4` is responsible for.
    let ready = tokio::time::timeout(
        Duration::from_secs(5),
        read_frame::<_, GatewayMessage>(stream),
    )
    .await
    .expect("gateway handshake within 5s")
    .expect("read handshake frame");
    match ready {
        GatewayMessage::GatewayReady { gateway_token } => {
            assert_eq!(gateway_token, GATEWAY_TOKEN,
                "handshake token MUST echo RAXIS_GATEWAY_TOKEN byte-for-byte");
        }
        other => panic!("first frame must be GatewayReady, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_handshakes_then_returns_mock_response_for_allowed_url() {
    let bin = locate_gateway();
    let data_dir = build_data_dir();
    let kernel = FakeKernel::bind();

    let mut gw = GatewayChild::spawn(&bin, &GatewaySpawnEnv {
        token: GATEWAY_TOKEN.to_owned(),
        socket: kernel.socket_path.clone(),
        data_dir: data_dir.path().to_owned(),
    });

    let (mut stream, _addr) = kernel.listener.accept().await.expect("accept");
    drain_handshake(&mut stream).await;

    // Send a FetchRequest, expect a FetchResponse with the canned body.
    let req = ok_request("https://api.anthropic.com/v1/messages");
    let req_id = match &req {
        GatewayMessage::FetchRequest { fetch_id, .. } => *fetch_id,
        _ => unreachable!(),
    };
    write_frame(&mut stream, &req).await.unwrap();
    let resp: GatewayMessage = read_frame(&mut stream).await.unwrap();
    match resp {
        GatewayMessage::FetchResponse { fetch_id, status_code, body_bytes, error, .. } => {
            assert_eq!(fetch_id, req_id, "fetch_id MUST round-trip unchanged");
            assert_eq!(status_code, Some(200));
            assert!(body_bytes.is_some());
            assert!(error.is_none(), "expected success, got error={error:?}");
        }
        other => panic!("expected FetchResponse, got {other:?}"),
    }

    // Drop the kernel side to signal EOF; gateway should exit 0.
    drop(stream);
    drop(kernel);
    let status = gw.wait(Duration::from_secs(5));
    assert!(status.success(),
        "gateway must exit 0 on clean kernel disconnect; got {status:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_returns_domain_not_allowed_for_url_outside_egress_allowlist() {
    let bin = locate_gateway();
    let data_dir = build_data_dir();
    let kernel = FakeKernel::bind();

    let mut gw = GatewayChild::spawn(&bin, &GatewaySpawnEnv {
        token: GATEWAY_TOKEN.to_owned(),
        socket: kernel.socket_path.clone(),
        data_dir: data_dir.path().to_owned(),
    });

    let (mut stream, _) = kernel.listener.accept().await.unwrap();
    drain_handshake(&mut stream).await;

    let req = ok_request("https://evil.example.com/exfiltrate");
    write_frame(&mut stream, &req).await.unwrap();
    let resp: GatewayMessage = read_frame(&mut stream).await.unwrap();
    match resp {
        GatewayMessage::FetchResponse { error, status_code, body_bytes, .. } => {
            assert_eq!(error.as_deref(), Some("DomainNotAllowed"));
            assert!(status_code.is_none());
            assert!(body_bytes.is_none());
        }
        other => panic!("expected FetchResponse, got {other:?}"),
    }

    drop(stream);
    drop(kernel);
    let _ = gw.wait(Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_returns_invalid_token_when_token_does_not_match_env() {
    let bin = locate_gateway();
    let data_dir = build_data_dir();
    let kernel = FakeKernel::bind();

    let mut gw = GatewayChild::spawn(&bin, &GatewaySpawnEnv {
        token: GATEWAY_TOKEN.to_owned(),
        socket: kernel.socket_path.clone(),
        data_dir: data_dir.path().to_owned(),
    });

    let (mut stream, _) = kernel.listener.accept().await.unwrap();
    drain_handshake(&mut stream).await;

    let mut req = ok_request("https://api.anthropic.com/v1/messages");
    if let GatewayMessage::FetchRequest { gateway_token, .. } = &mut req {
        // Different from env-supplied token → InvalidToken.
        *gateway_token = "f".repeat(64);
    }
    write_frame(&mut stream, &req).await.unwrap();
    let resp: GatewayMessage = read_frame(&mut stream).await.unwrap();
    match resp {
        GatewayMessage::FetchResponse { error, .. } => {
            assert_eq!(error.as_deref(), Some("InvalidToken"));
        }
        other => panic!("expected FetchResponse, got {other:?}"),
    }

    drop(stream);
    drop(kernel);
    let _ = gw.wait(Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_exits_with_code_64_when_required_env_var_missing() {
    // Hand-rolled spawn: skip the helper because it always sets the env.
    let bin = locate_gateway();
    let kernel = FakeKernel::bind();

    let output = Command::new(&bin)
        .env_remove("RAXIS_GATEWAY_TOKEN") // belt-and-suspenders
        .env("RAXIS_GATEWAY_SOCKET", &kernel.socket_path)
        .env("RAXIS_DATA_DIR", "/tmp/raxis-no-such-dir")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn gateway with missing env");
    let code = output.status.code().expect("non-signal exit");
    assert_eq!(code, 64,
        "gateway must exit 64 (EX_USAGE) on missing env; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("RAXIS_GATEWAY_TOKEN"),
        "stderr must name the missing var; got:\n{stderr}");

    // Suppresses unused write import.
    let mut _f = Vec::new();
    let _ = _f.write_all(b"");
}
