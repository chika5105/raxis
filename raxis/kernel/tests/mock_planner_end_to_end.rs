//! End-to-end mock-planner ⇄ kernel integration tests.
//!
//! Drives `<data_dir>/sockets/planner.sock` from a tiny mock planner over
//! real Unix Domain Sockets, against the *actual* `raxis-kernel` binary
//! (built and launched per-test by the shared `common::kernel_harness`).
//!
//! ## Why this file exists
//!
//! Unit tests in `src/` cover the handler pipeline; `tokio::io::duplex`
//! tests in `tests/operator_handshake_smoke.rs` cover the framing contract.
//! Neither pin the *integrated* shape that a real planner subprocess sees:
//!
//!   - that `planner.sock` is bound at the documented path with the
//!     documented mode bits at the moment "sockets bound" appears in stderr
//!     (kernel-core.md §2.2 step 7);
//!   - that `IpcMessage::IntentRequest` and `IpcMessage::EscalationRequest`
//!     frames written through `raxis-ipc::frame::write_frame` are decoded,
//!     dispatched, and round-trip back as the typed
//!     `IpcMessage::KernelIntentResponse` / `KernelEscalationResponse`
//!     variants the planner expects (peripherals.md §3.1);
//!   - that `accept_planner_loop` (`kernel/src/ipc/server.rs`) can sustain
//!     multiple frames per connection AND multiple connections in parallel
//!     without one bad / aborted connection killing the listener.
//!
//! ## What "dumb mock planner" means here
//!
//! The mock planner has *no* signed-plan ingestion, *no* witness submission,
//! *no* delegation flow. It just connects, sends typed frames, and reads
//! typed replies. Every request in this file uses a deliberately bogus
//! `session_token`, so all responses are `Rejected { Unauthorized }` (for
//! intents) or `Rejected { RateLimitExceeded }` (for escalations — see the
//! spec's "session-resolution failure → RateLimitExceeded" mapping in
//! `kernel/src/handlers/escalation.rs`). This is exactly what we want for a
//! v1 wire-shape test:
//!
//!   - we exercise the *full* socket → frame → handler dispatch → frame →
//!     socket round trip with a real binary, so any drift in the wire
//!     contract or the `IpcMessage` enum surface area fails immediately;
//!   - we do NOT have to seed sessions, lineages, initiatives, tasks, or
//!     git worktrees — a v2 follow-up that drives a real agent loop will
//!     extend the `MockPlanner` helper with those flows once the operator
//!     CLI / SDK is available end-to-end.
//!
//! Each test bootstraps its own kernel + data dir (no cross-test sharing)
//! and tears the kernel down with SIGTERM at the end. The harness'
//! `Drop` impl provides a SIGKILL safety net for panicking tests.

mod common;

use std::path::Path;
use std::time::Duration;

use raxis_ipc::{read_frame, write_frame, FrameError, IpcMessage};
use raxis_types::{
    CapabilityClass, EscalationClass, EscalationRejectionReason, EscalationRequest,
    EscalationResponse, IntentKind, IntentOutcome, IntentRequest, IntentResponse, PlannerErrorCode,
    RequestedEscalationScope, SessionId, TaskId, TaskState,
};
use tokio::net::UnixStream;
use uuid::Uuid;

use common::kernel_harness::KernelInstance;

// ---------------------------------------------------------------------------
// Test deadlines
// ---------------------------------------------------------------------------
// Generous on purpose — CI machines under load occasionally take >5s to
// bind sockets. Long enough to hide environmental noise, short enough that
// a true regression (kernel never binds) fails the test in well under a
// minute.
const READY_DEADLINE: Duration = Duration::from_secs(10);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
const ROUND_TRIP_DEADLINE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// MockPlanner — connect once, drive the wire
// ---------------------------------------------------------------------------

/// A minimal, dumb planner that owns one `UnixStream` to the kernel and a
/// per-instance sequence counter.
///
/// The instance is intentionally cheap to construct: real planners stand
/// these up at session-token issue time, but tests that *don't* drive a
/// real session can still use this struct to talk to the kernel — the
/// kernel never sees the planner's local counter (it validates the
/// `sequence_number` on each request against `sessions.sequence_number`),
/// so for bogus-token tests the counter is just a deterministic source of
/// monotonic, non-colliding values.
///
/// Every request method (`build_intent`, `build_escalation`) returns the
/// freshly built struct so the test can mutate fields before sending. This
/// keeps the planner uncoupled from the policy of any given test.
struct MockPlanner {
    stream: UnixStream,
    next_sequence_number: u64,
    next_nonce_seed: u128,
}

impl MockPlanner {
    /// Connect to `socket_path`. Awaits the OS-level `connect(2)`; the
    /// kernel's `accept_planner_loop` will spawn its per-connection task
    /// before we send our first frame.
    async fn connect<P: AsRef<Path>>(socket_path: P) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket_path).await?;
        Ok(Self {
            stream,
            next_sequence_number: 1,
            // Distinct seed per connection so two MockPlanners running in
            // parallel inside one test never produce colliding nonces.
            // 128-bit space + a nontrivial xor with `Uuid::new_v4()` makes
            // collisions astronomically unlikely.
            next_nonce_seed: u128::from_le_bytes(*Uuid::new_v4().as_bytes()),
        })
    }

    /// Mint the next 32-hex-char `envelope_nonce`. Counter-derived for
    /// determinism; the kernel only checks the format + uniqueness, not
    /// the entropy.
    fn next_nonce(&mut self) -> String {
        let n = self.next_nonce_seed;
        self.next_nonce_seed = self.next_nonce_seed.wrapping_add(1);
        format!("{n:032x}")
    }

    /// Build a minimal `IntentRequest` wired to the planner's next sequence
    /// number + nonce. The caller is free to override any field before
    /// sending.
    ///
    /// Defaults:
    ///   - `task_id` is a fresh UUID v4 (bogus → `FAIL_UNKNOWN_TASK` in the
    ///     real handler, but unreachable behind the bogus token check);
    ///   - `base_sha` / `head_sha` are `None` (only matters for
    ///     SHA-requiring kinds);
    ///   - `submitted_claims` is empty;
    ///   - `justification` is `Some(...)` for `ReportFailure` (the only
    ///     kind that requires it) and `None` otherwise.
    fn build_intent(&mut self, token: &str, kind: IntentKind) -> IntentRequest {
        let seq = self.next_sequence_number;
        self.next_sequence_number = seq.wrapping_add(1);
        IntentRequest {
            session_token: token.to_owned(),
            sequence_number: seq,
            envelope_nonce: self.next_nonce(),
            intent_kind: kind,
            task_id: fresh_task_id(),
            base_sha: None,
            head_sha: None,
            submitted_claims: vec![],
            justification: kind
                .requires_justification()
                .then(|| "mock-planner end-to-end test".to_owned()),
            idempotency_key: None,
            approval_token: None,
            approved: None,
            critique: None,
            resolved_via_escalation: None,
            tokens_used: None,
            structured_output: None,
        }
    }

    /// Build a minimal `EscalationRequest` with a fresh idempotency key.
    /// Default scope: `CapabilityUpgrade { capability: InfraRead }` — the
    /// least-privilege class so we never accidentally open a privileged
    /// path in a future v2 happy-path test.
    fn build_escalation(&mut self, token: &str) -> EscalationRequest {
        EscalationRequest {
            session_token: token.to_owned(),
            task_id: fresh_task_id(),
            class: EscalationClass::CapabilityUpgrade,
            requested_scope: RequestedEscalationScope::CapabilityUpgrade {
                capability: CapabilityClass::InfraRead,
            },
            justification: "mock-planner escalation".to_owned(),
            idempotency_key: Uuid::new_v4(),
        }
    }

    /// Send one `IpcMessage` frame and read the kernel's reply with a
    /// deadline. The kernel's planner dispatcher always responds with
    /// exactly one frame per request; the caller pattern-matches on the
    /// returned variant.
    async fn round_trip(&mut self, msg: &IpcMessage) -> Result<IpcMessage, FrameError> {
        write_frame(&mut self.stream, msg).await?;
        match tokio::time::timeout(ROUND_TRIP_DEADLINE, read_frame(&mut self.stream)).await {
            Ok(res) => res,
            Err(_) => panic!(
                "kernel did not reply to {} within {ROUND_TRIP_DEADLINE:?}",
                describe_message(msg),
            ),
        }
    }
}

/// Mint a fresh, well-formed `TaskId`. `TaskId` is an operator-chosen
/// string from the signed plan (not a UUID), so we synthesize a unique
/// `mock-task-<short-uuid>` value that satisfies the `TaskId::parse`
/// invariants (non-empty, ≤128 bytes, no control chars). The kernel will
/// fail the `tasks WHERE task_id=?` lookup on this value anyway in our
/// bogus-token tests, so the only constraint is wire-syntactic validity.
fn fresh_task_id() -> TaskId {
    let v = Uuid::new_v4().simple().to_string();
    TaskId::parse(&format!("mock-task-{v}"))
        .expect("synthesized TaskId must satisfy parse invariants")
}

/// Friendly variant name for panic messages — `IpcMessage` does not derive
/// a short Display.
///
/// Every variant of `raxis_ipc::IpcMessage` MUST appear here so the match
/// stays compiler-exhaustive: any future variant addition will surface as
/// an E0004 here and force the test author to make a deliberate decision
/// about whether the new variant is expected on the mock-planner wire.
/// This mirrors the structural-totality invariant pinned by
/// `kernel::observability::kernel_substrate_ipc_route` (see
/// `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01`).
///
/// Note on the Path-A3 admission variants
/// (`TproxyAdmissionRequest` / `KernelTproxyAdmissionResponse` /
/// `DnsResolveRequest` / `KernelDnsResolveResponse`,
/// `airgap-architecture.md §3`): these tests do not construct or
/// expect any of those variants — they are produced/consumed by
/// the in-VM `raxis-tproxy` substrate path, not by the dumb mock
/// planner. They are listed here purely so a panic message that
/// somehow surfaced one of them would print the variant name
/// instead of failing to compile this fixture. No behaviour
/// change for the variants these tests exercise.
fn describe_message(msg: &IpcMessage) -> &'static str {
    match msg {
        IpcMessage::IntentRequest(_) => "IntentRequest",
        IpcMessage::EscalationRequest(_) => "EscalationRequest",
        IpcMessage::PlannerFetchRequest(_) => "PlannerFetchRequest",
        IpcMessage::PlannerExitNotice { .. } => "PlannerExitNotice",
        IpcMessage::KernelIntentResponse(_) => "KernelIntentResponse",
        IpcMessage::KernelEscalationResponse(_) => "KernelEscalationResponse",
        IpcMessage::KernelPlannerFetchResponse(_) => "KernelPlannerFetchResponse",
        IpcMessage::KernelPlannerExitNoticeAck => "KernelPlannerExitNoticeAck",
        IpcMessage::TproxyAdmissionRequest(_) => "TproxyAdmissionRequest",
        IpcMessage::KernelTproxyAdmissionResponse(_) => "KernelTproxyAdmissionResponse",
        IpcMessage::DnsResolveRequest(_) => "DnsResolveRequest",
        IpcMessage::KernelDnsResolveResponse(_) => "KernelDnsResolveResponse",
        IpcMessage::WitnessSubmission(_) => "WitnessSubmission",
        IpcMessage::WitnessAck { .. } => "WitnessAck",
        IpcMessage::OperatorRequest(_) => "OperatorRequest",
        IpcMessage::OperatorResponse(_) => "OperatorResponse",
    }
}

// ---------------------------------------------------------------------------
// Local assertion helpers
// ---------------------------------------------------------------------------

/// Pattern-match a returned `IpcMessage` as a `KernelIntentResponse`,
/// failing the test with a clear message otherwise.
fn expect_intent_response(msg: IpcMessage) -> IntentResponse {
    match msg {
        IpcMessage::KernelIntentResponse(r) => r,
        other => panic!(
            "expected IpcMessage::KernelIntentResponse, got {}",
            describe_message(&other),
        ),
    }
}

/// Pattern-match a returned `IpcMessage` as a `KernelEscalationResponse`,
/// failing the test with a clear message otherwise.
fn expect_escalation_response(msg: IpcMessage) -> EscalationResponse {
    match msg {
        IpcMessage::KernelEscalationResponse(r) => r,
        other => panic!(
            "expected IpcMessage::KernelEscalationResponse, got {}",
            describe_message(&other),
        ),
    }
}

/// A deliberately well-formed but never-issued session token. 64 lowercase
/// hex chars — the same shape `authority::session::create_session` would
/// emit. The kernel will fail the `sessions WHERE session_token=?` lookup
/// and reject with `Unauthorized` (intents) / `RateLimitExceeded`
/// (escalations).
const FAKE_TOKEN: &str = "deadbeefcafebabefeedfacefadedfeed1122334455667788abcd1234efef0011";

// ---------------------------------------------------------------------------
// Test 1 — golden round trip (the "user's example, fleshed out")
// ---------------------------------------------------------------------------

/// Connect a mock planner, send one `IntentRequest` with a bogus session
/// token, and assert on the FULL response shape: variant, sequence-number
/// echo, error code, error_detail nullity, and task_state default.
///
/// This is the canonical "kernel is alive and the wire format works"
/// regression guard. If this test fails after a refactor, the wire
/// contract has drifted and every other planner-side test is suspect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn intent_with_unknown_session_is_rejected_unauthorized() {
    let mut kernel = KernelInstance::bootstrap_and_spawn();
    kernel.wait_until_ready_or_panic(READY_DEADLINE);

    let mut planner = MockPlanner::connect(&kernel.planner_socket())
        .await
        .expect("connect to planner.sock");

    let req = planner.build_intent(FAKE_TOKEN, IntentKind::SingleCommit);
    let req_seq = req.sequence_number;

    let reply = planner
        .round_trip(&IpcMessage::IntentRequest(req))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "kernel did not return a frame: {e}; kernel stderr so far:\n{}",
                kernel.captured_stderr(),
            );
        });

    let resp = expect_intent_response(reply);

    // Sequence number MUST echo (peripherals.md §3.1: "matches the
    // sequence_number of the IntentRequest"). Even on rejection.
    assert_eq!(
        resp.sequence_number, req_seq,
        "sequence_number must echo the request",
    );

    // task_state on early-rejection paths defaults to Admitted (handler
    // uses the FSM-default state because no real task was loaded).
    assert_eq!(
        resp.task_state,
        TaskState::Admitted,
        "task_state must be Admitted on session-resolution rejection",
    );

    match resp.outcome {
        IntentOutcome::Rejected {
            error_code,
            error_detail,
        } => {
            assert_eq!(
                error_code,
                PlannerErrorCode::Unauthorized,
                "bogus token must reject with UNAUTHORIZED (INV-08, peripherals.md §3.1); kernel stderr:\n{}",
                kernel.captured_stderr(),
            );
            // INV-08: error_detail is non-null only for FAIL_POLICY_VIOLATION.
            assert!(
                error_detail.is_none(),
                "error_detail MUST be None for UNAUTHORIZED (INV-08); got {error_detail:?}",
            );
        }
        IntentOutcome::Accepted { .. } => {
            panic!("kernel must NOT accept an intent with a bogus session_token");
        }
    }

    // Graceful teardown so we exercise (and don't lean on Drop's SIGKILL).
    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(status.success(), "kernel must exit cleanly after SIGTERM");
}

// ---------------------------------------------------------------------------
// Test 2 — multiple frames per connection
// ---------------------------------------------------------------------------

/// Send three `IntentRequest`s back-to-back on the same `UnixStream`. The
/// kernel must answer each one in order, echoing the request's
/// `sequence_number` on each reply. Pins kernel-core.md §2.2 "request-reply
/// loop" — the per-connection task does NOT close after one frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_connection_can_carry_multiple_intent_frames() {
    let mut kernel = KernelInstance::bootstrap_and_spawn();
    kernel.wait_until_ready_or_panic(READY_DEADLINE);

    let mut planner = MockPlanner::connect(&kernel.planner_socket())
        .await
        .expect("connect to planner.sock");

    // Three different intent kinds — exercises the dispatcher's "intent_kind
    // routes through the same socket" contract too.
    let kinds = [
        IntentKind::SingleCommit,
        IntentKind::IntegrationMerge,
        IntentKind::ReportFailure,
    ];

    for kind in kinds {
        let req = planner.build_intent(FAKE_TOKEN, kind);
        let expected_seq = req.sequence_number;

        let reply = planner
            .round_trip(&IpcMessage::IntentRequest(req))
            .await
            .expect("kernel returned a frame");

        let resp = expect_intent_response(reply);
        assert_eq!(
            resp.sequence_number, expected_seq,
            "frame N's response must echo frame N's sequence number (got mismatched reply for {kind:?})",
        );
        assert!(
            !resp.is_accepted(),
            "every bogus-token request must reject (kind={kind:?})",
        );
    }

    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(status.success());
}

// ---------------------------------------------------------------------------
// Test 3 — mixed message kinds on one connection
// ---------------------------------------------------------------------------

/// Send one `IntentRequest` followed by one `EscalationRequest` on the same
/// connection. Pin that the dispatcher (a) keeps the connection open across
/// the variant change and (b) returns the matching response variant for
/// each (`KernelIntentResponse` then `KernelEscalationResponse`).
///
/// This is the key invariant that makes `IpcMessage` worth keeping as one
/// enum: planners can multiplex variants on a single socket without
/// reconnecting, and the kernel's tag dispatch is the only thing that
/// matters for routing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planner_socket_routes_intent_then_escalation_on_one_connection() {
    let mut kernel = KernelInstance::bootstrap_and_spawn();
    kernel.wait_until_ready_or_panic(READY_DEADLINE);

    let mut planner = MockPlanner::connect(&kernel.planner_socket())
        .await
        .expect("connect to planner.sock");

    // ── Intent ────────────────────────────────────────────────────────────
    let intent = planner.build_intent(FAKE_TOKEN, IntentKind::SingleCommit);
    let intent_reply = planner
        .round_trip(&IpcMessage::IntentRequest(intent))
        .await
        .expect("kernel returned a frame for IntentRequest");
    let intent_resp = expect_intent_response(intent_reply);
    assert!(
        !intent_resp.is_accepted(),
        "bogus-token intent must reject; got {intent_resp:?}",
    );

    // ── Escalation on the SAME connection ────────────────────────────────
    let esc = planner.build_escalation(FAKE_TOKEN);
    let esc_reply = planner
        .round_trip(&IpcMessage::EscalationRequest(esc))
        .await
        .expect("kernel returned a frame for EscalationRequest");
    let esc_resp = expect_escalation_response(esc_reply);

    // The handler maps session-resolution failure to `RateLimitExceeded` so
    // the planner can back off rather than mistake a transient lookup
    // failure for a permanent denial. See `handlers/escalation.rs`
    // step-1 comment.
    match esc_resp {
        EscalationResponse::Rejected { reason } => {
            assert_eq!(
                reason,
                EscalationRejectionReason::RateLimitExceeded,
                "bogus session_token on EscalationRequest must surface as RateLimitExceeded",
            );
        }
        other => panic!("escalation must be Rejected on bogus token; got {other:?}"),
    }

    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(status.success());
}

// ---------------------------------------------------------------------------
// Test 4 — concurrent connections
// ---------------------------------------------------------------------------

/// Open four `MockPlanner` connections in parallel and have each one round-
/// trip a request. All four must complete; the kernel's per-connection
/// task spawn (`accept_planner_loop`) must service them concurrently.
///
/// The number 4 is small on purpose: enough to demonstrate parallelism
/// without making CI flaky on a slow build host. A regression that
/// serialises connections would still be detected (each round-trip has
/// the same `ROUND_TRIP_DEADLINE`, and a serialised handler would push
/// the slowest connection past it under load).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn planner_socket_serves_concurrent_connections() {
    let mut kernel = KernelInstance::bootstrap_and_spawn();
    kernel.wait_until_ready_or_panic(READY_DEADLINE);

    let socket_path = kernel.planner_socket();
    const N: usize = 4;

    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let path = socket_path.clone();
        handles.push(tokio::spawn(async move {
            let mut planner = MockPlanner::connect(&path)
                .await
                .unwrap_or_else(|e| panic!("planner #{i} connect failed: {e}"));

            let req = planner.build_intent(FAKE_TOKEN, IntentKind::SingleCommit);
            let req_seq = req.sequence_number;
            let reply = planner
                .round_trip(&IpcMessage::IntentRequest(req))
                .await
                .unwrap_or_else(|e| panic!("planner #{i} round_trip failed: {e}"));
            let resp = expect_intent_response(reply);
            assert_eq!(
                resp.sequence_number, req_seq,
                "planner #{i} reply must echo its request seq",
            );
            assert!(
                !resp.is_accepted(),
                "planner #{i} bogus-token request must reject",
            );
        }));
    }

    for (i, h) in handles.into_iter().enumerate() {
        h.await
            .unwrap_or_else(|e| panic!("planner task #{i} panicked: {e}"));
    }

    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(status.success());
}

// ---------------------------------------------------------------------------
// Test 5 — a peer's clean disconnect does not kill the listener
// ---------------------------------------------------------------------------

/// Open a connection and drop it without sending any frames (simulates a
/// crashed planner subprocess). The kernel must not get into a degraded
/// state — a fresh connection from a second mock planner must round-trip
/// successfully afterwards.
///
/// Pins `accept_planner_loop`'s `FrameError::Eof → break` branch (and the
/// fact that the per-connection task swallows the EOF rather than
/// returning an error to the parent loop).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planner_socket_survives_peer_dropping_connection_without_sending() {
    let mut kernel = KernelInstance::bootstrap_and_spawn();
    kernel.wait_until_ready_or_panic(READY_DEADLINE);

    let socket_path = kernel.planner_socket();

    // Phase 1: open and drop without writing anything.
    {
        let stream = UnixStream::connect(&socket_path)
            .await
            .expect("first connect");
        drop(stream);
    }

    // Phase 2: a brand-new planner must still get a reply.
    let mut planner = MockPlanner::connect(&socket_path)
        .await
        .expect("second connect after silent drop");
    let req = planner.build_intent(FAKE_TOKEN, IntentKind::SingleCommit);
    let req_seq = req.sequence_number;
    let reply = planner
        .round_trip(&IpcMessage::IntentRequest(req))
        .await
        .expect("kernel still reachable after peer dropped a silent conn");
    let resp = expect_intent_response(reply);
    assert_eq!(resp.sequence_number, req_seq);
    assert!(!resp.is_accepted());

    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(status.success());
}

// ---------------------------------------------------------------------------
// Test 6 — async-safety regression guard for `handlers/intent.rs`
//
// **Why this test exists.** Tests 1-5 above all use `FAKE_TOKEN`, a
// well-formed but never-issued session token. The kernel rejects them at
// Step 1 of the 13-step pipeline (session lookup miss), which is the
// single `lock_sync()` site that was already wrapped in
// `tokio::task::spawn_blocking`. So those tests never exercised Steps 2+.
//
// Before the `intent.rs` 3-phase async/sync refactor, every other
// `lock_sync()` site in the handler ran on a tokio worker thread and
// would panic the runtime with
//   "Cannot block the current thread from within a runtime"
// the moment a real planner with a valid session token reached Step 2.
// The connection would close, the test would observe a `FrameError::Eof`,
// and the kernel would log a panic on stderr.
//
// This test pins the fix: it inserts a real session row directly into
// `kernel.db`, then submits an `IntentRequest` carrying the matching
// session token. The kernel must:
//
//   - clear Step 1 (session lookup hit),
//   - clear Step 2 (`accept_envelope_and_advance_sequence` — the first
//     site that panicked pre-fix),
//   - clear Step 3 (task lookup), and
//   - reject with a STRUCTURED `FAIL_UNKNOWN_TASK` response (because no
//     task exists for the synthesized `task_id`).
//
// If the response is a structured rejection, the entire `lock_sync`
// chain ran on a blocking-pool thread as it should. If the kernel
// panics or the connection drops, the async-safety fix has regressed.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn intent_with_real_session_token_clears_step2_envelope_acceptance() {
    let mut kernel = KernelInstance::bootstrap_and_spawn();
    kernel.wait_until_ready_or_panic(READY_DEADLINE);

    // Insert a real session row directly. We use rusqlite against
    // kernel.db because the WAL mode the kernel runs in tolerates a
    // second writer briefly, and going through the operator socket
    // would require the full operator-signing handshake — overkill
    // for an async-safety regression guard whose only purpose is to
    // give Step 2 a session to find.
    let real_token = format!(
        "{:032x}{:032x}",
        Uuid::new_v4().as_u128(),
        Uuid::new_v4().as_u128(),
    );
    let real_session_id = SessionId::new_v4().as_str().to_owned();

    const SESSIONS: &str = raxis_store::Table::Sessions.as_str();

    let kernel_db_path = kernel.data_dir().join("kernel.db");
    {
        let conn = rusqlite::Connection::open(&kernel_db_path)
            .unwrap_or_else(|e| panic!("open kernel.db at {kernel_db_path:?}: {e}"));
        let now = raxis_types::unix_now_secs() as i64;
        let far_exp = now + 86_400;
        conn.execute(
            &format!(
                "INSERT INTO {SESSIONS} ( \
                     session_id, role_id, session_token, lineage_id, worktree_root, \
                     fetch_quota, sequence_number, created_at, expires_at \
                 ) VALUES (?1, 'planner', ?2, 'test-lineage', '/tmp/raxis-async-safety-test', \
                           10, 0, ?3, ?4)"
            ),
            rusqlite::params![real_session_id, real_token, now, far_exp],
        )
        .unwrap_or_else(|e| panic!("insert session row: {e}"));
    }

    let mut planner = MockPlanner::connect(&kernel.planner_socket())
        .await
        .expect("connect to planner.sock");
    let req = planner.build_intent(&real_token, IntentKind::SingleCommit);
    let req_seq = req.sequence_number;

    let reply = planner
        .round_trip(&IpcMessage::IntentRequest(req))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "kernel did not return a frame after a valid-session intent — \
                 likely a regression of the intent-handler async-safety fix. \
                 FrameError={e}; kernel stderr so far:\n{}",
                kernel.captured_stderr(),
            );
        });

    let resp = expect_intent_response(reply);
    assert_eq!(
        resp.sequence_number, req_seq,
        "sequence_number must echo even on rejection",
    );

    match resp.outcome {
        IntentOutcome::Rejected { error_code, .. } => {
            assert_eq!(
                error_code,
                PlannerErrorCode::FailUnknownTask,
                "expected FAIL_UNKNOWN_TASK (Step 3 miss), got {error_code:?}; \
                 kernel stderr:\n{}",
                kernel.captured_stderr(),
            );
        }
        IntentOutcome::Accepted { .. } => {
            panic!(
                "intent was Accepted without a seeded task — unexpected, \
                 but proves the lock_sync chain ran without panic"
            );
        }
    }

    // Crash-detection check: the kernel must NOT have panicked. If
    // the async-safety fix had regressed, the spawn_blocking-less
    // Step 2 would have panicked the worker; tokio swallows the panic
    // but the per-connection task logs it. Look for the canonical
    // panic message on stderr.
    let stderr = kernel.captured_stderr();
    assert!(
        !stderr.contains("Cannot block the current thread from within a runtime"),
        "kernel stderr contains the async-safety panic:\n{stderr}",
    );

    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(status.success(), "kernel must exit cleanly after SIGTERM");
}
