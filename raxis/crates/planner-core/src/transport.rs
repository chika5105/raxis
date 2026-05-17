//! `KernelTransport` — guest-side IPC client to the kernel
//! (planner socket / VSock).

//! "VSock frame reader/writer guest-side" + "Intent submission" +
//! "Witness/verdict submission" by giving each planner role binary
//! a single, transport-agnostic surface for sending
//! [`raxis_ipc::IpcMessage`] frames to the kernel and reading the
//! kernel's reply (always exactly one reply per request, per
//! `peripherals.md §3.1`).
//! ## Why a trait, not just a UDS connector
//! The planner-harness binaries are spawned in three different host
//! environments depending on the active substrate:
//! 1. **Subprocess isolation** (the default for the
//!    `raxis-live-e2e` test harness; pinned by the
//!    `raxis-isolation` `Subprocess` backend). The planner binary
//!    runs as a child process on the host and reaches the kernel
//!    over the same UDS socket the operator CLI uses
//!    (`<data_dir>/sockets/planner.sock`). The kernel-side spawn
//!    path stamps `RAXIS_KERNEL_PLANNER_SOCKET` into the child's
//!    environment so the planner does not need to know the data
//!    directory layout.
//! 2. **Apple-VZ / Firecracker VM** (production). The planner runs
//!    inside a guest VM with no UDS connectivity to the host; the
//!    `vsock` virtio device routes frames to a host-side VSock-to-UDS
//!    proxy. The kernel-side spawn path stamps
//!    `RAXIS_KERNEL_VSOCK_CID` + `RAXIS_KERNEL_VSOCK_PORT` into the
//!    guest's environment.
//! 3. **In-process unit tests** (this file's `#[cfg(test)]` mod). A
//!    `tokio::io::duplex` pair stands in for the UDS / VSock socket
//!    so tests can pin frame round-trips without standing up the
//!    full kernel.
//!    A trait-based design lets the dispatch loop and intent-submission
//!    helpers stay transport-agnostic: any binary that accepts
//!    `KernelTransport: KernelTransport` (the marker bound, see below)
//!    works the same way under all three substrates.
//! ## Wire shape
//! Every frame is `[u32 LE body_len][bincode body]` per
//! `raxis-ipc::frame` (`peripherals.md §3` opening normative note).
//! The planner side serialises [`raxis_ipc::IpcMessage`] variants:
//! * Outbound: `IntentRequest` / `EscalationRequest`
//! * Inbound:  `KernelIntentResponse` / `KernelEscalationResponse`
//!   The kernel always responds with exactly one frame per request;
//!   [`KernelTransport::request`] therefore writes one outbound frame
//!   and reads one inbound frame in a single round-trip. Multiplexed
//!   request streams are out of scope for V2 — the kernel's planner
//!   handler is sequential per session, so a single in-flight request
//!   per connection is the contract.
//! ## V2 limits
//! * **TLS / mTLS over the transport.** The UDS socket relies on
//!   filesystem permissions (`0660`, operator group) for auth; the
//!   VSock socket relies on the substrate-side CID enforcement.
//!   Neither layer carries TLS today; if a future release adds
//!   transport-level encryption, it goes on top of this trait
//!   without changing the call sites.
//! * **Reconnect semantics.** A read/write error tears down the
//!   connection; the calling planner role binary's outer loop
//!   decides whether to reconnect. We do not auto-reconnect inside
//!   the trait so the binary can choose between fail-fast (executor
//!   on a one-shot intent) and retry-with-backoff (reviewer
//!   long-poll) per role.

use raxis_ipc::frame::{read_frame, write_frame, FrameError};
use raxis_ipc::IpcMessage;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

/// Errors that can surface from the [`KernelTransport`] surface.
/// The variant set is deliberately small: the planner-harness binary
/// converts any [`TransportError`] to a structured-log line + exit
/// code per its role's escalation policy.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Frame-layer error from `raxis-ipc`. Wraps `FrameError` so the
    /// caller can pattern-match on the underlying I/O / codec failure
    /// (e.g. distinguishing a clean `Eof` from a truncated body).
    #[error("frame-layer error: {0}")]
    Frame(#[from] FrameError),

    /// The kernel responded with an `IpcMessage` variant that the
    /// planner-side caller did not expect for this round-trip
    /// (e.g. a [`raxis_ipc::IpcMessage::OperatorResponse`] arriving
    /// on the planner socket). Caught at the dispatch layer to fail
    /// fast on protocol misuse.
    #[error("unexpected response variant from kernel: {variant}")]
    UnexpectedResponseVariant {
        /// The discriminant name of the unexpected variant.
        variant: &'static str,
    },

    /// The transport address was missing from the boot environment
    /// (e.g. neither `RAXIS_KERNEL_PLANNER_SOCKET` nor
    /// `RAXIS_KERNEL_VSOCK_CID` was set). Surfaces from
    /// [`KernelTransportConfig::from_env_fn`] only — once a concrete
    /// transport is constructed, this variant is unreachable.
    #[error("kernel transport not configured (no UDS path or VSock CID/port in env)")]
    NotConfigured,

    /// The transport was configured for VSock but this build was
    /// compiled without the `vsock-transport` feature. Surfaces only
    /// in production VM substrates that boot before the feature
    /// stabilises; the planner role binary should fail closed and
    /// the kernel-side spawn path will record `SessionVmExited` with
    /// the structured exit code.
    #[error("vsock transport requested but `vsock-transport` feature not enabled")]
    VsockUnavailable,
}

// ---------------------------------------------------------------------------
// KernelTransport trait — the surface every planner-role binary uses
// ---------------------------------------------------------------------------

/// **Guest-side IPC client surface.** Every planner-role binary
/// holds one [`KernelTransport`] and uses it for the lifetime of the
/// session.
/// Synchronisation: implementations MUST be `Send + Sync`; the
/// dispatch loop awaits requests from a single task, but
/// long-running roles (the orchestrator) hand the transport into a
/// background heartbeat task that emits `KeepAlive` frames in
/// parallel with intent submission. The default UDS impl wraps the
/// duplex stream in a `tokio::sync::Mutex` so concurrent
/// `request(…)` calls serialise on the wire (the kernel's planner
/// handler is sequential per session anyway, so this just mirrors
/// the protocol contract on the client side).
/// Lifetime: `request(…)` is `&self` so a planner can construct one
/// `Arc<dyn KernelTransport>` and clone it across tasks. Closing
/// the connection happens implicitly on `Drop`.
#[async_trait::async_trait]
pub trait KernelTransport: Send + Sync {
    /// Send `outbound` and read exactly one reply frame from the
    /// kernel. Caller is responsible for matching the reply variant
    /// against the request kind.
    /// **Connection survival.** On `Err`, the implementation MAY
    /// have already torn down the underlying socket — the caller
    /// MUST treat the transport as poisoned and either reconnect or
    /// surface a hard failure. The trait does not expose a `reset`
    /// method because the only correct response to a frame error is
    /// to drop the transport and rebuild it from the boot
    /// environment (preserving the kernel's per-connection
    /// session-token authentication invariant).
    async fn request(&self, outbound: &IpcMessage) -> Result<IpcMessage, TransportError>;
}

// ---------------------------------------------------------------------------
// Boot-environment discovery
// ---------------------------------------------------------------------------

/// Where the kernel told this planner to connect, parsed from the
/// boot environment.
/// Pinned by `planner-harness.md §14.5` (the env-var contract);
/// extended by to cover the VSock CID/port pair the
/// production VM substrate stamps.
#[derive(Debug, Clone)]
pub enum KernelTransportConfig {
    /// Subprocess-isolation / in-process tests. The planner binary
    /// connects to the kernel's `planner.sock` UDS path directly.
    Uds {
        /// Filesystem path of the kernel's `planner.sock` socket.
        socket_path: PathBuf,
    },
    /// Firecracker VM (and any future substrate where the planner
    /// dials the host kernel). The planner binary reaches the
    /// kernel through the guest's `vsock` virtio device by
    /// **connecting outbound** to `(cid, port)`.
    /// Concrete connect logic lives behind the `vsock-transport`
    /// Cargo feature; the variant is always present so callers can
    /// pattern-match without `cfg`-gating, but constructing a
    /// transport from this variant on a build without the feature
    /// returns [`TransportError::VsockUnavailable`].
    Vsock {
        /// Context ID of the host (`2` for AF_VSOCK on the standard
        /// Apple-VZ / Firecracker host). Pinned by the kernel's
        /// session-spawn path.
        cid: u32,
        /// Port the kernel's host-side proxy is listening on.
        port: u32,
    },
    /// **Apple-VZ guest** — the planner binds an AF_VSOCK listener
    /// on `port` and accepts exactly one connection from the host
    /// kernel (which dials in via
    /// `VZVirtioSocketDevice.connectToPort:`). Once accepted the
    /// socket is wrapped in the same `StreamTransport` the
    /// `Vsock` and `Uds` variants use, so the framing protocol on
    /// top is identical.
    /// The asymmetry vs the Firecracker `Vsock` variant exists
    /// because Apple-VZ's `VZVirtioSocketDevice` supports the
    /// host-dials-guest direction natively but requires an
    /// Objective-C delegate (`VZVirtioSocketListener`) to do the
    /// inverse. Pinning the guest as the listener keeps the
    /// substrate's vsock wiring symmetric with what AVF already
    /// exposes from `connect_vsock`.
    /// Behind the same `vsock-transport` feature gate as `Vsock`.
    VsockListen {
        /// AF_VSOCK port the planner binds. Always `1024` in the
        /// canonical AVF substrate (matches
        /// `extensibility-traits.md §3.4` planner-port pin).
        port: u32,
    },
}

impl KernelTransportConfig {
    /// Read the kernel-stamped env vars and pick a transport.
    /// Precedence (matches the kernel-side spawn path):
    /// 1. `RAXIS_KERNEL_PLANNER_SOCKET` → [`KernelTransportConfig::Uds`]
    /// 2. `RAXIS_KERNEL_VSOCK_LISTEN_PORT` →
    ///    [`KernelTransportConfig::VsockListen`] (Apple-VZ guest)
    /// 3. `RAXIS_KERNEL_VSOCK_CID` + `RAXIS_KERNEL_VSOCK_PORT` →
    ///    [`KernelTransportConfig::Vsock`] (Firecracker / dial-out)
    ///    All missing ⇒ [`TransportError::NotConfigured`].
    ///    The closure shape `&str -> Option<String>` mirrors
    ///    `std::env::var(_).ok()` so tests can inject a hermetic env.
    pub fn from_env_fn<F>(f: F) -> Result<Self, TransportError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(path) = f("RAXIS_KERNEL_PLANNER_SOCKET") {
            if !path.is_empty() {
                return Ok(Self::Uds {
                    socket_path: PathBuf::from(path),
                });
            }
        }
        if let Some(port) = f("RAXIS_KERNEL_VSOCK_LISTEN_PORT") {
            // Listener mode (Apple-VZ guest). Empty value coerces
            // to NotConfigured rather than silently picking 0 — port
            // 0 is reserved by AF_VSOCK semantics and would shadow
            // a real misconfiguration.
            if !port.is_empty() {
                let port: u32 = port.parse().map_err(|_| TransportError::NotConfigured)?;
                return Ok(Self::VsockListen { port });
            }
        }
        if let (Some(cid), Some(port)) = (f("RAXIS_KERNEL_VSOCK_CID"), f("RAXIS_KERNEL_VSOCK_PORT"))
        {
            // Parse loosely: a malformed numeric value is a kernel
            // bug we want to surface as NotConfigured rather than
            // pretending we have a transport.
            let cid: u32 = cid.parse().map_err(|_| TransportError::NotConfigured)?;
            let port: u32 = port.parse().map_err(|_| TransportError::NotConfigured)?;
            return Ok(Self::Vsock { cid, port });
        }
        Err(TransportError::NotConfigured)
    }

    /// Convenience: read from the live process environment.
    pub fn from_process_env() -> Result<Self, TransportError> {
        Self::from_env_fn(|k| std::env::var(k).ok())
    }
}

// ---------------------------------------------------------------------------
// connect() — the production constructor
// ---------------------------------------------------------------------------

/// Build a [`KernelTransport`] from a [`KernelTransportConfig`].
/// **UDS path.** Direct `tokio::net::UnixStream::connect`. The
/// kernel's `accept_planner_loop` spawns a per-connection task on
/// the other side. Returns the trait object boxed for type-erasure
/// so the caller can hold an `Arc<dyn KernelTransport>` regardless
/// of substrate.
/// **VSock dial path.** Behind the `vsock-transport` feature only.
/// Without the feature we surface [`TransportError::VsockUnavailable`]
/// so the planner role binary fails fast with a structured exit
/// code rather than silently ignoring the kernel-stamped CID.
/// **VSock listen path (Apple-VZ guest).** Same feature gate. The
/// planner binds an AF_VSOCK listener on `(VMADDR_CID_ANY, port)`,
/// accepts exactly one connection from the host kernel, and wraps
/// the accepted stream. Backlog is set to 1 because the kernel
/// dials exactly once per session per
/// `extensibility-traits.md §3.4`.
pub async fn connect(
    cfg: &KernelTransportConfig,
) -> Result<Arc<dyn KernelTransport>, TransportError> {
    match cfg {
        KernelTransportConfig::Uds { socket_path } => {
            let stream = UnixStream::connect(socket_path)
                .await
                .map_err(|e| TransportError::Frame(FrameError::Io(e)))?;
            Ok(Arc::new(StreamTransport::new(stream)))
        }
        #[cfg(all(feature = "vsock-transport", target_os = "linux"))]
        KernelTransportConfig::Vsock { cid, port } => {
            // AF_VSOCK connect to (cid, port). The kernel-side proxy
            // listens on the host CID; the guest dials by passing the
            // host CID it was told via `RAXIS_KERNEL_VSOCK_CID`. Per
            // `planner-harness.md §14.5` and the kernel's
            // `accept_planner_loop`, the wire framing on top of vsock
            // is identical to the UDS path, so we wrap the stream in
            // the same `StreamTransport` as the UDS branch.
            let stream =
                tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(*cid, *port))
                    .await
                    .map_err(|e| TransportError::Frame(FrameError::Io(e)))?;
            Ok(Arc::new(StreamTransport::new(stream)))
        }
        #[cfg(not(all(feature = "vsock-transport", target_os = "linux")))]
        KernelTransportConfig::Vsock { .. } => Err(TransportError::VsockUnavailable),

        #[cfg(all(feature = "vsock-transport", target_os = "linux"))]
        KernelTransportConfig::VsockListen { port } => {
            // AF_VSOCK bind on (VMADDR_CID_ANY, port). VMADDR_CID_ANY
            // accepts on any local CID — the guest doesn't know its
            // own CID at boot and AVF assigns it implicitly. backlog
            // is exactly one because the kernel dials exactly once
            // per session.
            let listener = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
                tokio_vsock::VMADDR_CID_ANY,
                *port,
            ))
            .map_err(|e| TransportError::Frame(FrameError::Io(e)))?;
            let (stream, _peer) = listener
                .accept()
                .await
                .map_err(|e| TransportError::Frame(FrameError::Io(e)))?;
            Ok(Arc::new(StreamTransport::new(stream)))
        }
        #[cfg(not(all(feature = "vsock-transport", target_os = "linux")))]
        KernelTransportConfig::VsockListen { .. } => Err(TransportError::VsockUnavailable),
    }
}

// ---------------------------------------------------------------------------
// StreamTransport — the concrete duplex-stream impl shared by UDS,
// in-process duplex tests, and (via a future feature) VSock.
// ---------------------------------------------------------------------------

/// `KernelTransport` impl over any `AsyncRead + AsyncWrite` duplex
/// stream. Public so tests in this crate (and downstream crates with
/// integration tests) can drive a hermetic `tokio::io::duplex` pair
/// through the same code path the production UDS stream uses.
pub struct StreamTransport<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Read half + write half guarded by a single `Mutex` so
    /// `request(…)` is atomic at the wire-frame level (one outbound
    /// frame is followed by exactly one inbound frame before the
    /// next request gets a chance to write).
    halves: Mutex<StreamHalves<S>>,

    /// Per-request deadline for the read of the response. None ⇒ no
    /// timeout (used by tests; production binaries should always set
    /// a finite deadline so a wedged kernel doesn't park the planner
    /// indefinitely).
    request_deadline: Option<Duration>,
}

struct StreamHalves<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
}

impl<S> StreamTransport<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Wrap an existing duplex stream. The split happens here so the
    /// caller does not need to think about `tokio::io::split`.
    pub fn new(stream: S) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            halves: Mutex::new(StreamHalves { reader, writer }),
            request_deadline: None,
        }
    }

    /// Set a per-request response-read deadline. A `None` deadline
    /// disables the timeout (the default).
    pub fn with_request_deadline(mut self, d: Option<Duration>) -> Self {
        self.request_deadline = d;
        self
    }
}

#[async_trait::async_trait]
impl<S> KernelTransport for StreamTransport<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    async fn request(&self, outbound: &IpcMessage) -> Result<IpcMessage, TransportError> {
        let mut halves = self.halves.lock().await;
        // Outbound write — one frame.
        write_frame(&mut halves.writer, outbound).await?;
        // Inbound read — one frame, optionally bounded by deadline.
        let read_fut = read_frame::<_, IpcMessage>(&mut halves.reader);
        let resp = match self.request_deadline {
            None => read_fut.await,
            Some(d) => match tokio::time::timeout(d, read_fut).await {
                Ok(r) => r,
                Err(_) => {
                    return Err(TransportError::Frame(FrameError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "kernel response timeout after {d:?} \
                                 (planner→kernel transport)"
                        ),
                    ))));
                }
            },
        }?;
        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// async-trait
// ---------------------------------------------------------------------------
// `async-trait` 0.1 is brought in transitively via raxis-types →
// raxis-ipc → tokio. We add a direct dep below to make the import
// here self-evident; the macro re-export is what the trait uses
// behind the scenes.

// `Path` import survives the strict `unused_imports` lint by being
// exercised in `KernelTransportConfig::Uds::socket_path` typing
// (PathBuf -> &Path round-trips). Surfaced here so future refactors
// that shift to a borrow-only API don't have to re-introduce the
// import.
const _: fn(&Path) = |_| {};

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_ipc::frame::write_frame;
    use raxis_types::{
        IntentKind, IntentOutcome, IntentRequest, IntentResponse, PlannerErrorCode, TaskState,
    };
    use tokio::io::{duplex, DuplexStream};

    fn fixture_intent_request() -> IntentRequest {
        IntentRequest {
            session_token: "session-token-fixture".to_owned(),
            sequence_number: 1,
            envelope_nonce: format!("{:032x}", 0x1234567890abcdefu128),
            intent_kind: IntentKind::ReportFailure,
            task_id: raxis_types::TaskId::parse("task-fixture").unwrap(),
            base_sha: None,
            head_sha: None,
            submitted_claims: vec![],
            justification: Some("transport unit test".to_owned()),
            idempotency_key: None,
            approval_token: None,
            approved: None,
            critique: None,
            resolved_via_escalation: None,
            tokens_used: None,
            structured_output: None,
            sub_task_kind: None,
            parent_gate_failure_task_id: None,
            parent_gate_failure_type: None,
        }
    }

    fn fixture_intent_response_rejected(seq: u64) -> IntentResponse {
        IntentResponse {
            sequence_number: seq,
            task_state: TaskState::Failed,
            outcome: IntentOutcome::Rejected {
                error_code: PlannerErrorCode::InvalidRequest,
                error_detail: None,
            },
        }
    }

    /// `from_env_fn` selects UDS when `RAXIS_KERNEL_PLANNER_SOCKET`
    /// is set, regardless of whether VSock vars are also present —
    /// this matches the kernel-side spawn path for subprocess
    /// substrate.
    #[test]
    fn config_prefers_uds_path_over_vsock_vars() {
        let cfg = KernelTransportConfig::from_env_fn(|k| match k {
            "RAXIS_KERNEL_PLANNER_SOCKET" => Some("/tmp/planner.sock".to_owned()),
            "RAXIS_KERNEL_VSOCK_CID" => Some("2".to_owned()),
            "RAXIS_KERNEL_VSOCK_PORT" => Some("1024".to_owned()),
            "RAXIS_KERNEL_VSOCK_LISTEN_PORT" => Some("1024".to_owned()),
            _ => None,
        })
        .unwrap();
        match cfg {
            KernelTransportConfig::Uds { socket_path } => {
                assert_eq!(socket_path.to_str(), Some("/tmp/planner.sock"));
            }
            other => panic!("UDS path must take precedence; got {other:?}"),
        }
    }

    #[test]
    fn config_uses_vsock_when_only_vsock_vars_present() {
        let cfg = KernelTransportConfig::from_env_fn(|k| match k {
            "RAXIS_KERNEL_VSOCK_CID" => Some("2".to_owned()),
            "RAXIS_KERNEL_VSOCK_PORT" => Some("1024".to_owned()),
            _ => None,
        })
        .unwrap();
        match cfg {
            KernelTransportConfig::Vsock { cid, port } => {
                assert_eq!(cid, 2);
                assert_eq!(port, 1024);
            }
            other => panic!("expected VSock dial config; got {other:?}"),
        }
    }

    /// Listen mode wins over `Vsock` dial-mode when both are
    /// stamped — the AVF substrate sets `LISTEN_PORT` and never
    /// stamps `CID`/`PORT` for the same spawn, but `from_env_fn`
    /// must still pin precedence so a misconfigured spawn fails
    /// loudly rather than silently demoting to dial-mode.
    #[test]
    fn config_prefers_vsock_listen_over_vsock_dial() {
        let cfg = KernelTransportConfig::from_env_fn(|k| match k {
            "RAXIS_KERNEL_VSOCK_LISTEN_PORT" => Some("1024".to_owned()),
            "RAXIS_KERNEL_VSOCK_CID" => Some("2".to_owned()),
            "RAXIS_KERNEL_VSOCK_PORT" => Some("1024".to_owned()),
            _ => None,
        })
        .unwrap();
        match cfg {
            KernelTransportConfig::VsockListen { port } => assert_eq!(port, 1024),
            other => panic!("expected VsockListen; got {other:?}"),
        }
    }

    #[test]
    fn config_picks_vsock_listen_when_only_listen_var_set() {
        let cfg = KernelTransportConfig::from_env_fn(|k| match k {
            "RAXIS_KERNEL_VSOCK_LISTEN_PORT" => Some("1024".to_owned()),
            _ => None,
        })
        .unwrap();
        assert!(matches!(
            cfg,
            KernelTransportConfig::VsockListen { port: 1024 },
        ));
    }

    #[test]
    fn config_rejects_malformed_listen_port_as_not_configured() {
        let err = KernelTransportConfig::from_env_fn(|k| match k {
            "RAXIS_KERNEL_VSOCK_LISTEN_PORT" => Some("not-a-port".to_owned()),
            _ => None,
        })
        .unwrap_err();
        assert!(matches!(err, TransportError::NotConfigured));
    }

    #[test]
    fn config_returns_not_configured_when_env_is_empty() {
        let err = KernelTransportConfig::from_env_fn(|_| None).unwrap_err();
        assert!(matches!(err, TransportError::NotConfigured));
    }

    #[test]
    fn config_rejects_malformed_vsock_port_as_not_configured() {
        let err = KernelTransportConfig::from_env_fn(|k| match k {
            "RAXIS_KERNEL_VSOCK_CID" => Some("2".to_owned()),
            "RAXIS_KERNEL_VSOCK_PORT" => Some("not-a-port".to_owned()),
            _ => None,
        })
        .unwrap_err();
        assert!(matches!(err, TransportError::NotConfigured));
    }

    #[test]
    fn config_rejects_empty_uds_path_falls_back_to_not_configured() {
        // An empty `RAXIS_KERNEL_PLANNER_SOCKET` is a kernel-substrate
        // bug; we MUST NOT silently coerce it to "current directory".
        let err = KernelTransportConfig::from_env_fn(|k| match k {
            "RAXIS_KERNEL_PLANNER_SOCKET" => Some(String::new()),
            _ => None,
        })
        .unwrap_err();
        assert!(matches!(err, TransportError::NotConfigured));
    }

    /// `connect` on a `Vsock` config without the feature surfaces
    /// `VsockUnavailable` so the planner role binary can structured-
    /// log + exit. Pins the fail-closed posture.
    /// Runs only on builds that *don't* enable the feature
    /// (e.g. macOS, or Linux with the feature off). On Linux+feature,
    /// hitting this path would actually try to dial a vsock — so we
    /// skip it.
    #[cfg(not(all(feature = "vsock-transport", target_os = "linux")))]
    #[tokio::test]
    async fn connect_returns_vsock_unavailable_without_feature() {
        let cfg = KernelTransportConfig::Vsock { cid: 2, port: 1024 };
        match connect(&cfg).await {
            Err(TransportError::VsockUnavailable) => {}
            Err(other) => panic!("expected VsockUnavailable, got {other:?}"),
            Ok(_) => panic!("expected Err(VsockUnavailable)"),
        }

        let cfg = KernelTransportConfig::VsockListen { port: 1024 };
        match connect(&cfg).await {
            Err(TransportError::VsockUnavailable) => {}
            Err(other) => panic!("expected VsockUnavailable, got {other:?}"),
            Ok(_) => panic!("expected Err(VsockUnavailable)"),
        }
    }

    /// End-to-end frame round-trip: planner side sends an
    /// `IntentRequest`, mock kernel side reads the same struct and
    /// responds with a `KernelIntentResponse`, planner side reads the
    /// response off the wire. Pins `request(…)` against the actual
    /// `IpcMessage` codec.
    #[tokio::test]
    async fn stream_transport_round_trips_intent_request_and_response() {
        let (planner_side, mut kernel_side): (DuplexStream, DuplexStream) = duplex(64 * 1024);

        let transport = StreamTransport::new(planner_side);

        // Spawn the mock kernel side: read one frame, echo a fixed
        // response.
        let kernel_task = tokio::spawn(async move {
            // Read inbound IpcMessage::IntentRequest.
            let inbound: IpcMessage = read_frame(&mut kernel_side).await.unwrap();
            match inbound {
                IpcMessage::IntentRequest(req) => {
                    assert_eq!(req.session_token, "session-token-fixture");
                    assert_eq!(req.intent_kind, IntentKind::ReportFailure);
                }
                other => panic!("expected IntentRequest, got {other:?}"),
            }
            // Respond with KernelIntentResponse.
            let resp = IpcMessage::KernelIntentResponse(fixture_intent_response_rejected(1));
            write_frame(&mut kernel_side, &resp).await.unwrap();
        });

        let outbound = IpcMessage::IntentRequest(fixture_intent_request());
        let resp = transport.request(&outbound).await.unwrap();

        match resp {
            IpcMessage::KernelIntentResponse(r) => {
                assert_eq!(r.sequence_number, 1);
                match r.outcome {
                    IntentOutcome::Rejected { error_code, .. } => {
                        assert_eq!(error_code, PlannerErrorCode::InvalidRequest);
                    }
                    IntentOutcome::Accepted { .. } => {
                        panic!("expected Rejected outcome");
                    }
                }
            }
            other => panic!("expected KernelIntentResponse, got {other:?}"),
        }

        kernel_task.await.unwrap();
    }

    /// Two sequential requests on a single transport — pins the
    /// `Mutex<StreamHalves>` ordering. A bug in the lock would let
    /// the second `write_frame` race with the first `read_frame` and
    /// deadlock under load.
    #[tokio::test]
    async fn stream_transport_serialises_back_to_back_requests() {
        let (planner_side, mut kernel_side): (DuplexStream, DuplexStream) = duplex(64 * 1024);
        let transport = StreamTransport::new(planner_side);

        // Mock kernel: respond to two consecutive requests with
        // distinct sequence_numbers so the test pins per-request
        // correlation.
        let kernel_task = tokio::spawn(async move {
            for n in 0u64..2 {
                let _: IpcMessage = read_frame(&mut kernel_side).await.unwrap();
                let resp =
                    IpcMessage::KernelIntentResponse(fixture_intent_response_rejected(n + 100));
                write_frame(&mut kernel_side, &resp).await.unwrap();
            }
        });

        for n in 0u64..2 {
            let outbound = IpcMessage::IntentRequest(fixture_intent_request());
            let resp = transport.request(&outbound).await.unwrap();
            match resp {
                IpcMessage::KernelIntentResponse(r) => {
                    assert_eq!(r.sequence_number, n + 100);
                }
                other => panic!("unexpected response: {other:?}"),
            }
        }

        kernel_task.await.unwrap();
    }

    /// Per-request deadline pin: a kernel that never responds is
    /// surfaced as `FrameError::Io` with `ErrorKind::TimedOut`. The
    /// production planner-role binary maps this to a structured
    /// stall-recovery audit log + exit code.
    #[tokio::test]
    async fn stream_transport_request_deadline_fires_on_silent_kernel() {
        let (planner_side, _kernel_side): (DuplexStream, DuplexStream) = duplex(64 * 1024);
        // Hold _kernel_side without responding — the read on the
        // planner side will block until the deadline.
        let transport = StreamTransport::new(planner_side)
            .with_request_deadline(Some(Duration::from_millis(20)));

        let outbound = IpcMessage::IntentRequest(fixture_intent_request());
        let err = transport.request(&outbound).await.unwrap_err();
        match err {
            TransportError::Frame(FrameError::Io(io_err)) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::TimedOut);
            }
            other => panic!("expected Io(TimedOut), got {other:?}"),
        }
    }
}
