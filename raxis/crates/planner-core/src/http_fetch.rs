//! `HttpFetch` — pluggable HTTP transport for planner-side
//! [`crate::ModelClient`] implementations.
//!
//! Normative references:
//!   * `provider-failure-handling.md §2.1` — the planner ↔ kernel ↔
//!     gateway flow that egress-disabled guests rely on.
//!   * `peripherals.md §3.1` — the planner-socket
//!     `IpcMessage::PlannerFetchRequest` variant.
//!   * User clarification (this conversation): the Orchestrator has
//!     no credential proxies and no egress; it must reach the LLM
//!     through a kernel-mediated channel.
//!
//! ## Why a trait
//!
//! Every model client (`AnthropicClient`, `OpenAiClient`,
//! `BedrockClient`, `GeminiClient`, `SidecarModelClient`) needs the
//! same primitive: send an HTTP request to a known URL with known
//! headers + body, get a status / headers / body back. They differ
//! only in the URL, the request body shape, and the response parser.
//!
//! Today each client constructs its own `reqwest::Client` and POSTs
//! directly. That works in subprocess substrate (full host network)
//! but is impossible in `EgressTier::None` guests (Orchestrator,
//! Reviewer): the VM literally has no NIC.
//!
//! The fix is to abstract "make an HTTP call" into [`HttpFetch`]
//! and ship two impls:
//!
//! 1. [`DirectHttpFetch`] — wraps `reqwest::Client`. Used by the
//!    subprocess substrate, by host-side dev work, and by the
//!    `Tier1Tproxy` substrate path where the in-VM tproxy
//!    transparently routes to the kernel gateway. Equivalent to
//!    today's behaviour, just hoisted behind the trait.
//!
//! 2. [`KernelMediatedHttpFetch`] — wraps a
//!    [`crate::transport::KernelTransport`] and routes every
//!    request through the planner UDS / vsock as
//!    [`raxis_ipc::IpcMessage::PlannerFetchRequest`]. The kernel
//!    forwards to the gateway subprocess, the gateway injects
//!    credentials and dials upstream, and the response routes back
//!    over the same channel. Used by `EgressTier::None` guests
//!    where the planner cannot dial directly.
//!
//! Each [`crate::ModelClient`] takes `Arc<dyn HttpFetch>` at
//! construction time so the same client codepath supports both
//! transports.
//!
//! ## What is *not* abstracted here
//!
//! Streaming. SSE / chunked-transfer support is reqwest-specific
//! (uses `Response::bytes_stream`); generalising it requires a
//! parallel `HttpStreamFetch` trait + a chunked variant of the
//! kernel-mediated IPC. V2 GA punts on that — model clients keep
//! their existing `create_message_stream` implementations against
//! `reqwest::Client` for the substrates that have direct egress, and
//! kernel-mediated guests fall through the default
//! [`crate::ModelClient::create_message_stream`] body that wraps the
//! buffered call in a synthetic four-event stream. The dispatch
//! loop's tool-execution logic only depends on the terminal
//! `StreamEvent::Complete` event per `INV-PROVIDER-04`, so the
//! semantics are preserved.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use raxis_ipc::IpcMessage;
use raxis_types::{PlannerFetchKind, PlannerFetchRequest, PlannerFetchResponse};
use thiserror::Error;
use uuid::Uuid;

use crate::transport::{KernelTransport, TransportError};

/// One HTTP request issued by a model client.
///
/// The client owns the URL string + body bytes; the transport
/// borrows them via lifetime `'a` so we don't allocate twice.
#[derive(Debug)]
pub struct HttpFetchRequest<'a> {
    /// Full URL including scheme, host, path, query.
    pub url:     &'a str,
    /// HTTP method (`"POST"` for inference, `"GET"` for health
    /// probes).
    pub method:  &'a str,
    /// HTTP headers. Borrowed names + owned values so the client
    /// can pass `&'static str` literal names without per-call
    /// allocation.
    pub headers: Vec<(&'a str, String)>,
    /// Raw request body bytes. Empty for `GET`.
    pub body:    Vec<u8>,
    /// Per-attempt deadline. Implementors apply it as a wall-clock
    /// timeout that includes connect, write, read.
    pub timeout: Duration,
}

/// Response surface exposed to model clients.
#[derive(Debug)]
pub struct HttpFetchResponse {
    /// HTTP status code as returned by the upstream (e.g. 200, 401,
    /// 429, 500).
    pub status:  u16,
    /// Response headers. Lower-cased names per HTTP/1.1 case
    /// folding (the kernel-mediated impl preserves the gateway's
    /// case; the direct impl lowercases via `reqwest::HeaderName`).
    pub headers: Vec<(String, String)>,
    /// Raw body bytes. Empty `Vec` if the upstream returned no
    /// body.
    pub body:    Vec<u8>,
}

/// Failure modes a model client may observe from an
/// [`HttpFetch::fetch`] call.
///
/// **Note:** non-2xx HTTP status codes are NOT errors at this
/// layer — they surface as [`HttpFetchResponse`] with the actual
/// status. Only transport-level failures (timeout, connection,
/// kernel rejection) appear here. This matches the existing
/// per-client behaviour: `reqwest::Response::status()` returns the
/// non-2xx status without erroring; the model client decides
/// whether to map it to `ModelError::Upstream`.
#[derive(Debug, Error)]
pub enum HttpFetchError {
    /// Hit the per-request deadline before getting a response.
    /// Surfaced as `ModelError::Timeout` by every model client.
    #[error("http fetch timed out after {0:?}")]
    Timeout(Duration),

    /// Connect / DNS / TLS / framing-layer failure. Includes the
    /// kernel-mediated path's `GatewayUnavailable` and `NetworkError`
    /// codes.
    #[error("http transport: {0}")]
    Transport(String),
}

/// Pluggable HTTP transport.
#[async_trait]
pub trait HttpFetch: Send + Sync + std::fmt::Debug {
    /// Issue one HTTP request. Implementations MUST NOT panic on a
    /// non-2xx response — they surface the status in
    /// [`HttpFetchResponse::status`] and let the caller decide.
    async fn fetch<'a>(
        &self,
        req: HttpFetchRequest<'a>,
    ) -> Result<HttpFetchResponse, HttpFetchError>;
}

// ---------------------------------------------------------------------------
// DirectHttpFetch — `reqwest::Client` impl
// ---------------------------------------------------------------------------

/// Production direct-egress HTTP fetcher. Delegates to a single
/// shared `reqwest::Client` (HTTP/2 keep-alive, connection pooling).
#[derive(Debug, Clone)]
pub struct DirectHttpFetch {
    http: reqwest::Client,
}

impl DirectHttpFetch {
    /// Construct a new direct fetcher with the canonical client
    /// settings (10 s connect timeout, 30 s pool-idle keep-alive).
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest::Client::build is infallible with default config");
        Self { http }
    }

    /// Wrap an existing `reqwest::Client`. Used by tests that pin
    /// connection settings (e.g. point `base_url` at a mockito
    /// instance).
    pub fn from_client(http: reqwest::Client) -> Self {
        Self { http }
    }

    /// Borrow the underlying client. Streaming-capable model
    /// clients still construct `reqwest::RequestBuilder`s directly
    /// for `bytes_stream()`; this lets them share the connection
    /// pool with the buffered path.
    pub fn client(&self) -> &reqwest::Client {
        &self.http
    }
}

impl Default for DirectHttpFetch {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpFetch for DirectHttpFetch {
    async fn fetch<'a>(
        &self,
        req: HttpFetchRequest<'a>,
    ) -> Result<HttpFetchResponse, HttpFetchError> {
        let mut builder = match req.method {
            "GET"    => self.http.get(req.url),
            "POST"   => self.http.post(req.url),
            "PUT"    => self.http.put(req.url),
            "PATCH"  => self.http.patch(req.url),
            "DELETE" => self.http.delete(req.url),
            other    => {
                return Err(HttpFetchError::Transport(format!(
                    "DirectHttpFetch: unsupported HTTP method {other}",
                )))
            }
        };

        builder = builder.timeout(req.timeout);
        for (name, value) in &req.headers {
            builder = builder.header(*name, value.as_str());
        }
        if !req.body.is_empty() {
            builder = builder.body(req.body);
        }

        let resp = builder.send().await.map_err(|e| {
            if e.is_timeout() {
                HttpFetchError::Timeout(req.timeout)
            } else {
                HttpFetchError::Transport(e.to_string())
            }
        })?;

        let status  = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or_default().to_owned()))
            .collect();
        let body = resp
            .bytes()
            .await
            .map_err(|e| HttpFetchError::Transport(e.to_string()))?
            .to_vec();
        Ok(HttpFetchResponse { status, headers, body })
    }
}

// ---------------------------------------------------------------------------
// KernelMediatedHttpFetch — PlannerFetchRequest IPC impl
// ---------------------------------------------------------------------------

/// Kernel-mediated HTTP fetcher. Forwards every call to the kernel
/// over [`crate::transport::KernelTransport`] as
/// [`raxis_ipc::IpcMessage::PlannerFetchRequest`]; the kernel
/// dispatches to the gateway subprocess and routes the response
/// back as `KernelPlannerFetchResponse`.
///
/// One instance owns the per-spawn [`KernelTransport`] (whose mutex
/// serialises concurrent fetches on the wire — matching the
/// kernel's per-connection sequential dispatch contract) and the
/// per-spawn `session_token` the kernel re-validates on every
/// frame.
#[derive(Clone)]
pub struct KernelMediatedHttpFetch {
    transport:     Arc<dyn KernelTransport>,
    session_token: Arc<str>,
}

impl std::fmt::Debug for KernelMediatedHttpFetch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the session token: it is per-spawn key
        // material that authenticates the planner to the kernel.
        f.debug_struct("KernelMediatedHttpFetch")
            .field("session_token_len", &self.session_token.len())
            .finish()
    }
}

impl KernelMediatedHttpFetch {
    /// Construct a new kernel-mediated fetcher. `session_token` is
    /// the per-spawn 64-char hex token the kernel stamped into the
    /// planner's environment as `RAXIS_SESSION_TOKEN`.
    pub fn new(
        transport: Arc<dyn KernelTransport>,
        session_token: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            transport,
            session_token: session_token.into(),
        }
    }
}

#[async_trait]
impl HttpFetch for KernelMediatedHttpFetch {
    async fn fetch<'a>(
        &self,
        req: HttpFetchRequest<'a>,
    ) -> Result<HttpFetchResponse, HttpFetchError> {
        // V2 GA: planner-mediated fetches are inference unless the
        // caller explicitly overrides via headers (a future
        // `x-raxis-fetch-kind: data-fetch` opt-in would slot in
        // here for `WebFetch`-style tools). For now every
        // model-client call is `Inference`, which is the right
        // budget envelope for LLM calls.
        let timeout_ms = req.timeout.as_millis().min(u32::MAX as u128) as u32;

        let payload = PlannerFetchRequest {
            request_id:    Uuid::new_v4(),
            session_token: self.session_token.to_string(),
            fetch_kind:    PlannerFetchKind::Inference,
            url:           req.url.to_owned(),
            method:        req.method.to_owned(),
            headers:       req
                .headers
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
            body_bytes:    req.body,
            timeout_ms,
        };

        let outbound = IpcMessage::PlannerFetchRequest(payload);
        let inbound  = self.transport.request(&outbound).await.map_err(transport_to_fetch_error)?;

        let resp: PlannerFetchResponse = match inbound {
            IpcMessage::KernelPlannerFetchResponse(r) => r,
            other => {
                return Err(HttpFetchError::Transport(format!(
                    "kernel-mediated fetch: unexpected response variant: {}",
                    variant_name(&other),
                )))
            }
        };

        if let Some(reason) = resp.error.as_deref() {
            return Err(match reason {
                "TimeoutExceeded" => HttpFetchError::Timeout(req.timeout),
                _                 => HttpFetchError::Transport(reason.to_owned()),
            });
        }

        Ok(HttpFetchResponse {
            status:  resp.status_code.unwrap_or(0),
            headers: resp.headers,
            body:    resp.body_bytes.unwrap_or_default(),
        })
    }
}

fn transport_to_fetch_error(e: TransportError) -> HttpFetchError {
    match e {
        TransportError::Frame(fe) => {
            HttpFetchError::Transport(format!("kernel transport: {fe}"))
        }
        TransportError::UnexpectedResponseVariant { variant } => HttpFetchError::Transport(
            format!("kernel transport: unexpected response variant: {variant}"),
        ),
        TransportError::NotConfigured => HttpFetchError::Transport(
            "kernel transport: not configured".to_owned(),
        ),
        TransportError::VsockUnavailable => HttpFetchError::Transport(
            "kernel transport: vsock-transport feature not enabled".to_owned(),
        ),
    }
}

fn variant_name(msg: &IpcMessage) -> &'static str {
    match msg {
        IpcMessage::IntentRequest(_)              => "IntentRequest",
        IpcMessage::EscalationRequest(_)          => "EscalationRequest",
        IpcMessage::PlannerFetchRequest(_)        => "PlannerFetchRequest",
        IpcMessage::KernelIntentResponse(_)       => "KernelIntentResponse",
        IpcMessage::KernelEscalationResponse(_)   => "KernelEscalationResponse",
        IpcMessage::KernelPlannerFetchResponse(_) => "KernelPlannerFetchResponse",
        IpcMessage::WitnessSubmission(_)          => "WitnessSubmission",
        IpcMessage::WitnessAck { .. }             => "WitnessAck",
        IpcMessage::OperatorRequest(_)            => "OperatorRequest",
        IpcMessage::OperatorResponse(_)           => "OperatorResponse",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex;

    /// In-memory transport stub for the kernel-mediated
    /// round-trip tests below.
    #[derive(Debug)]
    struct StubTransport {
        response:    Mutex<Option<PlannerFetchResponse>>,
        last_url:    Mutex<Option<String>>,
        last_method: Mutex<Option<String>>,
        last_body:   Mutex<Option<Vec<u8>>>,
    }

    impl StubTransport {
        fn new(response: PlannerFetchResponse) -> Self {
            Self {
                response:    Mutex::new(Some(response)),
                last_url:    Mutex::new(None),
                last_method: Mutex::new(None),
                last_body:   Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl KernelTransport for StubTransport {
        async fn request(
            &self,
            outbound: &IpcMessage,
        ) -> Result<IpcMessage, TransportError> {
            if let IpcMessage::PlannerFetchRequest(req) = outbound {
                *self.last_url.lock().await    = Some(req.url.clone());
                *self.last_method.lock().await = Some(req.method.clone());
                *self.last_body.lock().await   = Some(req.body_bytes.clone());
            }
            let resp = self
                .response
                .lock()
                .await
                .take()
                .expect("StubTransport: only one round-trip pre-staged");
            Ok(IpcMessage::KernelPlannerFetchResponse(resp))
        }
    }

    #[tokio::test]
    async fn kernel_mediated_round_trip_preserves_url_and_body() {
        let response = PlannerFetchResponse {
            request_id:  Uuid::nil(),
            status_code: Some(200),
            headers:     vec![("content-type".into(), "application/json".into())],
            body_bytes:  Some(b"{\"ok\":true}".to_vec()),
            latency_ms:  10,
            error:       None,
        };
        let stub    = Arc::new(StubTransport::new(response));
        let fetcher = KernelMediatedHttpFetch::new(
            stub.clone() as Arc<dyn KernelTransport>,
            "tok-fixture",
        );
        let resp = fetcher
            .fetch(HttpFetchRequest {
                url:     "https://example.test/api",
                method:  "POST",
                headers: vec![("content-type", "application/json".to_owned())],
                body:    b"{\"hi\":1}".to_vec(),
                timeout: Duration::from_secs(30),
            })
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"{\"ok\":true}");
        assert_eq!(stub.last_url.lock().await.as_deref(), Some("https://example.test/api"));
        assert_eq!(stub.last_method.lock().await.as_deref(), Some("POST"));
        assert_eq!(
            stub.last_body.lock().await.as_deref(),
            Some(b"{\"hi\":1}".as_ref()),
        );
    }

    #[tokio::test]
    async fn kernel_mediated_timeout_surfaces_as_timeout_error() {
        let response = PlannerFetchResponse {
            request_id:  Uuid::nil(),
            status_code: None,
            headers:     vec![],
            body_bytes:  None,
            latency_ms:  10,
            error:       Some("TimeoutExceeded".to_owned()),
        };
        let stub    = Arc::new(StubTransport::new(response));
        let fetcher = KernelMediatedHttpFetch::new(stub as Arc<dyn KernelTransport>, "tok");
        let err = fetcher
            .fetch(HttpFetchRequest {
                url:     "https://example.test/api",
                method:  "POST",
                headers: vec![],
                body:    Vec::new(),
                timeout: Duration::from_secs(30),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, HttpFetchError::Timeout(_)));
    }

    #[tokio::test]
    async fn kernel_mediated_gateway_unavailable_surfaces_as_transport_error() {
        let response = PlannerFetchResponse {
            request_id:  Uuid::nil(),
            status_code: None,
            headers:     vec![],
            body_bytes:  None,
            latency_ms:  10,
            error:       Some("GatewayUnavailable".to_owned()),
        };
        let stub    = Arc::new(StubTransport::new(response));
        let fetcher = KernelMediatedHttpFetch::new(stub as Arc<dyn KernelTransport>, "tok");
        let err = fetcher
            .fetch(HttpFetchRequest {
                url:     "https://example.test/api",
                method:  "POST",
                headers: vec![],
                body:    Vec::new(),
                timeout: Duration::from_secs(30),
            })
            .await
            .unwrap_err();
        match err {
            HttpFetchError::Transport(msg) => assert!(msg.contains("GatewayUnavailable")),
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn debug_does_not_print_session_token() {
        let stub    = Arc::new(StubTransport::new(PlannerFetchResponse {
            request_id:  Uuid::nil(),
            status_code: Some(200),
            headers:     vec![],
            body_bytes:  Some(Vec::new()),
            latency_ms:  0,
            error:       None,
        }));
        let fetcher = KernelMediatedHttpFetch::new(
            stub as Arc<dyn KernelTransport>,
            "supersecrettoken",
        );
        let dbg = format!("{fetcher:?}");
        assert!(!dbg.contains("supersecrettoken"), "session token leaked into Debug output");
    }
}
