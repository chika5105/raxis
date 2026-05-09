//! V2_GAPS §C2 — per-provider circuit breaker (BLOCKER closure).
//!
//! Without this module, [`FallbackModelClient`] is **sticky on
//! failure**: once a primary provider starts failing the chain falls
//! through to the secondary and stays there even after the primary
//! recovers, because every subsequent dispatch is paid in full
//! against the failing primary before the fallback fires. That is
//! double cost (the primary attempts every time) and double latency
//! (the primary's full retry budget burns before the secondary is
//! even tried).
//!
//! The circuit breaker tracks per-provider consecutive failures. When
//! the threshold trips, the circuit **opens** and the
//! [`CircuitBreakerModelClient`] short-circuits with the last error
//! without making any upstream call. After `open_duration` elapses,
//! the circuit enters **half-open**: ONE probe is admitted; success
//! closes the circuit, failure re-opens it for another
//! `open_duration`.
//!
//! Wired through the same trait as [`RetryingModelClient`] /
//! [`FallbackModelClient`] so `BootContext::main` can compose:
//!
//! ```text
//! Fallback[
//!   Circuit[Retrying[AnthropicClient]],
//!   Circuit[Retrying[OpenAiClient]],
//!   Circuit[Retrying[BedrockClient]],
//! ]
//! ```
//!
//! ## Why a separate wrapper (vs. baking it into `Fallback`)
//!
//! Two reasons.
//!
//! 1. **Per-provider state.** The breaker MUST be 1:1 with a single
//!    upstream. A `Fallback`-internal breaker would force a single
//!    breaker for the chain, defeating the purpose (the chain
//!    succeeds via secondary while the primary's rate is "fine"
//!    overall).
//! 2. **Composability.** A planner binary that runs single-provider
//!    (Anthropic-only) STILL benefits from a breaker (drop the
//!    upstream call when 5 consecutive failures land in a 60 s
//!    window), even though there's no fallback chain. Wrapping each
//!    provider in its own breaker makes the chain optional.
//!
//! ## Semantics — pinned by `provider-failure-handling.md §6`
//!
//! | State        | Behaviour                                        |
//! |--------------|--------------------------------------------------|
//! | `Closed`     | Pass through; reset failure counter on success.  |
//! | `Open`       | Short-circuit with `last_err.clone()` (no upstream call). After `open_duration`, transition to `HalfOpen`. |
//! | `HalfOpen`   | Admit ONE probe. Success → `Closed`; failure → `Open` for another `open_duration`. While the probe is in flight, additional dispatches short-circuit as if `Open`. |
//!
//! ## What counts as a failure?
//!
//! Only retryable errors trip the breaker. A non-retryable 4xx is
//! the operator's bug, not the provider's outage; counting it would
//! open the circuit on a malformed request and starve later
//! well-formed traffic of the same provider. We use
//! [`is_retryable`] from `crate::retry` for the classification —
//! same predicate the retry shell uses, so the breaker and the
//! retry budget agree on what "transient" means.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::model::{MessageRequest, MessageResponse, ModelClient, ModelError};
use crate::retry::is_retryable;

// ---------------------------------------------------------------------------
// CircuitConfig
// ---------------------------------------------------------------------------

/// Per-provider circuit-breaker knobs.
#[derive(Debug, Clone)]
pub struct CircuitConfig {
    /// Consecutive retryable failures that flip `Closed` → `Open`.
    /// V2 default 5, matching the kernel-side sidecar breaker
    /// (`notifications/handler/sidecar.rs`) so operators only need
    /// to memorise one number.
    pub failure_threshold: u32,
    /// How long the circuit stays open before admitting a probe.
    /// V2 default 60 s.
    pub open_duration: Duration,
}

impl CircuitConfig {
    /// Production default: 5 consecutive failures opens; 60 s open
    /// before half-open probe. Mirrors the sidecar breaker.
    pub fn production_default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration:     Duration::from_secs(60),
        }
    }

    /// Test-tuned: 2 failures, 50 ms open. Lets unit tests drive
    /// state transitions without sleeping for a minute.
    pub fn for_tests() -> Self {
        Self {
            failure_threshold: 2,
            open_duration:     Duration::from_millis(50),
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitState
// ---------------------------------------------------------------------------

/// Three-state circuit breaker, observable for `raxis status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Pass through normally.
    Closed   = 0,
    /// Refuse all dispatches; transition to `HalfOpen` after the
    /// open-duration elapses.
    Open     = 1,
    /// Admit one probe. Success closes; failure re-opens.
    HalfOpen = 2,
}

impl CircuitState {
    fn from_u8(b: u8) -> Self {
        match b {
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }
    /// Stable wire short-string for `raxis status` JSON.
    pub fn as_str(&self) -> &'static str {
        match self {
            CircuitState::Closed   => "closed",
            CircuitState::Open     => "circuit_open",
            CircuitState::HalfOpen => "half_open",
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitBreakerModelClient
// ---------------------------------------------------------------------------

/// `ModelClient` adaptor that short-circuits when the inner client
/// has been failing in a row.
///
/// Wraps any `Arc<dyn ModelClient>` (typically a
/// [`RetryingModelClient`]) so the retry shell runs first, then the
/// breaker observes the *post-retry* failure as a single
/// "this provider is unhealthy" signal.
pub struct CircuitBreakerModelClient {
    inner:  Arc<dyn ModelClient>,
    config: CircuitConfig,
    /// Provider-shaped label used in log lines. Operators see this
    /// in stderr when the circuit transitions, so it MUST be a
    /// human-readable name (`"anthropic"`, `"openai"`, …) not a UUID.
    label:  String,

    state: AtomicU8,
    consecutive_failures: AtomicU64,
    /// When the circuit was opened (epoch nanos via
    /// `Instant::elapsed_since(epoch_origin)`). Used only to compute
    /// the half-open transition; persistence across kernel restarts
    /// is not required (a fresh boot starts every breaker `Closed`,
    /// which is the safe default).
    opened_at_unix_ms: AtomicU64,
    /// Last seen retryable error — replayed verbatim on
    /// short-circuit so the caller's error path doesn't have to
    /// special-case `CircuitOpen`. Held under a mutex because
    /// `ModelError` is not `Copy`.
    last_err: Mutex<Option<ModelError>>,
    /// Half-open probe-admission gate: `compare_exchange`'s on this
    /// from `false → true` to mint exactly one in-flight probe at
    /// a time. Reset to `false` when the probe completes (success
    /// closes; failure opens).
    half_open_probe_in_flight: AtomicU8,
}

impl CircuitBreakerModelClient {
    /// Wrap `inner` with a breaker labelled `label`.
    pub fn new(
        inner:  Arc<dyn ModelClient>,
        label:  impl Into<String>,
        config: CircuitConfig,
    ) -> Self {
        Self {
            inner,
            config,
            label: label.into(),
            state: AtomicU8::new(CircuitState::Closed as u8),
            consecutive_failures: AtomicU64::new(0),
            opened_at_unix_ms: AtomicU64::new(0),
            last_err: Mutex::new(None),
            half_open_probe_in_flight: AtomicU8::new(0),
        }
    }

    /// Snapshot for `raxis status` / observability.
    pub fn snapshot(&self) -> CircuitSnapshot {
        CircuitSnapshot {
            label: self.label.clone(),
            state: CircuitState::from_u8(self.state.load(Ordering::Acquire)),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
        }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Inspect the circuit and return how the next dispatch should
    /// flow. Mutates Open → HalfOpen lazily on the observation side
    /// so we don't need a background timer.
    fn admit(&self) -> Admit {
        let s = CircuitState::from_u8(self.state.load(Ordering::Acquire));
        match s {
            CircuitState::Closed => Admit::Pass,
            CircuitState::HalfOpen => self.try_acquire_probe(),
            CircuitState::Open => {
                let now = Self::now_ms();
                let opened = self.opened_at_unix_ms.load(Ordering::Relaxed);
                if now.saturating_sub(opened) >= self.config.open_duration.as_millis() as u64 {
                    // Transition Open → HalfOpen. Lose the CAS race?
                    // Other observers also see HalfOpen on next load
                    // and try_acquire_probe gates probe minting.
                    let _ = self.state.compare_exchange(
                        CircuitState::Open as u8,
                        CircuitState::HalfOpen as u8,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    self.try_acquire_probe()
                } else {
                    Admit::ShortCircuit
                }
            }
        }
    }

    fn try_acquire_probe(&self) -> Admit {
        match self.half_open_probe_in_flight.compare_exchange(
            0, 1, Ordering::AcqRel, Ordering::Acquire,
        ) {
            Ok(_)  => Admit::Probe,
            Err(_) => Admit::ShortCircuit,
        }
    }

    fn release_probe(&self) {
        self.half_open_probe_in_flight.store(0, Ordering::Release);
    }

    fn record_success(&self) {
        let prev = CircuitState::from_u8(self.state.load(Ordering::Acquire));
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.state.store(CircuitState::Closed as u8, Ordering::Release);
        self.opened_at_unix_ms.store(0, Ordering::Relaxed);
        if !matches!(prev, CircuitState::Closed) {
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"CircuitClosed\",\
                 \"provider\":\"{}\"}}",
                self.label,
            );
        }
        if let Ok(mut g) = self.last_err.lock() {
            *g = None;
        }
    }

    fn record_failure(&self, err: ModelError) {
        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut g) = self.last_err.lock() {
            *g = Some(clone_model_error(&err));
        }
        if n >= self.config.failure_threshold as u64 {
            self.opened_at_unix_ms.store(Self::now_ms(), Ordering::Relaxed);
            let prev = self.state.swap(CircuitState::Open as u8, Ordering::AcqRel);
            if prev != CircuitState::Open as u8 {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"CircuitOpened\",\
                     \"provider\":\"{}\",\"consecutive_failures\":{}}}",
                    self.label, n,
                );
            }
        }
    }

    fn cloned_last_err(&self) -> ModelError {
        self.last_err
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(clone_model_error))
            .unwrap_or_else(|| ModelError::Transport(format!(
                "circuit_open[{}]: provider rejected", self.label,
            )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admit {
    /// Closed — pass through.
    Pass,
    /// HalfOpen — single probe admitted.
    Probe,
    /// Open or another probe is in flight — short-circuit.
    ShortCircuit,
}

#[async_trait]
impl ModelClient for CircuitBreakerModelClient {
    async fn create_message(
        &self,
        req: &MessageRequest,
    ) -> Result<MessageResponse, ModelError> {
        match self.admit() {
            Admit::ShortCircuit => return Err(self.cloned_last_err()),
            Admit::Pass | Admit::Probe => {}
        }
        let was_probe = matches!(
            CircuitState::from_u8(self.state.load(Ordering::Acquire)),
            CircuitState::HalfOpen,
        );
        let result = self.inner.create_message(req).await;
        if was_probe { self.release_probe(); }
        match result {
            Ok(resp) => {
                self.record_success();
                Ok(resp)
            }
            Err(err) => {
                if is_retryable(&err) {
                    let cloned = clone_model_error(&err);
                    self.record_failure(cloned);
                }
                Err(err)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn clone_model_error(e: &ModelError) -> ModelError {
    match e {
        ModelError::Transport(s) => ModelError::Transport(s.clone()),
        ModelError::Timeout(d)   => ModelError::Timeout(*d),
        ModelError::Upstream { status, body } => ModelError::Upstream {
            status: *status, body: body.clone(),
        },
        ModelError::Json(s)      => ModelError::Json(s.clone()),
    }
}

/// Snapshot for `raxis status` / observability.
#[derive(Debug, Clone)]
pub struct CircuitSnapshot {
    /// Provider label (e.g. `"anthropic"`).
    pub label: String,
    /// Current state.
    pub state: CircuitState,
    /// Consecutive retryable failures since last success.
    pub consecutive_failures: u64,
}

// Suppress unused-import warning when no callers reach Instant.
#[allow(dead_code)]
const _UNUSED_INSTANT: Option<Instant> = None;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ContentBlock, MessageResponse, Usage};
    use std::sync::Mutex as StdMutex;

    fn ok_response() -> MessageResponse {
        MessageResponse {
            id:    "msg-ok".into(),
            kind:  "message".into(),
            role:  "assistant".into(),
            content: vec![ContentBlock::Text { text: "ok".into() }],
            stop_reason: Some("end_turn".into()),
            usage: Usage::default(),
            model: "claude-test".into(),
        }
    }

    fn empty_request() -> MessageRequest {
        MessageRequest {
            model:      "claude-test".into(),
            max_tokens: 8,
            system:     None,
            messages:   vec![],
            tools:      vec![],
            temperature: None,
        }
    }

    /// Test fake whose call results are scripted.
    struct ScriptedClient {
        script: StdMutex<Vec<Result<MessageResponse, ModelError>>>,
        calls:  AtomicU64,
    }

    impl ScriptedClient {
        fn new(script: Vec<Result<MessageResponse, ModelError>>) -> Self {
            Self { script: StdMutex::new(script), calls: AtomicU64::new(0) }
        }
        fn call_count(&self) -> u64 { self.calls.load(Ordering::Relaxed) }
    }

    #[async_trait]
    impl ModelClient for ScriptedClient {
        async fn create_message(
            &self,
            _req: &MessageRequest,
        ) -> Result<MessageResponse, ModelError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut g = self.script.lock().unwrap();
            if g.is_empty() {
                return Err(ModelError::Transport("script exhausted".into()));
            }
            g.remove(0)
        }
    }

    fn err_503() -> ModelError {
        ModelError::Upstream { status: 503, body: "outage".into() }
    }

    fn err_400() -> ModelError {
        ModelError::Upstream { status: 400, body: "bad".into() }
    }

    #[tokio::test]
    async fn closed_circuit_passes_calls_through() {
        let inner = Arc::new(ScriptedClient::new(vec![Ok(ok_response())]));
        let breaker = CircuitBreakerModelClient::new(
            Arc::clone(&inner) as Arc<dyn ModelClient>,
            "anthropic",
            CircuitConfig::for_tests(),
        );
        let resp = breaker.create_message(&empty_request()).await.unwrap();
        assert_eq!(resp.id, "msg-ok");
        assert_eq!(inner.call_count(), 1);
        assert_eq!(breaker.snapshot().state, CircuitState::Closed);
    }

    #[tokio::test]
    async fn opens_after_threshold_consecutive_retryable_failures() {
        let inner = Arc::new(ScriptedClient::new(vec![
            Err(err_503()),
            Err(err_503()),
            Ok(ok_response()), // would succeed if breaker admitted
        ]));
        let breaker = CircuitBreakerModelClient::new(
            Arc::clone(&inner) as Arc<dyn ModelClient>,
            "anthropic",
            CircuitConfig::for_tests(), // threshold=2
        );
        // 1st failure
        assert!(breaker.create_message(&empty_request()).await.is_err());
        // 2nd failure → opens
        assert!(breaker.create_message(&empty_request()).await.is_err());
        assert_eq!(breaker.snapshot().state, CircuitState::Open);
        // 3rd dispatch — short-circuits without calling the inner
        let err = breaker.create_message(&empty_request()).await.unwrap_err();
        match err {
            ModelError::Upstream { status, .. } => assert_eq!(status, 503),
            other => panic!("expected last 503, got {other:?}"),
        }
        assert_eq!(inner.call_count(), 2,
            "open circuit must NOT call upstream a 3rd time");
    }

    #[tokio::test]
    async fn non_retryable_errors_do_not_count_toward_threshold() {
        let inner = Arc::new(ScriptedClient::new(vec![
            Err(err_400()),
            Err(err_400()),
            Err(err_400()),
        ]));
        let breaker = CircuitBreakerModelClient::new(
            Arc::clone(&inner) as Arc<dyn ModelClient>,
            "anthropic",
            CircuitConfig::for_tests(), // threshold=2
        );
        for _ in 0..3 {
            assert!(breaker.create_message(&empty_request()).await.is_err());
        }
        // Despite 3 failures, none were retryable, so the breaker
        // is still Closed.
        assert_eq!(breaker.snapshot().state, CircuitState::Closed);
        assert_eq!(inner.call_count(), 3);
    }

    #[tokio::test]
    async fn half_open_probe_closes_circuit_on_success() {
        let inner = Arc::new(ScriptedClient::new(vec![
            Err(err_503()),
            Err(err_503()),
            Ok(ok_response()), // probe succeeds
            Ok(ok_response()),
        ]));
        let cfg = CircuitConfig::for_tests(); // open_duration=50ms
        let breaker = CircuitBreakerModelClient::new(
            Arc::clone(&inner) as Arc<dyn ModelClient>,
            "anthropic",
            cfg.clone(),
        );
        // Drive to Open
        let _ = breaker.create_message(&empty_request()).await;
        let _ = breaker.create_message(&empty_request()).await;
        assert_eq!(breaker.snapshot().state, CircuitState::Open);

        // Wait past open_duration so the next admit transitions to HalfOpen.
        tokio::time::sleep(cfg.open_duration + Duration::from_millis(20)).await;

        // Probe call — succeeds — circuit closes.
        let resp = breaker.create_message(&empty_request()).await.unwrap();
        assert_eq!(resp.id, "msg-ok");
        assert_eq!(breaker.snapshot().state, CircuitState::Closed);

        // Subsequent calls pass through normally.
        let resp = breaker.create_message(&empty_request()).await.unwrap();
        assert_eq!(resp.id, "msg-ok");
    }

    #[tokio::test]
    async fn half_open_probe_failure_re_opens_circuit() {
        let inner = Arc::new(ScriptedClient::new(vec![
            Err(err_503()),
            Err(err_503()),
            Err(err_503()), // probe fails
        ]));
        let cfg = CircuitConfig::for_tests();
        let breaker = CircuitBreakerModelClient::new(
            Arc::clone(&inner) as Arc<dyn ModelClient>,
            "anthropic",
            cfg.clone(),
        );
        let _ = breaker.create_message(&empty_request()).await;
        let _ = breaker.create_message(&empty_request()).await;
        tokio::time::sleep(cfg.open_duration + Duration::from_millis(20)).await;

        // Probe fails; circuit re-opens (state stays Open) AND the
        // failure counter increments past threshold again. We
        // reset record_failure path: counter does not reset on
        // probe failure, so it's still > threshold and remains
        // Open.
        assert!(breaker.create_message(&empty_request()).await.is_err());
        assert_eq!(breaker.snapshot().state, CircuitState::Open);
    }

    #[test]
    fn state_wire_strings_are_stable() {
        assert_eq!(CircuitState::Closed.as_str(),   "closed");
        assert_eq!(CircuitState::Open.as_str(),     "circuit_open");
        assert_eq!(CircuitState::HalfOpen.as_str(), "half_open");
    }
}
