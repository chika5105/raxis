//! V2_GAPS §C2 — per-provider circuit breaker (BLOCKER closure).
//!
//! Without this module, `FallbackModelClient` is **sticky on
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
//! Wired through the same trait as `RetryingModelClient` /
//! `FallbackModelClient` so `BootContext::main` can compose:
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
use std::time::Duration;

use async_trait::async_trait;

use crate::model::{MessageRequest, MessageResponse, ModelClient, ModelError};
use crate::retry::is_retryable;

// ---------------------------------------------------------------------------
// CircuitRow — snapshot of a single (provider, model) breaker row.
// ---------------------------------------------------------------------------

/// Snapshot of a single circuit-breaker row.
///
/// Returned by every `CircuitStore` mutation so the caller always sees
/// the post-mutation state without a separate read. Fields mirror the
/// `provider_circuit_state` SQLite table (migration 15,
/// `provider-failure-handling.md §6.4`).
#[derive(Debug, Clone)]
pub struct CircuitRow {
    /// Provider id (`anthropic`, `openai`, …) the row applies to.
    pub provider: String,
    /// Model key under that provider (e.g. `claude-3-5-sonnet`).
    pub model: String,
    /// Current circuit state (`Closed | Open | HalfOpen`).
    pub state: CircuitState,
    /// Monotonic count of consecutive `record_failure` calls since
    /// the last `record_success` (or row insert). Resets to `0` on
    /// success.
    pub consecutive_failures: u64,
    /// Stringified `failure_kind` of the most recent failure (e.g.
    /// `transport`, `timeout`, `upstream:5xx`). `None` until the
    /// first failure.
    pub last_failure_kind: Option<String>,
    /// HTTP status code of the most recent failure when known
    /// (only populated for `Upstream` failures). `None` for
    /// transport/timeout failures.
    pub last_failure_http_code: Option<u16>,
    /// Unix-millis timestamp at which the row last transitioned
    /// from `Closed`/`HalfOpen` to `Open`. `None` while the row
    /// is `Closed` and has never opened.
    pub opened_at_ms: Option<u64>,
    /// Unix-millis timestamp at which the current `Open` window
    /// expires (i.e. the next probe is admissible). `None` when
    /// not in `Open`.
    pub open_expires_at_ms: Option<u64>,
    /// `true` while a `HalfOpen` probe is in flight; blocks any
    /// concurrent probe from racing.
    pub half_open_inflight: bool,
    /// Unix-millis timestamp of the most recent `record_success`.
    /// `None` until the first success.
    pub last_success_at_ms: Option<u64>,
    /// Unix-millis timestamp of the most recent state transition,
    /// regardless of direction. Used by observability snapshots.
    pub last_state_change_at_ms: u64,
}

impl CircuitRow {
    /// Convenience: a fresh `Closed` row for a (provider, model) pair
    /// that has never been seen before (no row in the store).
    pub fn default_closed(provider: &str, model: &str) -> Self {
        let now = now_ms();
        Self {
            provider: provider.to_owned(),
            model: model.to_owned(),
            state: CircuitState::Closed,
            consecutive_failures: 0,
            last_failure_kind: None,
            last_failure_http_code: None,
            opened_at_ms: None,
            open_expires_at_ms: None,
            half_open_inflight: false,
            last_success_at_ms: None,
            last_state_change_at_ms: now,
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitStore — trait abstracting breaker state persistence.
// ---------------------------------------------------------------------------

/// Abstraction over circuit-breaker state persistence.
///
/// Two implementations ship with RAXIS V2:
///
/// * **`InMemoryCircuitStore`** (this crate) — in-process atomics;
///   used by unit tests and any deployment that doesn't need
///   persistence across restarts.
/// * **`SqliteCircuitStore`** (kernel crate) — backed by the
///   `provider_circuit_state` table in `kernel.db`. Every state
///   mutation executes inside a `BEGIN IMMEDIATE` transaction that
///   also inserts a `CircuitBreakerStateChanged` audit event
///   (INV-PROVIDER-08).
///
/// The trait is `Send + Sync` so it can be shared across tokio tasks.
#[async_trait]
pub trait CircuitStore: Send + Sync {
    /// Read the current state for `(provider, model)`.
    ///
    /// Returns a default `Closed` row if no entry exists yet.
    async fn load(&self, provider: &str, model: &str) -> CircuitRow;

    /// Atomically record a retryable failure.
    ///
    /// Increments `consecutive_failures`. If the new count reaches
    /// `config.failure_threshold`, transitions to `Open` and stamps
    /// `opened_at_ms` / `open_expires_at_ms`.
    ///
    /// Returns the post-mutation row.
    async fn record_failure(
        &self,
        provider: &str,
        model: &str,
        failure_kind: &str,
        http_code: Option<u16>,
        config: &CircuitConfig,
    ) -> CircuitRow;

    /// Atomically record a success.
    ///
    /// Resets `consecutive_failures` to 0. If the previous state was
    /// `HalfOpen`, transitions to `Closed`.
    ///
    /// Returns the post-mutation row.
    async fn record_success(&self, provider: &str, model: &str) -> CircuitRow;

    /// Try to acquire the half-open probe slot (CAS 0 → 1).
    ///
    /// Returns `true` if this caller won the slot and should dispatch
    /// a probe. Returns `false` if another caller already holds the
    /// slot (the current dispatch should short-circuit).
    async fn try_acquire_probe(&self, provider: &str, model: &str) -> bool;

    /// Release the half-open probe slot (set back to 0).
    ///
    /// Called after the probe attempt completes, regardless of outcome.
    async fn release_probe(&self, provider: &str, model: &str);

    /// Lazily promote `Open → HalfOpen` if `open_expires_at_ms` has
    /// elapsed. No-op if the state is not `Open` or the window hasn't
    /// expired yet.
    ///
    /// Returns the post-promotion row (which may be unchanged).
    async fn maybe_promote(&self, provider: &str, model: &str) -> CircuitRow;

    /// Manual operator reset: force the breaker to `Closed`.
    ///
    /// Resets `consecutive_failures`, clears `opened_at_ms`, and
    /// (on the SQLite impl) emits a `CircuitBreakerStateChanged`
    /// audit event with `trigger = "ManualReset"`.
    ///
    /// Returns the post-reset row.
    async fn manual_reset(&self, provider: &str, model: &str, operator: &str) -> CircuitRow;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Current wall-clock time in milliseconds since UNIX epoch.
///
/// Used by both in-memory and SQLite circuit stores for timestamping
/// state transitions. Monotonicity is not guaranteed (NTP can adjust
/// the clock backward); the circuit breaker tolerates this because
/// the `open_duration` window is advisory, not a correctness boundary.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

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
            open_duration: Duration::from_secs(60),
        }
    }

    /// Test-tuned: 2 failures, 50 ms open. Lets unit tests drive
    /// state transitions without sleeping for a minute.
    pub fn for_tests() -> Self {
        Self {
            failure_threshold: 2,
            open_duration: Duration::from_millis(50),
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitState — type alias to the canonical enum in raxis-types.
// ---------------------------------------------------------------------------

/// Re-export the canonical circuit breaker state enum from `raxis-types`.
/// All SQL column values and audit event payloads use
/// `CircuitBreakerState::as_sql_str()` — there is exactly one source of
/// truth for the wire-stable strings.
pub type CircuitState = raxis_types::CircuitBreakerState;

/// Mapping from atomic-stored `u8` discriminant to enum.
/// Used only by `InMemoryCircuitStore` (test backend).
fn circuit_state_from_u8(b: u8) -> CircuitState {
    match b {
        1 => CircuitState::Open,
        2 => CircuitState::HalfOpen,
        _ => CircuitState::Closed,
    }
}

/// Mapping from enum to atomic-stored `u8` discriminant.
fn circuit_state_to_u8(s: CircuitState) -> u8 {
    match s {
        CircuitState::Closed => 0,
        CircuitState::Open => 1,
        CircuitState::HalfOpen => 2,
    }
}

/// Stable wire short-string for `raxis status` JSON output.
/// Distinct from `CircuitState::as_sql_str()` which is PascalCase
/// for the SQLite column — this is the lowercase form the CLI
/// emits to JSON consumers.
pub fn circuit_state_wire_str(s: CircuitState) -> &'static str {
    match s {
        CircuitState::Closed => "closed",
        CircuitState::Open => "circuit_open",
        CircuitState::HalfOpen => "half_open",
    }
}

// ---------------------------------------------------------------------------
// InMemoryCircuitStore — test / single-process implementation.
// ---------------------------------------------------------------------------

use std::collections::HashMap;

/// Per-(provider, model) in-memory state entry.
struct InMemoryEntry {
    state: AtomicU8,
    consecutive_failures: AtomicU64,
    opened_at_ms: AtomicU64,
    open_expires_at_ms: AtomicU64,
    half_open_inflight: AtomicU8,
    last_success_at_ms: AtomicU64,
    last_state_change_ms: AtomicU64,
    last_failure_kind: Mutex<Option<String>>,
    last_failure_http_code: Mutex<Option<u16>>,
}

impl InMemoryEntry {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(circuit_state_to_u8(CircuitState::Closed)),
            consecutive_failures: AtomicU64::new(0),
            opened_at_ms: AtomicU64::new(0),
            open_expires_at_ms: AtomicU64::new(0),
            half_open_inflight: AtomicU8::new(0),
            last_success_at_ms: AtomicU64::new(0),
            last_state_change_ms: AtomicU64::new(now_ms()),
            last_failure_kind: Mutex::new(None),
            last_failure_http_code: Mutex::new(None),
        }
    }

    fn snapshot(&self, provider: &str, model: &str) -> CircuitRow {
        CircuitRow {
            provider: provider.to_owned(),
            model: model.to_owned(),
            state: circuit_state_from_u8(self.state.load(Ordering::Acquire)),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            last_failure_kind: self.last_failure_kind.lock().ok().and_then(|g| g.clone()),
            last_failure_http_code: self.last_failure_http_code.lock().ok().and_then(|g| *g),
            opened_at_ms: {
                let v = self.opened_at_ms.load(Ordering::Relaxed);
                if v == 0 {
                    None
                } else {
                    Some(v)
                }
            },
            open_expires_at_ms: {
                let v = self.open_expires_at_ms.load(Ordering::Relaxed);
                if v == 0 {
                    None
                } else {
                    Some(v)
                }
            },
            half_open_inflight: self.half_open_inflight.load(Ordering::Relaxed) == 1,
            last_success_at_ms: {
                let v = self.last_success_at_ms.load(Ordering::Relaxed);
                if v == 0 {
                    None
                } else {
                    Some(v)
                }
            },
            last_state_change_at_ms: self.last_state_change_ms.load(Ordering::Relaxed),
        }
    }
}

/// In-process `CircuitStore` backed by atomics in a `HashMap`.
///
/// - No persistence across process restart (all breakers start `Closed`).
/// - No audit events emitted on state transitions.
/// - Suitable for unit tests and single-process deployments where
///   persistence is not required.
pub struct InMemoryCircuitStore {
    entries: Mutex<HashMap<(String, String), Arc<InMemoryEntry>>>,
}

impl Default for InMemoryCircuitStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCircuitStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn get_or_create(&self, provider: &str, model: &str) -> Arc<InMemoryEntry> {
        let mut map = self.entries.lock().unwrap();
        map.entry((provider.to_owned(), model.to_owned()))
            .or_insert_with(|| Arc::new(InMemoryEntry::new()))
            .clone()
    }
}

#[async_trait]
impl CircuitStore for InMemoryCircuitStore {
    async fn load(&self, provider: &str, model: &str) -> CircuitRow {
        self.get_or_create(provider, model)
            .snapshot(provider, model)
    }

    async fn record_failure(
        &self,
        provider: &str,
        model: &str,
        failure_kind: &str,
        http_code: Option<u16>,
        config: &CircuitConfig,
    ) -> CircuitRow {
        let e = self.get_or_create(provider, model);
        let n = e.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        if let Ok(mut g) = e.last_failure_kind.lock() {
            *g = Some(failure_kind.to_owned());
        }
        if let Ok(mut g) = e.last_failure_http_code.lock() {
            *g = http_code;
        }

        if n >= config.failure_threshold as u64 {
            let now = now_ms();
            let expires = now + config.open_duration.as_millis() as u64;
            e.opened_at_ms.store(now, Ordering::Relaxed);
            e.open_expires_at_ms.store(expires, Ordering::Relaxed);
            let prev = e
                .state
                .swap(circuit_state_to_u8(CircuitState::Open), Ordering::AcqRel);
            if prev != circuit_state_to_u8(CircuitState::Open) {
                e.last_state_change_ms.store(now, Ordering::Relaxed);
            }
        }

        e.snapshot(provider, model)
    }

    async fn record_success(&self, provider: &str, model: &str) -> CircuitRow {
        let e = self.get_or_create(provider, model);
        let prev = circuit_state_from_u8(e.state.load(Ordering::Acquire));
        e.consecutive_failures.store(0, Ordering::Relaxed);
        e.state
            .store(circuit_state_to_u8(CircuitState::Closed), Ordering::Release);
        e.opened_at_ms.store(0, Ordering::Relaxed);
        e.open_expires_at_ms.store(0, Ordering::Relaxed);
        e.last_success_at_ms.store(now_ms(), Ordering::Relaxed);
        if prev != CircuitState::Closed {
            e.last_state_change_ms.store(now_ms(), Ordering::Relaxed);
        }
        e.snapshot(provider, model)
    }

    async fn try_acquire_probe(&self, provider: &str, model: &str) -> bool {
        let e = self.get_or_create(provider, model);
        e.half_open_inflight
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    async fn release_probe(&self, provider: &str, model: &str) {
        let e = self.get_or_create(provider, model);
        e.half_open_inflight.store(0, Ordering::Release);
    }

    async fn maybe_promote(&self, provider: &str, model: &str) -> CircuitRow {
        let e = self.get_or_create(provider, model);
        let s = circuit_state_from_u8(e.state.load(Ordering::Acquire));
        if s == CircuitState::Open {
            let now = now_ms();
            let expires = e.open_expires_at_ms.load(Ordering::Relaxed);
            if expires > 0 && now >= expires {
                let _ = e.state.compare_exchange(
                    circuit_state_to_u8(CircuitState::Open),
                    circuit_state_to_u8(CircuitState::HalfOpen),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                e.last_state_change_ms.store(now, Ordering::Relaxed);
            }
        }
        e.snapshot(provider, model)
    }

    async fn manual_reset(&self, provider: &str, model: &str, _operator: &str) -> CircuitRow {
        let e = self.get_or_create(provider, model);
        let now = now_ms();
        e.consecutive_failures.store(0, Ordering::Relaxed);
        e.state
            .store(circuit_state_to_u8(CircuitState::Closed), Ordering::Release);
        e.opened_at_ms.store(0, Ordering::Relaxed);
        e.open_expires_at_ms.store(0, Ordering::Relaxed);
        e.half_open_inflight.store(0, Ordering::Release);
        e.last_state_change_ms.store(now, Ordering::Relaxed);
        e.snapshot(provider, model)
    }
}

// ---------------------------------------------------------------------------
// CircuitBreakerModelClient
// ---------------------------------------------------------------------------

/// `ModelClient` adaptor that short-circuits when the inner client
/// has been failing in a row.
///
/// State is delegated to an `Arc<dyn CircuitStore>`. In production
/// this is a `SqliteCircuitStore` (kernel-side, transactional with
/// audit); in tests it is an `InMemoryCircuitStore`.
pub struct CircuitBreakerModelClient {
    inner: Arc<dyn ModelClient>,
    config: CircuitConfig,
    store: Arc<dyn CircuitStore>,
    /// Provider key for the store lookup (e.g. `"anthropic"`).
    provider: String,
    /// Model key for the store lookup (e.g. `"claude-opus-4.7"`).
    model_key: String,
    /// Human-readable label for log lines.
    label: String,
    /// Last seen retryable error — replayed verbatim on short-circuit.
    last_err: Mutex<Option<ModelError>>,
}

impl CircuitBreakerModelClient {
    /// Wrap `inner` with a breaker backed by `store`.
    pub fn new(
        inner: Arc<dyn ModelClient>,
        store: Arc<dyn CircuitStore>,
        provider: impl Into<String>,
        model: impl Into<String>,
        label: impl Into<String>,
        config: CircuitConfig,
    ) -> Self {
        Self {
            inner,
            config,
            store,
            provider: provider.into(),
            model_key: model.into(),
            label: label.into(),
            last_err: Mutex::new(None),
        }
    }

    /// Convenience constructor for tests: creates an `InMemoryCircuitStore`
    /// internally so callers don't have to wire one up.
    pub fn new_in_memory(
        inner: Arc<dyn ModelClient>,
        label: impl Into<String>,
        config: CircuitConfig,
    ) -> Self {
        let label = label.into();
        Self::new(
            inner,
            Arc::new(InMemoryCircuitStore::new()),
            label.clone(),
            "default",
            label,
            config,
        )
    }

    /// Snapshot for `raxis status` / observability.
    pub async fn snapshot(&self) -> CircuitSnapshot {
        let row = self.store.load(&self.provider, &self.model_key).await;
        CircuitSnapshot {
            label: self.label.clone(),
            state: row.state,
            consecutive_failures: row.consecutive_failures,
        }
    }

    /// Inspect the circuit and determine dispatch flow.
    async fn admit(&self) -> Admit {
        let row = self.store.load(&self.provider, &self.model_key).await;
        match row.state {
            CircuitState::Closed => Admit::Pass,
            CircuitState::HalfOpen => {
                if self
                    .store
                    .try_acquire_probe(&self.provider, &self.model_key)
                    .await
                {
                    Admit::Probe
                } else {
                    Admit::ShortCircuit
                }
            }
            CircuitState::Open => {
                let promoted = self
                    .store
                    .maybe_promote(&self.provider, &self.model_key)
                    .await;
                if promoted.state == CircuitState::HalfOpen {
                    if self
                        .store
                        .try_acquire_probe(&self.provider, &self.model_key)
                        .await
                    {
                        Admit::Probe
                    } else {
                        Admit::ShortCircuit
                    }
                } else {
                    Admit::ShortCircuit
                }
            }
        }
    }

    fn cloned_last_err(&self) -> ModelError {
        self.last_err
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(clone_model_error))
            .unwrap_or_else(|| {
                ModelError::Transport(format!("circuit_open[{}]: provider rejected", self.label,))
            })
    }

    fn failure_kind(err: &ModelError) -> &'static str {
        match err {
            ModelError::Transport(_) => "Transport",
            ModelError::Timeout(_) => "Timeout",
            ModelError::Upstream { .. } => "Unavailable",
            ModelError::Json(_) => "Malformed",
        }
    }

    fn http_code(err: &ModelError) -> Option<u16> {
        match err {
            ModelError::Upstream { status, .. } => Some(*status),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admit {
    Pass,
    Probe,
    ShortCircuit,
}

#[async_trait]
impl ModelClient for CircuitBreakerModelClient {
    async fn create_message(&self, req: &MessageRequest) -> Result<MessageResponse, ModelError> {
        match self.admit().await {
            Admit::ShortCircuit => return Err(self.cloned_last_err()),
            Admit::Pass | Admit::Probe => {}
        }
        let row_before = self.store.load(&self.provider, &self.model_key).await;
        let was_probe = row_before.state == CircuitState::HalfOpen;

        let result = self.inner.create_message(req).await;

        if was_probe {
            self.store
                .release_probe(&self.provider, &self.model_key)
                .await;
        }

        match result {
            Ok(resp) => {
                self.store
                    .record_success(&self.provider, &self.model_key)
                    .await;
                if row_before.state != CircuitState::Closed {
                    eprintln!(
                        "{{\"level\":\"info\",\"event\":\"CircuitClosed\",\
                         \"provider\":\"{}\"}}",
                        self.label,
                    );
                }
                if let Ok(mut g) = self.last_err.lock() {
                    *g = None;
                }
                Ok(resp)
            }
            Err(err) => {
                if is_retryable(&err) {
                    if let Ok(mut g) = self.last_err.lock() {
                        *g = Some(clone_model_error(&err));
                    }
                    let row = self
                        .store
                        .record_failure(
                            &self.provider,
                            &self.model_key,
                            Self::failure_kind(&err),
                            Self::http_code(&err),
                            &self.config,
                        )
                        .await;
                    if row.state == CircuitState::Open && row_before.state != CircuitState::Open {
                        eprintln!(
                            "{{\"level\":\"warn\",\"event\":\"CircuitOpened\",\
                             \"provider\":\"{}\",\"consecutive_failures\":{}}}",
                            self.label, row.consecutive_failures,
                        );
                    }
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
        ModelError::Timeout(d) => ModelError::Timeout(*d),
        ModelError::Upstream { status, body } => ModelError::Upstream {
            status: *status,
            body: body.clone(),
        },
        ModelError::Json(s) => ModelError::Json(s.clone()),
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
            id: "msg-ok".into(),
            kind: "message".into(),
            role: "assistant".into(),
            content: vec![ContentBlock::Text { text: "ok".into() }],
            stop_reason: Some("end_turn".into()),
            usage: Usage::default(),
            model: "claude-test".into(),
        }
    }

    fn empty_request() -> MessageRequest {
        MessageRequest {
            model: "claude-test".into(),
            max_tokens: 8,
            ..MessageRequest::default()
        }
    }

    /// Test fake whose call results are scripted.
    struct ScriptedClient {
        script: StdMutex<Vec<Result<MessageResponse, ModelError>>>,
        calls: AtomicU64,
    }

    impl ScriptedClient {
        fn new(script: Vec<Result<MessageResponse, ModelError>>) -> Self {
            Self {
                script: StdMutex::new(script),
                calls: AtomicU64::new(0),
            }
        }
        fn call_count(&self) -> u64 {
            self.calls.load(Ordering::Relaxed)
        }
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
        ModelError::Upstream {
            status: 503,
            body: "outage".into(),
        }
    }

    fn err_400() -> ModelError {
        ModelError::Upstream {
            status: 400,
            body: "bad".into(),
        }
    }

    #[tokio::test]
    async fn closed_circuit_passes_calls_through() {
        let inner = Arc::new(ScriptedClient::new(vec![Ok(ok_response())]));
        let breaker = CircuitBreakerModelClient::new_in_memory(
            Arc::clone(&inner) as Arc<dyn ModelClient>,
            "anthropic",
            CircuitConfig::for_tests(),
        );
        let resp = breaker.create_message(&empty_request()).await.unwrap();
        assert_eq!(resp.id, "msg-ok");
        assert_eq!(inner.call_count(), 1);
        assert_eq!(breaker.snapshot().await.state, CircuitState::Closed);
    }

    #[tokio::test]
    async fn opens_after_threshold_consecutive_retryable_failures() {
        let inner = Arc::new(ScriptedClient::new(vec![
            Err(err_503()),
            Err(err_503()),
            Ok(ok_response()), // would succeed if breaker admitted
        ]));
        let breaker = CircuitBreakerModelClient::new_in_memory(
            Arc::clone(&inner) as Arc<dyn ModelClient>,
            "anthropic",
            CircuitConfig::for_tests(), // threshold=2
        );
        // 1st failure
        assert!(breaker.create_message(&empty_request()).await.is_err());
        // 2nd failure → opens
        assert!(breaker.create_message(&empty_request()).await.is_err());
        assert_eq!(breaker.snapshot().await.state, CircuitState::Open);
        // 3rd dispatch — short-circuits without calling the inner
        let err = breaker.create_message(&empty_request()).await.unwrap_err();
        match err {
            ModelError::Upstream { status, .. } => assert_eq!(status, 503),
            other => panic!("expected last 503, got {other:?}"),
        }
        assert_eq!(
            inner.call_count(),
            2,
            "open circuit must NOT call upstream a 3rd time"
        );
    }

    #[tokio::test]
    async fn non_retryable_errors_do_not_count_toward_threshold() {
        let inner = Arc::new(ScriptedClient::new(vec![
            Err(err_400()),
            Err(err_400()),
            Err(err_400()),
        ]));
        let breaker = CircuitBreakerModelClient::new_in_memory(
            Arc::clone(&inner) as Arc<dyn ModelClient>,
            "anthropic",
            CircuitConfig::for_tests(), // threshold=2
        );
        for _ in 0..3 {
            assert!(breaker.create_message(&empty_request()).await.is_err());
        }
        // Despite 3 failures, none were retryable, so the breaker
        // is still Closed.
        assert_eq!(breaker.snapshot().await.state, CircuitState::Closed);
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
        let breaker = CircuitBreakerModelClient::new_in_memory(
            Arc::clone(&inner) as Arc<dyn ModelClient>,
            "anthropic",
            cfg.clone(),
        );
        // Drive to Open
        let _ = breaker.create_message(&empty_request()).await;
        let _ = breaker.create_message(&empty_request()).await;
        assert_eq!(breaker.snapshot().await.state, CircuitState::Open);

        // Wait past open_duration so the next admit transitions to HalfOpen.
        tokio::time::sleep(cfg.open_duration + Duration::from_millis(20)).await;

        // Probe call — succeeds — circuit closes.
        let resp = breaker.create_message(&empty_request()).await.unwrap();
        assert_eq!(resp.id, "msg-ok");
        assert_eq!(breaker.snapshot().await.state, CircuitState::Closed);

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
        let breaker = CircuitBreakerModelClient::new_in_memory(
            Arc::clone(&inner) as Arc<dyn ModelClient>,
            "anthropic",
            cfg.clone(),
        );
        let _ = breaker.create_message(&empty_request()).await;
        let _ = breaker.create_message(&empty_request()).await;
        tokio::time::sleep(cfg.open_duration + Duration::from_millis(20)).await;

        // Probe fails; circuit re-opens.
        assert!(breaker.create_message(&empty_request()).await.is_err());
        assert_eq!(breaker.snapshot().await.state, CircuitState::Open);
    }

    #[test]
    fn state_wire_strings_are_stable() {
        assert_eq!(circuit_state_wire_str(CircuitState::Closed), "closed");
        assert_eq!(circuit_state_wire_str(CircuitState::Open), "circuit_open");
        assert_eq!(circuit_state_wire_str(CircuitState::HalfOpen), "half_open");
    }

    #[test]
    fn state_sql_strings_match_check_constraint() {
        assert_eq!(CircuitState::Closed.as_sql_str(), "Closed");
        assert_eq!(CircuitState::Open.as_sql_str(), "Open");
        assert_eq!(CircuitState::HalfOpen.as_sql_str(), "HalfOpen");
    }

    #[test]
    fn state_sql_round_trip() {
        for s in [
            CircuitState::Closed,
            CircuitState::Open,
            CircuitState::HalfOpen,
        ] {
            assert_eq!(CircuitState::from_sql_str(s.as_sql_str()), Some(s));
        }
        // Unknown values return None.
        assert_eq!(CircuitState::from_sql_str("garbage"), None);
    }

    #[test]
    fn state_sql_check_in_clause_matches_all_variants() {
        let clause = CircuitState::sql_check_in_clause();
        assert!(clause.contains("'Closed'"));
        assert!(clause.contains("'Open'"));
        assert!(clause.contains("'HalfOpen'"));
    }
}
