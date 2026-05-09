//! V2_GAPS §C2 — provider failure handling (MVP).
//!
//! Wraps any [`ModelClient`] in a retry/backoff/fallback shell so a
//! transient upstream failure (network blip, 429, 5xx) does NOT bubble
//! up as a hard `DispatchError::Model` in the planner's first turn.
//!
//! The full spec (`provider-failure-handling.md`, 130 KB) calls for
//! per-provider retry budgets, circuit breakers, partial-response
//! recovery for streaming, and a typed `ProviderExhausted` escalation
//! flow. V2 lands the **operator-grade default** — exponential backoff
//! with jitter, optional fallback to a secondary client chain — and
//! defers the rest to V3.
//!
//! ## What this module does
//!
//! 1. [`RetryConfig`] — per-provider retry knobs (max retries, base
//!    delay, multiplier, jitter, total deadline).
//! 2. [`RetryingModelClient`] — `ModelClient` adaptor that retries
//!    transient errors against ONE upstream, surfaces a structured
//!    `LastError` when the budget is exhausted.
//! 3. [`FallbackModelClient`] — vector of `Arc<dyn ModelClient>`
//!    tried in declaration order; used to compose the
//!    `Anthropic → OpenAI → Bedrock` chain the spec calls out.
//!
//! ## Retry semantics
//!
//! `ModelError` variants partition into retryable vs. non-retryable:
//!
//! | Variant                  | Retryable | Why                                    |
//! |---|---|---|
//! | `Transport(_)`           | yes       | DNS / TLS / connect refused: transient |
//! | `Timeout(_)`             | yes       | Network slowness: transient            |
//! | `Upstream { 408, 429, 5xx }` | yes   | Rate-limited / server-side flake       |
//! | `Upstream { 4xx (other) }` | NO     | Client error: retry will not help      |
//! | `Json(_)`                | NO        | Wire shape break: bug, not transient   |
//!
//! Backoff is `base_delay * multiplier^attempt` with `±jitter%`
//! uniform jitter applied per-attempt. The sleep is bounded by the
//! configured `total_deadline` so a runaway retry never blocks a turn
//! beyond the operator's expected wall-clock.
//!
//! ## Why a wrapper, not a built-in retry inside `AnthropicClient`
//!
//! The dispatch loop (`crate::dispatch`) is provider-agnostic; making
//! retry orthogonal lets a future `OpenAiClient` / `BedrockClient`
//! reuse the same backoff machinery without re-implementing it.
//! Tests can substitute a `MockModelClient` that fails N times, then
//! succeeds, and verify the wrapper without driving any real HTTP.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::model::{MessageRequest, MessageResponse, ModelClient, ModelError};

// ---------------------------------------------------------------------------
// RetryConfig
// ---------------------------------------------------------------------------

/// Per-provider retry knobs. The dispatch loop's parent deadline
/// (the policy-derived per-turn ceiling) bounds the total time the
/// retry shell may spend; this struct bounds the *number* of retries
/// and the *shape* of the backoff inside that ceiling.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts after the initial call. A
    /// total of `1 + max_retries` model invocations may run.
    pub max_retries:    u32,
    /// Base delay before the first retry. The actual sleep is
    /// `base_delay * multiplier^attempt + jitter`.
    pub base_delay:     Duration,
    /// Multiplicative factor for each successive attempt. `2.0` ⇒
    /// classic exponential backoff (1s → 2s → 4s → …). `1.0` ⇒
    /// constant delay.
    pub multiplier:     f32,
    /// Jitter percentage applied to each sleep — `0.25` means each
    /// sleep is uniformly drawn from `[0.75x, 1.25x]` of the
    /// computed delay. `0.0` ⇒ no jitter (deterministic; useful in
    /// tests).
    pub jitter:         f32,
    /// Hard wall-clock ceiling on the entire retry budget (the
    /// initial call's own latency plus all sleeps + retries).
    /// `None` ⇒ no per-shell ceiling (the dispatch loop's parent
    /// deadline is the only bound).
    pub total_deadline: Option<Duration>,
    /// Per-call HTTP timeout. The wrapped `ModelClient` may also
    /// have its own timeout (e.g. `AnthropicClient::with_request_timeout`);
    /// this is the OUTER bound applied via `tokio::time::timeout`
    /// around the `create_message(...)` future. `None` ⇒ no extra
    /// timeout (use the inner client's).
    pub call_timeout:   Option<Duration>,
}

impl RetryConfig {
    /// Sensible production default — operator-grade for a single
    /// Anthropic provider:
    ///
    /// * 3 retries (4 total calls)
    /// * 500 ms base delay, 2.0× multiplier, 25 % jitter
    /// * 90 s total ceiling, 60 s per-call timeout
    pub fn anthropic_default() -> Self {
        Self {
            max_retries:    3,
            base_delay:     Duration::from_millis(500),
            multiplier:     2.0,
            jitter:         0.25,
            total_deadline: Some(Duration::from_secs(90)),
            call_timeout:   Some(Duration::from_secs(60)),
        }
    }

    /// Test-friendly: no jitter, no per-call timeout, no total
    /// deadline. Useful for deterministic unit tests.
    pub fn deterministic_for_tests(max_retries: u32) -> Self {
        Self {
            max_retries,
            base_delay:     Duration::from_millis(0),
            multiplier:     1.0,
            jitter:         0.0,
            total_deadline: None,
            call_timeout:   None,
        }
    }
}

// ---------------------------------------------------------------------------
// Retryability classifier
// ---------------------------------------------------------------------------

/// Decide whether `err` should be retried. See module-level table.
pub fn is_retryable(err: &ModelError) -> bool {
    match err {
        ModelError::Transport(_) => true,
        ModelError::Timeout(_)   => true,
        ModelError::Upstream { status, .. } => {
            *status == 408                           // request timeout
            || *status == 429                        // rate-limited
            || *status == 425                        // too-early
            || (500..600).contains(status)
        }
        ModelError::Json(_) => false,
    }
}

// ---------------------------------------------------------------------------
// RetryingModelClient
// ---------------------------------------------------------------------------

/// `ModelClient` adapter that retries the inner client per
/// [`RetryConfig`] when an error is classified as retryable.
pub struct RetryingModelClient {
    inner:  Arc<dyn ModelClient>,
    config: RetryConfig,
}

impl RetryingModelClient {
    /// Wrap `inner` with the given retry policy.
    pub fn new(inner: Arc<dyn ModelClient>, config: RetryConfig) -> Self {
        Self { inner, config }
    }

    /// Compute the per-attempt backoff sleep. Public so tests can
    /// pin the shape across `multiplier` / `jitter` choices.
    pub fn backoff_for(attempt: u32, cfg: &RetryConfig) -> Duration {
        let base_secs = cfg.base_delay.as_secs_f64();
        let scaled = base_secs * (cfg.multiplier as f64).powi(attempt as i32);
        // Jitter draw: uniform in [1.0 - jitter, 1.0 + jitter]. We
        // use a tiny self-rolled LCG seeded from the nanosecond clock
        // to avoid pulling `rand` for one call.
        let jitter_factor = if cfg.jitter > 0.0 {
            let nanos = Instant::now().elapsed().as_nanos() as u64;
            let lcg   = nanos.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let unit  = (lcg as u32) as f64 / (u32::MAX as f64); // [0, 1)
            1.0 + (unit * 2.0 - 1.0) * cfg.jitter as f64
        } else { 1.0 };
        let secs = (scaled * jitter_factor).max(0.0);
        Duration::from_secs_f64(secs)
    }
}

#[async_trait]
impl ModelClient for RetryingModelClient {
    async fn create_message(
        &self,
        req: &MessageRequest,
    ) -> Result<MessageResponse, ModelError> {
        let started = Instant::now();
        let mut last_err: Option<ModelError> = None;

        for attempt in 0..=self.config.max_retries {
            // Total-deadline check BEFORE the call so a long-running
            // earlier attempt cannot push us over the ceiling.
            if let Some(d) = self.config.total_deadline {
                if started.elapsed() > d {
                    break;
                }
            }

            let call_fut = self.inner.create_message(req);
            let result = match self.config.call_timeout {
                Some(t) => match tokio::time::timeout(t, call_fut).await {
                    Ok(r)  => r,
                    Err(_) => Err(ModelError::Timeout(t)),
                },
                None => call_fut.await,
            };

            match result {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    if !is_retryable(&err) || attempt == self.config.max_retries {
                        return Err(err);
                    }
                    last_err = Some(err);
                    let sleep_for = Self::backoff_for(attempt, &self.config);
                    if let Some(d) = self.config.total_deadline {
                        let remaining = d.checked_sub(started.elapsed()).unwrap_or_default();
                        if remaining.is_zero() {
                            break;
                        }
                        let bounded = sleep_for.min(remaining);
                        tokio::time::sleep(bounded).await;
                    } else {
                        tokio::time::sleep(sleep_for).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| ModelError::Transport(
            "retry budget exhausted with no recorded error".to_owned(),
        )))
    }
}

// ---------------------------------------------------------------------------
// FallbackModelClient
// ---------------------------------------------------------------------------

/// `ModelClient` that walks a chain of inner clients in declaration
/// order, only falling through to the next on a *retryable*
/// [`ModelError`] from the previous one.
///
/// Wire this as the outermost shell when an operator declares a
/// multi-provider failover chain (e.g.
/// `[providers]` table with `fallback = ["openai", "bedrock"]`).
/// The first client should usually itself be a [`RetryingModelClient`]
/// so the within-provider transient retries happen before the
/// cross-provider fallback fires.
pub struct FallbackModelClient {
    chain: Vec<Arc<dyn ModelClient>>,
}

impl FallbackModelClient {
    /// Construct a fallback chain. Empty chain ⇒ every call fails
    /// with `ModelError::Transport("no providers configured")`.
    pub fn new(chain: Vec<Arc<dyn ModelClient>>) -> Self {
        Self { chain }
    }
}

#[async_trait]
impl ModelClient for FallbackModelClient {
    async fn create_message(
        &self,
        req: &MessageRequest,
    ) -> Result<MessageResponse, ModelError> {
        if self.chain.is_empty() {
            return Err(ModelError::Transport(
                "no providers configured".to_owned(),
            ));
        }
        let mut last: Option<ModelError> = None;
        for client in &self.chain {
            match client.create_message(req).await {
                Ok(resp) => return Ok(resp),
                Err(err) if is_retryable(&err) => {
                    last = Some(err);
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
        Err(last.unwrap_or_else(|| ModelError::Transport(
            "fallback chain exhausted with no recorded error".to_owned(),
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ContentBlock, MessageResponse, Usage};
    use std::sync::Mutex;

    fn ok_response() -> MessageResponse {
        MessageResponse {
            id:    "msg-ok".to_owned(),
            kind:  "message".to_owned(),
            role:  "assistant".to_owned(),
            content: vec![ContentBlock::Text {
                text: "ok".to_owned(),
            }],
            stop_reason: Some("end_turn".to_owned()),
            usage: Usage::default(),
            model: "claude-test".to_owned(),
        }
    }

    fn empty_request() -> MessageRequest {
        MessageRequest {
            model:      "claude-test".to_owned(),
            max_tokens: 8,
            system:     None,
            messages:   vec![],
            tools:      vec![],
            temperature: None,
        }
    }

    /// Test fake — a model client that fails N times, then succeeds.
    struct FailThenSucceed {
        remaining_fails: Mutex<u32>,
        err_factory:     Box<dyn Fn() -> ModelError + Send + Sync>,
    }

    #[async_trait]
    impl ModelClient for FailThenSucceed {
        async fn create_message(
            &self,
            _req: &MessageRequest,
        ) -> Result<MessageResponse, ModelError> {
            let mut g = self.remaining_fails.lock().unwrap();
            if *g > 0 {
                *g -= 1;
                return Err((self.err_factory)());
            }
            Ok(ok_response())
        }
    }

    #[test]
    fn classifier_is_retryable_for_transient_classes() {
        assert!(is_retryable(&ModelError::Transport("dns".into())));
        assert!(is_retryable(&ModelError::Timeout(Duration::from_secs(1))));
        assert!(is_retryable(&ModelError::Upstream { status: 429, body: "rate".into() }));
        assert!(is_retryable(&ModelError::Upstream { status: 503, body: "outage".into() }));
        assert!(is_retryable(&ModelError::Upstream { status: 500, body: "internal".into() }));
    }

    #[test]
    fn classifier_is_not_retryable_for_client_errors() {
        assert!(!is_retryable(&ModelError::Upstream { status: 400, body: "bad".into() }));
        assert!(!is_retryable(&ModelError::Upstream { status: 401, body: "auth".into() }));
        assert!(!is_retryable(&ModelError::Upstream { status: 404, body: "ne".into() }));
        assert!(!is_retryable(&ModelError::Json("malformed".into())));
    }

    #[tokio::test]
    async fn retry_succeeds_after_two_transient_failures() {
        let inner = Arc::new(FailThenSucceed {
            remaining_fails: Mutex::new(2),
            err_factory:     Box::new(|| ModelError::Transport("blip".into())),
        });
        let client = RetryingModelClient::new(
            inner,
            RetryConfig::deterministic_for_tests(3),
        );
        let resp = client.create_message(&empty_request()).await.unwrap();
        assert_eq!(resp.id, "msg-ok");
    }

    #[tokio::test]
    async fn retry_surfaces_last_error_when_budget_exhausted() {
        let inner = Arc::new(FailThenSucceed {
            remaining_fails: Mutex::new(10),
            err_factory:     Box::new(|| ModelError::Upstream {
                status: 500, body: "outage".into(),
            }),
        });
        let client = RetryingModelClient::new(
            inner,
            RetryConfig::deterministic_for_tests(3),
        );
        let err = client.create_message(&empty_request()).await.unwrap_err();
        match err {
            ModelError::Upstream { status, .. } => assert_eq!(status, 500),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn retry_does_not_retry_non_retryable_errors() {
        let inner = Arc::new(FailThenSucceed {
            remaining_fails: Mutex::new(10),
            err_factory:     Box::new(|| ModelError::Upstream {
                status: 400, body: "bad request".into(),
            }),
        });
        let client = RetryingModelClient::new(
            Arc::clone(&(inner.clone() as Arc<dyn ModelClient>)),
            RetryConfig::deterministic_for_tests(5),
        );
        let err = client.create_message(&empty_request()).await.unwrap_err();
        match err {
            ModelError::Upstream { status, .. } => assert_eq!(status, 400),
            other => panic!("unexpected error: {other:?}"),
        }
        // Only the FIRST call consumed a fail; the budget never
        // ticked further.
        let remaining = *inner.remaining_fails.lock().unwrap();
        assert_eq!(remaining, 9,
            "non-retryable error must NOT exhaust the retry budget; \
             expected 9 remaining (1 consumed), got {remaining}");
    }

    #[tokio::test]
    async fn fallback_advances_to_next_provider_on_retryable_error() {
        let primary = Arc::new(FailThenSucceed {
            remaining_fails: Mutex::new(10), // never succeed
            err_factory:     Box::new(|| ModelError::Upstream {
                status: 503, body: "primary down".into(),
            }),
        }) as Arc<dyn ModelClient>;
        let secondary = Arc::new(FailThenSucceed {
            remaining_fails: Mutex::new(0), // always succeed
            err_factory:     Box::new(|| ModelError::Transport("never".into())),
        }) as Arc<dyn ModelClient>;
        let chain = FallbackModelClient::new(vec![primary, secondary]);
        let resp = chain.create_message(&empty_request()).await.unwrap();
        assert_eq!(resp.id, "msg-ok");
    }

    #[tokio::test]
    async fn fallback_does_not_advance_on_non_retryable_error() {
        let primary = Arc::new(FailThenSucceed {
            remaining_fails: Mutex::new(10),
            err_factory:     Box::new(|| ModelError::Upstream {
                status: 401, body: "auth".into(),
            }),
        }) as Arc<dyn ModelClient>;
        let secondary = Arc::new(FailThenSucceed {
            remaining_fails: Mutex::new(0),
            err_factory:     Box::new(|| ModelError::Transport("never".into())),
        }) as Arc<dyn ModelClient>;
        let chain = FallbackModelClient::new(vec![primary, secondary]);
        let err = chain.create_message(&empty_request()).await.unwrap_err();
        match err {
            ModelError::Upstream { status, .. } => assert_eq!(status, 401),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_fallback_chain_fails_explicitly() {
        let chain = FallbackModelClient::new(vec![]);
        let err = chain.create_message(&empty_request()).await.unwrap_err();
        match err {
            ModelError::Transport(s) => assert!(s.contains("no providers")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn backoff_grows_with_attempt() {
        let mut cfg = RetryConfig::deterministic_for_tests(3);
        cfg.base_delay = Duration::from_millis(100);
        cfg.multiplier = 2.0;
        let a0 = RetryingModelClient::backoff_for(0, &cfg);
        let a1 = RetryingModelClient::backoff_for(1, &cfg);
        let a2 = RetryingModelClient::backoff_for(2, &cfg);
        assert_eq!(a0, Duration::from_millis(100));
        assert_eq!(a1, Duration::from_millis(200));
        assert_eq!(a2, Duration::from_millis(400));
    }
}
