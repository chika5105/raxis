//! Intent submission helper — converts a dispatch-loop terminal
//! tool ([`crate::dispatch::DispatchOutcome::TerminalTool`]) into an
//! [`raxis_types::IntentRequest`] and ships it through the
//! [`crate::transport::KernelTransport`].
//!
//! Closes V2_GAPS.md §B1 substeps "Intent submission
//! (executor → kernel via VSock)" and (in part)
//! "Witness/verdict submission (reviewer → kernel via VSock)".
//!
//! ## Sequence numbering & nonce minting
//!
//! Each [`IntentSubmitter`] holds:
//!
//! * A monotonic `u64` sequence_number, starting at 1 and
//!   incremented per submission. Pinned by
//!   `peripherals.md §3.1` ("INV-PLANNER-04: monotonic per-session
//!   sequence_number").
//! * A 128-bit nonce seeded from a `Uuid::new_v4()` at construction.
//!   The kernel only checks the format + uniqueness, not the
//!   entropy; counter-derived nonces (incrementing the seed per
//!   submission) are sufficient and keep the per-session state
//!   small.
//!
//! ## Why a separate submitter, not a method on the dispatch loop
//!
//! The dispatch loop terminates with a tool name + JSON input; the
//! submitter knows how to convert each terminal tool into the
//! matching [`IntentKind`]. Splitting the concerns keeps each
//! piece small and lets a future planner introduce a custom
//! terminal tool without touching the dispatch loop.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

use raxis_ipc::IpcMessage;
use raxis_types::{
    CommitSha, EscalationClass, EscalationRequest, IntentKind,
    IntentRequest, IntentResponse, RequestedEscalationScope, TaskId,
    TokensReport,
};

use crate::transport::{KernelTransport, TransportError};

// ---------------------------------------------------------------------------
// IntentSubmitter
// ---------------------------------------------------------------------------

/// One per-session intent submitter. Holds the session token, the
/// task id, the per-session sequence + nonce counters, and the
/// rolling [`TokensReport`] last reported by the dispatch loop.
pub struct IntentSubmitter {
    transport:    Arc<dyn KernelTransport>,
    session_token: String,
    task_id:      TaskId,
    next_seq:     std::sync::atomic::AtomicU64,
    nonce_seed:   std::sync::atomic::AtomicU64,
    /// V2 `v2_extended_gaps.md §2.5` — last known cumulative LLM
    /// token usage. Updated by callers via
    /// [`IntentSubmitter::report_tokens`] every time the dispatch
    /// loop updates `(cum_in, cum_out)`. Stamped onto every
    /// outbound `IntentRequest::tokens_used` so the kernel can run
    /// the dollar-cost admission gate at intent admission time.
    ///
    /// Stored behind a `std::sync::Mutex` so the dispatch loop and
    /// the terminal-tool submission path (which run on the same
    /// task) can share without a `&mut`.
    tokens:       std::sync::Mutex<TokensReport>,
}

impl IntentSubmitter {
    /// Construct a new submitter.
    ///
    /// `session_token` is the value the kernel stamped into the
    /// guest env at spawn time (`RAXIS_SESSION_TOKEN`); the
    /// [`crate::BootEnv`] reads it.
    ///
    /// `task_id` is the planner-role binary's task id (the same
    /// value the orchestrator/executor/reviewer received via
    /// `--task-id` argv).
    pub fn new(
        transport:     Arc<dyn KernelTransport>,
        session_token: String,
        task_id:       TaskId,
    ) -> Self {
        Self {
            transport,
            session_token,
            task_id,
            next_seq:   std::sync::atomic::AtomicU64::new(1),
            // High 64 bits of a fresh UUID v4 as the nonce seed —
            // the kernel only checks 32-hex-char format + uniqueness,
            // so 64 bits of entropy is plenty.
            nonce_seed: std::sync::atomic::AtomicU64::new(
                u64::from_le_bytes(Uuid::new_v4().as_bytes()[..8].try_into().unwrap()),
            ),
            tokens:     std::sync::Mutex::new(TokensReport::default()),
        }
    }

    /// V2 `v2_extended_gaps.md §2.5` — record the latest cumulative
    /// LLM token counts. The dispatch loop calls this after every
    /// model turn so the next `submit_*` call carries an accurate
    /// `IntentRequest::tokens_used`.
    ///
    /// Replaces the stored report wholesale (the dispatch loop
    /// owns the cumulative state; the submitter is just a relay).
    pub fn report_tokens(&self, tokens: TokensReport) {
        *self.tokens.lock().expect("tokens mutex poisoned") = tokens;
    }

    /// Snapshot the most-recent token report. Used by the wire
    /// helpers below; exposed for tests that want to assert the
    /// snapshot after a series of `report_tokens` calls.
    pub fn last_token_report(&self) -> TokensReport {
        self.tokens.lock().expect("tokens mutex poisoned").clone()
    }

    fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    fn next_nonce(&self) -> String {
        let seed = self.nonce_seed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Render as 32-hex-char (fill the high 64 bits with the
        // task id hash so two submitters in the same process don't
        // collide, even if they happened to seed at the same
        // wall-clock moment).
        let task_hash = {
            let mut h: u64 = 0xcbf29ce484222325;
            for b in self.task_id.as_str().bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h
        };
        format!("{task_hash:016x}{seed:016x}")
    }

    /// Build a fresh `IntentRequest` skeleton with the per-session
    /// fields populated. Caller fills in the kind-specific fields.
    ///
    /// V2 `v2_extended_gaps.md §2.5` — `tokens_used` is stamped from
    /// the most-recent `report_tokens` snapshot. `Some(zero)` is
    /// the default when no LLM turn has fired yet (deterministic
    /// short-circuit terminal tools): the kernel still gets a
    /// truthful "zero token cost" report rather than a `None`.
    fn skeleton(&self, kind: IntentKind) -> IntentRequest {
        IntentRequest {
            session_token:           self.session_token.clone(),
            sequence_number:         self.next_seq(),
            envelope_nonce:          self.next_nonce(),
            intent_kind:             kind,
            task_id:                 self.task_id.clone(),
            base_sha:                None,
            head_sha:                None,
            submitted_claims:        vec![],
            justification:           None,
            idempotency_key:         None,
            approval_token:          None,
            approved:                None,
            critique:                None,
            resolved_via_escalation: None,
            tokens_used:             Some(self.last_token_report()),
        }
    }

    /// Submit a `SingleCommit` intent.
    ///
    /// `base_sha` / `head_sha` form the commit range the kernel
    /// will validate ancestry + path-allowlist over. Both are
    /// validated as 40-char lowercase hex on construction; a
    /// malformed value surfaces as
    /// [`SubmitError::MalformedInput`] before the wire round-trip.
    pub async fn submit_single_commit(
        &self,
        base_sha: &str,
        head_sha: &str,
    ) -> Result<IntentResponse, SubmitError> {
        let base = parse_commit_sha("base_sha", base_sha)?;
        let head = parse_commit_sha("head_sha", head_sha)?;
        let mut req = self.skeleton(IntentKind::SingleCommit);
        req.base_sha = Some(base);
        req.head_sha = Some(head);
        self.send(IpcMessage::IntentRequest(req)).await
    }

    /// Submit a `CompleteTask` intent.
    pub async fn submit_complete_task(
        &self,
        head_sha: &str,
    ) -> Result<IntentResponse, SubmitError> {
        let head = parse_commit_sha("head_sha", head_sha)?;
        let mut req = self.skeleton(IntentKind::CompleteTask);
        req.head_sha = Some(head);
        self.send(IpcMessage::IntentRequest(req)).await
    }

    /// Submit a `ReportFailure` intent.
    pub async fn submit_report_failure(
        &self,
        justification: String,
    ) -> Result<IntentResponse, SubmitError> {
        let mut req = self.skeleton(IntentKind::ReportFailure);
        req.justification = Some(justification);
        self.send(IpcMessage::IntentRequest(req)).await
    }

    /// Submit an `IntegrationMerge` intent (orchestrator role).
    pub async fn submit_integration_merge(
        &self,
        base_sha: &str,
        head_sha: &str,
    ) -> Result<IntentResponse, SubmitError> {
        let base = parse_commit_sha("base_sha", base_sha)?;
        let head = parse_commit_sha("head_sha", head_sha)?;
        let mut req = self.skeleton(IntentKind::IntegrationMerge);
        req.base_sha = Some(base);
        req.head_sha = Some(head);
        self.send(IpcMessage::IntentRequest(req)).await
    }

    /// Submit an `ActivateSubTask` intent (orchestrator role).
    ///
    /// `subtask_task_id` is the sub-task the orchestrator asks the
    /// kernel to activate; this REPLACES the orchestrator's own
    /// `task_id` field on the wire (per `intent.rs` doc, only
    /// `task_id` is read for this kind).
    pub async fn submit_activate_subtask(
        &self,
        subtask_task_id: TaskId,
    ) -> Result<IntentResponse, SubmitError> {
        let mut req = self.skeleton(IntentKind::ActivateSubTask);
        req.task_id = subtask_task_id;
        self.send(IpcMessage::IntentRequest(req)).await
    }

    /// Submit a `RetrySubTask` intent (orchestrator role).
    pub async fn submit_retry_subtask(
        &self,
        subtask_task_id: TaskId,
    ) -> Result<IntentResponse, SubmitError> {
        let mut req = self.skeleton(IntentKind::RetrySubTask);
        req.task_id = subtask_task_id;
        self.send(IpcMessage::IntentRequest(req)).await
    }

    /// Submit a `SubmitReview` intent (reviewer role).
    ///
    /// `approved = true` ⇒ green-light the predecessor executor's
    /// `evaluation_sha`. `approved = false` requires `critique`
    /// (max 32 KiB).
    pub async fn submit_review(
        &self,
        approved: bool,
        critique: Option<String>,
    ) -> Result<IntentResponse, SubmitError> {
        let mut req = self.skeleton(IntentKind::SubmitReview);
        req.approved = Some(approved);
        req.critique = critique;
        self.send(IpcMessage::IntentRequest(req)).await
    }

    /// Submit a generic `EscalationRequest`. Used by the planner
    /// loop when a tool requires a capability the session does not
    /// hold (e.g. infra-write).
    pub async fn submit_escalation(
        &self,
        class:           EscalationClass,
        requested_scope: RequestedEscalationScope,
        justification:   String,
    ) -> Result<IntentResponse, SubmitError> {
        let req = EscalationRequest {
            session_token:   self.session_token.clone(),
            task_id:         self.task_id.clone(),
            class,
            requested_scope,
            justification,
            idempotency_key: Uuid::new_v4(),
        };
        // Note: the kernel responds to EscalationRequest with
        // KernelEscalationResponse, not KernelIntentResponse — this
        // method's `Result<IntentResponse, ...>` shape exists as a
        // wire-shape convenience for callers that don't care about
        // the response variant. Tests assert against
        // `SubmitError::UnexpectedResponse` for the escalation
        // path.
        self.send(IpcMessage::EscalationRequest(req)).await
    }

    async fn send(
        &self,
        outbound: IpcMessage,
    ) -> Result<IntentResponse, SubmitError> {
        let resp = self.transport.request(&outbound).await?;
        match resp {
            IpcMessage::KernelIntentResponse(r) => Ok(r),
            other => Err(SubmitError::UnexpectedResponse(format!("{other:?}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire helpers — convert dispatch terminal tools into IPC intents
// ---------------------------------------------------------------------------

/// Tool name → [`IntentKind`] mapping for the executor role's
/// terminal tools.
///
/// Used by the executor's main loop to convert the dispatch-loop's
/// terminal-tool short-circuit into the matching IPC intent
/// without re-implementing the mapping in every binary.
pub fn executor_terminal_tool_to_intent_kind(name: &str) -> Option<IntentKind> {
    match name {
        "task_complete"  => Some(IntentKind::CompleteTask),
        "single_commit"  => Some(IntentKind::SingleCommit),
        "report_failure" => Some(IntentKind::ReportFailure),
        _ => None,
    }
}

/// Tool name → [`IntentKind`] mapping for the orchestrator role.
pub fn orchestrator_terminal_tool_to_intent_kind(name: &str) -> Option<IntentKind> {
    match name {
        "integration_merge" => Some(IntentKind::IntegrationMerge),
        "activate_subtask"  => Some(IntentKind::ActivateSubTask),
        "retry_subtask"     => Some(IntentKind::RetrySubTask),
        _ => None,
    }
}

/// Tool name → [`IntentKind`] mapping for the reviewer role.
pub fn reviewer_terminal_tool_to_intent_kind(name: &str) -> Option<IntentKind> {
    match name {
        "submit_review" => Some(IntentKind::SubmitReview),
        _ => None,
    }
}

/// Validate + wrap a model-supplied SHA hex string. Returns
/// [`SubmitError::MalformedInput`] on any structural problem so the
/// dispatch loop's caller can surface it back to the model as a
/// recoverable error rather than a hard failure.
fn parse_commit_sha(field: &'static str, raw: &str) -> Result<CommitSha, SubmitError> {
    CommitSha::parse(raw).map_err(|e| {
        SubmitError::MalformedInput(format!(
            "{field} {raw:?} not a valid commit SHA: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// SubmitError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SubmitError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("unexpected response variant: {0}")]
    UnexpectedResponse(String),
    #[error("malformed terminal-tool input: {0}")]
    MalformedInput(String),
}

// ---------------------------------------------------------------------------
// Wire-side helpers for dispatch-loop callers
// ---------------------------------------------------------------------------

/// Strip the `head_sha` field from a terminal-tool input and
/// return it. Used by the executor's main loop after a
/// `task_complete` terminal tool fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCompleteInput {
    pub head_sha: String,
}

impl TaskCompleteInput {
    pub fn parse(v: &serde_json::Value) -> Result<Self, SubmitError> {
        serde_json::from_value(v.clone()).map_err(|e| {
            SubmitError::MalformedInput(format!(
                "task_complete input not parseable: {e}"
            ))
        })
    }
}

/// Reviewer's `submit_review` terminal-tool input shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitReviewInput {
    pub approved: bool,
    #[serde(default)]
    pub critique: Option<String>,
}

impl SubmitReviewInput {
    pub fn parse(v: &serde_json::Value) -> Result<Self, SubmitError> {
        let parsed: Self = serde_json::from_value(v.clone()).map_err(|e| {
            SubmitError::MalformedInput(format!(
                "submit_review input not parseable: {e}"
            ))
        })?;
        if !parsed.approved && parsed.critique.is_none() {
            return Err(SubmitError::MalformedInput(
                "submit_review: critique required when approved=false".to_owned(),
            ));
        }
        Ok(parsed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::StreamTransport;
    use raxis_ipc::frame::{read_frame, write_frame};
    use raxis_types::{IntentOutcome, IntentResponse, PlannerErrorCode, TaskState};
    use tokio::io::duplex;

    fn fixture_response(seq: u64) -> IpcMessage {
        IpcMessage::KernelIntentResponse(IntentResponse {
            sequence_number: seq,
            task_state:      TaskState::Completed,
            outcome: IntentOutcome::Rejected {
                error_code:   PlannerErrorCode::InvalidRequest,
                error_detail: None,
            },
        })
    }

    #[tokio::test]
    async fn submit_complete_task_emits_correct_intent_kind() {
        let (planner_side, mut kernel_side) = duplex(64 * 1024);
        let transport = Arc::new(StreamTransport::new(planner_side));

        let kernel_task = tokio::spawn(async move {
            let inbound: IpcMessage = read_frame(&mut kernel_side).await.unwrap();
            match inbound {
                IpcMessage::IntentRequest(r) => {
                    assert_eq!(r.intent_kind, IntentKind::CompleteTask);
                    assert_eq!(r.sequence_number, 1);
                    assert_eq!(
                        r.head_sha.as_ref().map(|s| s.as_str()),
                        Some("0123456789abcdef0123456789abcdef01234567"),
                    );
                    assert_eq!(r.session_token, "session-tok");
                    // Nonce shape: 32 hex chars.
                    assert_eq!(r.envelope_nonce.len(), 32);
                    assert!(r.envelope_nonce.bytes().all(|b| b.is_ascii_hexdigit()));
                }
                other => panic!("expected IntentRequest, got {other:?}"),
            }
            write_frame(&mut kernel_side, &fixture_response(1)).await.unwrap();
        });

        let submitter = IntentSubmitter::new(
            transport,
            "session-tok".to_owned(),
            TaskId::parse("task-fixture").unwrap(),
        );
        let _resp = submitter.submit_complete_task(
            "0123456789abcdef0123456789abcdef01234567",
        ).await.unwrap();
        kernel_task.await.unwrap();
    }

    #[tokio::test]
    async fn submit_review_carries_approved_false_and_critique() {
        let (planner_side, mut kernel_side) = duplex(64 * 1024);
        let transport = Arc::new(StreamTransport::new(planner_side));

        let kernel_task = tokio::spawn(async move {
            let inbound: IpcMessage = read_frame(&mut kernel_side).await.unwrap();
            match inbound {
                IpcMessage::IntentRequest(r) => {
                    assert_eq!(r.intent_kind, IntentKind::SubmitReview);
                    assert_eq!(r.approved, Some(false));
                    assert_eq!(r.critique.as_deref(), Some("not enough tests"));
                }
                other => panic!("expected IntentRequest, got {other:?}"),
            }
            write_frame(&mut kernel_side, &fixture_response(1)).await.unwrap();
        });

        let submitter = IntentSubmitter::new(
            transport,
            "session-tok".to_owned(),
            TaskId::parse("review-task").unwrap(),
        );
        let _resp = submitter.submit_review(
            false,
            Some("not enough tests".to_owned()),
        ).await.unwrap();
        kernel_task.await.unwrap();
    }

    #[tokio::test]
    async fn back_to_back_submissions_increment_sequence_number() {
        let (planner_side, mut kernel_side) = duplex(64 * 1024);
        let transport = Arc::new(StreamTransport::new(planner_side));

        let kernel_task = tokio::spawn(async move {
            for n in 1u64..=3 {
                let inbound: IpcMessage = read_frame(&mut kernel_side).await.unwrap();
                match inbound {
                    IpcMessage::IntentRequest(r) => {
                        assert_eq!(r.sequence_number, n,
                            "expected per-session monotonic sequence_number, got {} on call {n}",
                            r.sequence_number);
                    }
                    other => panic!("expected IntentRequest, got {other:?}"),
                }
                write_frame(&mut kernel_side, &fixture_response(n)).await.unwrap();
            }
        });

        let submitter = IntentSubmitter::new(
            transport,
            "session-tok".to_owned(),
            TaskId::parse("task-x").unwrap(),
        );
        let _ = submitter.submit_report_failure("a".to_owned()).await.unwrap();
        let _ = submitter.submit_report_failure("b".to_owned()).await.unwrap();
        let _ = submitter.submit_report_failure("c".to_owned()).await.unwrap();
        kernel_task.await.unwrap();
    }

    #[test]
    fn task_complete_input_parse_round_trip() {
        let v = serde_json::json!({ "head_sha": "deadbeef" });
        let p = TaskCompleteInput::parse(&v).unwrap();
        assert_eq!(p.head_sha, "deadbeef");
    }

    #[test]
    fn submit_review_input_requires_critique_when_rejected() {
        let v = serde_json::json!({ "approved": false });
        let err = SubmitReviewInput::parse(&v).unwrap_err();
        match err {
            SubmitError::MalformedInput(msg) => {
                assert!(msg.contains("critique required"));
            }
            other => panic!("expected MalformedInput, got {other:?}"),
        }
    }

    #[test]
    fn submit_review_input_accepts_approved_true_without_critique() {
        let v = serde_json::json!({ "approved": true });
        let p = SubmitReviewInput::parse(&v).unwrap();
        assert!(p.approved);
        assert!(p.critique.is_none());
    }

    #[test]
    fn role_mapping_helpers_pin_terminal_tool_to_intent_kind() {
        assert_eq!(
            executor_terminal_tool_to_intent_kind("task_complete"),
            Some(IntentKind::CompleteTask),
        );
        assert_eq!(
            executor_terminal_tool_to_intent_kind("report_failure"),
            Some(IntentKind::ReportFailure),
        );
        assert_eq!(
            executor_terminal_tool_to_intent_kind("submit_review"),
            None,
            "executor MUST NOT have submit_review in its terminal-tool map",
        );
        assert_eq!(
            reviewer_terminal_tool_to_intent_kind("submit_review"),
            Some(IntentKind::SubmitReview),
        );
        assert_eq!(
            reviewer_terminal_tool_to_intent_kind("task_complete"),
            None,
            "reviewer MUST NOT have task_complete in its terminal-tool map",
        );
        assert_eq!(
            orchestrator_terminal_tool_to_intent_kind("integration_merge"),
            Some(IntentKind::IntegrationMerge),
        );
    }
}
