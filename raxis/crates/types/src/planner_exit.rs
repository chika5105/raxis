// raxis-types::planner_exit — structured planner exit outcome.
// Normative reference:
//   - specs/invariants.md `INV-FAILURE-REASON-CONCRETE-01`
//   - specs/v2/audit-paired-writes.md §14.8 (failure_reason concreteness)
//   - specs/v2/planner-harness.md (planner driver loop exit shapes)
// Why this type exists
// ====================
// A planner VM that exits without submitting a terminal intent
// (`CompleteTask` / `SubmitReview` / `ReportFailure`) forces the
// kernel into Mode-B premature-exit synthesis (see
// `session_spawn_orchestrator::spawn_planner_dispatcher`). Prior to
// `INV-FAILURE-REASON-CONCRETE-01` the kernel had no idea WHY the
// planner exited — the synthesised `block_reason` was a generic
// umbrella string ("MaxTurnsExceeded / TokensExceeded / DispatchIdle
// / process death") that listed every theoretical cause and named
// none of them concretely. The dashboard's
// `FailureReasonPanel` correctly flagged this as a kernel bug
// (red ⚠ KERNEL BUG badge per `INV-DASHBOARD-FAILURE-VISIBILITY-01`),
// but the operator still couldn't tell whether the executor needed
// a higher `RAXIS_PLANNER_MAX_TURNS`, a higher token cap, a
// substrate reboot, or something else entirely.
// `PlannerExitOutcome` closes that gap. The planner-core driver
// (which knows EXACTLY why the dispatch loop is exiting) wraps its
// `DriverOutcome` into a `PlannerExitOutcome` and ships it to the
// kernel via the new `IpcMessage::PlannerExitNotice` frame BEFORE
// the VM powers off. The kernel's `drive_planner_stream` captures
// the most-recently-received notice and threads it back through
// the `PlannerStreamOutcome` return value. The Mode-B synthesiser
// in `session_spawn_orchestrator` then formats a CONCRETE
// `block_reason` like:
//   "executor planner reached max_turns budget (60 used / 60 limit)
//    without submitting a terminal intent"
// instead of the multi-option umbrella.
// Wire contract
// =============
// The variants are serialised via the `IpcMessage::PlannerExitNotice`
// envelope (positional bincode 2.0.1 standard() — same codec as
// every other planner-socket frame). Adding a NEW variant is a
// minor-rev wire bump: existing kernels treat unknown variants as
// `Unknown { detail }` so the EOF path still surfaces a concrete
// reason even when the planner is newer than the kernel.

use serde::{Deserialize, Serialize};

/// Why the planner-core dispatch driver loop terminated.
/// One variant per terminal shape the driver can reach
/// (`crates/planner-core/src/driver.rs::DriverOutcome` →
/// `PlannerExitOutcome` mapping lives in
/// `planner-core::driver::driver_outcome_to_exit_outcome`).
/// `CleanCompletion` is the success path — the planner submitted
/// a terminal intent (`CompleteTask` / `SubmitReview` /
/// `ReportFailure` / `IntegrationMerge` / `ActivateSubTask` /
/// `RetrySubTask`) and is exiting normally. In that case the
/// kernel's Mode-B synthesis is a no-op because the EarlyResponse
/// dispatch on the terminal intent already drove the FSM.
/// All other variants represent gaps the operator must
/// triage:
///   * `MaxTurnsReached` — bump
///     `RAXIS_PLANNER_MAX_TURNS` or `[gateway].planner_max_turns_default`
///     in policy.
///   * `MaxTokensReached` — raise the relevant
///     `RAXIS_PLANNER_MAX_TOKENS_{INPUT,OUTPUT,TOTAL}_TOTAL`
///     ceiling or rein in the prompt / fanout.
///   * `IdleNoTerminalIntent` — the model declared `end_turn`
///     without emitting a terminal tool. Indicates a prompt /
///     tool-spec issue (the model thinks it's done but hasn't
///     selected `task_complete` / `report_failure`).
///   * `ToolErrorBudgetExhausted` — too many consecutive tool
///     errors. Future-reserved (no driver path emits this yet);
///     pinned here so the kernel side decoder stays exhaustive.
///   * `ExplicitGiveUp` — the role binary or driver decided to
///     bail without submitting a terminal intent (e.g.
///     KSB-assembly failure, sidecar env missing). `detail`
///     carries the verbatim driver-error chain.
///   * `Unknown` — defensive: the kernel saw a notice variant
///     it doesn't know how to decode. `detail` carries the
///     planner-side `Display` of the unknown outcome so the
///     synthesised `block_reason` is still concrete.
///     **Serde contract — INV-IPC-BINCODE.** Default external-tag
///     representation (NO `#[serde(tag = ...)]`). The earlier draft of
///     this enum used internally-tagged-with-content
///     (`#[serde(tag = "kind", content = "detail")]`) which renders as
///     `{"kind": "MaxTurnsReached", "detail": { "used": 60, "limit": 60 }}`
///     in JSON, but the canonical IPC encoder for this enum is
///     `bincode::serde` (frame `IpcMessage::PlannerExitNotice` on the
///     **bincode 2.0** planner socket per `crates/ipc/src/message.rs`).
///     `bincode::config::standard()` does NOT implement
///     `serde::Deserializer::deserialize_any`, so the internally-tagged
///     projection round-trips through the planner socket as
///     `Decode(Serde(IdentifierNotSupported))` — the iter57 forensic
///     surface, observed once per worker session-exit on the
///     `planner_frame_decode_failed` warn line. Switching to the
///     external-tag default form (`{"MaxTurnsReached": {"used": 60,
/// "limit": 60}}` in JSON, positional varint-tagged in bincode)
///     is the canonical fix and matches the same conclusion already
///     recorded for `IntentOutcome` (`crates/types/src/intent.rs:510`)
///     and for the discussion in §IPC
///     bincode contract. Variants and field names are unchanged so
///     the tag-only delta is backward-compatible at the audit-event
///     projection level (the audit chain sees the same kind / payload
///     keys after the kernel's `WorkerPostExitSynth` formatter
///     reshapes the value into the audit-event JSON envelope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlannerExitOutcome {
    /// The planner submitted a terminal intent and is exiting
    /// normally. The kernel's Mode-B synthesis is a no-op for
    /// this variant (the EarlyResponse dispatch on the terminal
    /// intent already drove the FSM); the planner still emits
    /// it so the kernel's "did the planner reach a clean
    /// completion?" question is decidable from one frame
    /// instead of inferred from "no notice + clean EOF".
    CleanCompletion {
        /// Name of the terminal tool that fired
        /// (`task_complete` / `report_failure` / `submit_review`
        /// / etc.). Used as forensic context only — the kernel
        /// has already processed the matching `IntentRequest`.
        tool_name: String,
    },

    /// `DispatchOutcome::MaxTurnsExceeded` reached
    /// `DispatchConfig::max_turns` without firing a terminal
    /// tool. Operator remedy: raise
    /// `RAXIS_PLANNER_MAX_TURNS` or
    /// `[gateway].planner_max_turns_default` in policy.
    MaxTurnsReached {
        /// Number of turns the dispatch loop actually consumed
        /// (= the `max_turns` ceiling). Stamped onto the
        /// synthesised `block_reason` so the operator sees
        /// `"60 used / 60 limit"` and can correlate to policy.
        used: u32,
        /// The configured `max_turns` ceiling.
        limit: u32,
    },

    /// `DispatchOutcome::TokensExceeded` — one of the per-session
    /// cumulative token caps tripped. Operator remedy: raise the
    /// matching `RAXIS_PLANNER_MAX_TOKENS_*_TOTAL` ceiling or
    /// reduce the prompt / fanout.
    MaxTokensReached {
        /// Which axis tripped: `"input"`, `"output"`, or
        /// `"total"`. Mirrors
        /// `DispatchOutcome::TokensExceeded::which`.
        which: String,
        /// Cumulative tokens observed on the tripping axis.
        used: u64,
        /// Configured ceiling on the tripping axis.
        limit: u64,
    },

    /// `DispatchOutcome::Idle` — the model said it was done
    /// (`stop_reason = "end_turn"`) without emitting a terminal
    /// tool. Treated as a hard failure for roles whose contract
    /// requires a terminal-tool submission (executor / reviewer /
    /// orchestrator).
    IdleNoTerminalIntent {
        /// Length of the final assistant text (joined across
        /// every `Text` block in the last turn) in bytes. Used
        /// as forensic context only; the full text is logged on
        /// the planner side at `step:"planner-idle"`.
        final_text_len: u32,
    },

    /// Future-reserved — the dispatch loop terminated because
    /// the consecutive tool-error count crossed a configured
    /// budget. No driver path emits this today; pinned here so
    /// the kernel-side decoder stays exhaustive across future
    /// driver additions.
    ToolErrorBudgetExhausted {
        /// Number of consecutive tool errors observed.
        errors: u32,
        /// Configured budget that was exhausted.
        budget: u32,
    },

    /// The driver bailed before the dispatch loop could
    /// terminate normally (e.g. KSB assembly failure, sidecar
    /// env var missing, model-client construction error). The
    /// `detail` field carries the verbatim
    /// `DriverError::to_string()` chain so the synthesised
    /// `block_reason` is operator-actionable.
    ExplicitGiveUp {
        /// Verbatim `DriverError::Display` (or equivalent
        /// driver-side error chain) explaining why the driver
        /// gave up.
        reason: String,
    },

    /// Defensive — kernel received a notice it could not decode
    /// (e.g. the planner is from a newer minor-rev that
    /// introduced a variant the kernel doesn't know yet). The
    /// notice path falls back to this variant with a textual
    /// description so the synthesised `block_reason` is still
    /// concrete instead of falling back to the multi-cause
    /// umbrella.
    Unknown {
        /// Free-form description of the unknown exit shape.
        detail: String,
    },
}

impl PlannerExitOutcome {
    /// True when this outcome means the kernel does NOT need to
    /// run Mode-B synthesis (the planner already submitted a
    /// terminal intent). Used by the kernel to skip the
    /// synthesised `Running → Failed` transition when the EOF
    /// arrives AFTER a `CleanCompletion` notice.
    pub fn is_clean_completion(&self) -> bool {
        matches!(self, PlannerExitOutcome::CleanCompletion { .. })
    }

    /// **`INV-FAILURE-REASON-CONCRETE-01`** — format the outcome
    /// into a CONCRETE operator-facing failure reason. The
    /// `role_str` argument is the worker class (`"executor"` /
    /// `"reviewer"` / `"orchestrator"`) — stamped onto the
    /// returned string so the dashboard's `FailureReasonPanel`
    /// can show e.g.
    ///   "executor planner reached max_turns budget
    ///    (60 used / 60 limit) without submitting a terminal
    ///    intent"
    /// instead of a generic umbrella. Returns `None` for
    /// `CleanCompletion` — the caller skips Mode-B synthesis
    /// entirely in that case.
    /// **Forbidden phrases the formatter MUST NOT use** (each
    /// would re-introduce the
    /// `INV-FAILURE-REASON-CONCRETE-01` regression):
    ///   * `"MaxTurnsExceeded / TokensExceeded / …"` — multi-
    ///     option umbrella the kernel synthesised pre-fix.
    ///   * `"unknown"` / `"unspecified"` / `"see logs"` /
    ///     `"internal error"` — opaque placeholders.
    ///     The witness test in `kernel/tests/concrete_reason_witness.rs`
    ///     asserts every variant produces a string that
    ///     (a) is non-empty, (b) does not match the forbidden
    ///     regex, and (c) names the specific cause.
    pub fn format_concrete_reason(&self, role_str: &str) -> Option<String> {
        match self {
            PlannerExitOutcome::CleanCompletion { .. } => None,
            PlannerExitOutcome::MaxTurnsReached { used, limit } => Some(format!(
                "{role_str} planner reached max_turns budget ({used} used / {limit} limit) \
                 without submitting a terminal intent — raise RAXIS_PLANNER_MAX_TURNS \
                 (or `[gateway].planner_max_turns_default` in policy) and retry."
            )),
            PlannerExitOutcome::MaxTokensReached { which, used, limit } => Some(format!(
                "{role_str} planner exceeded cumulative max_tokens cap on the {which} axis \
                 ({used} used / {limit} limit) — raise \
                 `RAXIS_PLANNER_MAX_TOKENS_{}_TOTAL` (or the matching policy field) and retry.",
                which.to_uppercase(),
            )),
            PlannerExitOutcome::IdleNoTerminalIntent { final_text_len } => Some(format!(
                "{role_str} planner declared end_turn (final_text {final_text_len} bytes) \
                 without selecting a terminal tool — the model thinks it is done but did \
                 not call `task_complete` / `report_failure` / `submit_review`. Inspect \
                 the planner stderr at step:\"planner-idle\" for the final assistant text \
                 and tighten the role NNSP / tool-spec so the model picks a terminal \
                 outcome on idle."
            )),
            PlannerExitOutcome::ToolErrorBudgetExhausted { errors, budget } => Some(format!(
                "{role_str} planner exhausted consecutive tool-error budget \
                 ({errors} errors / {budget} budget) — inspect the planner-dispatch \
                 stderr for the repeated tool failure and either widen the budget or \
                 fix the underlying tool error."
            )),
            PlannerExitOutcome::ExplicitGiveUp { reason } => Some(format!(
                "{role_str} planner driver gave up before the dispatch loop could \
                 terminate normally: {reason}"
            )),
            PlannerExitOutcome::Unknown { detail } => Some(format!(
                "{role_str} planner emitted an exit-notice variant the kernel could \
                 not decode (kernel/planner minor-rev skew?). Verbatim notice detail: \
                 {detail}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `INV-FAILURE-REASON-CONCRETE-01` — the forbidden-phrase
    /// regex MUST NOT match any `format_concrete_reason`
    /// output. Asserted per-variant so a future formatter
    /// regression that re-introduces the umbrella string fails
    /// this test verbatim.
    #[test]
    fn format_concrete_reason_avoids_forbidden_phrases() {
        let cases = vec![
            PlannerExitOutcome::MaxTurnsReached {
                used: 60,
                limit: 60,
            },
            PlannerExitOutcome::MaxTokensReached {
                which: "input".to_string(),
                used: 100_001,
                limit: 100_000,
            },
            PlannerExitOutcome::IdleNoTerminalIntent {
                final_text_len: 1234,
            },
            PlannerExitOutcome::ToolErrorBudgetExhausted {
                errors: 5,
                budget: 5,
            },
            PlannerExitOutcome::ExplicitGiveUp {
                reason: "sidecar env var RAXIS_PLANNER_SIDECAR_ENDPOINT missing".to_string(),
            },
            PlannerExitOutcome::Unknown {
                detail: "planner-vNEXT::DispatchOutcome::FutureVariant".to_string(),
            },
        ];
        let re = regex_like_forbidden();
        for c in cases {
            let got = c
                .format_concrete_reason("executor")
                .expect("non-clean variant returns Some");
            assert!(
                !got.is_empty(),
                "format_concrete_reason MUST be non-empty for {c:?}"
            );
            assert!(
                !re.iter().any(|needle| got.to_lowercase().contains(needle)),
                "format_concrete_reason for {c:?} contains a forbidden phrase: {got:?}"
            );
            // Concreteness witness: the string must name the
            // specific cause (a substring keyed on the variant
            // discriminator), not a multi-option list.
            let needle = match &c {
                PlannerExitOutcome::MaxTurnsReached { .. } => "max_turns",
                PlannerExitOutcome::MaxTokensReached { .. } => "max_tokens",
                PlannerExitOutcome::IdleNoTerminalIntent { .. } => "end_turn",
                PlannerExitOutcome::ToolErrorBudgetExhausted { .. } => "tool-error",
                PlannerExitOutcome::ExplicitGiveUp { .. } => "driver gave up",
                PlannerExitOutcome::Unknown { .. } => "exit-notice",
                PlannerExitOutcome::CleanCompletion { .. } => unreachable!(),
            };
            assert!(
                got.to_lowercase().contains(needle),
                "format_concrete_reason for {c:?} must name the specific cause \
                 (expected substring {needle:?}); got {got:?}"
            );
        }
    }

    /// `CleanCompletion` is the success path; the formatter
    /// returns `None` so the Mode-B synthesiser skips the
    /// synthesised transition.
    #[test]
    fn clean_completion_returns_none() {
        let c = PlannerExitOutcome::CleanCompletion {
            tool_name: "task_complete".to_string(),
        };
        assert!(c.is_clean_completion());
        assert!(c.format_concrete_reason("executor").is_none());
    }

    /// Wire round-trip — the tagged-enum serde shape MUST
    /// stay stable. Bincode parity is exercised end-to-end by
    /// the IPC roundtrip tests in `raxis-ipc`; here we pin the
    /// JSON shape so the audit-chain projection stays
    /// machine-parseable.
    /// INV-IPC-BINCODE: the wire shape is the default external-tag
    /// serde representation (`{"VariantName":{...payload...}}` in
    /// JSON, positional varint-tagged in bincode 2.0). Internal-tag
    /// (`{"kind":"...", "detail":{...}}`) is forbidden because
    /// `bincode::config::standard()` does NOT implement
    /// `serde::Deserializer::deserialize_any` and surfaces
    /// `Decode(Serde(IdentifierNotSupported))` on the planner socket
    /// for any internally-tagged enum (iter57 forensic surface).
    #[test]
    fn serde_json_roundtrip_external_tag() {
        let c = PlannerExitOutcome::MaxTurnsReached {
            used: 60,
            limit: 60,
        };
        let s = serde_json::to_string(&c).unwrap();
        assert!(
            s.contains("\"MaxTurnsReached\""),
            "expected external-tag variant key in {s:?}",
        );
        assert!(
            s.contains("\"used\":60") && s.contains("\"limit\":60"),
            "expected payload fields in {s:?}",
        );
        // Belt-and-braces: the internally-tagged shape MUST NOT
        // appear — that's the iter57 bincode regression baseline.
        assert!(
            !s.contains("\"kind\":\"MaxTurnsReached\""),
            "regression: internally-tagged shape detected in {s:?}; \
             see INV-IPC-BINCODE doc on PlannerExitOutcome",
        );
        let r: PlannerExitOutcome = serde_json::from_str(&s).unwrap();
        assert_eq!(r, c);
    }

    /// INV-IPC-BINCODE bincode round-trip witness: the planner-side
    /// notice frame MUST decode cleanly through `bincode::serde` so
    /// the kernel's `drive_planner_stream` can capture the exit
    /// outcome instead of falling back to the synthesised umbrella
    /// reason. Locks down the iter57 fix surface.
    #[test]
    fn serde_bincode_roundtrip_no_identifier_not_supported() {
        let c = PlannerExitOutcome::MaxTurnsReached {
            used: 60,
            limit: 60,
        };
        let bytes =
            bincode::serde::encode_to_vec(&c, bincode::config::standard()).expect("encode_to_vec");
        let (decoded, _read): (PlannerExitOutcome, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("decode_from_slice (this is the INV-IPC-BINCODE assertion)");
        assert_eq!(decoded, c);
    }

    /// The forbidden phrases under
    /// `INV-FAILURE-REASON-CONCRETE-01`. Kept lowercase; the
    /// test lowercases the formatter output before matching.
    fn regex_like_forbidden() -> Vec<&'static str> {
        // Substrings we forbid in any synthesised
        // `block_reason`. The kernel sweep test in
        // `kernel/tests/concrete_reason_witness.rs` uses the
        // SAME list to scan emit sites — keep these two in
        // sync.
        vec![
            "maxturnsexceeded / tokensexceeded",
            "tokensexceeded / dispatchidle",
            "dispatchidle / process death",
            "or process death",
            "(no reason)",
            "see logs",
            "internal error",
            "something went wrong",
            "unknown reason",
            "unspecified reason",
        ]
    }
}
