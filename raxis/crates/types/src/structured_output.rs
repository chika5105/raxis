// raxis-types::structured_output — V2 `v2_extended_gaps.md §3.2`
// typed mid-session communication enum.
//
// **Why a closed enum and not open-ended JSON.** The kernel is a
// reference monitor that structurally validates every IPC payload
// (R-2 — Mediated I/O). Open-ended JSON would create an
// unvalidatable surface — every consumer (audit chain, dashboard,
// downstream planner KSB) would have to re-implement validation,
// and none of them would be able to enforce schema invariants.
//
// The enum below is the SINGLE source of truth for what an agent
// can emit; adding a new variant is a wire-protocol bump and
// requires a coordinated change across `raxis-types`,
// `raxis-kernel::handlers`, the operator dashboard, and the CLI.
//
// **Invariant matrix (§3.2 spec):**
// * R-1  (Domain separation) — the kernel scopes every output to
//        the emitting session's `(initiative_id, task_id)`.
// * R-2  (Mediated I/O)      — submitted via the planner UDS, NEVER
//        a shared filesystem.
// * R-5  (Bounded capabilities) — the `structured_output` tool is
//        registered ONLY in the executor + orchestrator registries.
//        Reviewer registry never has it.
// * R-10 (Opaque rejection)  — kernel rejection codes never leak
//        internal state.
// * INV-PLANNER-HARNESS-04   — emitting a structured output IS a
//        model turn; the dispatch loop's turn counter increments
//        before the tool is dispatched.

use serde::{Deserialize, Serialize};

/// Hard cap for `DiagnosticFlag.message`. The §3.2 spec quotes
/// 1024 chars; we use bytes here because that's what `String::len`
/// returns and gives the kernel a true wire-shape ceiling.
pub const STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES: usize = 1_024;

/// Hard cap for `TaskSummary.approach`. Spec: ≤ 2048 chars.
pub const STRUCTURED_OUTPUT_MAX_APPROACH_BYTES: usize = 2_048;

/// Hard cap on a single `Vec<String>` payload (changed_paths /
/// files_modified). Per-element string is also capped at 4 KiB to
/// keep the audit chain payload bounded. Both are kernel-side
/// validation; the planner-side tool surface accepts any input
/// shape and lets the kernel's structural validator reject.
pub const STRUCTURED_OUTPUT_MAX_PATH_LIST_LEN: usize = 256;
pub const STRUCTURED_OUTPUT_MAX_PATH_BYTES: usize = 4_096;

/// Per-session rate limit. The spec uses 10 as the example; we
/// pin it here so the kernel and CLI agree on the number.
pub const STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT: u32 = 10;

/// **`v2_extended_gaps.md §3.2` — typed mid-session output kinds.**
///
/// Each variant has a fixed schema the kernel validates before
/// accepting; over-budget / malformed inputs are rejected with
/// `FAIL_STRUCTURED_OUTPUT_INVALID` and the audit chain records
/// no row.
///
/// **Wire shape (INV-IPC-BINCODE).** Default external-tag serde
/// representation. The canonical IPC encoder is `bincode::serde`
/// which does NOT support `serde::deserialize_any` and therefore
/// rejects the internally-tagged `#[serde(tag = "kind")]`
/// projection at the first wire round-trip with
/// `Decode(Serde(AnyNotSupported))` (regression caught against an
/// earlier draft of this enum). External-tag JSON projections
/// look like `{"ProgressReport": {...}}`; the variant-tag string
/// dashboards and SQL pivot on is exposed via
/// [`Self::variant_tag`] as a stable lower-snake-case projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StructuredOutputKind {
    /// Mid-session progress snapshot. Stored as an audit event +
    /// `structured_outputs` row; the operator dashboard renders it
    /// as a progress bar / file list.
    ProgressReport {
        /// Workspace-relative paths the executor has touched so far.
        /// Kernel caps the list at `STRUCTURED_OUTPUT_MAX_PATH_LIST_LEN`
        /// entries and each entry at `STRUCTURED_OUTPUT_MAX_PATH_BYTES`.
        files_modified: Vec<String>,
        /// Number of tests that passed in the most-recent run.
        tests_passing: u32,
        /// Number of tests that failed in the most-recent run.
        tests_failing: u32,
        /// Self-reported confidence in `[0.0, 1.0]`. Kernel CLAMPS
        /// to the closed range — values outside are NOT rejected
        /// (a confidence of `1.5` would block a perfectly-good
        /// progress report on a typo); they are coerced.
        confidence: f32,
    },

    /// "I found something the operator should see." Stored on the
    /// audit chain + `structured_outputs`. Critical-severity flags
    /// MAY trigger an escalation — the kernel handler is the
    /// authority on routing.
    DiagnosticFlag {
        /// Severity. Drives notification routing.
        severity: DiagnosticSeverity,
        /// Operator-facing message. Capped at
        /// `STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES`. Larger
        /// payloads are TRUNCATED with a "<truncated>" marker
        /// rather than rejected so a verbose model output still
        /// surfaces something operator-actionable.
        message: String,
        /// Optional file path or `path:line` reference pointing to
        /// the relevant source location. Workspace-relative;
        /// kernel applies the same path-list cap.
        evidence: Option<String>,
    },

    /// Executor → Orchestrator handoff. Stored on the task row so
    /// the orchestrator's KSB (§2.4) includes it when activating
    /// the next task.
    TaskSummary {
        /// Final commit SHA for the executor's work. Validated as a
        /// 40-char hex `CommitSha` at admission time.
        commit_sha: String,
        /// Workspace-relative paths the executor authored. Same
        /// caps as `ProgressReport.files_modified`.
        changed_paths: Vec<String>,
        /// One-paragraph rationale (≤
        /// `STRUCTURED_OUTPUT_MAX_APPROACH_BYTES`). Larger ⇒
        /// truncated with marker.
        approach: String,
    },
}

/// Operator-facing severity for [`StructuredOutputKind::DiagnosticFlag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Critical,
}

impl DiagnosticSeverity {
    /// Stable wire-string projection used by the SQL `kind` column
    /// and the CLI display. Lower-snake-case so it matches the
    /// JSON `serde(rename_all = "snake_case")` projection.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

impl StructuredOutputKind {
    /// Stable wire-string projection of the variant tag (the
    /// JSON `kind` field). Used by the SQL `kind` column and
    /// the CLI display.
    pub fn variant_tag(&self) -> &'static str {
        match self {
            Self::ProgressReport { .. } => "progress_report",
            Self::DiagnosticFlag { .. } => "diagnostic_flag",
            Self::TaskSummary { .. } => "task_summary",
        }
    }

    /// Apply the V2 §3.2 kernel-side validation: clamp confidence,
    /// truncate over-cap strings/lists, normalise the payload
    /// before storing it. Returns `Err(reason)` only for
    /// fundamentally-malformed inputs (e.g. a `commit_sha` that
    /// is not 40 hex chars); recoverable cap violations are
    /// silently truncated so a verbose agent never blocks on a
    /// `FAIL_STRUCTURED_OUTPUT_INVALID`.
    pub fn validate_and_normalise(&mut self) -> Result<(), &'static str> {
        match self {
            Self::ProgressReport {
                files_modified,
                confidence,
                ..
            } => {
                Self::truncate_path_list(files_modified);
                if !confidence.is_finite() {
                    *confidence = 0.0;
                }
                *confidence = confidence.clamp(0.0, 1.0);
            }
            Self::DiagnosticFlag {
                message, evidence, ..
            } => {
                Self::truncate_string(message, STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES);
                if let Some(ev) = evidence {
                    Self::truncate_string(ev, STRUCTURED_OUTPUT_MAX_PATH_BYTES);
                }
            }
            Self::TaskSummary {
                commit_sha,
                changed_paths,
                approach,
            } => {
                if commit_sha.len() != 40 || !commit_sha.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("task_summary.commit_sha must be 40 hex chars");
                }
                // Normalise to lowercase for the audit chain.
                commit_sha.make_ascii_lowercase();
                Self::truncate_path_list(changed_paths);
                Self::truncate_string(approach, STRUCTURED_OUTPUT_MAX_APPROACH_BYTES);
            }
        }
        Ok(())
    }

    fn truncate_path_list(list: &mut Vec<String>) {
        if list.len() > STRUCTURED_OUTPUT_MAX_PATH_LIST_LEN {
            list.truncate(STRUCTURED_OUTPUT_MAX_PATH_LIST_LEN);
        }
        for s in list.iter_mut() {
            Self::truncate_string(s, STRUCTURED_OUTPUT_MAX_PATH_BYTES);
        }
    }

    fn truncate_string(s: &mut String, max_bytes: usize) {
        if s.len() <= max_bytes {
            return;
        }
        // Walk back to a UTF-8 boundary that fits.
        let mut idx = max_bytes;
        while idx > 0 && !s.is_char_boundary(idx) {
            idx -= 1;
        }
        s.truncate(idx);
        s.push_str("…<truncated>");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_severity_wire_strings_pinned() {
        assert_eq!(DiagnosticSeverity::Info.as_str(), "info");
        assert_eq!(DiagnosticSeverity::Warning.as_str(), "warning");
        assert_eq!(DiagnosticSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn variant_tag_matches_serde_rename() {
        let p = StructuredOutputKind::ProgressReport {
            files_modified: vec![],
            tests_passing: 0,
            tests_failing: 0,
            confidence: 0.0,
        };
        assert_eq!(p.variant_tag(), "progress_report");
        let d = StructuredOutputKind::DiagnosticFlag {
            severity: DiagnosticSeverity::Info,
            message: "x".to_owned(),
            evidence: None,
        };
        assert_eq!(d.variant_tag(), "diagnostic_flag");
        let t = StructuredOutputKind::TaskSummary {
            commit_sha: "0".repeat(40),
            changed_paths: vec![],
            approach: "fix".to_owned(),
        };
        assert_eq!(t.variant_tag(), "task_summary");
    }

    #[test]
    fn validate_clamps_confidence_and_truncates_lists() {
        let mut k = StructuredOutputKind::ProgressReport {
            files_modified: (0..1024).map(|i| format!("p/{i}")).collect(),
            tests_passing: 100,
            tests_failing: 0,
            confidence: 1.5,
        };
        k.validate_and_normalise().unwrap();
        match k {
            StructuredOutputKind::ProgressReport {
                files_modified,
                confidence,
                ..
            } => {
                assert_eq!(files_modified.len(), STRUCTURED_OUTPUT_MAX_PATH_LIST_LEN);
                assert_eq!(confidence, 1.0);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn validate_truncates_diagnostic_message_at_cap() {
        let huge = "x".repeat(STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES * 4);
        let mut k = StructuredOutputKind::DiagnosticFlag {
            severity: DiagnosticSeverity::Critical,
            message: huge,
            evidence: None,
        };
        k.validate_and_normalise().unwrap();
        match k {
            StructuredOutputKind::DiagnosticFlag { message, .. } => {
                assert!(message.len() < STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES * 4);
                assert!(message.ends_with("…<truncated>"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn validate_rejects_non_hex_commit_sha() {
        let mut k = StructuredOutputKind::TaskSummary {
            commit_sha: "not-a-real-sha".to_owned(),
            changed_paths: vec![],
            approach: "fix".to_owned(),
        };
        let err = k.validate_and_normalise().unwrap_err();
        assert!(err.contains("commit_sha"));
    }

    #[test]
    fn validate_normalises_uppercase_commit_sha() {
        let mut k = StructuredOutputKind::TaskSummary {
            commit_sha: "A".repeat(40),
            changed_paths: vec![],
            approach: "fix".to_owned(),
        };
        k.validate_and_normalise().unwrap();
        match k {
            StructuredOutputKind::TaskSummary { commit_sha, .. } => {
                assert_eq!(commit_sha, "a".repeat(40));
            }
            _ => unreachable!(),
        }
    }

    /// Bincode + serde_json round-trip for every variant — pins the
    /// wire shape so the kernel and CLI agree on the on-the-wire
    /// projection. INV-IPC-BINCODE: we use the default external-tag
    /// representation so `bincode::serde` round-trips
    /// (`#[serde(tag = "kind")]` would surface
    /// `Decode(Serde(AnyNotSupported))`); the human-friendly
    /// snake-case tag is exposed separately via
    /// [`StructuredOutputKind::variant_tag`].
    #[test]
    fn round_trip_bincode_and_json_for_every_variant() {
        let kinds: Vec<StructuredOutputKind> = vec![
            StructuredOutputKind::ProgressReport {
                files_modified: vec!["a.rs".into(), "b.rs".into()],
                tests_passing: 10,
                tests_failing: 1,
                confidence: 0.75,
            },
            StructuredOutputKind::DiagnosticFlag {
                severity: DiagnosticSeverity::Warning,
                message: "be careful here".into(),
                evidence: Some("src/lib.rs:42".into()),
            },
            StructuredOutputKind::TaskSummary {
                commit_sha: "0".repeat(40),
                changed_paths: vec!["x.rs".into()],
                approach: "split into helper".into(),
            },
        ];
        for k in kinds {
            let bytes = bincode::serde::encode_to_vec(&k, bincode::config::standard()).unwrap();
            let (back, _): (StructuredOutputKind, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(back, k, "bincode round-trip");

            let s = serde_json::to_string(&k).unwrap();
            let back: StructuredOutputKind = serde_json::from_str(&s).unwrap();
            assert_eq!(back, k, "json round-trip");
        }
    }

    /// `DiagnosticSeverity` is a unit-only enum and uses
    /// `rename_all = "snake_case"` so the JSON projection uses
    /// `"info" / "warning" / "critical"`. This shape is wire-stable
    /// — the SQL `severity` column and the operator dashboard
    /// match on it byte-for-byte.
    #[test]
    fn diagnostic_severity_json_round_trip_uses_snake_case() {
        for s in [
            DiagnosticSeverity::Info,
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Critical,
        ] {
            let json: String = serde_json::to_string(&s).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", s.as_str()),
                "DiagnosticSeverity JSON must match its as_str() projection"
            );
            let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(back, s);
        }
    }
}
