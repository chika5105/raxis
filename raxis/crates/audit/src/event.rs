// raxis-audit-tools::event — AuditEvent and AuditEventKind.
//
// Normative reference: kernel-store.md §2.5.2 "Audit record format"
//
// Every kernel state mutation that succeeds emits exactly one AuditEvent
// AFTER the SQLite commit (write ordering invariant, §2.5.2).
//
// The AuditEvent JSON wire format is:
//   {
//     "seq":           42,
//     "event_id":      "<uuid-v4>",
//     "event_kind":    "IntentAccepted",
//     "session_id":    "<uuid or null>",
//     "task_id":       "<task-id or null>",
//     "initiative_id": "<initiative-id or null>",
//     "payload":       { ... },
//     "emitted_at":    1714500000,
//     "prev_sha256":   "<hex SHA-256 of previous line bytes>"
//   }

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// AuditEvent — the top-level record type written to JSONL.
// ---------------------------------------------------------------------------

/// A single audit record, serialised as one JSONL line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonically increasing counter, kernel-local. Reset only at genesis.
    /// Gaps indicate a reconciliation gap (crash between commit and JSONL write).
    pub seq: u64,

    /// Random UUID v4 per event; never reused.
    pub event_id: Uuid,

    /// Human-readable event discriminant (matches AuditEventKind variant name).
    pub event_kind: String,

    /// The session associated with this event, if any.
    pub session_id: Option<String>,

    /// The task associated with this event, if any.
    pub task_id: Option<String>,

    /// The initiative associated with this event, if any.
    pub initiative_id: Option<String>,

    /// Event-kind-specific structured payload.
    pub payload: serde_json::Value,

    /// Unix seconds (UTC) when this record was emitted.
    pub emitted_at: i64,

    /// SHA-256 of the raw bytes of the previous JSONL line (including '\n').
    /// "0000...0000" (64 zeroes) for the first record in a segment.
    pub prev_sha256: String,
}

// ---------------------------------------------------------------------------
// SecurityViolationClass — V2 adversarial-input taxonomy.
// v2-deep-spec.md §Step 13 ("Separating Adversarial Input from Alignment
// Failures").
//
// The discriminator is serialised by `#[serde(tag = "kind")]` on
// `AuditEventKind::SecurityViolation` (via the inner enum's PascalCase
// rename), giving the on-wire shape:
//
//     {
//       "kind": "SecurityViolation",
//       "session_id": "...",
//       "violation_class": "FrameMalformation" | "AuthorityProbe" | "Replay",
//       ...
//     }
//
// Forensic tools and the notification router match on `violation_class`
// directly to decide severity (e.g. AuthorityProbe is a higher-priority
// page than FrameMalformation, because it implies the attacker has a
// valid session token).
// ---------------------------------------------------------------------------

/// Adversarial-input class for `AuditEventKind::SecurityViolation`.
///
/// **Spec drift contract.** Adding a new variant requires the static
/// dispatch matrix or pre-auth blocklist (v2-deep-spec.md §Step 15)
/// to be updated in lock-step. The pinned-count test below catches
/// silent additions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SecurityViolationClass {
    /// Class 1 — the received bytes are not valid bincode for any known
    /// `IntentRequest` variant. The frame is rejected before
    /// deserialization completes. `session_id` is `None` because the
    /// frame did not parse far enough to identify a session.
    FrameMalformation,
    /// Class 2 — a session with a valid session token submits an intent
    /// its `session_agent_type` is not authorized to send (e.g. an
    /// Executor sending `ActivateSubTask`). The static dispatch matrix
    /// catches this before any handler runs (v2-deep-spec.md §Step 20).
    AuthorityProbe,
    /// Class 3 — an envelope_nonce already seen, OR a sequence_number
    /// ≤ the session's stored sequence_number, where the kernel has
    /// cryptographic evidence the frame is a hostile replay rather
    /// than a benign retry of an in-flight request. (Benign retries
    /// route to `ReplayRejected`, not here.)
    Replay,
}

impl SecurityViolationClass {
    /// All variants — pinned-count regression target. See the test
    /// `security_violation_class_variant_count_is_pinned` for the
    /// drift contract.
    pub const ALL: [Self; 3] = [
        Self::FrameMalformation,
        Self::AuthorityProbe,
        Self::Replay,
    ];

    /// Stable on-wire string name (matches the PascalCase serde
    /// projection). Useful for log aggregation pipelines that match
    /// on string discriminators rather than parsing JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FrameMalformation => "FrameMalformation",
            Self::AuthorityProbe    => "AuthorityProbe",
            Self::Replay            => "Replay",
        }
    }
}

impl std::fmt::Display for SecurityViolationClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// AuditEventKind — structured payload constructors for every event type.
//
// These are the normative event kinds referenced throughout kernel-core.md
// and kernel-store.md. Each variant serialises into the `payload` field.
// The variant name (as_str) is written into `event_kind`.
// ---------------------------------------------------------------------------

/// Structured payload for each type of kernel audit event.
/// Serialised into `AuditEvent.payload` using serde_json.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "PascalCase")]
pub enum AuditEventKind {
    // --- Kernel lifecycle ---
    KernelStarted {
        data_dir: String,
        policy_epoch: u64,
        schema_version: i64,
    },
    KernelStopped {
        reason: String,
    },

    /// V2 agent-runtime substrate selection record.
    ///
    /// Emitted exactly once per kernel boot, immediately after
    /// `KernelStarted`, by `kernel/src/main.rs`. Records which
    /// substrate (`firecracker-1.x` / `apple-vz-14.x` / etc.) the
    /// kernel admitted at boot and what tier its
    /// `verify_isolation_guarantee` reported. Audit replay tooling
    /// uses this row to attribute every subsequent `SessionVmSpawned`
    /// event to a known substrate.
    ///
    /// Defined in `extensibility-traits.md §3.8` (boot-order step 6a).
    IsolationSubstrateSelected {
        /// `Backend::backend_id` of the admitted substrate. Stable
        /// string; audit dashboards group on it.
        backend_id: String,
        /// PascalCase tier the substrate self-reported and that
        /// passed admission. Always one of
        /// `R1Conformant{,Strong}` / `WasmSandbox` / `FallbackOnly`
        /// — never `TestOnly`, since production refuses
        /// absolutely.
        tier: String,
        /// `true` iff this admission required the operator-supplied
        /// `--unsafe-fallback-isolation` flag (paired with the
        /// adjacent `IsolationFallbackBypass` event).
        fallback_bypass: bool,
    },

    /// V2 fallback-substrate bypass record.
    ///
    /// Emitted exactly once per kernel boot iff
    /// `IsolationSubstrateSelected.fallback_bypass == true`. Records
    /// the operator-acknowledged downgrade of the isolation
    /// substrate below the `R-1` bar (e.g. running on a Linux host
    /// without `/dev/kvm` and accepting the namespace fallback).
    ///
    /// Defined in `extensibility-traits.md §3.5` and §3.8 — the
    /// kernel is required to emit this event BEFORE admitting any
    /// session under a `FallbackOnly` substrate.
    IsolationFallbackBypass {
        /// Operator-supplied reason string from the boot flag.
        /// Empty string if the operator gave none.
        reason: String,
        /// `Backend::backend_id` of the admitted substrate.
        backend_id: String,
    },

    /// V2 boot-time substrate refusal record. Emitted by
    /// `kernel/src/main.rs` immediately before the kernel exits
    /// with `BOOT_ERR_ISOLATION_UNAVAILABLE` (exit code 64) when
    /// `isolation_select::select_isolation_backend` returns
    /// `Err`. Required by `extensibility-traits.md §3.8` so the
    /// audit chain records why a kernel boot was aborted —
    /// otherwise downstream tooling would see only the genesis
    /// row + the absence of `KernelStarted`.
    IsolationSubstrateRefused {
        /// Stringified `SelectError` from the isolation selector.
        /// Free-form for now (forensic only); pinned-string
        /// encoding can land later if dashboards need it.
        reason: String,
    },

    /// V2 per-session VM-spawn record. Emitted by
    /// `raxis-session-spawn::SessionSpawnService::spawn_session`
    /// AFTER `IsolationBackend::spawn` returns Ok and AFTER the
    /// per-session credential proxies + egress-admission listener
    /// are bound. Pairs 1:1 with a later `SessionVmExited`.
    ///
    /// Defined in `extensibility-traits.md §3.5, §3.8` (boot-step 6a
    /// references) and `credential-proxy.md §2`.
    ///
    /// **Why this is a separate variant from `SessionCreated`.**
    /// `SessionCreated` (V1) records an *operator-facing* row in the
    /// `sessions` SQL table; it lands at `OperatorRequest::
    /// CreateSession` time, BEFORE any VM is booted. `SessionVmSpawned`
    /// records the V2 *substrate-facing* moment when the agent VM
    /// actually started — those two moments are temporally and
    /// architecturally distinct (a session row may exist for hours
    /// before its VM boots; the V2 substrate may refuse to boot a
    /// session row that V1 admission accepted).
    SessionVmSpawned {
        /// Session id the VM was booted for. References both
        /// `sessions.session_id` and the spawn-service's per-VM
        /// session table.
        session_id:        String,
        /// Owning task id (`None` for the canonical Orchestrator
        /// session, which has no `[[tasks]]` row).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        task_id:           Option<String>,
        /// Owning initiative id; pins the spawn into the
        /// initiative's lineage.
        initiative_id:     String,
        /// `Backend::backend_id()` of the substrate that booted the
        /// VM. Stable string; pairs with `IsolationSubstrateSelected`
        /// at audit-replay time.
        backend_id:        String,
        /// `EgressTier` that the substrate enforces for this VM,
        /// stringified PascalCase. Operator dashboards key on this
        /// to surface "Tier1Tproxy" vs "Tier2CredProxy" sessions.
        egress_tier:       String,
        /// `host:port` of the per-session egress-admission listener
        /// the in-guest tproxy phones home to. Loopback in dev,
        /// vsock-shaped at V2 GA. Recorded for forensic replay
        /// (so a misbehaving session's admission stream can be
        /// correlated back to its kernel-side listener).
        admission_loopback: String,
        /// Number of credential proxies bound for this session.
        /// Each is itself recorded by an adjacent
        /// `CredentialProxyStarted` event; this field is the
        /// audit-replay-side cardinality check.
        credential_proxies: u32,
    },

    /// V2 per-session VM-exit record. Emitted by
    /// `raxis-session-spawn::SessionSpawnService::terminate_session`
    /// AFTER `IsolationSession::shutdown` returns and BEFORE the
    /// credential-proxy `CredentialProxyStopped` events fire (so
    /// audit-chain readers see the VM-exit-then-cleanup ordering).
    ///
    /// Pairs 1:1 with `SessionVmSpawned`. `audit-paired-writes.md`
    /// lints enforce the pairing.
    SessionVmExited {
        /// Echo of the spawn event's `session_id`.
        session_id:    String,
        /// Stable, PascalCase classification of the exit. One of:
        ///   * `"GracefulExit"` — guest PID 1 returned a code.
        ///   * `"SignalKilled"` — substrate sent a signal.
        ///   * `"Timeout"`      — grace expired without exit.
        ///   * `"BackendError"` — substrate-internal failure.
        /// Closed set; new variants land here AND in
        /// `IsolationError::ExitStatus` together.
        signal_class:  String,
        /// Numeric exit code reduced from `ExitStatus`. Mapping is
        /// pinned by `raxis-session-spawn::exit_status_code` —
        /// dashboards rely on the specific numbers (e.g. -2 for
        /// `BackendError`).
        exit_code:     i32,
        /// Free-form payload from the substrate when
        /// `signal_class == "BackendError"`. `None` for the other
        /// classes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        backend_error: Option<String>,
    },

    /// V2 `elastic-vm-scaling.md §3.2` — per-attempt record of a
    /// transient-failure respawn against the same `VmSpec`. Emitted
    /// once per retry by the kernel's bounded-retry loop in
    /// `session_spawn_orchestrator`, BEFORE the next
    /// `SessionVmSpawned` (or before the terminating
    /// `SessionVmFailedFinal`).
    ///
    /// Pairs N:1 with the eventual `SessionVmSpawned` (success) or
    /// the terminating `SessionVmFailedFinal` (exhausted attempts).
    /// The kernel writes the attempt counter starting at `1` for
    /// the first respawn (i.e. the original spawn that failed is
    /// attempt 0; the first retry is attempt 1).
    ///
    /// **Honours INV-ELASTIC-02 / INV-ELASTIC-07.** A
    /// `SessionVmRespawnAttempted` is NEVER emitted for an
    /// `IsolationFailureClass::Permanent` failure — those go
    /// straight to `SessionVmFailedFinal`. The `failure_class`
    /// field carries the projected class verbatim
    /// (`"Transient"` only, by construction; the field exists on
    /// the wire so audit-replay readers can sanity-check the
    /// invariant).
    SessionVmRespawnAttempted {
        /// Session id the respawn targets. References
        /// `sessions.session_id`.
        session_id:        String,
        /// Owning task id (`None` for the canonical Orchestrator
        /// session, which has no `[[tasks]]` row).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        task_id:           Option<String>,
        /// Owning initiative id; pins the respawn into the
        /// initiative's lineage.
        initiative_id:     String,
        /// 1-indexed attempt counter. The first retry is
        /// `attempt = 1`; the original spawn is implicitly
        /// `attempt = 0` and is reflected by the previous
        /// `SessionVmSpawned` / failure-emitting code path.
        attempt:           u32,
        /// Operator-policy ceiling (`policy.[elastic].
        /// transient_retry_max_attempts`) at the time of this
        /// respawn. Recorded so dashboards can surface
        /// "attempt 2 of 3"-style progress without re-reading
        /// the policy snapshot.
        max_attempts:      u32,
        /// Failure-class projection of the previous attempt's
        /// `IsolationError` per `IsolationError::classify` —
        /// always `"Transient"` by construction.
        failure_class:     String,
        /// Substrate-facing reason string from the previous
        /// attempt. Unstructured (the substrate's diagnostic
        /// message) — operator-facing diagnostics only; the
        /// kernel does not key behaviour off the value.
        previous_reason:   String,
        /// Backoff applied before this respawn, in milliseconds.
        /// Computed as `min(initial * 2^(attempt-1), max)` per
        /// `elastic-vm-scaling.md §3.2`. Recorded so audit-replay
        /// can confirm the backoff schedule honoured the policy
        /// caps.
        backoff_ms:        u32,
    },

    /// V2 `elastic-vm-scaling.md §3.2 / §3.3` — terminal failure of
    /// the kernel-side spawn lifecycle. Emitted exactly once per
    /// failed spawn lineage when one of:
    ///
    /// * The spawn surfaced an `IsolationFailureClass::Permanent`
    ///   (no retries; INV-ELASTIC-02).
    /// * The bounded retry loop exhausted
    ///   `transient_retry_max_attempts` (INV-ELASTIC-06).
    ///
    /// **Pairing.** `SessionVmFailedFinal` is mutually exclusive
    /// with `SessionVmSpawned` for the same `(session_id,
    /// attempt-lineage)`: a session that lands a `SessionVmSpawned`
    /// never emits `SessionVmFailedFinal` for the same lineage,
    /// and vice versa. The audit-paired-writes invariant
    /// (`audit-paired-writes.md §4`) is extended in this commit
    /// to cover this either/or rule.
    SessionVmFailedFinal {
        /// Session id whose spawn lineage failed.
        session_id:        String,
        /// Owning task id (`None` for the canonical Orchestrator
        /// session).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        task_id:           Option<String>,
        /// Owning initiative id; pins the failure into the
        /// initiative's lineage.
        initiative_id:     String,
        /// Total attempts taken before giving up (1-indexed; e.g.
        /// `1` when a `Permanent` first-attempt failure surfaces,
        /// `transient_retry_max_attempts + 1` when retries
        /// exhaust).
        total_attempts:    u32,
        /// Failure-class projection of the LAST attempt per
        /// `IsolationError::classify` (one of `"Transient"` or
        /// `"Permanent"`). When `"Transient"`, the lineage hit
        /// the retry-exhaustion path; when `"Permanent"`, the
        /// lineage short-circuited at the first failure.
        failure_class:     String,
        /// Final substrate-facing reason string. Audit-replay
        /// dashboards surface this as the operator diagnostic.
        final_reason:      String,
    },

    /// V2 `elastic-vm-scaling.md §4` — admitted scaling decision.
    /// Emitted by the dynamic-scaling engine after a scale-up
    /// (`direction = "Up"`, requires `policy.[elastic].enabled =
    /// true`) or a next-spawn scale-down (`direction = "Down"`,
    /// allowed even when `enabled = false`).
    ///
    /// **Pairing.** A scale-up emits this event in the SAME audit
    /// transaction as the new `SessionVmSpawned` — INV-ELASTIC-03
    /// (write-then-emit). A scale-down is recorded once per
    /// next-spawn the bias applies to.
    SessionVmScaleEvent {
        /// Session id the scaling decision applies to. For
        /// scale-up via respawn-with-larger this is the NEW
        /// session id; the previous session's
        /// `SessionVmExited` is emitted independently as part of
        /// the drain.
        session_id:        String,
        /// Owning task id (`None` for the orchestrator session).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        task_id:           Option<String>,
        /// Owning initiative id.
        initiative_id:     String,
        /// `"Up"` or `"Down"`. Stable PascalCase string;
        /// dashboards key on this. INV-ELASTIC-05 requires that
        /// `direction = "Up"` is mechanically forbidden when
        /// the resolved `elastic` flag is `false` for this
        /// session — emitting that combination is a kernel bug.
        direction:         String,
        /// Pre-decision vCPU count.
        prev_vcpus:        u32,
        /// Post-decision vCPU count (`prev_vcpus * 2` clamped to
        /// the policy ceiling for scale-up; ≤ `prev_vcpus` for
        /// scale-down).
        new_vcpus:         u32,
        /// Pre-decision memory in MiB.
        prev_memory_mb:    u32,
        /// Post-decision memory in MiB (`prev_memory_mb * 3 / 2`
        /// clamped to the policy ceiling for scale-up; ≤
        /// `prev_memory_mb` for scale-down).
        new_memory_mb:     u32,
        /// Substrate-agnostic reason for the decision. Free-form
        /// audit-string; the kernel does not key behaviour off the
        /// value. Examples: `"InferenceTokenBurnRate"`,
        /// `"MemoryPressure"`, `"NextSpawnUnderUtilizedBias"`.
        reason:            String,
    },

    /// V2 `elastic-vm-scaling.md §4.3` — scaling decision deferred
    /// because the per-minute rate limit
    /// (`policy.[elastic].max_concurrent_scaling_events_per_minute`)
    /// would be exceeded. INV-ELASTIC-04: a soft event, never a
    /// hard failure — the spawn lifecycle continues against the
    /// pre-scale-up `VmSpec`.
    SessionVmScaleDeferred {
        /// Session id the deferred decision applied to.
        session_id:        String,
        /// Owning task id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        task_id:           Option<String>,
        /// Owning initiative id.
        initiative_id:     String,
        /// What the engine was about to do (`"Up"` or `"Down"`)
        /// before the rate-limit check denied admission.
        direction:         String,
        /// Stable PascalCase reason tag. Closed set:
        ///   * `"RateLimit"` — the per-minute window was full.
        /// New reasons land here AND in the kernel-side decision
        /// engine in lockstep.
        reason:             String,
    },

    /// A security boundary the kernel enforces was violated AT the
    /// moment a fail-closed guard surfaced the violation. Distinct
    /// from "policy admission rejected an operator's request"
    /// (those are `PlanRejected` / IPC error paths) — this variant
    /// records mechanical, kernel-internal trust-boundary checks
    /// that detected tampering or version-mismatch.
    ///
    /// Normative references:
    /// * `planner-harness.md §4.5` (`INV-PLANNER-HARNESS-02`) —
    ///   `kind = "ReviewerImageDigestMismatch"`.
    /// * `planner-harness.md §4.7` (`INV-PLANNER-HARNESS-05`) —
    ///   `kind = "OrchestratorImageDigestMismatch"`.
    /// * `system-requirements.md §3` — the operator-facing
    ///   "Tampered or version-mismatched canonical image on disk"
    ///   error mode.
    ///
    /// **Wire shape.** `violation_kind` is a stable PascalCase string
    /// so audit dashboards and `raxis doctor canonical-images`
    /// consume one taxonomy. The kind set is closed (drift-protected
    /// by tests in `raxis-canonical-images::CanonicalImageKind::audit_kind`).
    /// The field name is `violation_kind` rather than `kind` because
    /// the enum's `#[serde(tag = "kind")]` already reserves the
    /// `kind` JSON key for the variant discriminant
    /// (`"SecurityViolationDetected"`); a same-named struct field
    /// would collide on the wire. `expected` and `actual` are
    /// lowercase-hex 64-character SHA-256 strings when the violation
    /// is digest-shaped; both fields are `None` for non-digest
    /// violations to keep this variant useful as a forward-compatible
    /// umbrella for future `INV-*` enforcement seams.
    SecurityViolationDetected {
        /// PascalCase kind tag (closed set; see doc-comment above).
        violation_kind: String,
        /// Hex-encoded SHA-256 the kernel expected, when applicable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected: Option<String>,
        /// Hex-encoded SHA-256 the kernel observed, when applicable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actual: Option<String>,
        /// Forensic-only: the path or symbolic location the kernel
        /// was attempting to verify. Free-form to keep the variant
        /// useful for non-filesystem checks (e.g. an in-memory
        /// constant mismatch).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },

    // --- Initiative lifecycle ---
    InitiativeCreated {
        initiative_id: String,
        plan_hash: String,
        signed_by: String,
        signed_at: i64,
    },
    PlanApproved {
        initiative_id: String,
        task_count: usize,
    },
    PlanRejected {
        initiative_id: String,
    },
    /// V2_GAPS §12.4 — `OperatorRequest::DryRunAdmit` (V2.4) emits
    /// exactly one `DryRunAdmitted` audit event per call so the
    /// operator's local audit chain reflects which plan was
    /// dry-run admitted at which time. This is the **only**
    /// write side-effect of `DryRunAdmit`; per
    /// `operator-ergonomics.md §12.3` (low-priority informational
    /// audit allowance) the handler is otherwise read-only.
    ///
    /// The event is intentionally **rate-limit-free** in V2.4
    /// (operators almost always run dry-run by hand or under CI
    /// gating). V3 will layer per-operator rate limiting onto the
    /// kernel's audit-rate-limit table; the wire shape below is
    /// forward-compatible.
    DryRunAdmitted {
        /// Operator-supplied submitter id (mirrors the
        /// `OperatorRequest::DryRunAdmit::submitted_by` wire field;
        /// historical V1 `CreateInitiative` carried the same field
        /// pre-V2.5).
        submitted_by:   String,
        /// Active policy epoch at the moment of dry-run; lets a
        /// later forensic query line dry-run results up against
        /// the epoch the live submission ran under.
        policy_epoch:   u64,
        /// SHA-256 hex of the `plan_toml` bytes — the same
        /// digest the kernel would compute at live submission.
        plan_sha256:    String,
        /// The would-be `target_ref` resolved from the plan and
        /// the policy `[git]` section.
        target_ref:     String,
        /// Number of non-fatal warnings the handler returned.
        warnings_count: u32,
        /// Workspace lane the plan declared.
        lane_id:        String,
        /// Number of `[[tasks]]` entries in the plan.
        task_count:     u32,
    },
    /// kernel-store.md §2.5.8 `path_scope_override` semantics:
    /// emitted by `approve_plan` for **every** task in the plan that has
    /// `path_scope_override = true`. Records the override at the moment
    /// the kernel honors it, so an auditor can reconstruct exactly which
    /// task IDs ran with `effective_allow == UNIVERSAL` and under whose
    /// operator approval. The signing tool's `--allow-path-override`
    /// acknowledgement is a separate gate (Part 4 normative) but does
    /// NOT replace this kernel-side audit emit — offline-signing
    /// workflows still produce this event when the kernel processes
    /// the plan.
    ///
    /// `approving_operator_display_name` is the operator's
    /// `display_name` from the policy bundle at the moment of emit
    /// (a snapshot, not a live join). It is `None` for two reasons
    /// only:
    ///   1. The event was written before the display-name plumbing
    ///      shipped (legacy segment); the CLI render layer falls
    ///      back to `operator_certificates` lookup and marks the
    ///      result as historical.
    ///   2. The kernel could not resolve the fingerprint at emit
    ///      time (extremely rare — would require the operator that
    ///      just authenticated and signed the plan to have been
    ///      removed from the bundle a microsecond later; only
    ///      realistic in tight epoch-rotation races).
    /// See `kernel-store.md` §2.5.2 "Operator display-name fields"
    /// for the cross-variant convention.
    PathScopeOverrideApplied {
        initiative_id: String,
        task_id: String,
        approving_operator: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approving_operator_display_name: Option<String>,
    },
    InitiativeStateChanged {
        initiative_id: String,
        from_state: String,
        to_state: String,
    },
    /// `triggered_by_operator_display_name` mirrors the convention
    /// described on `PathScopeOverrideApplied` above. Both fields are
    /// `Option` because `triggered_by_operator` itself is optional
    /// (kernel-internal aborts have no operator) — when the
    /// fingerprint is `None` the display name is necessarily `None`
    /// as well.
    InitiativeAborted {
        initiative_id: String,
        triggered_by_operator: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        triggered_by_operator_display_name: Option<String>,
    },

    // --- Task lifecycle ---
    TaskAdmitted {
        task_id: String,
        initiative_id: String,
        lane_id: String,
    },
    TaskStateChanged {
        task_id: String,
        from_state: String,
        to_state: String,
        actor: String,
        policy_epoch: u64,
    },

    // --- Intent acceptance ---
    IntentAccepted {
        task_id: String,
        session_id: String,
        intent_kind: String,
        base_sha: Option<String>,
        head_sha: Option<String>,
        sequence_number: u64,
        remaining_units: u64,
    },
    IntentRejected {
        task_id: String,
        session_id: String,
        intent_kind: String,
        error_code: String,
        sequence_number: u64,
    },

    /// **V2 (Step 30 + integration-merge.md §7).** Emitted when the
    /// kernel admits an `IntentKind::IntegrationMerge` and updates
    /// `initiatives.current_sha` to `commit_sha` (Phase 1 of the
    /// transactional boundary, before the host-side main-branch
    /// fast-forward).
    ///
    /// **Attribution semantics (Step 30).** When
    /// `operator_assisted = true`, the merge SHA was authored by
    /// the human operator under the linked `escalation_id`
    /// (Path 2: manual host-side `git commit`); the RAXIS audit
    /// chain attributes the **structural request** to the
    /// Orchestrator session and the **physical authorship** to the
    /// operator escalation. Together with the `EscalationConsumed`
    /// event that immediately precedes this one, the chain is
    /// self-contained for INV-05 forensic reproducibility — an
    /// auditor never needs to correlate against `git log --author`.
    ///
    /// `operator_assisted = false` (the default) covers both
    /// (a) conflict-free merges and
    /// (b) Path 1 LLM-guided resolutions (the Orchestrator
    ///     re-attempts the merge using an operator hint and produces
    ///     a fresh SHA; the resolution flow is structural to the
    ///     Orchestrator, not the operator, so no attribution
    ///     adjustment is warranted).
    ///
    /// Forward compat: `operator_assisted` and `escalation_id` are
    /// `default = false` / `default = None` on deserialisation so
    /// pre-Step-30 segments parse cleanly.
    IntegrationMergeCompleted {
        initiative_id: String,
        session_id: String,
        commit_sha: String,
        previous_sha: String,
        /// Step 30 attribution: true ⇔ this merge was admitted with
        /// `IntentRequest.resolved_via_escalation = Some(_)` and the
        /// kernel verified Check 6b (`escalations.status = 'Consumed'`,
        /// `class = 'MergeConflict'`, `session_id =` submitting
        /// session).
        #[serde(default)]
        operator_assisted: bool,
        /// Step 30 attribution: the consumed escalation that produced
        /// this commit (Path 2 manual operator commit). `None` when
        /// `operator_assisted = false`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        escalation_id: Option<String>,
        /// V2.5 `integration-merge.md §11.3` — the fully-qualified
        /// `target_ref` (e.g. `refs/heads/main`) the kernel attempted
        /// to advance during Phase 2. Recorded so boot recovery can
        /// re-run `commit_merge_to_target_ref` against the same ref
        /// without re-resolving plan-fields (which may not be
        /// repopulated yet at recovery time).
        ///
        /// `#[serde(default)]` for forensic replay only — pre-V2.5
        /// segments lack the field; recovery filters by
        /// `git_apply_pending = 1` (column added by migration 16),
        /// which is `0` for those rows, so recovery never has to act
        /// on a missing-target_ref event.
        #[serde(default)]
        target_ref: String,
    },

    /// V2 `v2_extended_gaps.md §1.2` — emitted when the kernel's
    /// host-side fast-forward of the operator-configured `target_ref`
    /// after a successful `IntegrationMerge` (Phase 1) fails. The
    /// underlying `commit_merge_to_target_ref` is non-mutating on
    /// failure (locks-and-retries, atomic ref update via
    /// `git update-ref`), so this audit event is purely an alarm bell
    /// for the operator: the merge commit is still recorded in the
    /// initiative worktree, the SQLite intent has been committed, but
    /// `<target_ref>` does NOT yet point at it. The operator either
    /// hand-rolls the fast-forward or runs the next-boot recovery
    /// pass that re-drives `commit_merge_to_target_ref` (the call is
    /// idempotent on success).
    ///
    /// `category` discriminates so dashboards/alerts can route:
    ///   * `"target_ref_advanced_concurrently"` — someone else moved
    ///     `target_ref` during the merge and the fast-forward is no
    ///     longer trivial.
    ///   * `"unopenable_main_repo"` — the central main repo is
    ///     missing or corrupt.
    ///   * `"missing_commit"` — the merge commit was not visible to
    ///     the main repo (orchestrator never pushed up).
    ///   * `"git_failed"` — git plumbing returned a non-zero exit.
    ///   * `"deadline_exceeded"` — wall-clock timeout while taking
    ///     the cross-process worktree lock.
    ///   * `"other"` — any other classification.
    MergeFastForwardFailed {
        /// Initiative the fast-forward belongs to.
        initiative_id: String,
        /// Commit SHA the kernel attempted to fast-forward to.
        commit_sha:    String,
        /// Operator-configured target ref (`refs/heads/<name>`).
        target_ref:    String,
        /// Stable-wire short string for the failure class.
        category:      String,
        /// Free-form reason captured from the failure path.
        /// Truncated at 4 KiB to keep audit rows bounded.
        reason:        String,
    },

    /// V2_GAPS §C6 — emitted when the kernel begins a push to the
    /// configured upstream remote after a successful Phase 3 of
    /// `IntegrationMerge`. The matching success → `PushCompleted` or
    /// failure → `PushFailed` follows.
    PushAttempted {
        /// Initiative the push belongs to.
        initiative_id: String,
        /// Commit SHA being pushed.
        commit_sha:    String,
        /// Remote name (`"origin"` typically).
        remote:        String,
        /// Refspec (`"refs/heads/main:refs/heads/main"` typically).
        refspec:       String,
    },

    /// V2_GAPS §C6 — emitted on `git push` exit-0. Carries the
    /// short summary line from `git push`'s stderr so an operator
    /// querying audit can see the upstream's confirmation message
    /// without re-running.
    PushCompleted {
        /// Initiative the push belongs to.
        initiative_id: String,
        /// Commit SHA that was pushed.
        commit_sha:    String,
        /// Remote name.
        remote:        String,
        /// Refspec.
        refspec:       String,
        /// First-line summary of the push (`git push` stderr).
        summary:       String,
    },

    /// V2_GAPS §C6 — emitted on `git push` exit-non-zero or on
    /// deadline / spawn failure. The kernel's parent transaction is
    /// already committed; `PushFailed` is purely informational and
    /// does NOT roll back the merge.
    PushFailed {
        /// Initiative the push belongs to.
        initiative_id: String,
        /// Commit SHA the kernel attempted to push.
        commit_sha:    String,
        /// Remote name (or `""` if the failure happened before a
        /// remote was selected — e.g. policy misconfiguration).
        remote:        String,
        /// Refspec (or `""` for early failures).
        refspec:       String,
        /// Stable-wire short string for the failure class. One of:
        /// `"push_failed"` (non-zero exit), `"spawn_failed"`
        /// (subprocess could not start), `"deadline_exceeded"`
        /// (wall-clock timeout), `"unopenable_repo"` (main repo
        /// missing).
        category:      String,
        /// Free-form reason captured from the failure path.
        /// Truncated at 4 KiB to keep audit rows bounded.
        reason:        String,
    },

    // --- Session management ---
    /// Emitted when the kernel creates a new planner session row.
    ///
    /// **V2 attribution chain (v2-deep-spec.md §Step 7).** A V2 session
    /// carries four fields that uniquely tie its work back to a
    /// human-signed plan at a known policy epoch:
    ///
    ///   * `session_id`         — this session row.
    ///   * `initiative_id`      — the initiative this session belongs to
    ///                            (None for legacy V1 free-running sessions
    ///                            that predate hierarchical orchestration).
    ///   * `plan_bundle_sha256` — SHA-256 of the canonical V2 plan bundle
    ///                            (`plan-bundle-sealing.md §8.2`). For
    ///                            legacy V1 initiatives this carries
    ///                            `plan_artifact_sha256` and the V1 chain
    ///                            (`plan_artifact_sha256 →
    ///                            signed_plan_artifacts → plan.sig →
    ///                            operator pubkey`) remains valid for
    ///                            forensic reproducibility. The CLI render
    ///                            layer disambiguates by joining against
    ///                            the table that currently holds the
    ///                            artifact.
    ///   * `policy_epoch`       — kernel policy epoch at session-creation
    ///                            time (None for legacy V1 segments that
    ///                            predate the field).
    ///   * `session_agent_type` — V2 agent kind ("Orchestrator" |
    ///                            "Executor" | "Reviewer"), None for V1.
    ///
    /// Reconstruction (V2): commit SHA → CompleteTask audit event →
    /// session_id → SessionCreated event → plan_bundle_sha256 →
    /// plan_bundles row → bundle signature → operator public key. The
    /// chain is cryptographically complete and requires no out-of-band
    /// data. (V1: same, but through `signed_plan_artifacts` /
    /// `plan_artifact_sha256` per the legacy chain.)
    ///
    /// **Forward compat.** All four V2 fields are `Option`-typed with
    /// `default` and `skip_serializing_if = "Option::is_none"` so legacy
    /// segments that wrote SessionCreated without them still
    /// deserialise cleanly under the new struct shape (see the
    /// `legacy_session_created_without_v2_fields_still_deserializes`
    /// test below).
    SessionCreated {
        session_id: String,
        role: String,
        lineage_id: String,
        worktree_root: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initiative_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        plan_bundle_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_agent_type: Option<String>,
    },
    /// `revoked_by_display_name` follows the cross-variant
    /// convention in `kernel-store.md` §2.5.2 "Operator display-name
    /// fields": present when the kernel could resolve `revoked_by` to
    /// an operator entry in the policy bundle at emit time, absent
    /// otherwise (legacy segment, or an operator that vanished from
    /// policy between authentication and emit — extremely rare).
    SessionRevoked {
        session_id: String,
        revoked_by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revoked_by_display_name: Option<String>,
    },

    // --- Delegation ---
    /// `granted_by_display_name` follows the cross-variant
    /// convention in `kernel-store.md` §2.5.2 "Operator display-name
    /// fields".
    DelegationGranted {
        delegation_id: String,
        session_id: String,
        capability_class: String,
        expires_at: i64,
        granted_by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        granted_by_display_name: Option<String>,
    },
    DelegationMarkedStale {
        delegation_id: String,
        session_id: String,
        capability_class: String,
        reason: String,
    },

    // --- Witness / gate ---
    WitnessAccepted {
        verifier_run_id: String,
        task_id: String,
        gate_type: String,
        result_class: String,
        evaluation_sha: String,
    },
    WitnessRejected {
        verifier_run_id: String,
        task_id: String,
        reason: String,
    },
    VerifierProcessFailed {
        task_id: String,
        exit_code: Option<i32>,
        gate_type: String,
    },

    /// V2 Step 25 — emitted after a `SubmitReview` SQLite commit, when
    /// the cross-Reviewer aggregator
    /// (`raxis-kernel::initiatives::review_aggregation::
    /// compute_aggregate_review_verdict`) has reached a TERMINAL
    /// outcome for the Executor task that the just-completed Reviewer
    /// depends on.
    ///
    /// **Class.** Single-class (pure observability). The aggregator
    /// performs no SQLite mutation; the underlying state transition
    /// (Reviewer's `tasks.review_verdict` write + `Running →
    /// Completed`) was already paired with `TaskStateChanged` inside
    /// the `SubmitReview` transaction. This event is the
    /// audit-replay-side anchor that records the *aggregated*
    /// (logical-AND across N parallel Reviewers) verdict the kernel
    /// observed once every sibling Reviewer had submitted.
    ///
    /// **Emission rule.** Emitted at most once per `SubmitReview`
    /// commit, AND only when the aggregator transitions out of
    /// `Pending` — i.e. when the just-completed Reviewer was the
    /// LAST sibling to submit. Earlier submissions (still
    /// `Pending`) are silent. `NoSuccessors` is impossible here
    /// (the calling Reviewer is itself a successor) but is
    /// surfaced as a defense-in-depth verdict for malformed plans.
    ///
    /// **Why this is single-class.** Per
    /// `audit-paired-writes.md §4`, paired-class events MUST mutate
    /// SQLite state. The aggregator is a pure read predicate; the
    /// only state mutation it observes is the Reviewer's own
    /// `tasks.review_verdict` row, which was already paired with
    /// `TaskStateChanged` inside the SubmitReview transaction. The
    /// downstream consequences (`KernelPush::AllReviewersPassed` /
    /// `KernelPush::ReviewRejected`) are deferred to gap §12.1
    /// (push transport); this audit row is the kernel-side anchor
    /// the future emitter call site reads.
    ///
    /// Defined in `v2-deep-spec.md §Step 25` and
    /// `verifier-processes.md §11`.
    ReviewAggregationCompleted {
        /// Executor task whose Reviewer set was aggregated. Joins
        /// `task_dag_edges` to find every sibling Reviewer.
        executor_task_id: String,
        /// The Reviewer whose `SubmitReview` triggered the
        /// aggregator (i.e. the LAST sibling to submit). Provides
        /// the causal anchor between this event and its preceding
        /// `TaskStateChanged { state: Completed }` for the same
        /// Reviewer task.
        triggered_by_reviewer_task_id: String,
        /// Number of Reviewer successors aggregated. Always ≥ 1
        /// (the triggering Reviewer is itself counted); 0 implies
        /// `NoSuccessors` (defense-in-depth, malformed plan).
        reviewer_count: u32,
        /// Stable string verdict — exactly one of:
        /// `"AllPassed"` / `"AtLeastOneRejected"` / `"NoSuccessors"`.
        /// `"Pending"` is NEVER emitted (the aggregator is silent
        /// while any Reviewer is still pending).
        verdict: String,
    },

    // --- Escalation ---
    EscalationSubmitted {
        escalation_id: String,
        task_id: String,
        class: String,
        lineage_id: String,
    },
    /// `approved_by_display_name` follows the cross-variant
    /// convention in `kernel-store.md` §2.5.2 "Operator display-name
    /// fields".
    EscalationApproved {
        escalation_id: String,
        approved_by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approved_by_display_name: Option<String>,
    },
    /// `denied_by_display_name` follows the cross-variant convention
    /// in `kernel-store.md` §2.5.2 "Operator display-name fields".
    EscalationDenied {
        escalation_id: String,
        denied_by: String,
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        denied_by_display_name: Option<String>,
    },
    EscalationTimedOut {
        escalation_id: String,
    },
    EscalationConsumed {
        escalation_id: String,
        approval_token_id: String,
        action_hash: String,
        policy_epoch: u64,
    },
    LineageQuarantined {
        lineage_id: String,
        trigger_count: u64,
    },
    /// Emitted when a planner submission would push a lineage past
    /// `policy.escalation_max_per_window`. The submission is rejected
    /// (`EscalationResponse::Rejected { RateLimitExceeded }`) and the
    /// lineage's `quarantine_trigger_count` advances by one.
    /// philosophy.md §"Escalation — rate-limiter fires" calls this out
    /// as a required audit kind.
    EscalationRateLimitExceeded {
        lineage_id: String,
        /// The window-local count *after* the rejected attempt is logged
        /// — i.e. it is exactly `escalation_max_per_window + 1` for the
        /// first overflow and stays at the cap for the rest of the
        /// window. Useful for forensic reconstruction.
        attempted_count: u64,
        window_start: i64,
    },

    // --- Policy epoch ---
    /// `triggered_by_display_name` follows the cross-variant
    /// convention in `kernel-store.md` §2.5.2 "Operator display-name
    /// fields". The lookup is performed against the **incoming**
    /// bundle (i.e. the one being installed by this advance), not
    /// the previous one — so an operator who renames themselves as
    /// part of the rotation is recorded under the new name.
    PolicyEpochAdvanced {
        new_epoch_id: u64,
        policy_sha256: String,
        triggered_by: String,
        delegations_marked_stale: u64,
        sessions_invalidated: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        triggered_by_display_name: Option<String>,
    },
    PolicyAdvanceRejected {
        reason: String,
        artifact_epoch: Option<u64>,
        current_epoch: u64,
    },
    PolicyAdvanceFailed {
        reason: String,
        new_epoch_id: u64,
    },

    // --- IPC auth / replay prevention ---
    ReplayRejected {
        session_id: String,
        sequence_num: u64,
        reason: String,
    },

    // --- V2 security: adversarial-input separation (v2-deep-spec.md §Step 13)
    /// Emitted when the kernel detects genuine adversarial input on the
    /// VSock IPC channel — distinct from `IntentRejected` (alignment
    /// failures by an honest planner). The separation matters because
    /// adversarial events represent compromised-binary or hostile-process
    /// signals that warrant terminal connection actions
    /// (v2-deep-spec.md §Step 14: SecurityViolation closes the connection
    /// and revokes the session token), while `IntentRejected` is a
    /// routine LLM-misalignment event a well-functioning planner emits.
    ///
    /// Three classes route here (`SecurityViolationClass`):
    ///
    ///   1. `FrameMalformation` — the received bytes are not valid
    ///      bincode for any known IntentRequest variant; the frame is
    ///      rejected before deserialization completes. Triggered by a
    ///      compromised planner binary or a hostile process injecting
    ///      raw bytes onto the VSock channel.
    ///   2. `AuthorityProbe` — a session with a valid session token
    ///      submits an intent its `session_agent_type` is not authorized
    ///      to send (e.g. an Executor sending `ActivateSubTask`). The
    ///      static dispatch matrix (v2-deep-spec.md §Step 20) catches
    ///      this before any handler runs.
    ///   3. `Replay` — an envelope_nonce already seen, OR a
    ///      sequence_number ≤ the session's stored sequence_number.
    ///      Distinct from `ReplayRejected` (alignment), which fires
    ///      when an honest planner retries an in-flight intent: the
    ///      `Replay` SecurityViolation class is reserved for cases
    ///      where the kernel has cryptographic evidence of a hostile
    ///      replay (e.g. the same nonce reused from a different
    ///      sequence number, indicating a captured-and-replayed frame
    ///      not a benign retry).
    ///
    /// `raw_frame_sha256` is SHA-256 of the raw on-wire bytes of the
    /// rejected frame. The raw bytes are NOT stored (they may contain
    /// untrusted attacker-controlled data); the hash enables forensic
    /// correlation with packet captures or other side-channel evidence.
    /// `frame_size` is included for triage filtering.
    ///
    /// CLI surface: `raxis audit query --event-type SecurityViolation`.
    SecurityViolation {
        /// `Some(...)` for class 2 + 3 (the kernel had a session row to
        /// match against). `None` for class 1 (the frame did not even
        /// parse far enough to identify a session).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
        violation_class: SecurityViolationClass,
        raw_frame_sha256: String,
        frame_size: u32,
        /// VSock CID of the peer that submitted the offending frame.
        /// Populated for every class so the operator can correlate to a
        /// specific VM or host process. `None` only for the legacy UDS
        /// path (V1 sessions; pre-VSock frames carry no CID).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_cid: Option<u32>,
    },

    // --- Recovery ---
    ReconciliationGap {
        missing_seq: u64,
        reconstructed_event: String,
        reconstructed: bool,
    },
    TaskBlockedForRecovery {
        task_id: String,
        block_reason: String,
    },
    DelegationSignatureUnverifiable {
        delegation_id: String,
        expected_signer_unknown_in_current_policy: bool,
    },

    // --- Gateway supervisor (peripherals.md §3.2 "Spawn model") ---
    /// Emitted by `gateway::supervisor::spawn_and_supervise` each time
    /// it spawns a fresh `raxis-gateway` subprocess. `attempt` is
    /// 1-indexed across the kernel-process lifetime; an `attempt` > 1
    /// means a previous gateway crashed and the supervisor respawned.
    /// `token_prefix` is the first 8 hex chars of the new
    /// `gateway_process_token` — the full token never appears in
    /// audit records (it is an in-process secret).
    GatewaySpawned {
        token_prefix: String,
        binary_path: String,
        attempt: u32,
    },
    /// The supervised gateway subprocess exited (clean or otherwise).
    /// `exit_code = None` when the child was killed by a signal or
    /// could not be reaped. Followed by either another `GatewaySpawned`
    /// (back-off + respawn) or `GatewayQuarantined` (max crashes hit).
    GatewayCrashed {
        token_prefix: String,
        exit_code: Option<i32>,
        attempt: u32,
    },
    /// The supervisor exceeded `[gateway].max_consecutive_respawns`
    /// and stopped respawning. Subsequent `FetchRequest`s short-circuit
    /// to `error: "GatewayUnavailable"` until the operator restarts
    /// the kernel.
    GatewayQuarantined {
        reason: String,
        total_attempts: u32,
    },
    /// Best-effort kernel→gateway signal (e.g. `EpochAdvanced`) failed
    /// to deliver. Per kernel-core.md §`policy_manager.rs` Phase 3 this
    /// MUST NOT roll back the epoch advance — the gateway's own
    /// failure-closed contract (`peripherals.md` §3.2 "Domain allowlist
    /// re-validation") is the second line of defence (gateway returns
    /// `PolicyReloadFailed` until its on-disk reload succeeds).
    ///
    /// `signal` is the `GatewayMessage` variant short-name (e.g.
    /// `"EpochAdvanced"`). `reason` is a stable short string from
    /// `GatewayCallError::category()`: `"unavailable"`, `"dropped"`,
    /// `"gateway_error"`, `"unexpected_reply"`.
    GatewaySignalFailed {
        signal: String,
        new_epoch_id: Option<u64>,
        reason: String,
    },

    // --- Notifications (cli-readonly.md §5.6.3) ---
    /// A per-channel notification handler returned an error. The
    /// originating mutation is unaffected — handler failure NEVER
    /// aborts the parent transaction (cli-readonly.md §5.6.3).
    ///
    /// `channel_id` matches `[[notifications.channels]].id` from the
    /// active policy. `event_kind` is the `AuditEventKind` discriminant
    /// of the event we tried to deliver. `reason` is a short, stable
    /// classification string (`"io"`, `"target_invalid"`, `"network"`,
    /// `"upstream_rejected"`, `"credential_unavailable"`,
    /// `"backpressure"`, `"circuit_open"`); the verbose error text
    /// goes to the kernel stderr log.
    NotificationDeliveryFailed {
        channel_id: String,
        event_kind: String,
        reason:     String,
    },

    /// V2_GAPS §C4 — successful notification delivery.
    ///
    /// `channel_kind` is one of `"Shell" | "File" | "Email" |
    /// "Webhook" | "Sidecar"` (the wire enum's variant string).
    /// `upstream_trace_id` is `Some(_)` only for kinds that surface
    /// an upstream id (Sidecar `trace_id`, SMTP `Message-ID`,
    /// Webhook `X-Trace-Id` if present); `None` for Shell/File which
    /// have no upstream. `delivery_ms` is wall-clock latency including
    /// retries; `attempts` counts how many retries the dispatcher
    /// did (1 for first-try success).
    NotificationDelivered {
        channel_id:        String,
        channel_kind:      String,
        event_kind:        String,
        source_event_id:   String,
        upstream_trace_id: Option<String>,
        delivery_ms:       u64,
        attempts:          u32,
    },

    // --- Provider circuit breaker (provider-failure-handling.md §6.3) -----
    /// Emitted on every circuit-breaker state-class transition. State
    /// transitions execute inside a single `BEGIN IMMEDIATE` SQLite
    /// transaction that atomically updates `provider_circuit_state`
    /// AND inserts this audit event (INV-PROVIDER-08). A kernel crash
    /// between the two cannot leave a moved breaker with no audit
    /// record — either both land or neither does.
    ///
    /// **Emission rule.** This event is written when and only when
    /// `from_state != to_state` OR `consecutive_failures` crossed
    /// `trip_threshold`. A `Closed → Closed` success does NOT emit
    /// (the breaker counter resets silently). A `HalfOpen → Closed`
    /// probe-success DOES emit (state-class transition).
    ///
    /// **Manual reset.** When an operator runs `raxis providers
    /// reset --provider P --model M`, the kernel forces the breaker
    /// to `Closed` and emits this event with
    /// `trigger = "ManualReset"` + `operator` populated.
    ///
    /// Defined in `provider-failure-handling.md §6.3` and the
    /// `provider_circuit_state` DDL (migration 15, §6.4).
    CircuitBreakerStateChanged {
        /// Provider key (e.g. `"anthropic"`, `"openai"`).
        provider:             String,
        /// Model key (e.g. `"claude-opus-4.7"`).
        model:                String,
        /// State before this transition.
        from_state:           String,
        /// State after this transition.
        to_state:             String,
        /// Consecutive retryable failures at the moment of transition.
        consecutive_failures: u32,
        /// Error category of the failure that triggered the transition
        /// (e.g. `"Unavailable"`, `"Timeout"`). `None` for success-
        /// driven transitions (`HalfOpen → Closed`) and manual resets.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_failure_kind:    Option<String>,
        /// When the circuit will expire its `Open` state and promote
        /// to `HalfOpen`. `None` when `to_state != "Open"`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        open_expires_at_ms:   Option<u64>,
        /// What caused this transition. One of:
        /// `"FailureThreshold"` — consecutive failures reached trip_threshold.
        /// `"ProbeSuccess"` — half-open probe succeeded.
        /// `"ProbeFailure"` — half-open probe failed, re-opened.
        /// `"OpenWindowElapsed"` — lazy Open → HalfOpen promotion.
        /// `"ManualReset"` — operator ran `raxis providers reset`.
        trigger:              String,
        /// Operator fingerprint when `trigger = "ManualReset"`.
        /// `None` for all other triggers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operator:             Option<String>,
    },


    // --- Operator certificates (kernel-store.md §2.5.7, security-model.md §cert-lifecycle) ---
    /// Emitted by `policy_manager::advance_epoch` (and the genesis path)
    /// for every cert-bound `OperatorEntry` mirrored into the
    /// `operator_certificates` view table on a successful epoch
    /// install. The audit-chain mirror is the authoritative ledger of
    /// "who is currently a cert-bound operator at epoch N" — the
    /// `operator_certificates` SQLite table is a denormalised view
    /// optimised for reads, but if it is ever lost (disk corruption,
    /// schema rebuild) it can be reconstructed by replaying these
    /// audit records.
    ///
    /// Field semantics:
    ///
    /// * `pubkey_fingerprint` — SHA-256[:16] hex of `pubkey_hex`.
    /// * `epoch_id` — the policy epoch this cert is now scoped to.
    /// * `cert_kind` — `"Standard"` or `"EmergencyRecovery"` (matches
    ///   `CertKind::as_str`). The field is named `cert_kind` (NOT just
    ///   `kind`) because the audit-event enum uses `#[serde(tag =
    ///   "kind")]` for the variant discriminator, and a payload field
    ///   with the same key would collide on the JSON wire.
    /// * `display_name` — operator label (free-form).
    /// * `not_before` — unix seconds; cert validity start (sentinel `0`
    ///   for `EmergencyRecovery`).
    /// * `not_after` — unix seconds; cert validity end (sentinel `0`
    ///   for `EmergencyRecovery`).
    /// * `permitted_ops` — list of operator op names this cert is
    ///   allowed to invoke. Already normalised by the policy bundle
    ///   (e.g. `EmergencyRecovery` is structurally pinned to
    ///   `["RotateEpoch"]`).
    /// * `force_misconfig_bypass` — `true` if the operator entry opted
    ///   into bypassing structural cert-validation errors. The bypass
    ///   itself emits a separate `OperatorCertMisconfigBypassed` event
    ///   for each rule that was relaxed.
    /// * `previous_fingerprint` — `Some(fp)` when this cert install is a
    ///   rotation (the operator ran `raxis cert install --replace-for
    ///   <previous_fp> --new-cert <path>`), `None` for the very first
    ///   install of a fresh operator entry. The kernel infers a
    ///   rotation by diffing the old and new policy bundles at epoch
    ///   advance: if an entry's `pubkey_hex` is unchanged but the
    ///   embedded cert's `self_sig_hex` (or any other cert field) is
    ///   different, it's a rotation and we record the prior cert's
    ///   fingerprint so the audit chain captures continuity. (The
    ///   pubkey is unchanged across a rotation by INV-CERT-04 — see
    ///   `cli/src/commands/cert.rs::install`.)
    OperatorCertInstalled {
        pubkey_fingerprint:     String,
        epoch_id:               u64,
        cert_kind:              String,
        display_name:           String,
        not_before:             i64,
        not_after:              i64,
        permitted_ops:          Vec<String>,
        force_misconfig_bypass: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_fingerprint:   Option<String>,
    },

    /// Emitted at policy load when a structural cert-validation error
    /// would normally fail the load BUT the operator entry has set
    /// `force_misconfig_bypass = true`. The bypass is honoured (the
    /// epoch advances) AND this audit event records every individual
    /// invariant that was relaxed, so an auditor can reconstruct the
    /// exact set of rules the operator chose to override.
    ///
    /// Self-signature failures and pubkey/fingerprint mismatches are
    /// NEVER bypassable (they would let an attacker spoof an
    /// operator's identity); those errors fail-closed regardless of
    /// `force_misconfig_bypass` and never produce this event.
    ///
    /// `violations` is the verbatim `Display` string of every
    /// structural error that was relaxed for this entry, in the
    /// order the validator surfaced them. The strings come straight
    /// from the `CertError` Display impls and are intentionally
    /// human-readable (so a forensic auditor reading the chain sees
    /// the same wording the operator saw at validate time).
    OperatorCertMisconfigBypassed {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        cert_kind:          String,
        display_name:       String,
        violations:         Vec<String>,
    },

    /// Emitted by the cert-check runtime sweep when a Standard cert is
    /// inside its Expiring zone (i.e. `now >= not_after - warn_window`
    /// AND `now < not_after`). The operator IPC dispatcher emits this
    /// AT MOST ONCE PER EPOCH for a given cert — the sweep is gated by
    /// an in-process dedupe set keyed on `(pubkey_fingerprint, epoch_id)`.
    /// Subsequent ops by the same operator in the same epoch are
    /// silently allowed without re-emitting (so a chatty operator
    /// doesn't flood the chain).
    ///
    /// The op the operator was about to invoke is included so an
    /// auditor can correlate the warning with downstream activity.
    OperatorCertExpiringSoon {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        op:                 String,
        not_after:          i64,
        days_remaining:     i64,
    },

    /// Emitted by the cert-check runtime sweep when a Standard cert is
    /// inside its Grace zone (i.e. `now >= not_after` AND
    /// `now < not_after + grace_window`). Same once-per-epoch dedupe
    /// posture as `OperatorCertExpiringSoon`. Operations are still
    /// permitted in the Grace zone — this event is the "this is your
    /// last chance to rotate" warning before the cert hits the
    /// Expired zone.
    OperatorCertInGracePeriod {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        op:                 String,
        not_after:          i64,
        grace_ends_at:      i64,
    },

    /// Emitted by the cert-check runtime sweep when an op is DENIED
    /// because the cert is in its Expired zone (i.e.
    /// `now >= not_after + grace_window`). The IPC dispatcher returns
    /// `FAIL_CERT_EXPIRED` to the operator and writes this audit
    /// event in the same Phase-1.5 emit step as the rejection
    /// response. Unlike the Expiring/Grace events this is NOT
    /// deduped — every denied op produces one record so an auditor
    /// can see exactly which operations were attempted post-expiry.
    OperatorCertExpiredOpDenied {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        op:                 String,
        not_after:          i64,
        expired_at:         i64,
    },

    /// Emitted when an `EmergencyRecovery` cert is used to invoke
    /// any operator op (in v1 always `RotateEpoch` because of the
    /// structural pin). This is the audit hook for the break-glass
    /// posture: emergency-cert use is never silent, so an operator
    /// who legitimately rotated the epoch via the emergency key
    /// has a record they can present, and an attacker who
    /// compromises the key cannot use it without leaving a trace.
    EmergencyOperatorUsed {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        op:                 String,
    },

    // --- Break-glass (kernel-core.md §2.3 `src/breakglass.rs`) -----------------
    //
    // V1 Tier 4: emergency operator override mechanism. Activation
    // suspends gate enforcement (claims, witnesses, policy approval)
    // and is surrounded by ceremony, logging, and TTL.
    //
    // INV-BG-1 — every action taken under an active break-glass MUST
    // emit a `BreakglassAction` row referencing the activation_id.
    //
    // INV-BG-2 — `BreakglassActivated` requires two distinct operator
    // signatures; the kernel verifies both against the bundled
    // `[[operators]]` registry before persisting the activation.
    /// Two-operator-signed break-glass activation accepted by the
    /// kernel. The activation suspends gate enforcement until
    /// `expires_at` (TTL-bounded) or until a `BreakglassDeactivated`
    /// event lands first.
    BreakglassActivated {
        /// UUID-v4 generated by the kernel when the activation is
        /// admitted; every subsequent `BreakglassAction` references
        /// it.
        activation_id: String,
        /// Operator pubkey fingerprints (32-hex) of both signers, in
        /// canonical sort order. Always exactly two entries.
        activated_by:  Vec<String>,
        /// Wallclock at admission, RFC-3339 UTC.
        activated_at:  String,
        /// Wallclock at TTL expiry, RFC-3339 UTC. The kernel refuses
        /// `expires_at > activated_at + breakglass_max_duration`.
        expires_at:    String,
        /// Free-form one-line operator-supplied justification (256
        /// bytes max; redactor sanitises CRLF to spaces).
        justification: String,
    },

    /// Break-glass activation deactivated before TTL. One operator
    /// signature is sufficient for deactivation — the ceremony only
    /// guards activation.
    BreakglassDeactivated {
        /// Activation_id originally returned by `BreakglassActivated`.
        activation_id:  String,
        /// Pubkey fingerprint of the operator who deactivated.
        deactivated_by: String,
        /// Wallclock at deactivation, RFC-3339 UTC.
        deactivated_at: String,
    },

    /// One bypassed action under an active break-glass. The kernel's
    /// gate-evaluation pipeline emits this *before* short-circuiting
    /// the gate decision, so the audit chain records every
    /// emergency-bypass use.
    BreakglassAction {
        /// Activation_id this action was admitted under.
        activation_id:      String,
        /// Session id (or `"-"` for global actions like a CLI policy
        /// load).
        session_id:         String,
        /// Free-form one-line description of the bypassed action,
        /// e.g. `"intent admission for task=… kind=CompleteTask"`.
        action_description: String,
        /// Wallclock at action time, RFC-3339 UTC.
        action_at:          String,
    },

    // --- Read-only CLI: redaction reveal (cli-readonly.md §5.4.2 / §5.7.2) ---
    /// Emitted by the read-only CLI when an operator runs a command
    /// with `--reveal-paths` (or any future redaction-bypass flag).
    /// This is the **only** audit event the read-only CLI is allowed
    /// to write into the chain — see cli-readonly.md §5.7.3.
    ///
    /// Recording the read makes path-list disclosure observable
    /// without forbidding it: operators can still debug, but they
    /// leave a trace in the same hash-chained log as every kernel
    /// state mutation.
    ///
    /// Field semantics:
    ///   * `actor`   — who triggered the reveal. The CLI uses the
    ///     operator's pubkey fingerprint (32 hex chars, matches the
    ///     `[meta].signed_by` form in `policy.toml`) when an
    ///     `--operator-key` is supplied; otherwise falls back to
    ///     `cli:<unix-user>`.
    ///   * `table`   — logical table the data came from
    ///     (e.g. `"task_plan_fields"`).
    ///   * `column`  — which redacted column was revealed
    ///     (e.g. `"path_allowlist"`, `"path_export_globs"`, or the
    ///     synthetic `"all"` for a whole-row reveal).
    ///   * `command` — the CLI invocation that triggered the reveal,
    ///     stored as a short, stable string (e.g. `"inspect"`).
    ///
    /// The companion `task_id` foreign-key column on `AuditEvent`
    /// carries the task whose paths were revealed; this payload
    /// duplicates it so log readers don't have to project two fields
    /// to surface the read target in JSON output.
    PathReadAccessed {
        actor:    String,
        table:    String,
        column:   String,
        task_id:  String,
        command:  String,
    },

    // --- Initiative quarantine (kernel-store.md §2.5.8) -------------------
    /// Emitted when an operator individually quarantines an initiative
    /// via `raxis initiative quarantine <id>`. The IPC dispatcher
    /// inserts a row into `initiative_quarantines` and writes this
    /// audit event in the same Phase-1.5 emit step. Subsequent
    /// `IntentRequest`s against this initiative are rejected with
    /// `FAIL_INITIATIVE_QUARANTINED` by the planner intent gate.
    ///
    /// `quarantined_by` is the operator pubkey_fingerprint (32 hex
    /// chars) issuing the command. `reason` is a free-form label;
    /// NULL when the operator did not supply `--reason`.
    /// `quarantined_by_display_name` follows the cross-variant
    /// convention in `kernel-store.md` §2.5.2 "Operator display-name
    /// fields".
    InitiativeQuarantined {
        initiative_id:  String,
        quarantined_by: String,
        reason:         Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quarantined_by_display_name: Option<String>,
    },

    /// Rollup event written by `raxis operator quarantine-plans-by
    /// <fingerprint>`. Surfaces the SWEEP itself (one record), with
    /// the count of newly-quarantined initiatives + the target
    /// operator. Each individual collateral quarantine still emits
    /// its own `InitiativeQuarantined` event with the
    /// `quarantined_by` field set to the rotating operator's
    /// fingerprint — that's the per-row record. This event is the
    /// "the operator pressed the big red button" header.
    /// `quarantined_by_display_name` and `target_display_name`
    /// follow the cross-variant convention in `kernel-store.md`
    /// §2.5.2 "Operator display-name fields". Both are independently
    /// optional because the *target* of a quarantine sweep may have
    /// already been removed from the active policy (e.g. the
    /// operator just rotated `target_fingerprint` out of policy
    /// before pressing the big red button to clean up the
    /// initiatives that operator approved); in that case the
    /// `target_display_name` falls back to a CLI-side lookup with
    /// the historical-cert annotation per `kernel-store.md` §2.5.2.
    OperatorQuarantineSwept {
        target_fingerprint: String,
        quarantined_by:     String,
        count:              u64,
        reason:             Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quarantined_by_display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_display_name: Option<String>,
    },

    // --- CredentialBackend resolutions (extensibility-traits.md §4.5
    //     conformance contract — every `resolve` MUST emit one such
    //     event; every `rotate` MUST emit `CredentialRotated`).
    /// Emitted when a `CredentialBackend::resolve` returns. `success`
    /// reflects whether the resolve produced a value; the credential
    /// VALUE is never recorded — only the name and the consumer's
    /// identity. Required by `INV-CRED-AUDIT-01` (per §4.5 of
    /// `extensibility-traits.md`): every resolve emits exactly one
    /// audit event.
    ///
    /// Field semantics:
    ///   * `name` — the policy-declared credential name
    ///     (e.g. `"postgres-staging"`, `"providers.anthropic-prod"`).
    ///   * `consumer_kind` — stable short string identifying the
    ///     consumer subsystem (`"gateway"`, `"credential_proxy"`,
    ///     `"isolation_kernel_signer"`, `"operator_cli"`).
    ///   * `consumer_id` — disambiguator within the consumer kind:
    ///     for `gateway` the provider_id; for `credential_proxy` the
    ///     `<session_id>:<proxy_type>:<proxy_port>`; for `operator_cli`
    ///     the operator pubkey fingerprint. Free-form short string.
    ///   * `backend_kind` — stable short string identifying the
    ///     `CredentialBackend` impl (`"file"`, `"vault"`,
    ///     `"aws_secrets_manager"`, `"azure_key_vault"`, `"pkcs11"`).
    ///   * `success` — whether the resolution returned `Ok`. Failure
    ///     reasons (`NotFound`, `PermissionDenied`, `BackendUnavailable`)
    ///     are NOT included as variants here — operators that want
    ///     post-mortem failure reasons read the kernel logs alongside
    ///     this event. The wire-stable boolean is sufficient for
    ///     forensic audit.
    CredentialAccessed {
        name:          String,
        consumer_kind: String,
        consumer_id:   String,
        backend_kind:  String,
        success:       bool,
    },

    /// Emitted when a `CredentialBackend::rotate` succeeds. The new
    /// VALUE is never recorded — only the name and the operator
    /// pubkey fingerprint that authorised the rotation.
    /// `INV-CRED-AUDIT-02`: every successful rotation emits one such
    /// event AFTER the underlying store has acknowledged the write
    /// (atomic-rename for `file`, KV v2 versioned write for `vault`).
    ///
    /// Failed rotations do NOT emit this event; they surface as
    /// `CredentialError` returned to the operator CLI.
    CredentialRotated {
        name:                String,
        actor_fingerprint:   String,
        backend_kind:        String,
    },

    /// V2_GAPS §C7 — emitted when `raxis credential add` writes a new
    /// credential file. Carries the public-facing metadata only; the
    /// credential VALUE is never recorded. Forensic queries match
    /// on `name` to follow a credential through its lifecycle
    /// (`CredentialRegistered` → `CredentialAccessed`* →
    /// `CredentialRotated`* → `CredentialRemoved`).
    ///
    /// Field semantics:
    ///   * `name`             — policy-declared credential name.
    ///   * `proxy_type`       — operator-supplied `--type` label
    ///     (`postgres`, `mysql`, `redis`, `k8s`, `aws`, `gcp`,
    ///     `azure`, ...). Empty string when the operator did not
    ///     pass `--type`.
    ///   * `environment`      — operator-supplied `--env` label
    ///     (matches `[[environment_gates]].label` in policy).
    ///     Empty string when omitted.
    ///   * `actor_fingerprint`— operator pubkey 32-hex prefix
    ///     (matches `policy.toml [meta].signed_by`).
    ///   * `backend_kind`     — concrete backend impl name (today:
    ///     always `"file"`).
    CredentialRegistered {
        name:               String,
        proxy_type:         String,
        environment:        String,
        actor_fingerprint:  String,
        backend_kind:       String,
    },

    /// V2_GAPS §C7 — emitted when `raxis credential remove` deletes
    /// a credential file. `forced` distinguishes the defensive
    /// (`--force` was supplied) from the (V3-future) "gracefully
    /// detected zero active sessions" path.
    CredentialRemoved {
        name:               String,
        actor_fingerprint:  String,
        backend_kind:       String,
        forced:             bool,
    },

    /// V2_GAPS §D1 — emitted when `raxis cert revoke` writes a
    /// signed revocation record under `<data_dir>/revocations/`.
    /// The record itself is the durable artifact; this audit event
    /// is the wire-stable signal that other observability paths
    /// (`raxis log`, the operator inbox) match on.
    OperatorCertRevoked {
        subject_pubkey_fingerprint:    String,
        subject_display_name:          Option<String>,
        reason:                        String,
        revoked_at:                    i64,
        reference:                     String,
        revoked_by_pubkey_fingerprint: String,
    },

    /// V2_GAPS §D1 — emitted EVERY TIME the kernel denies an
    /// operator op because the operator cert has been revoked.
    /// Not deduped: every rejection is a forensic breadcrumb so
    /// a forensic timeline can reconstruct exactly when an
    /// attacker tried to reuse a revoked cert.
    OperatorCertRevokedOpDenied {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        op:                 String,
        reason:             String,
        revoked_at:         i64,
    },

    // ── V2_GAPS §D2 — host-capacity admission + watchdogs ──────────────
    //
    // V2 ships the *cap-enforcement* slice of `host-capacity.md` plus a
    // basic disk-full watchdog. The full admission queue with `Queued`
    // session state, round-robin fairness, per-operator overrides, and
    // WAL pressure monitoring is deferred to V3 (see
    // `V2_GAPS.md §D2`).

    /// Emitted when an `ActivateSubTask` (or first-task spawn) is
    /// refused because a host-capacity cap would be exceeded. V2
    /// returns `FAIL_VM_CONCURRENCY_AT_CAP` to the caller; the
    /// in-flight work continues, and the agent is expected to retry
    /// after the kernel signals capacity availability.
    ///
    /// `cap_kind` is one of `"VmCount"`, `"VmMemory"`,
    /// `"PerInitiativeVm"`. V2 only emits `"VmCount"`; the other
    /// variants are reserved for V3's full admission queue.
    AdmissionDeferredAtCap {
        /// Cap that fired (`"VmCount"`, `"VmMemory"`, …).
        cap_kind:        String,
        /// `running` count at the moment of the decision.
        current_running: u32,
        /// The cap configured in `policy.toml [host_capacity]`.
        cap:             u32,
        /// Optional initiative the deferred sub-task belongs to.
        initiative_id:   Option<String>,
        /// Optional task id the deferral applies to.
        task_id:         Option<String>,
    },

    /// Emitted when the global admission queue is at depth and a
    /// new intent must be rejected outright. V2 uses this when
    /// `admission_queue_depth` is exhausted (see
    /// `host-capacity.md §10.1`).
    AdmissionQueueFull {
        intent_kind:        String,
        operator:           Option<String>,
        rejected_at_depth:  u32,
    },

    /// Emitted when the disk-full watchdog (5-second poll on
    /// `statvfs(disk_root)`) transitions from `DiskHealthy` to
    /// `DiskFullHalt`. V2 only implements `disk_full_behavior =
    /// "halt_admit"`; `gc_then_retry` and `halt_all` are V3.
    DiskFullHaltEntered {
        free_mb:  u64,
        cap_mb:   u64,
        behavior: String,
    },

    /// Emitted when the disk-full watchdog transitions from
    /// `DiskFullHalt` back to `DiskHealthy`. Records how long the
    /// halt lasted so operators can size disk capacity from the
    /// audit trail.
    DiskHealthyAfterFull {
        previous_free_mb:      u64,
        current_free_mb:       u64,
        halt_duration_seconds: u64,
    },

    /// Emitted when the kernel needs an operator to take action
    /// (disk pressure, FD limit insufficient, initiative
    /// starvation, …). `attention_kind` is a free-form short
    /// string for V2 (`"DiskFull"`, `"FdLimitInsufficient"`,
    /// `"InitiativeStarvation"`, …); future invariants may pin
    /// specific values per `host-capacity.md §13`. The field is
    /// not named `kind` because the audit-event enum already uses
    /// `#[serde(tag = "kind")]` for its variant discriminator.
    OperatorAttentionRequired {
        attention_kind: String,
        details:        String,
    },

    /// V2_GAPS §12.1 — emitted by `kernel/src/push/dispatcher.rs`
    /// when a `KernelPush` variant is enqueued for delivery to a
    /// session. V2.3 ships an in-memory `tokio::sync::broadcast`
    /// fan-out so internal subscribers (review-aggregation hooks,
    /// future operator subscribers) receive the push synchronously,
    /// AND mirrors every push to the audit chain so the trail is
    /// durably observable even when no live subscriber is attached.
    /// The full session-addressed VSock/UDS transport with the
    /// `pending_pushes` SQL queue is V3.
    KernelPushEnqueued {
        /// Recipient session.
        session_id: String,
        /// Per-session monotonic push counter (matches
        /// `KernelPushFrame::push_id`).
        push_id: u64,
        /// Tag of the inner `KernelPush` variant
        /// (`SubTaskActivated`, `SubTaskCompleted`, etc.) so the
        /// audit trail can be filtered without parsing the body.
        push_kind: String,
        /// Originating initiative_id when the push relates to a
        /// specific initiative. None for variants that aren't
        /// initiative-scoped.
        initiative_id: Option<String>,
        /// Optional task_id surfaced on the audit row for grep-
        /// friendliness; the full payload is reconstructible from
        /// the kernel's push log.
        task_id: Option<String>,
    },

    /// V2_GAPS §C7 — emitted when `raxis credential verify` runs.
    /// V2 verification is structural-only (file presence, mode 0600,
    /// uid match, non-empty body, optional `KEY=VALUE` parse).
    /// V3 will extend this with a live network probe per proxy type;
    /// the audit-event shape is forward-compatible with that.
    CredentialVerified {
        name:               String,
        proxy_type:         String,
        success:            bool,
        latency_ms:         u64,
        actor_fingerprint:  String,
        backend_kind:       String,
    },

    // --- Tier 1 transparent egress (`vm-network-isolation.md §3.2`).
    /// Emitted when the kernel's egress admission service admits
    /// one outbound connection from the agent VM. Carries the
    /// host-or-SNI it admitted on, the original destination
    /// `(ip, port)` after iptables redirect, and the layer-7
    /// protocol guess from the in-VM proxy.
    ///
    /// `INV-EGRESS-AUDIT-01`: every Admit verdict from
    /// `AdmissionService::admit` MUST be reflected by exactly one
    /// such event AFTER the verdict is sent back to the proxy.
    /// The audit-after-decision order matches the
    /// audit-after-commit order used elsewhere — the agent must
    /// not observe an admission whose audit failed.
    TransparentProxyAdmitted {
        /// Session whose VM the connection came from.
        session_id:        String,
        /// Host or SNI passed to admission. `None` when the in-VM
        /// proxy could not extract one (raw TCP database bypass).
        host_or_sni:       Option<String>,
        /// Original destination address as seen by the proxy.
        original_dst_ip:   String,
        /// Original destination port.
        original_dst_port: u16,
        /// Layer-7 protocol guess (`https` / `http` / `tcp`).
        protocol:          String,
    },

    /// Emitted when the kernel's egress admission service denies
    /// one outbound connection. Carries the same target info as
    /// `TransparentProxyAdmitted` plus a stable `reason` string
    /// from the `DenyReason` enum.
    ///
    /// Note: a `proxy_target_bypass` denial ALSO emits a separate
    /// `SecurityViolation` event (per `vm-network-isolation.md §5`
    /// proxy-bypass detection) — the two events together are how
    /// forensic tooling distinguishes "agent tried a forbidden
    /// host" from "agent tried to reach a credential proxy's real
    /// upstream directly".
    TransparentProxyDenied {
        /// Session whose VM the connection came from.
        session_id:        String,
        /// Host or SNI passed to admission, when available.
        host_or_sni:       Option<String>,
        /// Original destination address as seen by the proxy.
        original_dst_ip:   String,
        /// Original destination port.
        original_dst_port: u16,
        /// Layer-7 protocol guess (`https` / `http` / `tcp`).
        protocol:          String,
        /// Stable short reason string (`host_not_in_allowlist`,
        /// `proxy_target_bypass`, `protocol_not_permitted`,
        /// `port_not_redirected`, `unknown`).
        reason:            String,
    },

    // --- Credential proxy lifecycle (`credential-proxy.md §5`).
    /// Emitted when the kernel binds a credential-proxy listener
    /// for a task. Carries the `proxy_type` (`postgres`, `http`,
    /// etc.), the policy-declared credential `name`, the loopback
    /// `addr` the agent will connect to, and the consumer identity
    /// (`session_id` of the agent).
    ///
    /// Single-class event (per `audit-paired-writes.md §4` —
    /// observability emitted alongside the proxy's
    /// already-tracked SQLite registry rows; the proxy registry
    /// state mutation is paired-class through its own event).
    CredentialProxyStarted {
        /// Session whose VM the proxy is provisioned for.
        session_id:      String,
        /// Proxy type (`postgres`, `http`, `mysql`, etc.).
        proxy_type:      String,
        /// Policy-declared credential name. Never the value.
        credential_name: String,
        /// Loopback address the agent connects to.
        addr:            String,
    },

    /// Emitted when the kernel tears down a credential-proxy
    /// listener for a task. Carries the same identity fields plus
    /// the final counters snapshot.
    CredentialProxyStopped {
        /// Session whose VM the proxy was provisioned for.
        session_id:         String,
        /// Proxy type (`postgres`, `http`, `mysql`, etc.).
        proxy_type:         String,
        /// Policy-declared credential name. Never the value.
        credential_name:    String,
        /// Total accepted connections served.
        connections_served: u32,
        /// Number of requests/queries forwarded.
        forwards_completed: u32,
        /// Number of requests/queries rejected by `Restrictions`.
        forwards_blocked:   u32,
    },

    /// Emitted by the Postgres credential proxy on every audited
    /// query. Carries the SQL sha256 (always) plus the plaintext
    /// query (only when policy `[inference_audit] log_content =
    /// true`). Single-class observability event — the underlying
    /// proxy state row is paired through the lifecycle pair above.
    DatabaseQueryExecuted {
        /// Session whose VM submitted the query.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// Operation kind (`SELECT`, `INSERT`, ...).
        operation:       String,
        /// SHA-256 of the SQL text. Always present.
        sql_sha256:      String,
        /// Plaintext SQL. `None` unless policy opt-in is set.
        sql_plaintext:   Option<String>,
        /// True if the proxy refused the query under restrictions.
        blocked:         bool,
    },

    /// Emitted by a database credential proxy (Postgres, MySQL,
    /// MSSQL, MongoDB, Redis) when the upstream returns the terminal
    /// frame for a forwarded query (`ReadyForQuery` / final
    /// `OK_Packet` / `DONE` / `OP_MSG response` / RESP terminal
    /// frame). Pairs with the prior `DatabaseQueryExecuted` event
    /// (same `sql_sha256`) so an audit reader can compute the round-
    /// trip duration and compare the agent's observed result against
    /// the proxy-captured row count. Single-class observability event;
    /// see `credential-proxy.md §14.5.1`.
    DatabaseQueryCompleted {
        /// Session whose VM submitted the query.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// Proxy type (`"postgres" | "mysql" | "mssql" | "mongodb" |
        /// "redis"`).
        proxy_type:      String,
        /// SHA-256 of the SQL / command text. Matches the prior
        /// `DatabaseQueryExecuted` event so an audit reader can pair
        /// the two without indexing on `(session_id, seq)`.
        sql_sha256:      String,
        /// Number of rows returned by the upstream (`0` for write
        /// statements / commands that produce no result set).
        rows_returned:   u64,
        /// Number of payload bytes relayed upstream→agent for this
        /// query (RowDescription + DataRow + CommandComplete +
        /// ReadyForQuery, or the protocol equivalent).
        bytes_returned:  u64,
        /// Wall-clock duration from agent's first byte of the query
        /// to the upstream's terminal frame, in milliseconds.
        duration_ms:     u32,
        /// `Some(<sqlstate or errno>)` if the upstream returned an
        /// error response; `None` on success.
        upstream_error:  Option<String>,
    },

    /// Emitted by a TCP-protocol credential proxy (Postgres, MySQL,
    /// MSSQL, MongoDB, Redis, SMTP) once the first allowed-query
    /// upstream connection has completed its protocol-level
    /// authentication handshake. Pairs (`Started` ↔ `Connected` ↔
    /// `Stopped`) with the proxy's `CredentialProxyStarted` /
    /// `CredentialProxyStopped` lifecycle. Single-class observability
    /// event. See `credential-proxy.md §14.5.2`.
    CredentialProxyUpstreamConnected {
        /// Session whose VM holds the agent connection that triggered
        /// upstream contact.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// Proxy type (`"postgres" | ... | "smtp"`).
        proxy_type:      String,
        /// Upstream **hostname from the credential URL** (NOT a
        /// resolved IP) so dashboards can group events by upstream
        /// cluster without leaking DNS-resolution noise.
        upstream_host:   String,
        /// Upstream port from the credential URL (after default-port
        /// substitution if the URL omitted it).
        upstream_port:   u16,
        /// True if the upstream connection negotiated TLS
        /// (`?sslmode=require` / `?ssl-mode=REQUIRED` / `?tls=true` /
        /// `?encrypt=true` / `smtps:` scheme).
        tls:             bool,
        /// Wall-clock from `TcpStream::connect()` start to first
        /// usable session, in milliseconds.
        handshake_ms:    u32,
    },

    /// Emitted by a TCP-protocol credential proxy on every upstream-
    /// connect attempt that did NOT reach a usable session
    /// (DNS / TCP / TLS / protocol-level authentication / timeout).
    /// Single-class observability event; see
    /// `credential-proxy.md §14.5.3`. The `detail` field carries a
    /// short, redacted message — the proxy implementation MUST strip
    /// any substring matching `password=…` / `:secret@` /
    /// `?password=` from upstream error text before it reaches this
    /// envelope.
    CredentialProxyUpstreamFailed {
        /// Session whose VM holds the agent connection that triggered
        /// upstream contact.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// Proxy type (`"postgres" | ... | "smtp"`).
        proxy_type:      String,
        /// Upstream hostname from the credential URL.
        upstream_host:   String,
        /// Upstream port from the credential URL.
        upstream_port:   u16,
        /// Failure category. One of `"DnsResolveFailed" |
        /// "TcpConnectFailed" | "TlsHandshakeFailed" |
        /// "ProtocolHandshakeFailed" | "AuthRejected" | "Timeout"`.
        reason:          String,
        /// Short redacted message; never carries credential bytes.
        detail:          String,
    },

    /// Emitted by the HTTP credential proxy on every forwarded
    /// (or rejected) request. Carries the SHA-256 of `<METHOD>
    /// <path>`, the status code returned to the agent, and a
    /// `blocked` flag. Single-class observability event.
    HttpProxyRequestExecuted {
        /// Session whose VM submitted the request.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// Request method (uppercase).
        method:          String,
        /// Request path (no scheme/host).
        path:            String,
        /// SHA-256 of `"<METHOD> <path>"`.
        path_sha256:     String,
        /// Status returned to the agent (or 0 if the proxy
        /// short-circuited before any HTTP shape was decided).
        status_code:     u16,
        /// True if a restriction blocked this request.
        blocked:         bool,
    },

    /// Emitted by the Redis credential proxy on every audited
    /// command (forwarded or blocked). Carries the SHA-256 of the
    /// rendered RESP request frame the upstream would have seen
    /// (always present), the uppercased command verb, and a
    /// `blocked` flag. Single-class observability event paired
    /// with the `CredentialProxyStarted` / `CredentialProxyStopped`
    /// lifecycle pair.
    ///
    /// Spec reference: `credential-proxy.md §4.5` (RESP proxy);
    /// the `frame_sha256` lets reviewers cross-correlate against
    /// the upstream Redis logs without putting the command
    /// arguments on the audit chain.
    RedisCommandExecuted {
        /// Session whose VM submitted the command.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// Uppercased command verb (e.g. `"GET"`, `"AUTH"`).
        command:         String,
        /// SHA-256 of the rendered RESP request frame the upstream
        /// would have seen. Always present.
        frame_sha256:    String,
        /// True if the proxy refused the command under restrictions.
        blocked:         bool,
    },

    /// Emitted by the AWS credential proxy on every served (or
    /// blocked) IAM container-credential-provider request.
    /// Carries the request path, SHA-256 of `<METHOD> <path>`, the
    /// declared role ARN (or empty), and a `blocked` flag.
    /// Single-class observability event paired with the
    /// `CredentialProxyStarted` / `CredentialProxyStopped`
    /// lifecycle pair.
    ///
    /// Spec reference: `credential-proxy.md §3.2` (AWS proxy);
    /// the proxy issues a synthetic IAM credential JSON envelope
    /// per request, so each event corresponds to one cached SDK
    /// credential window.
    AwsCredentialServed {
        /// Session whose VM made the request.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// Request path (`/creds`, etc.).
        path:            String,
        /// SHA-256 of `"<METHOD> <path>"`.
        path_sha256:     String,
        /// Operator-declared IAM role ARN. Empty when the decl
        /// does not declare one.
        role_arn:        String,
        /// V2_GAPS §9 Phase 2 — operator-declared service scope
        /// (e.g. `["s3", "sqs"]`). Echoed in audit so reviewers
        /// can cross-check the egress allowlist; runtime
        /// enforcement is the V3 SigV4-aware egress proxy.
        /// Empty list when the operator declared no scope.
        #[serde(default)]
        allowed_services: Vec<String>,
        /// V2_GAPS §9 Phase 2 — operator-declared region scope
        /// (e.g. `["us-east-1"]`). Same enforcement model as
        /// `allowed_services`.
        #[serde(default)]
        allowed_regions:  Vec<String>,
        /// True if a restriction blocked the request.
        blocked:         bool,
    },

    /// Emitted by the GCP credential proxy on every served (or
    /// blocked) compute-metadata-server request. Mirrors the AWS
    /// event shape so downstream consumers process all four of
    /// (AWS, GCP, Azure, K8s) through one switch. Carries the
    /// declared GCP project ID — never the access token bytes.
    GcpMetadataServed {
        /// Session whose VM made the request.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// Request path (`/computeMetadata/v1/...`).
        path:            String,
        /// SHA-256 of `"<METHOD> <path>"`.
        path_sha256:     String,
        /// Operator-declared GCP project ID.
        project_id:      String,
        /// V2_GAPS §9 Phase 2 — operator-declared OAuth scopes.
        /// Echoed in audit so reviewers can confirm the scope
        /// narrowing the proxy applied to the token response.
        /// Empty list when no scope-level intent was declared.
        #[serde(default)]
        allowed_scopes: Vec<String>,
        /// True if a restriction or missing
        /// `Metadata-Flavor: Google` header blocked the request.
        blocked:         bool,
    },

    /// Emitted by the Azure credential proxy on every served (or
    /// blocked) IMDS token request. Carries the requested
    /// resource URI so reviewers can confirm tokens were only
    /// minted for operator-declared resources.
    AzureTokenServed {
        /// Session whose VM made the request.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// Request path (always `/metadata/identity/oauth2/token`
        /// in V2; future-proofed for additional IMDS endpoints).
        path:            String,
        /// Resource URI the agent requested in the `?resource=`
        /// query parameter. Empty when the parameter was missing.
        resource:        String,
        /// SHA-256 of `"<METHOD> <path>?resource=<resource>"`.
        request_sha256:  String,
        /// Operator-declared tenant ID.
        tenant_id:       String,
        /// V2_GAPS §9 Phase 2 — operator-declared ARM action
        /// vocabulary for the requested resource. Echoed in audit
        /// so reviewers can confirm the declared scope. Empty list
        /// when no per-resource action filter was declared. V2.3
        /// is declarative + audit echo + `x-ms-allowed-actions`
        /// response header; runtime ARM-URL gating lands in V3.
        #[serde(default)]
        allowed_actions: Vec<String>,
        /// True if a restriction or missing `Metadata: true`
        /// header blocked the request.
        blocked:         bool,
    },

    /// V3 cloud-forwarding event. Emitted by the AWS / GCP /
    /// Azure credential proxy each time it performs (or attempts)
    /// a real upstream token-exchange call against the cloud
    /// control plane. Carries the upstream FQDN, the exchange
    /// kind (closed enum from `specs/v3/cloud-proxy-forwarding.md
    /// §2`), the wall-clock latency, the upstream HTTP status,
    /// the byte count of the redacted response, and a boolean
    /// recording whether the request carried a signed payload
    /// (SigV4 for AWS, JWT for GCP, none for Azure). Never the
    /// request or response bytes themselves.
    ///
    /// Spec reference: `specs/v3/cloud-proxy-forwarding.md §5.1`.
    /// Paired with the in-VM-facing
    /// `AwsCredentialServed` / `GcpMetadataServed` /
    /// `AzureTokenServed` event so an audit reader can compute
    /// "one upstream exchange per N in-VM requests" cardinality.
    CloudCredentialForwarded {
        /// Session whose VM made the request.
        session_id:        String,
        /// Policy-declared credential name.
        credential_name:   String,
        /// `"aws" | "gcp" | "azure"` — closed enum.
        provider:          String,
        /// `"assume_role" | "jwt_bearer" | "client_credentials"` —
        /// closed enum.
        exchange_kind:     String,
        /// Upstream FQDN the proxy called. Never a full URL,
        /// never carries query parameters. Always one of the
        /// hosts in the §3 allowlist.
        upstream_endpoint: String,
        /// `"success" | "failure"`.
        outcome:           String,
        /// Wall-clock duration of the upstream call in
        /// milliseconds. `0` on transport failures that did not
        /// produce a response.
        latency_ms:        u32,
        /// Upstream HTTP status code. `0` on transport failure.
        status_code:       u16,
        /// Byte count of the upstream response body. NEVER the
        /// body itself; the count is for redaction-respecting
        /// rate sizing.
        redacted_response_size: u32,
        /// Whether the request carried a cryptographic signature
        /// (SigV4 / JWT). `false` for Azure client-credentials
        /// (which authenticates with a shared secret only).
        request_signature_present: bool,
    },

    /// V3 cloud-forwarding denial event. Emitted by the cloud
    /// proxy when a forwarding attempt is refused or fails.
    /// The `reason` is a closed enum from
    /// `specs/v3/cloud-proxy-forwarding.md §5.2`:
    /// `"egress_allowlist" | "missing_credential" |
    /// "misconfigured" | "upstream_5xx" | "upstream_4xx" |
    /// "upstream_malformed" | "timeout" | "network"`.
    ///
    /// A `CloudCredentialForwardingDenied` event is in addition
    /// to (NOT a replacement for) the in-VM-facing
    /// `*ServedCredential` event, which still fires with the
    /// upstream-canonical error envelope per §6.
    CloudCredentialForwardingDenied {
        /// Session whose VM made the request.
        session_id:        String,
        /// Policy-declared credential name.
        credential_name:   String,
        /// `"aws" | "gcp" | "azure"`.
        provider:          String,
        /// Closed-enum exchange kind: `"assume_role" |
        /// "jwt_bearer" | "client_credentials"`.
        #[serde(default)]
        exchange_kind:     String,
        /// Canonical upstream FQDN the proxy attempted to dial
        /// (or would have, on a construction-time refusal).
        /// Empty for `egress_allowlist` denials that never had
        /// a host.
        #[serde(default)]
        upstream_endpoint: String,
        /// Closed-enum denial reason (see above).
        reason:            String,
        /// HTTP status observed (0 when no HTTP wire was
        /// reached).
        #[serde(default)]
        status_code:       u16,
        /// Wall-clock latency at the point of failure, in
        /// milliseconds.
        #[serde(default)]
        latency_ms:        u32,
    },

    /// V3 cloud-forwarding cache-hit event. Emitted by the cloud
    /// proxy each time it serves a request from its in-memory
    /// short-lived-token cache without dispatching to the cloud
    /// control plane. Carries the cached token's age in
    /// milliseconds and the remaining TTL until expiry, so an
    /// operator can correlate cache hit rates with the
    /// `lease_seconds` / `cache_ttl_safety_window_ms` plan
    /// settings.
    CloudCredentialCacheHit {
        /// Session whose VM made the request.
        session_id:       String,
        /// Policy-declared credential name.
        credential_name:  String,
        /// `"aws" | "gcp" | "azure"`.
        provider:         String,
        /// Closed-enum exchange kind: `"assume_role" |
        /// "jwt_bearer" | "client_credentials"`.
        #[serde(default)]
        exchange_kind:    String,
        /// Age of the cached token in milliseconds (now -
        /// refreshed_at).
        age_ms:           u32,
        /// Time remaining until the cached token expires, in
        /// milliseconds. May be less than the safety window
        /// (in which case a background refresh has been or will
        /// be scheduled by the same request path).
        ttl_remaining_ms: u32,
    },

    /// V3 cloud-forwarding cache-refresh event. Emitted by the
    /// cloud proxy when a background refresh successfully
    /// installed a fresh short-lived token in the cache. Pairs
    /// with the `CloudCredentialForwarded { outcome: "success" }`
    /// event the same refresh triggered. Carries the prior age
    /// and the new TTL so operators can detect cache thrash.
    CloudCredentialCacheRefreshed {
        /// Session whose VM made the request that triggered the
        /// refresh.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// `"aws" | "gcp" | "azure"`.
        provider:        String,
        /// Closed-enum exchange kind.
        #[serde(default)]
        exchange_kind:   String,
        /// Age in ms of the cached token BEFORE the refresh.
        prior_age_ms:    u32,
        /// TTL in ms of the freshly-installed token.
        new_ttl_ms:      u32,
    },

    /// Emitted by the MongoDB credential proxy on every classified
    /// (or blocked) command issued through the `OP_MSG` wire
    /// protocol. Mirrors the `RedisCommandExecuted` shape so
    /// downstream consumers handle Redis and MongoDB commands
    /// through a single switch. Carries the command name (e.g.
    /// `"find"`, `"insert"`), the SHA-256 of the rendered
    /// `OP_MSG` body the upstream would have seen, and the
    /// `blocked` flag.
    ///
    /// Spec reference: `credential-proxy.md` (MongoDB proxy
    /// section); the `frame_sha256` lets reviewers
    /// cross-correlate against the upstream MongoDB logs
    /// without putting BSON document bodies on the audit chain.
    MongoCommandExecuted {
        /// Session whose VM submitted the command.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// MongoDB command name (e.g. `"find"`, `"insert"`,
        /// `"hello"`). Lower-cased to match the wire protocol.
        command:         String,
        /// SHA-256 (hex-encoded) of the rendered `OP_MSG` body
        /// the upstream would have seen. Always present.
        body_sha256:     String,
        /// True if the proxy refused the command under
        /// restrictions.
        blocked:         bool,
    },

    /// Emitted by the SMTP credential proxy when an envelope passes
    /// every restriction gate and is forwarded to the upstream
    /// relay. Carries the SHA-256 of the canonical
    /// `<sender>\n<rcpt1>\n<rcpt2>...` envelope key (so reviewers
    /// can cross-correlate against the upstream relay's logs
    /// without having the recipient list itself land in the audit
    /// chain), the recipient count, and the bytes-relayed counter.
    /// Single-class observability event — the underlying
    /// `task_credential_proxies` row is paired through the
    /// lifecycle pair (`CredentialProxyStarted` /
    /// `CredentialProxyStopped`).
    ///
    /// Spec reference: `email-and-notification-channels.md §3.3`
    /// (`SmtpProxyMessageSent`); the V2 implementation pins the
    /// `kind` string to `SmtpMessageRelayed` to mirror the proxy
    /// crate's `EnvelopeOutcome::Relayed` so the cross-walk is
    /// 1:1.
    SmtpMessageRelayed {
        /// Session whose VM submitted the envelope.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// SHA-256 (hex-encoded) of the canonical envelope key
        /// (`<sender>\n<rcpt1>\n<rcpt2>...`). Always present.
        envelope_sha256: String,
        /// Number of recipients in the envelope (>= 1, post-gate).
        recipient_count: u32,
        /// Total DATA bytes the agent submitted.
        bytes_relayed:   u64,
    },

    /// Emitted by the SMTP credential proxy when an envelope is
    /// rejected at the proxy boundary (sender not allowed,
    /// recipient domain not allowed, recipient cap exceeded,
    /// message too large, rate limit exceeded). Carries the same
    /// envelope SHA-256 as the matching `SmtpMessageRelayed`
    /// shape, plus a stable short reason string the operator can
    /// filter on (`sender_not_allowed`, `recipient_not_allowed`,
    /// `too_many_recipients`, `message_too_large`,
    /// `rate_limit_exceeded`). Single-class observability event.
    SmtpMessageRejected {
        /// Session whose VM submitted the envelope.
        session_id:      String,
        /// Policy-declared credential name.
        credential_name: String,
        /// SHA-256 (hex-encoded) of the canonical envelope key
        /// (`<sender>\n<rcpt1>\n<rcpt2>...`).
        envelope_sha256: String,
        /// Number of recipients in the envelope (may be 0 if
        /// rejected pre-RCPT TO).
        recipient_count: u32,
        /// Total DATA bytes the agent submitted (0 if rejected
        /// pre-DATA).
        bytes_submitted: u64,
        /// Stable short reason string for filtering. Matches the
        /// `audit_summary` prefixes the proxy crate documents in
        /// `credential-proxy.md §22`.
        reason:          String,
    },

    // --- V2 §3.2 typed structured outputs --------------------------------
    /// Emitted by `handlers::intent::handle_structured_output` whenever
    /// an executor or orchestrator agent submits a `StructuredOutput`
    /// intent and the kernel-side validator accepts the payload. The
    /// row is the audit-chain projection of `structured_outputs`
    /// (`Table::StructuredOutputs`) — the operator dashboard joins the
    /// two so a chain replay reconstructs the full payload.
    ///
    /// Carries enough metadata for forensic correlation but **does
    /// not** include the full payload (the dashboard / CLI fetch the
    /// payload from `structured_outputs.payload_json` keyed on
    /// `output_id`). Keeping the audit row compact bounds the chain
    /// growth — a verbose progress-report stream can produce dozens
    /// of rows per task and we do not want each row to embed kilobytes
    /// of file lists.
    ///
    /// CLI surface: `raxis audit query --event-type StructuredOutputEmitted`.
    StructuredOutputEmitted {
        /// `output_id` PK of the matching `structured_outputs` row.
        output_id:     String,
        /// Initiative the emitting session belongs to.
        initiative_id: String,
        /// Task the emitting session is bound to.
        task_id:       String,
        /// Emitting session.
        session_id:    String,
        /// Variant tag (`progress_report`, `diagnostic_flag`,
        /// `task_summary`) — matches `StructuredOutputKind::variant_tag`.
        ///
        /// **Field-name note.** Renamed from `kind` to
        /// `output_kind` because the parent `AuditEventKind` enum
        /// uses `#[serde(tag = "kind")]` for its internal-tag
        /// projection; serde rejects a struct-variant field whose
        /// name collides with the internal tag.
        output_kind:   String,
        /// `info` / `warning` / `critical` for `diagnostic_flag`,
        /// `None` for the other two variants.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        severity:      Option<String>,
        /// Byte length of the validated/normalised
        /// `payload_json` written to `structured_outputs`. Operators
        /// can quickly spot pathologically-large outputs without
        /// pulling the body.
        payload_bytes: u32,
    },

    /// Emitted by the operator dashboard's
    /// `PUT /api/policy/toml` write surface AFTER
    /// `policy_manager::advance_epoch` succeeds. Provides a
    /// dashboard-distinct lineage so an auditor can see at a
    /// glance which policy advances came from the web UI vs the
    /// CLI's `raxis policy reload`.
    ///
    /// This event is in addition to (NOT in place of) the
    /// canonical `PolicyEpochAdvanced` record that `advance_epoch`
    /// writes for every successful advance.
    ///
    /// Field semantics:
    ///   * `operator_fingerprint` — pubkey-fingerprint of the
    ///     operator whose JWT authenticated the PUT.
    ///   * `previous_epoch` — epoch the kernel was running before
    ///     the advance.
    ///   * `new_epoch` — epoch the kernel is running after the
    ///     advance; identical to the corresponding
    ///     `PolicyEpochAdvanced.epoch_id`.
    ///   * `policy_sha256` — SHA-256 of the new policy artifact
    ///     bytes; matches the `PolicyEpochAdvanced.policy_sha256`
    ///     in the same chain segment.
    PolicyUpdatedViaDashboard {
        /// Operator pubkey fingerprint (SHA-256[:16] hex).
        operator_fingerprint: String,
        /// Epoch the kernel was running before the PUT.
        previous_epoch:       u64,
        /// Epoch the kernel is running after the PUT.
        new_epoch:            u64,
        /// SHA-256 of the new policy artifact bytes.
        policy_sha256:        String,
    },

    /// **V2 `integration-merge.md §11.3` Case A** — emitted by
    /// startup recovery when an initiative was found with
    /// `git_apply_pending = 1` AND `current_sha != refs/heads/main`,
    /// and the recovery successfully re-ran Phase 2
    /// (`git fetch` + `git update-ref`) to restore consistency.
    /// The matching SQLite UPDATE clears the flag in the same
    /// post-condition. INV-MERGE-CONSISTENCY (§11.8).
    GitConsistencyRepaired {
        /// Initiative whose merge was repaired.
        initiative_id:    String,
        /// SHA the kernel restored on `refs/heads/<target_ref>`.
        db_sha:           String,
        /// SHA `refs/heads/<target_ref>` was at BEFORE recovery —
        /// either the unchanged base sha (Case A — Phase 2 missed
        /// entirely), or a fetched-but-not-ref-updated state.
        previous_git_sha: String,
        /// `refs/heads/<name>` the recovery operated on (matches
        /// the operator-configured target_ref at admission time).
        target_ref:       String,
    },

    /// **V2 `integration-merge.md §11.3` Case B** — emitted by
    /// startup recovery when an initiative was found with
    /// `git_apply_pending = 1` AND `current_sha = refs/heads/main`
    /// (Phase 2 fully succeeded; only Phase 3's flag-clearing
    /// SQLite UPDATE was missed across the crash). Recovery
    /// runs the missing UPDATE and emits this event.
    GitConsistencyVerified {
        /// Initiative whose pending flag was cleared.
        initiative_id: String,
        /// SHA observed identical between SQLite and the git ref.
        sha:           String,
        /// `refs/heads/<name>` the recovery operated on.
        target_ref:    String,
    },

    /// **V2 `integration-merge.md §11.3` Case C — INV-MERGE-CONSISTENCY
    /// (§11.8) violation.** Emitted by startup recovery when a row
    /// with `git_apply_pending = 1` cannot be reconciled because
    /// the originating Orchestrator's worktree (referenced by the
    /// most-recent `IntegrationMergeCompleted` audit event) is
    /// missing from disk OR does not contain `current_sha` as a
    /// reachable commit. The kernel transitions the initiative to
    /// `Blocked` and intentionally does NOT clear
    /// `git_apply_pending` — the inconsistency persists in the
    /// record until an operator intervenes via
    /// `raxis initiative abort` (or, if the worktree can be
    /// restored from backup, via a recovery-mode boot).
    ///
    /// Distinct from `AuditEventKind::SecurityViolation` (which is
    /// reserved for the V2 wire-frame violation taxonomy of
    /// §13). The git-state inconsistency is a durability /
    /// recovery class violation, not a frame-validation class.
    GitStateInconsistent {
        /// Initiative whose merge cannot be reconciled.
        initiative_id:   String,
        /// SQLite-side `current_sha` (kernel-authoritative).
        db_sha:          String,
        /// Git-side `refs/heads/<target_ref>` SHA observed at
        /// recovery time — left in place by recovery.
        git_sha:         String,
        /// `refs/heads/<name>` the recovery operated on.
        target_ref:      String,
        /// Stable-wire short string for the underlying cause.
        /// One of:
        ///   * `"orchestrator_worktree_missing"` — the worktree
        ///     directory the audit event named no longer exists.
        ///   * `"orchestrator_worktree_unreachable_commit"` — the
        ///     worktree directory exists but does not have
        ///     `db_sha` as a reachable commit.
        ///   * `"audit_record_missing"` — no
        ///     `IntegrationMergeCompleted` event for this
        ///     `(initiative_id, db_sha)` pair was found in the
        ///     audit log (chain corruption — extreme case).
        reason:          String,
    },
}

impl AuditEventKind {
    /// The canonical event_kind string written to the `event_kind` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KernelStarted { .. } => "KernelStarted",
            Self::KernelStopped { .. } => "KernelStopped",
            Self::IsolationSubstrateSelected { .. } => "IsolationSubstrateSelected",
            Self::IsolationFallbackBypass { .. } => "IsolationFallbackBypass",
            Self::IsolationSubstrateRefused { .. } => "IsolationSubstrateRefused",
            Self::SessionVmSpawned { .. } => "SessionVmSpawned",
            Self::SessionVmExited { .. } => "SessionVmExited",
            Self::SessionVmRespawnAttempted { .. } => "SessionVmRespawnAttempted",
            Self::SessionVmFailedFinal { .. }      => "SessionVmFailedFinal",
            Self::SessionVmScaleEvent { .. }       => "SessionVmScaleEvent",
            Self::SessionVmScaleDeferred { .. }    => "SessionVmScaleDeferred",
            Self::SecurityViolationDetected { .. } => "SecurityViolationDetected",
            Self::InitiativeCreated { .. } => "InitiativeCreated",
            Self::PlanApproved { .. } => "PlanApproved",
            Self::PlanRejected { .. } => "PlanRejected",
            Self::PathScopeOverrideApplied { .. } => "PathScopeOverrideApplied",
            Self::InitiativeStateChanged { .. } => "InitiativeStateChanged",
            Self::InitiativeAborted { .. } => "InitiativeAborted",
            Self::TaskAdmitted { .. } => "TaskAdmitted",
            Self::TaskStateChanged { .. } => "TaskStateChanged",
            Self::IntentAccepted { .. } => "IntentAccepted",
            Self::IntentRejected { .. } => "IntentRejected",
            Self::IntegrationMergeCompleted { .. } => "IntegrationMergeCompleted",
            Self::MergeFastForwardFailed { .. }   => "MergeFastForwardFailed",
            Self::PushAttempted { .. }            => "PushAttempted",
            Self::PushCompleted { .. }            => "PushCompleted",
            Self::PushFailed    { .. }            => "PushFailed",
            Self::SessionCreated { .. } => "SessionCreated",
            Self::SessionRevoked { .. } => "SessionRevoked",
            Self::DelegationGranted { .. } => "DelegationGranted",
            Self::DelegationMarkedStale { .. } => "DelegationMarkedStale",
            Self::WitnessAccepted { .. } => "WitnessAccepted",
            Self::WitnessRejected { .. } => "WitnessRejected",
            Self::VerifierProcessFailed { .. } => "VerifierProcessFailed",
            Self::ReviewAggregationCompleted { .. } => "ReviewAggregationCompleted",
            Self::EscalationSubmitted { .. } => "EscalationSubmitted",
            Self::EscalationApproved { .. } => "EscalationApproved",
            Self::EscalationDenied { .. } => "EscalationDenied",
            Self::EscalationTimedOut { .. } => "EscalationTimedOut",
            Self::EscalationConsumed { .. } => "EscalationConsumed",
            Self::LineageQuarantined { .. } => "LineageQuarantined",
            Self::EscalationRateLimitExceeded { .. } => "EscalationRateLimitExceeded",
            Self::PolicyEpochAdvanced { .. } => "PolicyEpochAdvanced",
            Self::PolicyAdvanceRejected { .. } => "PolicyAdvanceRejected",
            Self::PolicyAdvanceFailed { .. } => "PolicyAdvanceFailed",
            Self::ReplayRejected { .. } => "ReplayRejected",
            Self::ReconciliationGap { .. } => "ReconciliationGap",
            Self::TaskBlockedForRecovery { .. } => "TaskBlockedForRecovery",
            Self::DelegationSignatureUnverifiable { .. } => "DelegationSignatureUnverifiable",
            Self::GatewaySpawned { .. } => "GatewaySpawned",
            Self::GatewayCrashed { .. } => "GatewayCrashed",
            Self::GatewayQuarantined { .. } => "GatewayQuarantined",
            Self::GatewaySignalFailed { .. } => "GatewaySignalFailed",
            Self::NotificationDeliveryFailed { .. } => "NotificationDeliveryFailed",
            Self::NotificationDelivered { .. } => "NotificationDelivered",
            Self::OperatorCertInstalled { .. } => "OperatorCertInstalled",
            Self::OperatorCertMisconfigBypassed { .. } => "OperatorCertMisconfigBypassed",
            Self::OperatorCertExpiringSoon { .. } => "OperatorCertExpiringSoon",
            Self::OperatorCertInGracePeriod { .. } => "OperatorCertInGracePeriod",
            Self::OperatorCertExpiredOpDenied { .. } => "OperatorCertExpiredOpDenied",
            Self::EmergencyOperatorUsed { .. } => "EmergencyOperatorUsed",
            Self::BreakglassActivated { .. }   => "BreakglassActivated",
            Self::BreakglassDeactivated { .. } => "BreakglassDeactivated",
            Self::BreakglassAction { .. }      => "BreakglassAction",
            Self::PathReadAccessed { .. } => "PathReadAccessed",
            Self::InitiativeQuarantined { .. } => "InitiativeQuarantined",
            Self::OperatorQuarantineSwept { .. } => "OperatorQuarantineSwept",
            Self::SecurityViolation { .. } => "SecurityViolation",
            Self::CredentialAccessed { .. } => "CredentialAccessed",
            Self::CredentialRotated { .. } => "CredentialRotated",
            Self::CredentialRegistered { .. } => "CredentialRegistered",
            Self::CredentialRemoved { .. } => "CredentialRemoved",
            Self::CredentialVerified { .. } => "CredentialVerified",
            Self::OperatorCertRevoked { .. } => "OperatorCertRevoked",
            Self::OperatorCertRevokedOpDenied { .. } => "OperatorCertRevokedOpDenied",
            Self::AdmissionDeferredAtCap { .. } => "AdmissionDeferredAtCap",
            Self::AdmissionQueueFull { .. } => "AdmissionQueueFull",
            Self::DiskFullHaltEntered { .. } => "DiskFullHaltEntered",
            Self::DiskHealthyAfterFull { .. } => "DiskHealthyAfterFull",
            Self::OperatorAttentionRequired { .. } => "OperatorAttentionRequired",
            Self::KernelPushEnqueued { .. } => "KernelPushEnqueued",
            Self::TransparentProxyAdmitted { .. } => "TransparentProxyAdmitted",
            Self::TransparentProxyDenied { .. } => "TransparentProxyDenied",
            Self::CredentialProxyStarted { .. } => "CredentialProxyStarted",
            Self::CredentialProxyStopped { .. } => "CredentialProxyStopped",
            Self::DatabaseQueryExecuted { .. } => "DatabaseQueryExecuted",
            Self::DatabaseQueryCompleted { .. } => "DatabaseQueryCompleted",
            Self::CredentialProxyUpstreamConnected { .. } => "CredentialProxyUpstreamConnected",
            Self::CredentialProxyUpstreamFailed { .. } => "CredentialProxyUpstreamFailed",
            Self::HttpProxyRequestExecuted { .. } => "HttpProxyRequestExecuted",
            Self::RedisCommandExecuted { .. } => "RedisCommandExecuted",
            Self::AwsCredentialServed { .. } => "AwsCredentialServed",
            Self::GcpMetadataServed { .. } => "GcpMetadataServed",
            Self::AzureTokenServed { .. } => "AzureTokenServed",
            Self::CloudCredentialForwarded { .. } => "CloudCredentialForwarded",
            Self::CloudCredentialForwardingDenied { .. } => "CloudCredentialForwardingDenied",
            Self::CloudCredentialCacheHit { .. } => "CloudCredentialCacheHit",
            Self::CloudCredentialCacheRefreshed { .. } => "CloudCredentialCacheRefreshed",
            Self::MongoCommandExecuted { .. } => "MongoCommandExecuted",
            Self::SmtpMessageRelayed { .. } => "SmtpMessageRelayed",
            Self::SmtpMessageRejected { .. } => "SmtpMessageRejected",
            Self::DryRunAdmitted { .. } => "DryRunAdmitted",
            Self::StructuredOutputEmitted { .. } => "StructuredOutputEmitted",
            Self::CircuitBreakerStateChanged { .. } => "CircuitBreakerStateChanged",
            Self::PolicyUpdatedViaDashboard { .. } => "PolicyUpdatedViaDashboard",
            Self::GitConsistencyRepaired { .. }    => "GitConsistencyRepaired",
            Self::GitConsistencyVerified { .. }    => "GitConsistencyVerified",
            Self::GitStateInconsistent { .. }      => "GitStateInconsistent",
        }
    }
}

#[cfg(test)]
mod path_read_accessed_tests {
    use super::*;

    #[test]
    fn path_read_accessed_kind_string_matches_variant_name() {
        let kind = AuditEventKind::PathReadAccessed {
            actor:   "fp-7d2c00".to_owned(),
            table:   "task_plan_fields".to_owned(),
            column:  "path_allowlist".to_owned(),
            task_id: "task-001".to_owned(),
            command: "inspect".to_owned(),
        };
        assert_eq!(kind.as_str(), "PathReadAccessed");
    }

    #[test]
    fn path_read_accessed_serialises_with_kind_tag_and_all_fields() {
        let kind = AuditEventKind::PathReadAccessed {
            actor:   "fp-7d2c00".to_owned(),
            table:   "task_plan_fields".to_owned(),
            column:  "path_allowlist".to_owned(),
            task_id: "task-001".to_owned(),
            command: "inspect".to_owned(),
        };
        let v = serde_json::to_value(&kind).expect("serialises");
        assert_eq!(v["kind"], serde_json::json!("PathReadAccessed"));
        assert_eq!(v["actor"], serde_json::json!("fp-7d2c00"));
        assert_eq!(v["table"], serde_json::json!("task_plan_fields"));
        assert_eq!(v["column"], serde_json::json!("path_allowlist"));
        assert_eq!(v["task_id"], serde_json::json!("task-001"));
        assert_eq!(v["command"], serde_json::json!("inspect"));
    }

    // ── operator-cert audit kinds ──────────────────────────────────

    /// Pin every cert-related variant's `kind` discriminant string.
    /// A future rename of any variant breaks this test, so the wire
    /// shape that downstream tools (`raxis verify-chain`,
    /// `raxis cert list`, the notification router) match against
    /// cannot drift silently.
    #[test]
    fn operator_cert_kind_strings_are_pinned() {
        let cases: Vec<(AuditEventKind, &str)> = vec![
            (AuditEventKind::OperatorCertInstalled {
                pubkey_fingerprint: "fp".into(), epoch_id: 1, cert_kind: "Standard".into(),
                display_name: "chika".into(), not_before: 0, not_after: 0,
                permitted_ops: vec![], force_misconfig_bypass: false,
                previous_fingerprint: None,
            }, "OperatorCertInstalled"),
            (AuditEventKind::OperatorCertMisconfigBypassed {
                pubkey_fingerprint: "fp".into(), epoch_id: 1,
                cert_kind: "Standard".into(), display_name: "chika".into(),
                violations: vec!["x".into()],
            }, "OperatorCertMisconfigBypassed"),
            (AuditEventKind::OperatorCertExpiringSoon {
                pubkey_fingerprint: "fp".into(), epoch_id: 1, op: "AbortTask".into(),
                not_after: 0, days_remaining: 14,
            }, "OperatorCertExpiringSoon"),
            (AuditEventKind::OperatorCertInGracePeriod {
                pubkey_fingerprint: "fp".into(), epoch_id: 1, op: "AbortTask".into(),
                not_after: 0, grace_ends_at: 0,
            }, "OperatorCertInGracePeriod"),
            (AuditEventKind::OperatorCertExpiredOpDenied {
                pubkey_fingerprint: "fp".into(), epoch_id: 1, op: "AbortTask".into(),
                not_after: 0, expired_at: 0,
            }, "OperatorCertExpiredOpDenied"),
            (AuditEventKind::EmergencyOperatorUsed {
                pubkey_fingerprint: "fp".into(), epoch_id: 1, op: "RotateEpoch".into(),
            }, "EmergencyOperatorUsed"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.as_str(), expected,
                "as_str() drifted for {expected}");
        }
    }

    /// Confirm the cert-installed payload serialises with every field
    /// and round-trips through JSON. This is the audit-chain mirror
    /// of the `operator_certificates` view-table row, so a wire-shape
    /// drift here would silently break replay-from-audit-chain
    /// recovery (kernel-store.md §2.5.7).
    #[test]
    fn operator_cert_installed_serialises_all_fields() {
        let kind = AuditEventKind::OperatorCertInstalled {
            pubkey_fingerprint:     "abcd0123".to_owned(),
            epoch_id:               2,
            cert_kind:              "Standard".to_owned(),
            display_name:           "chika".to_owned(),
            not_before:             1_700_000_000,
            not_after:              1_731_536_000,
            permitted_ops:          vec!["AbortTask".to_owned(), "ApprovePlan".to_owned()],
            force_misconfig_bypass: false,
            previous_fingerprint:   None,
        };
        let v = serde_json::to_value(&kind).expect("serialises");
        // The serde tag (`#[serde(tag = "kind")]`) writes the variant
        // discriminator into the JSON `kind` field; the payload's own
        // `cert_kind` field is named distinctly to avoid the collision
        // that an identically-named payload field would cause.
        assert_eq!(v["kind"], serde_json::json!("OperatorCertInstalled"));
        assert_eq!(v["pubkey_fingerprint"], serde_json::json!("abcd0123"));
        assert_eq!(v["epoch_id"], serde_json::json!(2));
        assert_eq!(v["cert_kind"], serde_json::json!("Standard"));
        assert_eq!(v["display_name"], serde_json::json!("chika"));
        assert_eq!(v["not_before"], serde_json::json!(1_700_000_000_i64));
        assert_eq!(v["not_after"], serde_json::json!(1_731_536_000_i64));
        assert_eq!(v["permitted_ops"], serde_json::json!(["AbortTask", "ApprovePlan"]));
        assert_eq!(v["force_misconfig_bypass"], serde_json::json!(false));

        // Round-trip pins lossless field decode for chain replay.
        let s = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::OperatorCertInstalled {
                pubkey_fingerprint, epoch_id, cert_kind, display_name,
                not_before, not_after, permitted_ops, force_misconfig_bypass,
                previous_fingerprint,
            } => {
                assert_eq!(pubkey_fingerprint, "abcd0123");
                assert_eq!(epoch_id,           2);
                assert_eq!(cert_kind,          "Standard");
                assert_eq!(display_name,       "chika");
                assert_eq!(not_before,         1_700_000_000);
                assert_eq!(not_after,          1_731_536_000);
                assert_eq!(permitted_ops,      vec!["AbortTask".to_owned(), "ApprovePlan".to_owned()]);
                assert!(!force_misconfig_bypass);
                assert!(previous_fingerprint.is_none(),
                    "previous_fingerprint defaults to None for non-rotation installs");
            }
            other => panic!("expected OperatorCertInstalled; got {other:?}"),
        }
    }

    /// Pin the wire shape of the two quarantine event kinds. Same
    /// rationale as the cert-kind pin above: downstream tools
    /// (`raxis verify-chain`, `raxis inspect quarantine`, the
    /// notification router) match on the discriminator string and
    /// any silent rename would break replay.
    #[test]
    fn quarantine_kind_strings_are_pinned() {
        let cases: Vec<(AuditEventKind, &str)> = vec![
            (AuditEventKind::InitiativeQuarantined {
                initiative_id: "i1".into(), quarantined_by: "fp".into(),
                reason: Some("compromised key".into()),
                quarantined_by_display_name: None,
            }, "InitiativeQuarantined"),
            (AuditEventKind::OperatorQuarantineSwept {
                target_fingerprint: "chika-fp".into(),
                quarantined_by:     "rot-fp".into(),
                count:              3,
                reason:             None,
                quarantined_by_display_name: None,
                target_display_name:        None,
            }, "OperatorQuarantineSwept"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.as_str(), expected, "as_str() drifted for {expected}");
        }
    }

    #[test]
    fn initiative_quarantined_round_trips_through_json() {
        let kind = AuditEventKind::InitiativeQuarantined {
            initiative_id:  "init-7".to_owned(),
            quarantined_by: "fp-rot".to_owned(),
            reason:         Some("compromised plan signer".to_owned()),
            quarantined_by_display_name: Some("Chika".to_owned()),
        };
        let s = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::InitiativeQuarantined {
                initiative_id, quarantined_by, reason,
                quarantined_by_display_name,
            } => {
                assert_eq!(initiative_id,  "init-7");
                assert_eq!(quarantined_by, "fp-rot");
                assert_eq!(reason.as_deref(), Some("compromised plan signer"));
                assert_eq!(quarantined_by_display_name.as_deref(), Some("Chika"),
                    "display name must round-trip through the JSON wire");
            }
            other => panic!("expected InitiativeQuarantined; got {other:?}"),
        }
    }

    #[test]
    fn operator_quarantine_swept_round_trips_through_json() {
        let kind = AuditEventKind::OperatorQuarantineSwept {
            target_fingerprint: "chika-fp".to_owned(),
            quarantined_by:     "rot-fp".to_owned(),
            count:              42,
            reason:             None,
            quarantined_by_display_name: Some("Jinanwa".to_owned()),
            target_display_name:        Some("Chika".to_owned()),
        };
        let s = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::OperatorQuarantineSwept {
                target_fingerprint, quarantined_by, count, reason,
                quarantined_by_display_name, target_display_name,
            } => {
                assert_eq!(target_fingerprint, "chika-fp");
                assert_eq!(quarantined_by,     "rot-fp");
                assert_eq!(count,              42);
                assert!(reason.is_none());
                assert_eq!(quarantined_by_display_name.as_deref(), Some("Jinanwa"));
                assert_eq!(target_display_name.as_deref(),         Some("Chika"));
            }
            other => panic!("expected OperatorQuarantineSwept; got {other:?}"),
        }
    }

    /// `display_name` fields are optional; legacy chain segments
    /// written before the plumbing shipped MUST still deserialize.
    /// This pins the forward-compat shape — adding the field can
    /// never break an old reader.
    #[test]
    fn legacy_quarantine_records_without_display_name_still_deserialize() {
        let legacy_initiative = serde_json::json!({
            "kind":           "InitiativeQuarantined",
            "initiative_id":  "init-9",
            "quarantined_by": "fp-old",
            "reason":         null,
        });
        let parsed: AuditEventKind = serde_json::from_value(legacy_initiative).unwrap();
        match parsed {
            AuditEventKind::InitiativeQuarantined {
                quarantined_by_display_name, ..
            } => assert!(quarantined_by_display_name.is_none(),
                "missing field must default to None"),
            other => panic!("expected InitiativeQuarantined; got {other:?}"),
        }

        let legacy_swept = serde_json::json!({
            "kind":               "OperatorQuarantineSwept",
            "target_fingerprint": "chika-fp",
            "quarantined_by":     "rot-fp",
            "count":              0,
            "reason":             null,
        });
        let parsed: AuditEventKind = serde_json::from_value(legacy_swept).unwrap();
        match parsed {
            AuditEventKind::OperatorQuarantineSwept {
                quarantined_by_display_name, target_display_name, ..
            } => {
                assert!(quarantined_by_display_name.is_none());
                assert!(target_display_name.is_none());
            }
            other => panic!("expected OperatorQuarantineSwept; got {other:?}"),
        }
    }

    #[test]
    fn emergency_operator_used_round_trips() {
        let kind = AuditEventKind::EmergencyOperatorUsed {
            pubkey_fingerprint: "fp-emerg".to_owned(),
            epoch_id:           5,
            op:                 "RotateEpoch".to_owned(),
        };
        let s = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::EmergencyOperatorUsed { pubkey_fingerprint, epoch_id, op } => {
                assert_eq!(pubkey_fingerprint, "fp-emerg");
                assert_eq!(epoch_id, 5);
                assert_eq!(op,       "RotateEpoch");
            }
            other => panic!("expected EmergencyOperatorUsed; got {other:?}"),
        }
    }

    /// Pin the misconfig-bypass payload shape. The `violations` list
    /// captures every relaxed structural rule verbatim; downstream
    /// notification routes match on `kind == "OperatorCertMisconfigBypassed"`
    /// and inspect `violations` to decide whether to page.
    #[test]
    fn operator_cert_misconfig_bypassed_serialises_violations_list() {
        let kind = AuditEventKind::OperatorCertMisconfigBypassed {
            pubkey_fingerprint: "fp-x".to_owned(),
            epoch_id:           3,
            cert_kind:          "EmergencyRecovery".to_owned(),
            display_name:       "break-glass".to_owned(),
            violations:         vec![
                "EmergencyRecovery cert MUST declare permitted_ops = [\"RotateEpoch\"] only".to_owned(),
                "warn_before_expiry_days must be > 0".to_owned(),
            ],
        };
        let v = serde_json::to_value(&kind).unwrap();
        assert_eq!(v["kind"], serde_json::json!("OperatorCertMisconfigBypassed"));
        assert_eq!(v["pubkey_fingerprint"], serde_json::json!("fp-x"));
        assert_eq!(v["epoch_id"], serde_json::json!(3));
        assert_eq!(v["cert_kind"], serde_json::json!("EmergencyRecovery"));
        assert_eq!(v["display_name"], serde_json::json!("break-glass"));
        assert_eq!(v["violations"].as_array().unwrap().len(), 2);
        assert!(v["violations"][0].as_str().unwrap().contains("RotateEpoch"));
    }

    #[test]
    fn path_read_accessed_round_trips_through_json() {
        let kind = AuditEventKind::PathReadAccessed {
            actor:   "cli:chika".to_owned(),
            table:   "task_plan_fields".to_owned(),
            column:  "path_export_globs".to_owned(),
            task_id: "t-42".to_owned(),
            command: "inspect".to_owned(),
        };
        let s    = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::PathReadAccessed { actor, table, column, task_id, command } => {
                assert_eq!(actor,   "cli:chika");
                assert_eq!(table,   "task_plan_fields");
                assert_eq!(column,  "path_export_globs");
                assert_eq!(task_id, "t-42");
                assert_eq!(command, "inspect");
            }
            other => panic!("expected PathReadAccessed; got {other:?}"),
        }
    }

    // ── V2 SecurityViolation (v2-deep-spec.md §Step 13) ─────────────────────

    /// Pinned variant count for the adversarial-input class taxonomy.
    /// Adding a new class requires the static dispatch matrix
    /// (v2-deep-spec.md §Step 20) AND the pre-auth blocklist
    /// (v2-deep-spec.md §Step 15) to be updated in lock-step. The pin
    /// surfaces drift at the test level before any handler regresses.
    #[test]
    fn security_violation_class_variant_count_is_pinned() {
        assert_eq!(SecurityViolationClass::ALL.len(), 3,
            "V2 has exactly 3 SecurityViolationClass variants \
             (FrameMalformation, AuthorityProbe, Replay); bumping this \
             requires dispatch-matrix + pre-auth blocklist updates.");
    }

    /// Each class round-trips through JSON with the exact PascalCase
    /// string the audit-replay tooling matches against.
    #[test]
    fn security_violation_class_serde_round_trip() {
        for &c in &SecurityViolationClass::ALL {
            let s = serde_json::to_string(&c).unwrap();
            let back: SecurityViolationClass = serde_json::from_str(&s).unwrap();
            assert_eq!(back, c, "round-trip failed for {c:?}: {s}");
            assert_eq!(c.as_str(), s.trim_matches('"'),
                "as_str must equal the JSON-projected discriminator");
            assert_eq!(c.to_string(), c.as_str(),
                "Display impl must equal as_str");
        }
    }

    /// Pin the on-wire shape of a class-1 (FrameMalformation)
    /// SecurityViolation: no session_id, no peer_cid (UDS path),
    /// raw_frame_sha256 captured for forensic correlation.
    #[test]
    fn security_violation_class_1_serialises_without_session_id() {
        let kind = AuditEventKind::SecurityViolation {
            session_id:       None,
            violation_class:  SecurityViolationClass::FrameMalformation,
            raw_frame_sha256: "deadbeef".repeat(8), // 64-char hex
            frame_size:       42,
            peer_cid:         Some(123),
        };
        let v = serde_json::to_value(&kind).unwrap();
        assert_eq!(v["kind"], serde_json::json!("SecurityViolation"));
        assert_eq!(v["violation_class"], serde_json::json!("FrameMalformation"));
        assert_eq!(v["frame_size"], serde_json::json!(42));
        assert_eq!(v["peer_cid"], serde_json::json!(123));
        // None fields are skipped by `skip_serializing_if = Option::is_none`.
        assert!(!v.as_object().unwrap().contains_key("session_id"),
            "session_id must be elided from class-1 wire shape");
    }

    /// Pin the on-wire shape of a class-2 (AuthorityProbe)
    /// SecurityViolation: session_id IS present (the kernel had a
    /// session to match against). This is the case the static dispatch
    /// matrix produces.
    #[test]
    fn security_violation_class_2_serialises_with_session_id() {
        let kind = AuditEventKind::SecurityViolation {
            session_id:       Some("s-abc".to_owned()),
            violation_class:  SecurityViolationClass::AuthorityProbe,
            raw_frame_sha256: "f".repeat(64),
            frame_size:       128,
            peer_cid:         Some(7),
        };
        let v = serde_json::to_value(&kind).unwrap();
        assert_eq!(v["kind"], serde_json::json!("SecurityViolation"));
        assert_eq!(v["violation_class"], serde_json::json!("AuthorityProbe"));
        assert_eq!(v["session_id"], serde_json::json!("s-abc"));
    }

    /// Round-trip through JSON for the Replay class. The replay
    /// SecurityViolation is the highest-stakes variant — false
    /// positives revoke the session token, so wire-shape stability is
    /// load-bearing for the replay-detection unit tests in the IPC
    /// layer.
    #[test]
    fn security_violation_replay_round_trips() {
        let kind = AuditEventKind::SecurityViolation {
            session_id:       Some("s-replay".to_owned()),
            violation_class:  SecurityViolationClass::Replay,
            raw_frame_sha256: "ab".repeat(32),
            frame_size:       1024,
            peer_cid:         None,
        };
        let s = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::SecurityViolation {
                session_id, violation_class, raw_frame_sha256, frame_size, peer_cid,
            } => {
                assert_eq!(session_id.as_deref(), Some("s-replay"));
                assert_eq!(violation_class, SecurityViolationClass::Replay);
                assert_eq!(raw_frame_sha256.len(), 64);
                assert_eq!(frame_size, 1024);
                assert!(peer_cid.is_none(),
                    "peer_cid is None on the legacy UDS path");
            }
            other => panic!("expected SecurityViolation; got {other:?}"),
        }
    }

    /// `SecurityViolation` discriminator is wire-stable. Forensic
    /// queries (`raxis audit query --event-type SecurityViolation`)
    /// match on this exact string.
    #[test]
    fn security_violation_kind_string_is_pinned() {
        let kind = AuditEventKind::SecurityViolation {
            session_id:       None,
            violation_class:  SecurityViolationClass::FrameMalformation,
            raw_frame_sha256: "0".repeat(64),
            frame_size:       0,
            peer_cid:         None,
        };
        assert_eq!(kind.as_str(), "SecurityViolation");
    }

    // ── V2 SessionCreated attribution chain (v2-deep-spec.md §Step 7) ────────

    /// V2 sessions carry the 4-field attribution chain:
    /// `(session_id, initiative_id, plan_bundle_sha256, policy_epoch)`
    /// plus `session_agent_type`. All five fields round-trip through
    /// JSON without information loss.
    #[test]
    fn v2_session_created_attribution_chain_round_trips() {
        let kind = AuditEventKind::SessionCreated {
            session_id:        "s-1".to_owned(),
            role:              "planner".to_owned(),
            lineage_id:        "l-1".to_owned(),
            worktree_root:     Some("/work/orch".to_owned()),
            initiative_id:     Some("init-7".to_owned()),
            plan_bundle_sha256: Some("a".repeat(64)),
            policy_epoch:      Some(42),
            session_agent_type: Some("Orchestrator".to_owned()),
        };
        let s = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::SessionCreated {
                session_id, role, lineage_id, worktree_root,
                initiative_id, plan_bundle_sha256, policy_epoch, session_agent_type,
            } => {
                assert_eq!(session_id, "s-1");
                assert_eq!(role,       "planner");
                assert_eq!(lineage_id, "l-1");
                assert_eq!(worktree_root.as_deref(), Some("/work/orch"));
                assert_eq!(initiative_id.as_deref(), Some("init-7"));
                assert_eq!(plan_bundle_sha256.as_ref().map(|s| s.len()), Some(64));
                assert_eq!(policy_epoch, Some(42));
                assert_eq!(session_agent_type.as_deref(), Some("Orchestrator"));
            }
            other => panic!("expected SessionCreated; got {other:?}"),
        }
    }

    /// Forward-compat: a legacy V1 SessionCreated record (no V2 fields)
    /// MUST still deserialise under the new struct shape. This pins
    /// the `#[serde(default)] + skip_serializing_if = Option::is_none`
    /// contract for every V2 attribution field.
    #[test]
    fn legacy_session_created_without_v2_fields_still_deserializes() {
        let legacy = serde_json::json!({
            "kind":          "SessionCreated",
            "session_id":    "s-legacy",
            "role":          "planner",
            "lineage_id":    "l-1",
            "worktree_root": null,
        });
        let parsed: AuditEventKind = serde_json::from_value(legacy).unwrap();
        match parsed {
            AuditEventKind::SessionCreated {
                initiative_id, plan_bundle_sha256, policy_epoch,
                session_agent_type, ..
            } => {
                assert!(initiative_id.is_none(),
                    "missing initiative_id must default to None");
                assert!(plan_bundle_sha256.is_none(),
                    "missing plan_bundle_sha256 must default to None");
                assert!(policy_epoch.is_none(),
                    "missing policy_epoch must default to None");
                assert!(session_agent_type.is_none(),
                    "missing session_agent_type must default to None");
            }
            other => panic!("expected SessionCreated; got {other:?}"),
        }
    }

    /// V2 attribution fields are elided from the JSON when None — a
    /// V1 session emitted under the V2 codebase must produce wire
    /// bytes byte-identical to a legacy V1 emit (modulo audit chain
    /// hash inputs that are unchanged anyway). This is the
    /// `skip_serializing_if = Option::is_none` contract.
    #[test]
    fn v1_session_created_under_v2_codebase_omits_v2_fields_on_wire() {
        let kind = AuditEventKind::SessionCreated {
            session_id:        "s-v1".to_owned(),
            role:              "planner".to_owned(),
            lineage_id:        "l-1".to_owned(),
            worktree_root:     None,
            initiative_id:     None,
            plan_bundle_sha256: None,
            policy_epoch:      None,
            session_agent_type: None,
        };
        let v = serde_json::to_value(&kind).unwrap();
        let obj = v.as_object().unwrap();
        // Only V1 fields plus the discriminator + null worktree_root
        // (which is part of the V1 shape) appear on the wire.
        assert!(!obj.contains_key("initiative_id"));
        assert!(!obj.contains_key("plan_bundle_sha256"));
        assert!(!obj.contains_key("policy_epoch"));
        assert!(!obj.contains_key("session_agent_type"));
        assert_eq!(obj["kind"], serde_json::json!("SessionCreated"));
        assert_eq!(obj["session_id"], serde_json::json!("s-v1"));
    }

    /// V2 Step 30: `IntegrationMergeCompleted` round-trips through
    /// JSON when the merge was operator-assisted (escalation_id +
    /// operator_assisted = true present on the wire).
    #[test]
    fn integration_merge_completed_operator_assisted_round_trips_through_json() {
        let kind = AuditEventKind::IntegrationMergeCompleted {
            initiative_id:     "init-7".into(),
            session_id:        "sess-orch-1".into(),
            commit_sha:        "abc1234".into(),
            previous_sha:      "f3d21a09".into(),
            operator_assisted: true,
            escalation_id:     Some("esc-42".into()),
            target_ref:        "refs/heads/main".into(),
        };
        let s    = serde_json::to_string(&kind).unwrap();
        let back = serde_json::from_str::<AuditEventKind>(&s).unwrap();
        match back {
            AuditEventKind::IntegrationMergeCompleted {
                initiative_id, session_id, commit_sha, previous_sha,
                operator_assisted, escalation_id, target_ref,
            } => {
                assert_eq!(initiative_id,     "init-7");
                assert_eq!(session_id,        "sess-orch-1");
                assert_eq!(commit_sha,        "abc1234");
                assert_eq!(previous_sha,      "f3d21a09");
                assert!(operator_assisted,
                    "operator_assisted must round-trip as true — \
                     dropping it would erase Step 30 attribution");
                assert_eq!(escalation_id.as_deref(), Some("esc-42"));
                assert_eq!(target_ref, "refs/heads/main",
                    "target_ref must round-trip so boot recovery can re-run \
                     commit_merge_to_target_ref against the same ref");
            }
            other => panic!("expected IntegrationMergeCompleted; got {other:?}"),
        }
    }

    /// V2 Step 30: a standard (non-operator-assisted) merge omits
    /// `escalation_id` from the wire and serialises
    /// `operator_assisted: false`. Forward-compat: a legacy reader
    /// that has not learned the new variant fields still parses the
    /// shape via `#[serde(default)]`.
    #[test]
    fn integration_merge_completed_standard_merge_round_trips_through_json() {
        let kind = AuditEventKind::IntegrationMergeCompleted {
            initiative_id:     "init-7".into(),
            session_id:        "sess-orch-1".into(),
            commit_sha:        "def5678".into(),
            previous_sha:      "f3d21a09".into(),
            operator_assisted: false,
            escalation_id:     None,
            target_ref:        "refs/heads/main".into(),
        };
        let v = serde_json::to_value(&kind).unwrap();
        let obj = v.as_object().unwrap();
        // operator_assisted is a primitive — serde never elides it
        // even when false; that is the desired invariant (the field
        // is the discriminator for forensic reconstruction).
        assert_eq!(obj["operator_assisted"], serde_json::json!(false));
        // escalation_id is Option-typed with skip-on-None.
        assert!(!obj.contains_key("escalation_id"),
            "escalation_id MUST be elided when None so legacy V1 audit \
             readers can parse the line without learning the new field");
        assert_eq!(obj["kind"], serde_json::json!("IntegrationMergeCompleted"));

        // Decode round-trip preserves the None on escalation_id.
        let back = serde_json::from_value::<AuditEventKind>(v).unwrap();
        match back {
            AuditEventKind::IntegrationMergeCompleted {
                operator_assisted, escalation_id, ..
            } => {
                assert!(!operator_assisted);
                assert!(escalation_id.is_none());
            }
            other => panic!("expected IntegrationMergeCompleted; got {other:?}"),
        }
    }

    /// V2 `v2_extended_gaps.md §1.2` — `MergeFastForwardFailed`
    /// round-trips through JSON, carrying every classification field
    /// an operator dashboard / runbook needs to route the alert
    /// without re-running the kernel. The variant is the durable
    /// signal that Phase 1 (SQLite intent commit) succeeded but
    /// Phase 2 (host-side `target_ref` advance) did not — pinning the
    /// shape protects the downstream consumers (ops dashboards,
    /// recovery driver) from silent drift.
    #[test]
    fn merge_fast_forward_failed_round_trips_through_json() {
        let kind = AuditEventKind::MergeFastForwardFailed {
            initiative_id: "init-ff-1".into(),
            commit_sha:    "abc1234".into(),
            target_ref:    "refs/heads/main".into(),
            category:      "target_ref_advanced_concurrently".into(),
            reason:        "ref txn rejected: expected 0000…, got deadbeef".into(),
        };
        let s    = serde_json::to_string(&kind).unwrap();
        let v    = serde_json::from_str::<serde_json::Value>(&s).unwrap();
        let obj  = v.as_object().unwrap();
        assert_eq!(obj["kind"], serde_json::json!("MergeFastForwardFailed"));
        assert_eq!(obj["initiative_id"], serde_json::json!("init-ff-1"));
        assert_eq!(obj["target_ref"],    serde_json::json!("refs/heads/main"));
        assert_eq!(
            obj["category"],
            serde_json::json!("target_ref_advanced_concurrently"),
            "category MUST round-trip verbatim — dashboards pivot on it",
        );

        let back = serde_json::from_str::<AuditEventKind>(&s).unwrap();
        match back {
            AuditEventKind::MergeFastForwardFailed {
                initiative_id, commit_sha, target_ref, category, reason,
            } => {
                assert_eq!(initiative_id, "init-ff-1");
                assert_eq!(commit_sha,    "abc1234");
                assert_eq!(target_ref,    "refs/heads/main");
                assert_eq!(category,      "target_ref_advanced_concurrently");
                assert!(reason.contains("ref txn rejected"));
            }
            other => panic!("expected MergeFastForwardFailed; got {other:?}"),
        }
    }

    /// V2 `v2_extended_gaps.md §1.2` — the variant's
    /// `as_str()` projection MUST equal the on-wire JSON
    /// `kind` field. This is the contract the
    /// audit-segment grep'er and the chain-walker rely on.
    #[test]
    fn merge_fast_forward_failed_kind_string_matches_wire() {
        let kind = AuditEventKind::MergeFastForwardFailed {
            initiative_id: "init-x".into(),
            commit_sha:    "fff".into(),
            target_ref:    "refs/heads/feature".into(),
            category:      "git_failed".into(),
            reason:        "exit 128".into(),
        };
        assert_eq!(kind.as_str(), "MergeFastForwardFailed");
        let s = serde_json::to_string(&kind).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["kind"], serde_json::json!("MergeFastForwardFailed"));
    }

    /// Forward-compat: an older audit segment that emitted
    /// `IntegrationMergeCompleted` without the Step 30 fields MUST
    /// still deserialise — `operator_assisted` defaults to `false`,
    /// `escalation_id` defaults to `None`. `target_ref` (V2.5) also
    /// defaults to `""` — recovery filters by `git_apply_pending = 1`
    /// (column added by migration 16, default 0 for pre-V2.5 rows),
    /// so an empty `target_ref` from a legacy segment is never acted
    /// on. This pins the `#[serde(default)]` contract.
    #[test]
    fn legacy_integration_merge_completed_without_step30_fields_still_deserializes() {
        let legacy = serde_json::json!({
            "kind":          "IntegrationMergeCompleted",
            "initiative_id": "init-old",
            "session_id":    "sess-old",
            "commit_sha":    "ddddddd",
            "previous_sha":  "ccccccc",
        });
        let parsed: AuditEventKind = serde_json::from_value(legacy).unwrap();
        match parsed {
            AuditEventKind::IntegrationMergeCompleted {
                operator_assisted, escalation_id, target_ref, ..
            } => {
                assert!(!operator_assisted,
                    "missing operator_assisted defaults to false");
                assert!(escalation_id.is_none(),
                    "missing escalation_id defaults to None");
                assert!(target_ref.is_empty(),
                    "missing target_ref defaults to empty string");
            }
            other => panic!("expected IntegrationMergeCompleted; got {other:?}"),
        }
    }
}

#[cfg(test)]
mod credential_proxy_kind_tests {
    use super::*;

    #[test]
    fn credential_proxy_started_kind_string_is_pinned() {
        let kind = AuditEventKind::CredentialProxyStarted {
            session_id:      "sess-1".to_owned(),
            proxy_type:      "postgres".to_owned(),
            credential_name: "db-staging".to_owned(),
            addr:            "127.0.0.1:5432".to_owned(),
        };
        assert_eq!(kind.as_str(), "CredentialProxyStarted");
        let v = serde_json::to_value(&kind).expect("serialises");
        assert_eq!(v["kind"],            serde_json::json!("CredentialProxyStarted"));
        assert_eq!(v["session_id"],      serde_json::json!("sess-1"));
        assert_eq!(v["proxy_type"],      serde_json::json!("postgres"));
        assert_eq!(v["credential_name"], serde_json::json!("db-staging"));
        assert_eq!(v["addr"],            serde_json::json!("127.0.0.1:5432"));
    }

    #[test]
    fn credential_proxy_stopped_kind_string_and_counters_pinned() {
        let kind = AuditEventKind::CredentialProxyStopped {
            session_id:         "sess-1".to_owned(),
            proxy_type:         "postgres".to_owned(),
            credential_name:    "db-staging".to_owned(),
            connections_served: 7,
            forwards_completed: 5,
            forwards_blocked:   2,
        };
        assert_eq!(kind.as_str(), "CredentialProxyStopped");
        let v = serde_json::to_value(&kind).expect("serialises");
        assert_eq!(v["kind"],               serde_json::json!("CredentialProxyStopped"));
        assert_eq!(v["connections_served"], serde_json::json!(7));
        assert_eq!(v["forwards_completed"], serde_json::json!(5));
        assert_eq!(v["forwards_blocked"],   serde_json::json!(2));
    }

    #[test]
    fn database_query_executed_kind_string_and_fields_pinned() {
        let kind = AuditEventKind::DatabaseQueryExecuted {
            session_id:      "sess-1".to_owned(),
            credential_name: "db-staging".to_owned(),
            operation:       "SELECT".to_owned(),
            sql_sha256:      "deadbeef".to_owned(),
            sql_plaintext:   None,
            blocked:         false,
        };
        assert_eq!(kind.as_str(), "DatabaseQueryExecuted");
        let v = serde_json::to_value(&kind).expect("serialises");
        assert_eq!(v["kind"],          serde_json::json!("DatabaseQueryExecuted"));
        assert_eq!(v["operation"],     serde_json::json!("SELECT"));
        assert_eq!(v["sql_sha256"],    serde_json::json!("deadbeef"));
        assert_eq!(v["sql_plaintext"], serde_json::json!(null));
        assert_eq!(v["blocked"],       serde_json::json!(false));
    }

    #[test]
    fn http_proxy_request_executed_kind_string_and_fields_pinned() {
        let kind = AuditEventKind::HttpProxyRequestExecuted {
            session_id:      "sess-1".to_owned(),
            credential_name: "kube-prod".to_owned(),
            method:          "GET".to_owned(),
            path:            "/api/v1/widgets".to_owned(),
            path_sha256:     "cafebabe".to_owned(),
            status_code:     200,
            blocked:         false,
        };
        assert_eq!(kind.as_str(), "HttpProxyRequestExecuted");
        let v = serde_json::to_value(&kind).expect("serialises");
        assert_eq!(v["kind"],        serde_json::json!("HttpProxyRequestExecuted"));
        assert_eq!(v["method"],      serde_json::json!("GET"));
        assert_eq!(v["path"],        serde_json::json!("/api/v1/widgets"));
        assert_eq!(v["path_sha256"], serde_json::json!("cafebabe"));
        assert_eq!(v["status_code"], serde_json::json!(200));
        assert_eq!(v["blocked"],     serde_json::json!(false));
    }
}
