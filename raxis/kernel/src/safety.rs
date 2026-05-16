//! Kernel-wide panic taxonomy and the `fatal_safety_critical` helper.
//!
//! Normative reference: `specs/invariants.md`
//! `INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01`.
//!
//! The kernel daemon classifies every panic-class failure into one of
//! three categories so the recovery layers (Layer 1 site-specific
//! `block_in_place`, Layer 2 per-handler `catch_unwind` boundaries,
//! Layer 3 global `panic_hook`) preserve **safety** even while
//! preserving **liveness**. Recovery must NEVER weaken a safety
//! invariant; if it would, the work is upgraded to a fatal class
//! that bypasses recovery.
//!
//! ### Categories
//!
//! * [`KernelPanicCategory::SafetyCritical`] — trust-anchor mismatch,
//!   canonical-image signature mismatch, audit-chain hash drift,
//!   plan-bundle seal failure, schema-corruption-detected-mid-tx,
//!   capability-check inconsistency. These MUST crash the daemon.
//!   Reach via [`fatal_safety_critical`] which calls
//!   [`std::process::abort`] — bypasses every `catch_unwind`, every
//!   panic hook, and skips unwind. Supervisor restarts cleanly,
//!   nothing observed mid-corrupt. We TRUST these aborts; they are a
//!   deliberate refusal to keep running.
//!
//! * [`KernelPanicCategory::FatalForInitiative`] — corruption scoped
//!   to one initiative (orphan lane reservation, lineage hash
//!   mismatch, terminal-criteria contradiction). Mark the initiative
//!   `Failed { reason: KernelInvariantViolated }`, refuse all new
//!   work on its lane, daemon keeps serving everyone else, operator
//!   must inspect manually. NOT auto-recoverable. The catch_unwind
//!   boundary (Layer 2) routes this category to the
//!   "fail-this-initiative-but-keep-the-daemon" path; iter66 does
//!   not yet implement Layer 2, so today this category is reserved
//!   for future use and behaves identically to
//!   [`KernelPanicCategory::RecoverableHandlerBug`] at the global
//!   panic hook.
//!
//! * [`KernelPanicCategory::RecoverableHandlerBug`] — programming
//!   errors (lock_sync misuse, deserialization off-by-one, unwrap on
//!   a None that "couldn't happen"). Layer 2 catches and downgrades
//!   to a typed `HandlerError::HandlerPanicked`; daemon continues.
//!   Operator can re-queue from the last clean witness via the
//!   iter65 `OperatorApprove` recovery path. Layer 3 (global panic
//!   hook) classifies an *uncategorised* panic as this — i.e. any
//!   plain `panic!()` whose payload is not wrapped in
//!   [`FatalKernelPanic`] is assumed to be a recoverable handler
//!   bug. The hook still emits the audit row + Critical
//!   notification, then chains to the default hook so the unwind
//!   continues and the supervisor restarts. The daemon is replaced
//!   cleanly; recovery picks up state from SQL.
//!
//! ### `FatalKernelPanic` payload sentinel
//!
//! [`FatalKernelPanic`] is the panic-payload sentinel that Layer 2
//! (`catch_unwind` boundary) will inspect to route panics by
//! category. Today (iter66) the payload is constructed only at the
//! `fatal_safety_critical` site (which `abort`s instead of
//! `panic!`s, so the payload is never thrown), but the type is
//! stable and ready for Layer 2 to use directly.
//!
//! The pattern for Layer 2 (iter67):
//!
//! ```ignore
//! match catch_unwind(AssertUnwindSafe(handler_future)).await {
//!     Ok(v) => Ok(v),
//!     Err(payload) => {
//!         if let Some(fatal) = payload.downcast_ref::<FatalKernelPanic>() {
//!             match fatal.category {
//!                 KernelPanicCategory::SafetyCritical => {
//!                     // Should never be reachable — fatal_safety_critical
//!                     // calls abort(), not panic!. Defense in depth: if
//!                     // we ever see this payload, re-throw to crash the
//!                     // daemon. Liveness is forfeit when safety is at
//!                     // risk.
//!                     std::panic::resume_unwind(payload);
//!                 }
//!                 KernelPanicCategory::FatalForInitiative => {
//!                     fail_initiative(initiative_id, KernelInvariantViolated, fatal);
//!                     Err(HandlerError::HandlerPanicked { /* ... */ })
//!                 }
//!                 KernelPanicCategory::RecoverableHandlerBug => {
//!                     fail_session(session_id, HandlerPanicked, fatal);
//!                     Err(HandlerError::HandlerPanicked { /* ... */ })
//!                 }
//!             }
//!         } else {
//!             // Uncategorised plain panic. Treat as RecoverableHandlerBug.
//!             fail_session(session_id, HandlerPanicked, payload_str(&payload));
//!             Err(HandlerError::HandlerPanicked { /* ... */ })
//!         }
//!     }
//! }
//! ```

use std::fmt::Display;
use std::sync::Arc;
use std::sync::OnceLock;

use raxis_audit_tools::{AuditEventKind, AuditSink};

/// Three-way classification of every panic-class failure in the kernel.
/// See module docs for the per-category contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelPanicCategory {
    /// Trust / signature / audit-chain / schema corruption. NEVER
    /// recover; calls [`std::process::abort`] via
    /// [`fatal_safety_critical`]. Only the supervisor sees this
    /// (next boot synthesises `KernelRestartInitiated { reason:
    /// "PanicAbort" }`).
    SafetyCritical,

    /// Initiative-scoped corruption. Mark the initiative `Failed`,
    /// daemon keeps serving everyone else. Reserved for Layer 2
    /// (`catch_unwind` boundary, iter67); today routes through the
    /// `RecoverableHandlerBug` arm at the global panic hook.
    FatalForInitiative,

    /// Plain handler bug. Catch, downgrade to
    /// `HandlerError::HandlerPanicked`, mark session `Failed`,
    /// daemon continues, operator can `OperatorApprove` recovery.
    RecoverableHandlerBug,
}

impl KernelPanicCategory {
    /// Stable wire string for audit/event payloads. Pinned so the
    /// dashboard can route on the value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SafetyCritical => "SafetyCritical",
            Self::FatalForInitiative => "FatalForInitiative",
            Self::RecoverableHandlerBug => "RecoverableHandlerBug",
        }
    }
}

/// Panic-payload sentinel inspected by Layer 2 (`catch_unwind`
/// boundary, iter67) and the Layer 3 global panic hook to route a
/// thrown panic by category. See module docs for the catch-side
/// pattern.
#[derive(Debug, Clone)]
pub struct FatalKernelPanic {
    pub category: KernelPanicCategory,
    pub invariant_id: &'static str,
    pub detail: String,
    pub location: &'static std::panic::Location<'static>,
}

impl Display for FatalKernelPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FatalKernelPanic[{cat}] {inv} at {loc}: {det}",
            cat = self.category.as_str(),
            inv = self.invariant_id,
            loc = self.location,
            det = self.detail,
        )
    }
}

/// Process-global handle the [`fatal_safety_critical`] helper uses
/// to best-effort emit the `KernelSafetyInvariantViolated` audit
/// row before `abort`. Set once at boot from `kernel/src/main.rs`
/// after the audit sink is constructed; subsequent calls are no-ops
/// (the boot path installs exactly one audit sink for the whole
/// process lifetime).
///
/// **Re-entrancy:** the helper acquires the sink via
/// [`OnceLock::get`] (lock-free read) so a panic during audit emit
/// does not recurse into the helper. If the sink itself panics, the
/// helper falls through to the structured stderr line + abort —
/// the abort is the durable signal.
static SAFETY_AUDIT_SINK: OnceLock<Arc<dyn AuditSink>> = OnceLock::new();

/// Install the audit sink the [`fatal_safety_critical`] helper
/// uses for its best-effort emit. Idempotent — only the first
/// call wins; subsequent calls are silently dropped (the kernel
/// boot path constructs the sink exactly once).
pub fn install_safety_audit_sink(sink: Arc<dyn AuditSink>) {
    let _ = SAFETY_AUDIT_SINK.set(sink);
}

/// Refusal-to-continue helper for safety-critical invariant
/// violations. Diverges via [`std::process::abort`].
///
/// `INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01`: when a
/// kernel-internal check detects that continuing would corrupt
/// state observable to operators or downstream consumers (audit
/// chain, signed plan bundle, capability delegation, canonical
/// image trust anchor), the kernel MUST refuse to continue rather
/// than recover. `panic!` is insufficient — a future
/// `catch_unwind` boundary could swallow it. `abort` bypasses
/// every layer.
///
/// Order of operations:
///   1. Synchronous structured stderr line (`KernelSafetyInvariantViolated`)
///      so the log aggregator sees the refusal even if every
///      higher layer is wedged.
///   2. Best-effort audit emit via the process-global sink (no-op
///      if [`install_safety_audit_sink`] was never called or the
///      sink itself errors).
///   3. [`std::process::abort`] — process dies hard, supervisor
///      restarts cleanly, recovery picks up state from SQL.
///
/// Destructors do NOT run; flushed-before-abort state is the
/// caller's responsibility (use [`fatal_safety_critical`] only at
/// integrity-checkpoint sites, not mid-write).
#[track_caller]
pub fn fatal_safety_critical(invariant_id: &'static str, detail: impl Display) -> ! {
    let location = std::panic::Location::caller();
    let detail_str = detail.to_string();

    eprintln!(
        "{{\"level\":\"fatal\",\"event\":\"KernelSafetyInvariantViolated\",\
         \"invariant\":\"{inv}\",\"location\":\"{file}:{line}:{col}\",\
         \"detail\":{det}}}",
        inv = invariant_id,
        file = location.file(),
        line = location.line(),
        col = location.column(),
        det = serde_json::Value::String(detail_str.clone()),
    );

    if let Some(sink) = SAFETY_AUDIT_SINK.get() {
        let event = AuditEventKind::KernelSafetyInvariantViolated {
            invariant_id: invariant_id.to_owned(),
            location: format!(
                "{}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            ),
            detail: detail_str,
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = sink.emit(event, None, None, None);
        }));
    }

    std::process::abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_as_str_is_pinned() {
        assert_eq!(
            KernelPanicCategory::SafetyCritical.as_str(),
            "SafetyCritical"
        );
        assert_eq!(
            KernelPanicCategory::FatalForInitiative.as_str(),
            "FatalForInitiative"
        );
        assert_eq!(
            KernelPanicCategory::RecoverableHandlerBug.as_str(),
            "RecoverableHandlerBug"
        );
    }

    #[test]
    #[track_caller]
    fn fatal_kernel_panic_display_includes_all_fields() {
        let f = FatalKernelPanic {
            category: KernelPanicCategory::SafetyCritical,
            invariant_id: "INV-TEST-EXAMPLE-01",
            detail: "trust anchor mismatch: expected aaaa, got bbbb".to_owned(),
            location: std::panic::Location::caller(),
        };
        let s = f.to_string();
        assert!(s.contains("SafetyCritical"), "got {s}");
        assert!(s.contains("INV-TEST-EXAMPLE-01"), "got {s}");
        assert!(s.contains("trust anchor mismatch"), "got {s}");
    }

    /// `INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01`:
    /// installing the audit sink twice is idempotent — the first
    /// call wins. Boot is the canonical install site; subsequent
    /// reinstalls (e.g. policy-manager handing off, hot-reload
    /// edge cases) MUST NOT silently swap the sink under a
    /// `fatal_safety_critical` caller mid-flight.
    ///
    /// We can't actually exercise `fatal_safety_critical` inside a
    /// `#[test]` (it `abort`s — process dies, harness fails). The
    /// install-idempotency contract is structural: `OnceLock::set`
    /// returns Err on second call, and the wrapper discards the
    /// Err so external callers never see the duplicate-set error.
    /// We do NOT call `SAFETY_AUDIT_SINK.set(...)` from inside a
    /// `#[test]` because that would race with any future test
    /// process that needed the sink. Process-level coverage of
    /// `abort` behaviour is via the `std::process::Command`
    /// integration test in `kernel/tests/safety_abort.rs`.
    #[test]
    fn install_safety_audit_sink_signature_is_idempotent_safe() {
        // Compile-time: the wrapper takes `Arc<dyn AuditSink>` and
        // returns `()`. The `OnceLock::set` Err is discarded via
        // `let _ = ...`. This test exists so a future refactor
        // that changes the signature trips a compile error here
        // before it can break boot.
        let f: fn(Arc<dyn AuditSink>) = install_safety_audit_sink;
        let _ = f;
    }
}
