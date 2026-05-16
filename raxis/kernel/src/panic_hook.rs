//! Layer 3 of the kernel's recovery taxonomy: the global panic hook.
//!
//! Normative reference: `specs/invariants.md`
//! `INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01`.
//!
//! ### Layered defense recap
//!
//! 1. **Layer 1 — site-specific recovery.** Known bug classes
//!    (`Store::lock_sync` from async, etc.) are wrapped at the
//!    boundary so the work succeeds + emits telemetry instead of
//!    panicking. See `INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01`.
//!
//! 2. **Layer 2 — per-handler `catch_unwind` boundary** (iter67).
//!    Every IPC dispatch / scheduler-poll iteration / spawned
//!    background task wraps its body in
//!    `futures::FutureExt::catch_unwind(AssertUnwindSafe(future))`,
//!    inspects the payload for [`crate::safety::FatalKernelPanic`],
//!    routes by [`crate::safety::KernelPanicCategory`], and returns
//!    a typed error. NOT yet implemented; the hook below assumes
//!    Layer 2 is absent.
//!
//! 3. **Layer 3 — this module.** Last-resort backstop. Catches every
//!    panic that escaped Layers 1 + 2. Synchronously emits:
//!
//!    a. Structured stderr (`KernelPanicCaught` JSON line) — the
//!    durable signal that the log aggregator + supervisor see.
//!    b. Best-effort audit row via the captured audit sink.
//!    c. Best-effort Critical operator notification.
//!    d. Chains to the previously installed panic hook (which
//!    ultimately reaches the Rust default hook so the standard
//!    panic banner prints + the unwind continues).
//!
//!    The hook does NOT swallow panics. Unwinding proceeds; the
//!    daemon eventually reaches `process::exit` (panic = "unwind"
//!    profile) or `abort` (panic = "abort" profile). Either way the
//!    supervisor restarts and the next boot synthesises a
//!    `KernelRestartInitiated { reason: "PanicAbort" }` audit row.
//!
//! ### Safety-preservation contract
//!
//! Per `INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01`,
//! recovery layers MUST NOT weaken any of the kernel's safety
//! invariants. The hook's contributions:
//!
//! * The eprintln IS the durable signal. Audit + notification are
//!   best-effort decorations; their failure does NOT alter the
//!   panic outcome (Rust unwind continues regardless).
//!
//! * The hook NEVER catches a panic — it only enriches it. A
//!   panic-in-handler still tears the calling stack down. Future
//!   Layer 2 will catch at the dispatch boundary; this hook fires
//!   for panics that escape that boundary too.
//!
//! * The hook MUST NOT panic from inside itself (recursive panic
//!   aborts immediately with no diagnostic). All emit paths are
//!   wrapped in [`std::panic::catch_unwind`] +
//!   [`std::panic::AssertUnwindSafe`].
//!
//! * Safety-critical refusals (signature mismatch, trust anchor
//!   mismatch, audit-chain hash drift) reach
//!   [`crate::safety::fatal_safety_critical`] which calls
//!   [`std::process::abort`] — bypasses this hook entirely. The
//!   hook is for plain `panic!` / unwrap / index-out-of-bounds /
//!   recoverable-handler-bug class panics only.

use std::sync::Arc;

use raxis_audit_tools::{AuditEventKind, AuditSink};

use crate::safety::{FatalKernelPanic, KernelPanicCategory};

/// Maximum bytes of panic payload + backtrace we serialise into the
/// audit row. The audit chain stores the full event JSON; truncating
/// caps the per-row blast radius if a panic message is pathologically
/// large (e.g. an unwrap on a 10MB error string).
const PANIC_PAYLOAD_TRUNCATE_BYTES: usize = 4 * 1024;
const PANIC_BACKTRACE_TRUNCATE_BYTES: usize = 16 * 1024;

/// Install the kernel's global panic hook, composed with whatever
/// hook is currently installed (so the existing
/// `TaskLlmCapture::flush_all` hook continues to fire). Safe to
/// call exactly once at boot AFTER the audit sink has been
/// constructed and BEFORE the gateway pump + IPC server come up so
/// any boot-time panic past audit-init is caught.
///
/// The composed chain:
///   1. The hook installed here (this module's emit).
///   2. The previous hook (if any — typically the
///      `TaskLlmCapture::flush_all` hook from `kernel/src/main.rs`).
///   3. The Rust default hook (printed by the chain via the
///      previous hook delegating).
///
/// Notification sink is optional — if `notification_sink` is
/// `None`, the Critical-priority dashboard alert is skipped (the
/// audit row + eprintln are still emitted). Callers SHOULD pass
/// `Some(...)` once the dashboard sink is wired up; passing `None`
/// is the early-boot path before the dashboard is online.
pub fn install_kernel_panic_hook(
    audit_sink: Arc<dyn AuditSink>,
    notification_sink: Option<Arc<dyn NotificationSinkApi>>,
) {
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Recursive-panic guard. If anything below panics, we'd
        // recurse into this hook and the Rust runtime would
        // `abort` immediately without a diagnostic. Wrap the
        // whole emit body in catch_unwind so the chain to the
        // previous hook always runs even if our enrichment
        // exploded.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            emit_panic_event(info, audit_sink.as_ref(), notification_sink.as_deref());
        }));
        // Always chain to the previous hook so the existing
        // TaskLlmCapture flush + the Rust default panic banner
        // both still fire. This is the unwinding path; the
        // process eventually terminates.
        prev_hook(info);
    }));
}

/// Trait used by [`install_kernel_panic_hook`] to emit Critical
/// operator notifications without taking a hard dependency on the
/// dashboard-kernel crate's concrete sink type. Implementors:
/// `raxis_dashboard_kernel::NotificationSink` (production) and the
/// fake in `kernel/tests/panic_hook.rs` (regression tests).
pub trait NotificationSinkApi: Send + Sync {
    /// Emit a Critical-priority operator notification with the
    /// given title + body + location identifier. Best-effort —
    /// implementors swallow errors; the panic-hook caller does
    /// not check the return.
    fn emit_critical(&self, title: &str, body: &str, location: &str);
}

/// Inner emit path — the catch_unwind-guarded body of the hook
/// closure. Pure-sync; no `await`s; no allocations larger than
/// [`PANIC_PAYLOAD_TRUNCATE_BYTES`] +
/// [`PANIC_BACKTRACE_TRUNCATE_BYTES`].
fn emit_panic_event(
    info: &std::panic::PanicHookInfo<'_>,
    audit_sink: &dyn AuditSink,
    notification_sink: Option<&dyn NotificationSinkApi>,
) {
    let location_str = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "<unknown>".to_owned());
    let thread_name = std::thread::current()
        .name()
        .unwrap_or("<unnamed>")
        .to_owned();
    let (payload_str, category) = classify_payload(info);
    let payload_truncated = truncate_to(&payload_str, PANIC_PAYLOAD_TRUNCATE_BYTES);
    let backtrace = std::backtrace::Backtrace::force_capture().to_string();
    let backtrace_truncated = truncate_to(&backtrace, PANIC_BACKTRACE_TRUNCATE_BYTES);

    // Step 1: structured stderr — the durable signal.
    eprintln!(
        "{{\"level\":\"fatal\",\"event\":\"KernelPanicCaught\",\
         \"category\":\"{cat}\",\"location\":\"{loc}\",\"thread\":\"{thr}\",\
         \"payload\":{payload_json}}}",
        cat = category.as_str(),
        loc = location_str,
        thr = thread_name,
        payload_json = serde_json::Value::String(payload_truncated.clone()),
    );

    // Step 2: best-effort audit emit.
    let event = AuditEventKind::KernelPanicCaught {
        category: category.as_str().to_owned(),
        location: location_str.clone(),
        thread: thread_name.clone(),
        payload: payload_truncated.clone(),
        backtrace: backtrace_truncated,
    };
    let _ = audit_sink.emit(event, None, None, None);

    // Step 3: best-effort Critical operator notification.
    if let Some(sink) = notification_sink {
        sink.emit_critical(
            "Kernel panic caught",
            &format!("{}: {}", category.as_str(), payload_truncated),
            &location_str,
        );
    }
}

/// Inspect the panic payload for a [`FatalKernelPanic`] sentinel
/// and return `(payload_string, category)`. Defaults to
/// [`KernelPanicCategory::RecoverableHandlerBug`] for plain
/// `panic!` / `unwrap` / `expect` payloads.
fn classify_payload(info: &std::panic::PanicHookInfo<'_>) -> (String, KernelPanicCategory) {
    let payload = info.payload();

    // Prefer the FatalKernelPanic sentinel if present (Layer 2's
    // intended throw shape, iter67).
    if let Some(fatal) = payload.downcast_ref::<FatalKernelPanic>() {
        return (fatal.to_string(), fatal.category);
    }

    // Standard library panic payloads come through as &'static str
    // (panic!("literal")) or String (panic!("formatted {}", x)).
    let payload_str = if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        format!(
            "<non-string panic payload of type {:?}>",
            std::any::type_name_of_val(payload)
        )
    };

    (payload_str, KernelPanicCategory::RecoverableHandlerBug)
}

/// Truncate a string to at most `max_bytes` UTF-8 bytes, splitting
/// at a char boundary. Appends `…(truncated, full was N bytes)` if
/// truncation occurred.
fn truncate_to(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    format!("{}…(truncated, full was {} bytes)", &s[..end], s.len())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_string_is_identity() {
        assert_eq!(truncate_to("hello", 100), "hello");
        assert_eq!(truncate_to("", 100), "");
    }

    #[test]
    fn truncate_long_string_appends_marker() {
        let s = "x".repeat(8 * 1024);
        let t = truncate_to(&s, 1024);
        assert!(t.starts_with(&"x".repeat(1024)));
        assert!(t.contains("(truncated, full was 8192 bytes)"));
    }

    #[test]
    fn truncate_respects_char_boundary() {
        // 4-byte UTF-8 char at position [3..7]; max_bytes=5 must
        // not split mid-char.
        let s = "abc🎉def";
        let t = truncate_to(s, 5);
        // The truncation must not panic and must produce valid UTF-8.
        assert!(std::str::from_utf8(t.as_bytes()).is_ok());
    }
}
