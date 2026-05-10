// raxis-kernel::notifications::handler — per-channel-kind handlers.
//
// V2 forward-only surface (no Webhook backward-compat shim): four
// concrete channel kinds — Shell, File, Email, Sidecar.  Shell + File
// share a code path (append a JSON line to a file); Email does a
// minimal SMTP submission with STARTTLS + AUTH PLAIN; Sidecar does an
// HTTP POST through the per-channel semaphore + circuit breaker
// (V2_GAPS.md §C4 design).
//
// The full §6.5 idempotency table + persistent-connection refactor in
// `email-and-notification-channels.md` is V3-grade. The V2 handlers
// are best-effort fire-and-forget — failure surfaces as
// `NotificationDeliveryFailed { reason: "<category>" }` and never
// blocks the kernel commit path.

pub mod email;
pub mod file;
pub mod sidecar;
