// raxis-kernel::notifications::handler — per-channel-kind handlers.
//
// V2 closeout (gap-c4-webhook / gap-c4-email): the four channel kinds
// declared by `policy.toml` — Shell, File, Webhook, Email — each have
// a concrete handler module. Shell + File share a code path (append a
// JSON line to a file); Webhook does an HTTPS POST; Email does a
// minimal SMTP submission with STARTTLS + AUTH PLAIN.
//
// The full §6.5 idempotency table + persistent-connection refactor in
// `email-and-notification-channels.md` is V3-grade. The V2 handlers
// are best-effort fire-and-forget — failure surfaces as
// `NotificationDeliveryFailed { reason: "<category>" }` and never
// blocks the kernel commit path.

pub mod email;
pub mod file;
pub mod sidecar;
pub mod webhook;
