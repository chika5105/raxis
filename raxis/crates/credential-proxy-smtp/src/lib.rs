//! `raxis-credential-proxy-smtp` — SMTP credential proxy.
//!
//! Normative reference: `specs/v2/credential-proxy.md §1` (core
//! principle: the agent never sees the secret) and `§3` (concrete
//! proxy types — SMTP relay).
//!
//! # What this MVP supports
//!
//!   * **Inbound SMTP-shaped accept**. The agent VM connects to a
//!     localhost listener whose protocol shape is the dial-tone of
//!     RFC 5321: `EHLO/HELO`, `MAIL FROM`, `RCPT TO`, `DATA`, `.`,
//!     `QUIT`. The proxy speaks line-buffered SMTP-over-TCP; STARTTLS
//!     is intentionally NOT advertised on the inbound listener
//!     because the proxy owns both ends of the connection (the
//!     localhost socket and the upstream relay) — encrypting the
//!     in-VM hop adds key management with no security gain. The
//!     proxy advertises one capability: `250-AUTH` (so SDKs that
//!     insist on auth still work) but accepts whatever credentials
//!     the agent sends and discards them.
//!   * **Sender / recipient envelope gates**. `Restrictions` carries
//!     `allowed_sender_address` (pin the From address — typical
//!     transactional-email pattern), `allowed_recipient_domains`
//!     (limit RCPT TO to e.g. `@example.com`), and
//!     `max_recipients_per_message`. Any RCPT TO outside the
//!     allowlist is rejected with a 550 error and recorded as
//!     `SmtpRecipientBlocked`.
//!   * **DATA size cap**. `max_message_bytes` truncates oversize
//!     messages with `552 5.3.4 message size exceeds fixed limit`.
//!   * **Rate limiting**. `max_messages_per_minute` rolls a per-
//!     proxy token bucket. Excess messages are rejected at the
//!     `MAIL FROM` boundary with `421 4.7.0 rate limit exceeded`.
//!   * **Outbound forwarding**. Messages that pass envelope
//!     checks are submitted to the upstream relay via a fresh
//!     SMTP-over-TLS dial (the upstream's host + port + AUTH
//!     credential bytes resolve through the
//!     `Arc<dyn CredentialBackend>` per submission so rotations
//!     land mid-session).
//!   * **Audit emission**. `SmtpMessageAccepted`, `SmtpMessageRejected`,
//!     and `SmtpMessageRelayed` are produced with the consumer
//!     identity, the recipient hash, and the byte-count.
//!
//! # What is deferred
//!
//!   * **STARTTLS on the inbound listener**. Out of scope; the
//!     listener is loopback-only and the upstream hop is over TLS.
//!   * **DKIM / DMARC signing**. The upstream relay is expected to
//!     handle these; transparent SMTP relays (AWS SES, SendGrid,
//!     Postmark) do this for the operator.
//!   * **`AUTH SCRAM-SHA-256`**. The MVP supports `AUTH PLAIN` and
//!     `AUTH LOGIN`; SCRAM-SHA-256 lands when an upstream relay
//!     requires it.
//!   * **`SUBMIT` (port 587) vs `SMTPS` (port 465) vs `SMTP` (25)
//!     selection**. The upstream `host:port` is policy-configured,
//!     so the operator picks the submission mode; the proxy speaks
//!     STARTTLS when the upstream advertises it.
//!   * **Pipelining**. The MVP processes one envelope at a time
//!     across the inbound socket; pipelining (RFC 2920) is not
//!     advertised.
//!
//! # Threat model
//!
//! The proxy is the only sub-system in the agent VM that holds the
//! upstream credential bytes. Even a fully-compromised agent
//! process cannot exfiltrate them because:
//!
//!   1. The credential value never crosses the inbound listener —
//!      the agent's `AUTH PLAIN` payload is **discarded**.
//!   2. The kernel's `CredentialBackend` resolves the bytes per
//!      submission through `ConsumerIdentity` (not a long-lived
//!      handle).
//!   3. The proxy refuses to dial any upstream other than the one
//!      pinned at `bind` time, so a compromised agent cannot
//!      redirect outbound traffic.
//!   4. The recipient envelope is filtered before the upstream dial,
//!      so a compromised agent cannot send to attacker-controlled
//!      addresses (the worst-case is the agent spamming the
//!      operator-permitted domain set).

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use raxis_credentials::{ConsumerIdentity, CredentialBackend, CredentialName};

pub mod restriction;
pub mod wire;

pub use restriction::{
    EnvelopeRejection, RecipientCheck, Restrictions,
};
pub use wire::{ProxyError, SmtpProxy};

// ---------------------------------------------------------------------------
// Owned consumer identity (mirrors postgres / http proxies — the three
// proxies are intentionally siblings, never a shared dep).
// ---------------------------------------------------------------------------

/// Owned form of `ConsumerIdentity` used in the proxy's audit events.
#[derive(Debug, Clone)]
pub struct OwnedConsumer {
    /// Subsystem identifier.
    pub kind: String,
    /// Free-form disambiguator within `kind`.
    pub id:   String,
}

impl OwnedConsumer {
    /// Convenience constructor.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self { kind: kind.into(), id: id.into() }
    }
    /// Borrow as the trait-facing form.
    pub fn as_ref(&self) -> ConsumerIdentity<'_> {
        ConsumerIdentity::new(&self.kind, &self.id)
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// How the proxy authenticates to the upstream SMTP relay. The agent
/// VM never sees these values; the proxy renders the wire-format
/// payload from the credential bytes resolved through
/// `CredentialBackend`.
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// `AUTH PLAIN base64(\0user\0password)`.
    Plain {
        /// Username placed before the `\0password`.
        user: String,
    },
    /// `AUTH LOGIN`: server prompts `334 VXNlcm5hbWU6` (Username) →
    /// client sends base64(user); server prompts `334 UGFzc3dvcmQ6`
    /// (Password) → client sends base64(password).
    Login {
        /// Username sent in the first `334` exchange.
        user: String,
    },
}

/// Configuration for one SMTP proxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the inbound listener binds to (typically
    /// `127.0.0.1:0` so the kernel can hand the chosen port to the
    /// VM via env-var injection).
    pub listen_addr: String,
    /// `host:port` of the upstream SMTP relay. The proxy refuses to
    /// dial any other address per the threat-model § above. The
    /// scheme is implicit: SMTP-with-STARTTLS on a `host:port` pair.
    pub upstream_host_port: String,
    /// Whether the upstream connection should always run STARTTLS
    /// (i.e. refuse to send the credential over a cleartext channel).
    /// Defaults to `true` in the kernel callsite; set `false` only
    /// for in-process integration tests against a localhost fake.
    pub require_upstream_tls: bool,
    /// Credential to inject. Resolved via `CredentialBackend` per
    /// submission so rotations land mid-session.
    pub credential_name: CredentialName,
    /// How to shape the auth handshake against the upstream.
    pub auth_mode: AuthMode,
    /// Identity of the agent session this proxy serves.
    pub consumer: OwnedConsumer,
    /// Effective restriction set parsed out of
    /// `[tasks.credentials.restrictions]`.
    pub restrictions: Restrictions,
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Counters surfaced for `CredentialProxyStopped`.
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// Number of accepted connections served (regardless of success).
    pub connections_served:  AtomicU32,
    /// Number of full message envelopes accepted by the proxy
    /// (passed envelope gates and were submitted to upstream).
    pub messages_relayed:    AtomicU32,
    /// Number of full message envelopes rejected before relay
    /// (rate-limit / sender / recipient / size violation).
    pub messages_rejected:   AtomicU32,
    /// Number of recipients accepted across all relayed messages.
    pub recipients_accepted: AtomicU32,
    /// Total DATA bytes accepted across all relayed messages.
    pub bytes_relayed:       AtomicU64,
}

impl ProxyStats {
    /// Snapshot the counters.
    pub fn snapshot(&self) -> ProxyStatsSnapshot {
        ProxyStatsSnapshot {
            connections_served:  self.connections_served .load(Ordering::Relaxed),
            messages_relayed:    self.messages_relayed   .load(Ordering::Relaxed),
            messages_rejected:   self.messages_rejected  .load(Ordering::Relaxed),
            recipients_accepted: self.recipients_accepted.load(Ordering::Relaxed),
            bytes_relayed:       self.bytes_relayed      .load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot of proxy counters at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyStatsSnapshot {
    /// Number of accepted connections served.
    pub connections_served:  u32,
    /// Number of full message envelopes accepted by the proxy.
    pub messages_relayed:    u32,
    /// Number of full message envelopes rejected before relay.
    pub messages_rejected:   u32,
    /// Number of recipients accepted across all relayed messages.
    pub recipients_accepted: u32,
    /// Total DATA bytes accepted across all relayed messages.
    pub bytes_relayed:       u64,
}

// ---------------------------------------------------------------------------
// Audit hook
// ---------------------------------------------------------------------------

/// Audit-event payload the proxy emits on each envelope decision.
/// Mirrors the postgres / http proxies' shape: enriched with the
/// consumer identity, a SHA-256 of the canonical `<sender→
/// {recipients}>` envelope key, and the bytes-relayed.
#[derive(Debug, Clone)]
pub struct EnvelopeAudit {
    /// What happened to this envelope.
    pub outcome:           EnvelopeOutcome,
    /// Owned consumer identity (the agent session).
    pub consumer:          OwnedConsumer,
    /// `Sha256("<sender>\n<rcpt1>\n<rcpt2>...")` — the audit key
    /// for cross-correlation with the upstream relay's logs without
    /// revealing the recipient list.
    pub envelope_sha256:   [u8; 32],
    /// Number of recipients in the envelope.
    pub recipient_count:   u32,
    /// Total DATA bytes the agent submitted (before any size cap).
    pub bytes_submitted:   u64,
    /// `Some(reason)` for rejected envelopes; `None` for relayed.
    pub rejection_reason:  Option<String>,
}

/// Disposition of an envelope at the proxy boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeOutcome {
    /// Envelope passed all gates and was submitted to upstream.
    Relayed,
    /// Envelope rejected at the proxy. The `rejection_reason` field
    /// of `EnvelopeAudit` carries the human-readable cause.
    Rejected,
}

/// Sink the kernel-side `CredentialProxyManager` plugs into; per
/// the postgres / http parity contract the proxy crate stays
/// dependency-free of `raxis-audit-tools`. The manager wraps an
/// `AuditSink` adapter around the trait.
pub trait EnvelopeAuditSink: Send + Sync {
    /// Record one envelope decision.
    fn emit(&self, event: EnvelopeAudit);
}

/// Convenience no-op sink for tests that don't care about the
/// audit trail.
#[derive(Default)]
pub struct NoopEnvelopeAuditSink;

impl EnvelopeAuditSink for NoopEnvelopeAuditSink {
    fn emit(&self, _event: EnvelopeAudit) {}
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Convenience: bind a proxy listener and return it. Re-exported
/// from `wire::SmtpProxy::bind` so the call shape mirrors the
/// `postgres::Proxy::bind` and `http::HttpProxy::bind` conventions.
pub async fn bind(
    backend: Arc<dyn CredentialBackend>,
    config:  ProxyConfig,
    audit:   Arc<dyn EnvelopeAuditSink>,
) -> Result<SmtpProxy, ProxyError> {
    SmtpProxy::bind(backend, config, audit).await
}

/// Compute the canonical `Sha256("<sender>\n<rcpt1>\n<rcpt2>\n...")`
/// envelope key. Pulled out as `pub` so out-of-band tools can
/// reproduce the audit-key hash.
pub fn compute_envelope_sha256(sender: &str, recipients: &[String]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(sender.as_bytes());
    h.update(b"\n");
    for r in recipients {
        h.update(r.as_bytes());
        h.update(b"\n");
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `compute_envelope_sha256` is byte-stable against the canonical
    /// input shape. Pin against accidental ordering changes.
    #[test]
    fn envelope_hash_matches_canonical_sender_then_newline_separated_rcpts() {
        let h = compute_envelope_sha256(
            "noreply@example.com",
            &["alice@example.org".to_owned(), "bob@example.org".to_owned()],
        );
        assert_eq!(
            hex::encode(h),
            {
                use sha2::{Digest, Sha256};
                let mut s = Sha256::new();
                s.update(b"noreply@example.com\nalice@example.org\nbob@example.org\n");
                hex::encode::<[u8; 32]>(s.finalize().into())
            },
            "envelope hash must equal Sha256(\"<sender>\\n<rcpt>\\n...\")",
        );
    }

    /// Envelope hash is sensitive to recipient order. Pins against an
    /// accidental sort that would let a tamperer rotate the recipient
    /// list without the audit hash changing.
    #[test]
    fn envelope_hash_is_recipient_order_sensitive() {
        let h_ab = compute_envelope_sha256(
            "noreply@example.com",
            &["alice@example.org".to_owned(), "bob@example.org".to_owned()],
        );
        let h_ba = compute_envelope_sha256(
            "noreply@example.com",
            &["bob@example.org".to_owned(), "alice@example.org".to_owned()],
        );
        assert_ne!(h_ab, h_ba);
    }
}
