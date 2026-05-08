//! Restriction set + envelope checks for the SMTP credential proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §3` ("SMTP relay") and
//! `§3.5` ("HTTP audit-only mode" — same shape principle: the
//! restriction set is a flat plain-data struct so it can be parsed
//! directly out of `[tasks.credentials.restrictions]` in the signed
//! plan).

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`
/// for `proxy_type = "smtp"`.
///
/// All four fields default to "unrestricted" so a minimal policy
/// (`[restrictions]` section omitted) produces a working proxy with
/// no envelope filtering — appropriate for trusted-tenant workloads
/// where the upstream relay's own filters provide the final gate.
/// Production deployments typically pin every field per
/// `credential-proxy.md §3` ("SMTP relay") guidance.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// If set, the proxy rejects any `MAIL FROM` whose address is
    /// not bytewise-equal to this string. Comparison is
    /// case-insensitive on the domain part per RFC 5321 §2.4 but
    /// case-sensitive on the local-part (the spec says the
    /// local-part is preserved as-is by the proxy).
    #[serde(default)]
    pub allowed_sender_address: Option<String>,
    /// Recipient domains the proxy will forward. An empty vector
    /// means "no recipient domain restriction" (the proxy still
    /// applies `max_recipients_per_message`). Each entry MUST be
    /// the bare domain — e.g. `"example.com"`, NOT
    /// `"@example.com"` or `"https://example.com"`.
    #[serde(default)]
    pub allowed_recipient_domains: Vec<String>,
    /// Maximum recipients in one envelope. `None` = unlimited.
    /// Typical production value: 50 (matches AWS SES per-message
    /// recipient cap).
    #[serde(default)]
    pub max_recipients_per_message: Option<u32>,
    /// Maximum DATA bytes per message. `None` = unlimited (the
    /// upstream relay still has its own cap). Typical production
    /// value: 10 MiB (matches AWS SES default).
    #[serde(default)]
    pub max_message_bytes: Option<u64>,
    /// Maximum messages per minute relayed by this proxy. `None`
    /// = unlimited. The proxy enforces this by tracking submission
    /// timestamps in a rolling 60-second window; excess attempts
    /// are rejected at the `MAIL FROM` boundary with `421` so the
    /// agent's SMTP client retries with backoff.
    #[serde(default)]
    pub max_messages_per_minute: Option<u32>,
}

impl Restrictions {
    /// Convenience constructor for the typical transactional-email
    /// posture: pin the From address, scope recipients to one
    /// domain, cap recipients per message, cap message bytes,
    /// rate-limit at 60 messages/minute.
    pub fn transactional(
        from:       impl Into<String>,
        rcpt_domain: impl Into<String>,
    ) -> Self {
        Self {
            allowed_sender_address:    Some(from.into()),
            allowed_recipient_domains: vec![rcpt_domain.into()],
            max_recipients_per_message: Some(50),
            max_message_bytes:          Some(10 * 1024 * 1024),
            max_messages_per_minute:    Some(60),
        }
    }

    /// Returns `Ok(())` if `addr` is permitted as the envelope
    /// sender; otherwise [`EnvelopeRejection::SenderNotAllowed`].
    pub fn check_sender(&self, addr: &str) -> Result<(), EnvelopeRejection> {
        let Some(expected) = &self.allowed_sender_address else {
            return Ok(());
        };
        if envelope_eq_ci_domain(expected, addr) {
            Ok(())
        } else {
            Err(EnvelopeRejection::SenderNotAllowed {
                expected: expected.clone(),
                got:      addr.to_owned(),
            })
        }
    }

    /// Returns `RecipientCheck::Allowed` / `RecipientCheck::Blocked`
    /// for one recipient address. The proxy iterates this over the
    /// envelope's RCPT TO list and rejects the whole envelope if
    /// any recipient is blocked (RFC 5321 §3.3 — partial recipient
    /// rejection IS legal, but we reject-all to keep the audit
    /// shape simple).
    pub fn check_recipient(&self, addr: &str) -> RecipientCheck {
        if self.allowed_recipient_domains.is_empty() {
            return RecipientCheck::Allowed;
        }
        let dom = match split_domain(addr) {
            Some(d) => d.to_ascii_lowercase(),
            None    => return RecipientCheck::Blocked {
                reason: format!("recipient {addr:?} has no @domain part"),
            },
        };
        if self.allowed_recipient_domains.iter().any(|d| d.eq_ignore_ascii_case(&dom)) {
            RecipientCheck::Allowed
        } else {
            RecipientCheck::Blocked {
                reason: format!(
                    "recipient domain {dom:?} is not in allowed_recipient_domains",
                ),
            }
        }
    }

    /// Returns `Ok(())` if `recipient_count` is within the per-
    /// message ceiling, otherwise
    /// [`EnvelopeRejection::TooManyRecipients`].
    pub fn check_recipient_count(&self, recipient_count: u32) -> Result<(), EnvelopeRejection> {
        let Some(cap) = self.max_recipients_per_message else {
            return Ok(());
        };
        if recipient_count <= cap {
            Ok(())
        } else {
            Err(EnvelopeRejection::TooManyRecipients {
                limit: cap,
                got:   recipient_count,
            })
        }
    }

    /// Returns `Ok(())` if `byte_count` is within the per-message
    /// ceiling, otherwise [`EnvelopeRejection::MessageTooLarge`].
    pub fn check_message_size(&self, byte_count: u64) -> Result<(), EnvelopeRejection> {
        let Some(cap) = self.max_message_bytes else {
            return Ok(());
        };
        if byte_count <= cap {
            Ok(())
        } else {
            Err(EnvelopeRejection::MessageTooLarge {
                limit: cap,
                got:   byte_count,
            })
        }
    }
}

/// Why an envelope was rejected (rendered into the SMTP error and
/// the audit-event payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeRejection {
    /// `MAIL FROM` address didn't match `allowed_sender_address`.
    SenderNotAllowed {
        /// What the policy required.
        expected: String,
        /// What the agent submitted.
        got:      String,
    },
    /// One or more `RCPT TO` addresses fell outside
    /// `allowed_recipient_domains`. The first blocking recipient's
    /// reason is captured.
    RecipientNotAllowed {
        /// Human-readable explanation.
        reason: String,
    },
    /// Envelope had more recipients than `max_recipients_per_message`.
    TooManyRecipients {
        /// Configured ceiling.
        limit: u32,
        /// What the agent submitted.
        got:   u32,
    },
    /// Message body exceeded `max_message_bytes`.
    MessageTooLarge {
        /// Configured ceiling, in bytes.
        limit: u64,
        /// What the agent submitted, in bytes.
        got:   u64,
    },
    /// Per-minute rate limit exceeded. The proxy delays the rejection
    /// to the next `MAIL FROM` so the bucket re-fills naturally.
    RateLimitExceeded {
        /// Configured per-minute ceiling.
        limit: u32,
    },
}

impl EnvelopeRejection {
    /// Render the rejection as a single human-readable line for the
    /// audit-event payload and for the SMTP error response. Stable
    /// surface — drift would silently change downstream dashboards
    /// keyed off the prefix.
    pub fn audit_summary(&self) -> String {
        match self {
            Self::SenderNotAllowed { expected, got } => format!(
                "sender_not_allowed expected={expected} got={got}",
            ),
            Self::RecipientNotAllowed { reason } => format!(
                "recipient_not_allowed reason={reason}",
            ),
            Self::TooManyRecipients { limit, got } => format!(
                "too_many_recipients limit={limit} got={got}",
            ),
            Self::MessageTooLarge { limit, got } => format!(
                "message_too_large limit={limit} got={got}",
            ),
            Self::RateLimitExceeded { limit } => format!(
                "rate_limit_exceeded limit_per_minute={limit}",
            ),
        }
    }
}

/// Per-recipient outcome from [`Restrictions::check_recipient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientCheck {
    /// Recipient is in the allowed-domain set (or no restriction is
    /// configured).
    Allowed,
    /// Recipient is rejected; the proxy issues a `550` and records
    /// `SmtpRecipientBlocked` in the audit chain.
    Blocked {
        /// Human-readable cause.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip surrounding `<>`-brackets and split off the `@domain` tail.
/// Returns `None` if the address has no `@`. RFC 5321 §3.5 allows
/// the `<>` form for the null sender, but we treat that as a
/// missing-domain case and let the caller decide how to surface
/// it.
pub(crate) fn split_domain(addr: &str) -> Option<&str> {
    let trimmed = strip_angle_brackets(addr);
    trimmed.rsplit_once('@').map(|(_local, dom)| dom)
}

fn strip_angle_brackets(addr: &str) -> &str {
    let s = addr.trim();
    if s.starts_with('<') && s.ends_with('>') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Compare two SMTP envelope addresses with case-insensitive domain
/// matching and case-sensitive local-part matching. Mirrors the RFC
/// 5321 §2.4 rule.
fn envelope_eq_ci_domain(a: &str, b: &str) -> bool {
    let a = strip_angle_brackets(a);
    let b = strip_angle_brackets(b);
    let (ai, ad) = match a.rsplit_once('@') { Some(t) => t, None => return false };
    let (bi, bd) = match b.rsplit_once('@') { Some(t) => t, None => return false };
    ai == bi && ad.eq_ignore_ascii_case(bd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_allows_everything() {
        let r = Restrictions::default();
        assert!(r.check_sender("user@anywhere.example").is_ok());
        assert_eq!(
            r.check_recipient("admin@nope.example"),
            RecipientCheck::Allowed,
        );
        assert!(r.check_recipient_count(1_000).is_ok());
        assert!(r.check_message_size(u64::MAX).is_ok());
    }

    #[test]
    fn transactional_pins_sender_recipient_size_and_count() {
        let r = Restrictions::transactional("noreply@example.com", "example.org");
        assert!(r.check_sender("noreply@example.com").is_ok());
        assert!(r.check_sender("attacker@elsewhere.example").is_err());
        assert_eq!(
            r.check_recipient("alice@example.org"),
            RecipientCheck::Allowed,
        );
        assert!(matches!(
            r.check_recipient("bob@nope.example"),
            RecipientCheck::Blocked { .. },
        ));
        assert!(r.check_recipient_count(50).is_ok());
        assert!(matches!(
            r.check_recipient_count(51).unwrap_err(),
            EnvelopeRejection::TooManyRecipients { limit: 50, got: 51 },
        ));
        assert!(r.check_message_size(10 * 1024 * 1024).is_ok());
        assert!(matches!(
            r.check_message_size(10 * 1024 * 1024 + 1).unwrap_err(),
            EnvelopeRejection::MessageTooLarge { limit, got: _ } if limit == 10 * 1024 * 1024,
        ));
    }

    #[test]
    fn sender_check_is_case_insensitive_on_domain_only() {
        let r = Restrictions {
            allowed_sender_address:     Some("Noreply@Example.COM".to_owned()),
            allowed_recipient_domains:  vec![],
            max_recipients_per_message: None,
            max_message_bytes:          None,
            max_messages_per_minute:    None,
        };
        // Same casing on local part, different casing on domain → OK.
        assert!(r.check_sender("Noreply@example.com").is_ok());
        assert!(r.check_sender("Noreply@EXAMPLE.COM").is_ok());
        // Different casing on local part → REJECT (RFC 5321 §2.4).
        assert!(r.check_sender("noreply@example.com").is_err());
    }

    #[test]
    fn recipient_check_handles_angle_brackets_and_no_at() {
        let r = Restrictions {
            allowed_sender_address:     None,
            allowed_recipient_domains:  vec!["example.org".to_owned()],
            max_recipients_per_message: None,
            max_message_bytes:          None,
            max_messages_per_minute:    None,
        };
        assert_eq!(r.check_recipient("<alice@example.org>"), RecipientCheck::Allowed);
        match r.check_recipient("malformed-no-at-sign") {
            RecipientCheck::Blocked { reason } => {
                assert!(reason.contains("no @domain"), "reason was {reason:?}");
            }
            other => panic!("expected Blocked for malformed addr, got {other:?}"),
        }
    }

    #[test]
    fn audit_summary_strings_are_stable() {
        assert_eq!(
            EnvelopeRejection::SenderNotAllowed {
                expected: "noreply@example.com".into(),
                got:      "attacker@elsewhere.example".into(),
            }.audit_summary(),
            "sender_not_allowed expected=noreply@example.com got=attacker@elsewhere.example",
        );
        assert_eq!(
            EnvelopeRejection::TooManyRecipients { limit: 50, got: 51 }.audit_summary(),
            "too_many_recipients limit=50 got=51",
        );
        assert_eq!(
            EnvelopeRejection::MessageTooLarge { limit: 1_000, got: 5_000 }.audit_summary(),
            "message_too_large limit=1000 got=5000",
        );
        assert_eq!(
            EnvelopeRejection::RateLimitExceeded { limit: 60 }.audit_summary(),
            "rate_limit_exceeded limit_per_minute=60",
        );
        assert_eq!(
            EnvelopeRejection::RecipientNotAllowed {
                reason: "recipient domain \"nope.example\" is not in allowed_recipient_domains".into(),
            }.audit_summary(),
            "recipient_not_allowed reason=recipient domain \"nope.example\" is not in allowed_recipient_domains",
        );
    }

    #[test]
    fn split_domain_round_trips_canonical_addrs() {
        assert_eq!(split_domain("user@example.com"), Some("example.com"));
        assert_eq!(split_domain("<user@example.com>"), Some("example.com"));
        assert_eq!(split_domain("nodomain"), None);
        assert_eq!(split_domain(""), None);
        // RFC 5321 §3.5 allows a quoted-local with `@` inside; we
        // split on the LAST `@` so `"alice@home"@example.com` still
        // resolves to example.com.
        assert_eq!(split_domain("\"alice@home\"@example.com"), Some("example.com"));
    }
}
