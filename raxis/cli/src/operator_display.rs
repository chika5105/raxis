//! `raxis-cli::operator_display` — render operator fingerprints
//! with their human-readable display names.
//!
//! Normative reference: `kernel-store.md` §2.5.2 "Operator
//! display-name fields" and the cross-variant convention defined
//! there. Every CLI surface that prints an operator-bearing audit
//! event, inbox notification, session row, escalation, or policy
//! row routes through [`format_operator`] (or the higher-level
//! [`format_operator_with_lookup`]) so the rendered identity is
//! consistent across `raxis log`, `raxis inbox`, `raxis status`,
//! `raxis sessions`, `raxis escalations`, `raxis verify-chain`,
//! `raxis policy show --history`, etc.
//!
//! # Three-state resolution
//!
//! Given an operator fingerprint and an optional embedded
//! display-name snapshot from the audit event payload, the
//! resolver classifies into one of:
//!
//! 1. **`Embedded`** — the audit event itself carries
//!    `<field>_display_name`. This is the snapshot the kernel
//!    pinned at emit time. It is the authoritative humane name
//!    for that event, even if the operator's cert has since
//!    rotated to a different name. Rendered as
//!    `"Chika (chika-fp-prefix)"`.
//!
//! 2. **`HistoricalCurrent`** — the audit event has no embedded
//!    name (legacy segment, pre-display-name plumbing) but the
//!    fingerprint resolves in the current `operator_certificates`
//!    view. We render the *current* name with an explicit
//!    `[historical cert; current name shown — event predates
//!    display-name plumbing]` annotation so the operator knows
//!    the rendered name is from the live cert table, not from
//!    the event itself.
//!
//! 3. **`Unknown`** — neither the embedded name nor the live
//!    `operator_certificates` view yields a name. The operator
//!    has been removed from policy entirely (revoked cert, or
//!    they were never in this deployment). Rendered as
//!    `"<unknown> (fp-prefix) [operator no longer in policy]"`.
//!
//! # Why this lives in the CLI, not the read-side store crate
//!
//! The `operator_certificates` view is the right data source
//! (it's the live, denormalised `display_name` table maintained
//! by `policy_manager::advance_epoch`) but the *formatting*
//! decision — how to render the historical / unknown cases — is
//! an operator-experience choice the kernel doesn't make. Same
//! reason `raxis status` formats relative timestamps in the CLI
//! and not the kernel.
//!
//! # Performance — cached lookup
//!
//! [`OperatorNameLookup`] holds a `HashMap<fingerprint,
//! display_name>` populated once from a single
//! `operator_certificates::list_all` call, then served from
//! memory for every render call in the same `raxis log`/`raxis
//! inbox`/etc. invocation. The on-disk audit chain can run to
//! tens of thousands of records; doing one cert-table lookup per
//! record would dominate render time on large chains. The lookup
//! is keyed by full fingerprint (32 hex chars) so prefix
//! collisions are impossible.

use std::collections::HashMap;
use std::path::Path;

use crate::errors::CliError;

/// Cap for the truncated fingerprint shown in human-friendly
/// output. Long enough to be visually distinct (operators often
/// have 4–6 entries; the first 8 hex chars give 4 bytes of
/// entropy = trivially distinguishable in any realistic
/// deployment) and short enough to keep one log line under a
/// typical 80-col terminal.
pub const FINGERPRINT_DISPLAY_PREFIX_LEN: usize = 8;

/// Lookup table of fingerprint → current display-name, sourced
/// from the live `operator_certificates` view at CLI startup.
///
/// `None` for surfaces that don't have access to a kernel.db
/// (e.g. `raxis log` against a copied-out audit dir on a triage
/// laptop). When the lookup is `None`, every render falls
/// through to the embedded-name-or-unknown branch — historical
/// resolution silently degrades to "unknown" rather than
/// throwing a hard error.
#[derive(Debug, Clone, Default)]
pub struct OperatorNameLookup {
    /// Crate-visible so unit tests in sibling CLI modules can
    /// hand-build a lookup without needing a kernel.db on disk.
    pub(crate) by_fingerprint: HashMap<String, String>,
}

impl OperatorNameLookup {
    /// Empty lookup — used when the kernel.db is unavailable.
    /// Equivalent to `Default::default()`; provided as a named
    /// constructor so the call site reads more clearly.
    pub fn empty() -> Self {
        Self {
            by_fingerprint: HashMap::new(),
        }
    }

    /// Construct from an explicit `(fingerprint, display_name)`
    /// iterator. Crate-visible because outside the CLI the only
    /// supported source is [`Self::load_from_data_dir`], but
    /// sibling unit tests need a deterministic in-memory builder.
    #[cfg(test)]
    pub(crate) fn from_pairs<I, S1, S2>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S1, S2)>,
        S1: Into<String>,
        S2: Into<String>,
    {
        Self {
            by_fingerprint: pairs
                .into_iter()
                .map(|(fp, n)| (fp.into(), n.into()))
                .collect(),
        }
    }

    /// Build a lookup by reading the live `operator_certificates`
    /// view from `<data_dir>/kernel.db`. Returns an empty lookup
    /// (silently) if the DB is missing — the CLI is allowed to
    /// run against an audit-only triage layout that has no
    /// kernel.db at all.
    pub fn load_from_data_dir(data_dir: &Path) -> Result<Self, CliError> {
        let db_path = data_dir.join("kernel.db");
        if !db_path.exists() {
            return Ok(Self::empty());
        }
        let conn = raxis_store::open_ro(&db_path).map_err(|e| {
            CliError::Policy(format!(
                "open {} read-only for operator-name lookup: {e}",
                db_path.display(),
            ))
        })?;
        let rows = match raxis_store::views::operator_certificates::list_all(&conn) {
            Ok(rs) => rs,
            // An empty / never-bootstrapped table is not an error;
            // it simply means no operator names will resolve and
            // the renderer falls through to the unknown branch
            // for every fingerprint. (Different from a malformed
            // table, which IS surfaced.)
            Err(raxis_store::views::operator_certificates::OperatorCertViewError::Sqlite(_)) => {
                return Ok(Self::empty());
            }
            Err(e) => {
                return Err(CliError::Policy(format!(
                    "list operator_certificates for name lookup: {e}",
                )))
            }
        };
        let by_fingerprint = rows
            .into_iter()
            .map(|r| (r.pubkey_fingerprint, r.display_name))
            .collect();
        Ok(Self { by_fingerprint })
    }

    /// Look up the current display name for `fingerprint`.
    /// `None` when the operator is not in the live view (removed
    /// from policy, or this lookup is `empty()`).
    pub fn current(&self, fingerprint: &str) -> Option<&str> {
        self.by_fingerprint.get(fingerprint).map(String::as_str)
    }
}

/// Three-state classification of how the renderer arrived at a
/// human name for a fingerprint. Exposed mainly for tests; the
/// production renderer uses [`format_operator_with_lookup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedOperatorName<'a> {
    /// Name came from the audit event itself (kernel snapshot at
    /// emit time). This is the authoritative case — no annotation.
    Embedded { display_name: &'a str },
    /// Name came from the live `operator_certificates` view
    /// because the audit event had no embedded name (legacy
    /// segment). We can't prove this name was current at emit
    /// time, so the rendered string MUST carry the historical
    /// annotation per `kernel-store.md` §2.5.2.
    HistoricalCurrent { current_display_name: &'a str },
    /// Neither source yielded a name — the operator is no longer
    /// in policy and the audit event predates display-name
    /// plumbing. The rendered string MUST carry the
    /// `operator no longer in policy` annotation.
    Unknown,
}

/// Truncate a fingerprint to the prefix shown in human output.
/// Full fingerprint is always retrievable via `--json` / the
/// underlying audit record.
pub fn fingerprint_prefix(fingerprint: &str) -> &str {
    let cap = FINGERPRINT_DISPLAY_PREFIX_LEN.min(fingerprint.len());
    &fingerprint[..cap]
}

/// Resolve a fingerprint + optional embedded snapshot into a
/// [`ResolvedOperatorName`] using the supplied live-view lookup.
/// Pure function — the lookup is the only side-data input.
pub fn resolve_operator_name<'a>(
    fingerprint: &'a str,
    embedded_name: Option<&'a str>,
    live_lookup: &'a OperatorNameLookup,
) -> ResolvedOperatorName<'a> {
    if let Some(name) = embedded_name {
        // Empty-string display names are treated as "missing";
        // the kernel never emits an empty name (the policy
        // validator rejects empty `display_name` at load time)
        // but we defend against it for forward-compat and for
        // hand-edited test segments.
        if !name.is_empty() {
            return ResolvedOperatorName::Embedded { display_name: name };
        }
    }
    if let Some(current) = live_lookup.current(fingerprint) {
        return ResolvedOperatorName::HistoricalCurrent {
            current_display_name: current,
        };
    }
    ResolvedOperatorName::Unknown
}

/// Render an operator fingerprint + optional embedded name into
/// a human-friendly string. This is the canonical CLI render
/// helper; every surface that prints an operator goes through
/// this function so the operator-experience contract from
/// `kernel-store.md` §2.5.2 is enforced uniformly.
///
/// Examples:
/// ```text
/// Chika (a1b2c3d4)
/// Jinanwa (deadbeef)
/// Chika (a1b2c3d4) [historical cert; current name shown — event predates display-name plumbing]
/// <unknown> (a1b2c3d4) [operator no longer in policy]
/// ```
pub fn format_operator_with_lookup(
    fingerprint: &str,
    embedded_name: Option<&str>,
    live_lookup: &OperatorNameLookup,
) -> String {
    let prefix = fingerprint_prefix(fingerprint);
    match resolve_operator_name(fingerprint, embedded_name, live_lookup) {
        ResolvedOperatorName::Embedded { display_name } => {
            format!("{display_name} ({prefix})")
        }
        ResolvedOperatorName::HistoricalCurrent {
            current_display_name,
        } => {
            format!(
                "{current_display_name} ({prefix}) \
                 [historical cert; current name shown — event predates display-name plumbing]",
            )
        }
        ResolvedOperatorName::Unknown => {
            format!("<unknown> ({prefix}) [operator no longer in policy]")
        }
    }
}

/// Convenience wrapper over [`format_operator_with_lookup`] that
/// takes an empty lookup. Use this from CLI commands that have
/// no kernel.db access (e.g. `raxis log` running against a
/// copied-out audit dir). Reserved for future surfaces — `raxis
/// log`, `policy show --history`, and the inbox summary all use
/// the lookup-aware variant directly today.
#[allow(dead_code)]
pub fn format_operator(fingerprint: &str, embedded_name: Option<&str>) -> String {
    format_operator_with_lookup(fingerprint, embedded_name, &OperatorNameLookup::empty())
}

// ---------------------------------------------------------------------------
// Audit-event payload extraction
// ---------------------------------------------------------------------------

/// One operator reference extracted from an audit event payload.
/// The renderer uses this to surface every operator-bearing
/// field on a single audit record without having to know the
/// per-variant field names at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedOperator {
    /// The role this operator played in the event — e.g.
    /// `"approving_operator"`, `"granted_by"`, `"target"`. Used
    /// to label the rendered output (`approved_by: Chika
    /// (a1b2c3d4)`).
    pub role: String,
    pub fingerprint: String,
    /// Snapshot from the event payload, if any.
    pub embedded_name: Option<String>,
}

/// Walk the payload of an audit event and pull out every
/// operator-bearing `(fingerprint, embedded_name)` pair we
/// recognise. The recognised field names track the variants
/// listed in `kernel-store.md` §2.5.2 "Operator display-name
/// fields"; an unknown variant simply yields no extractions
/// (forward-compat).
///
/// The payload shape is the JSON object the kernel writes —
/// either the top-level event object (containing `payload: {
/// ... }`) or the inner `payload` object directly. Both are
/// accepted because different on-disk layouts exist (the JSONL
/// chain wraps payloads under `payload`, but the inbox writer
/// inlines them).
pub fn extract_operators_from_event(event: &serde_json::Value) -> Vec<ExtractedOperator> {
    // Accept either the top-level event (peek at `payload` if
    // present) or the inner payload object.
    let payload = event.get("payload").unwrap_or(event);

    // Field-pair table: (fingerprint_field, display_name_field, role_label).
    // Order matches the variant order in `audit/event.rs` for
    // readability of test-snapshot diffs.
    const PAIRS: &[(&str, &str, &str)] = &[
        (
            "approving_operator",
            "approving_operator_display_name",
            "approving_operator",
        ),
        (
            "triggered_by_operator",
            "triggered_by_operator_display_name",
            "triggered_by",
        ),
        ("revoked_by", "revoked_by_display_name", "revoked_by"),
        ("granted_by", "granted_by_display_name", "granted_by"),
        ("approved_by", "approved_by_display_name", "approved_by"),
        ("denied_by", "denied_by_display_name", "denied_by"),
        ("triggered_by", "triggered_by_display_name", "triggered_by"),
        (
            "quarantined_by",
            "quarantined_by_display_name",
            "quarantined_by",
        ),
        ("target_fingerprint", "target_display_name", "target"),
    ];

    let mut out = Vec::new();
    for (fp_field, name_field, role) in PAIRS {
        let Some(fp) = payload.get(*fp_field).and_then(|v| v.as_str()) else {
            continue;
        };
        if fp.is_empty() {
            continue;
        }
        let embedded_name = payload
            .get(*name_field)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        out.push(ExtractedOperator {
            role: (*role).to_owned(),
            fingerprint: fp.to_owned(),
            embedded_name,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn embedded_name_takes_precedence_over_live_lookup() {
        let mut lookup = OperatorNameLookup::empty();
        lookup.by_fingerprint.insert(
            "abcd1234abcd1234abcd1234abcd1234".to_owned(),
            "ChikaRotated".to_owned(),
        );
        let resolved =
            resolve_operator_name("abcd1234abcd1234abcd1234abcd1234", Some("Chika"), &lookup);
        assert_eq!(
            resolved,
            ResolvedOperatorName::Embedded {
                display_name: "Chika"
            },
            "embedded snapshot must win — it is the authoritative \
             name *at the time of the event*"
        );
    }

    #[test]
    fn historical_current_kicks_in_only_when_embedded_is_absent() {
        let mut lookup = OperatorNameLookup::empty();
        lookup.by_fingerprint.insert(
            "deadbeefdeadbeefdeadbeefdeadbeef".to_owned(),
            "Jinanwa".to_owned(),
        );
        let resolved = resolve_operator_name("deadbeefdeadbeefdeadbeefdeadbeef", None, &lookup);
        assert_eq!(
            resolved,
            ResolvedOperatorName::HistoricalCurrent {
                current_display_name: "Jinanwa",
            }
        );
    }

    #[test]
    fn empty_string_embedded_name_is_treated_as_missing() {
        // The kernel never emits empty display names (validator
        // rejects them at load time) but a hand-edited segment
        // could; the renderer must not blank-render in that case.
        let mut lookup = OperatorNameLookup::empty();
        lookup.by_fingerprint.insert(
            "abcd1234abcd1234abcd1234abcd1234".to_owned(),
            "Live".to_owned(),
        );
        let resolved = resolve_operator_name("abcd1234abcd1234abcd1234abcd1234", Some(""), &lookup);
        assert_eq!(
            resolved,
            ResolvedOperatorName::HistoricalCurrent {
                current_display_name: "Live",
            }
        );
    }

    #[test]
    fn unknown_when_neither_source_yields_a_name() {
        let lookup = OperatorNameLookup::empty();
        let resolved = resolve_operator_name("no_one_fp", None, &lookup);
        assert_eq!(resolved, ResolvedOperatorName::Unknown);
    }

    #[test]
    fn format_operator_renders_each_branch() {
        let mut lookup = OperatorNameLookup::empty();
        lookup.by_fingerprint.insert(
            "abcd1234abcd1234abcd1234abcd1234".to_owned(),
            "ChikaCurrent".to_owned(),
        );

        // (a) Embedded — no annotation.
        let s = format_operator_with_lookup(
            "abcd1234abcd1234abcd1234abcd1234",
            Some("ChikaSnapshot"),
            &lookup,
        );
        assert_eq!(s, "ChikaSnapshot (abcd1234)");

        // (b) Historical current — must carry the historical
        //     annotation (operators reading their own logs need
        //     to know the name didn't come from the event itself).
        let s = format_operator_with_lookup("abcd1234abcd1234abcd1234abcd1234", None, &lookup);
        assert!(s.starts_with("ChikaCurrent (abcd1234)"));
        assert!(
            s.contains("[historical cert"),
            "historical-cert annotation MUST be present for legacy events: {s}"
        );
        assert!(s.contains("predates display-name plumbing"));

        // (c) Unknown — must say so explicitly.
        let s = format_operator_with_lookup("999999999999999999", None, &lookup);
        assert_eq!(s, "<unknown> (99999999) [operator no longer in policy]");
    }

    #[test]
    fn fingerprint_prefix_truncates_long_strings_and_passes_short_ones() {
        assert_eq!(
            fingerprint_prefix("abcdefghijklmnop"),
            "abcdefgh",
            "long fingerprints get truncated to 8 chars"
        );
        assert_eq!(
            fingerprint_prefix("abc"),
            "abc",
            "short strings pass through unchanged"
        );
        assert_eq!(fingerprint_prefix(""), "", "empty input does not panic");
    }

    #[test]
    fn extract_operators_finds_path_scope_override_pair() {
        let payload = json!({
            "kind": "PathScopeOverrideApplied",
            "initiative_id":      "init-1",
            "task_id":            "t-1",
            "approving_operator": "abcd1234abcd1234abcd1234abcd1234",
            "approving_operator_display_name": "Chika",
        });
        let extracted = extract_operators_from_event(&payload);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].role, "approving_operator");
        assert_eq!(extracted[0].fingerprint, "abcd1234abcd1234abcd1234abcd1234");
        assert_eq!(extracted[0].embedded_name.as_deref(), Some("Chika"));
    }

    #[test]
    fn extract_operators_pulls_both_pairs_from_quarantine_swept() {
        let payload = json!({
            "kind":                        "OperatorQuarantineSwept",
            "target_fingerprint":          "ffffffff00000000ffffffff00000000",
            "quarantined_by":              "abcd1234abcd1234abcd1234abcd1234",
            "count":                       5,
            "reason":                      null,
            "quarantined_by_display_name": "Jinanwa",
            "target_display_name":         "RotatedOutChika",
        });
        let extracted = extract_operators_from_event(&payload);
        assert_eq!(
            extracted.len(),
            2,
            "both quarantined_by AND target operator must be extracted"
        );
        let by_role: std::collections::HashMap<_, _> =
            extracted.iter().map(|e| (e.role.as_str(), e)).collect();
        let q = by_role["quarantined_by"];
        assert_eq!(q.fingerprint, "abcd1234abcd1234abcd1234abcd1234");
        assert_eq!(q.embedded_name.as_deref(), Some("Jinanwa"));
        let t = by_role["target"];
        assert_eq!(t.fingerprint, "ffffffff00000000ffffffff00000000");
        assert_eq!(t.embedded_name.as_deref(), Some("RotatedOutChika"));
    }

    #[test]
    fn extract_operators_handles_legacy_payload_without_display_name() {
        // Pre-display-name plumbing event: only the fingerprint
        // field is present. The extractor still surfaces the
        // operator with `embedded_name = None`.
        let payload = json!({
            "kind":         "EscalationApproved",
            "escalation_id":"esc-1",
            "approved_by":  "abcd1234abcd1234abcd1234abcd1234",
        });
        let extracted = extract_operators_from_event(&payload);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].role, "approved_by");
        assert!(
            extracted[0].embedded_name.is_none(),
            "legacy event must yield a `None` embedded name; the renderer \
             falls back to the live operator_certificates lookup"
        );
    }

    #[test]
    fn extract_operators_walks_nested_payload_object() {
        // The audit JSONL chain wraps the kind discriminator under
        // `payload`, while the inbox writer inlines fields. Both
        // shapes must work — see `kernel-store.md` §2.5.2 audit
        // record format.
        let event = json!({
            "seq":          7,
            "event_kind":   "EscalationApproved",
            "payload": {
                "kind":         "EscalationApproved",
                "escalation_id":"esc-1",
                "approved_by":  "abcd1234abcd1234abcd1234abcd1234",
                "approved_by_display_name": "Chika",
            }
        });
        let extracted = extract_operators_from_event(&event);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].embedded_name.as_deref(), Some("Chika"));
    }

    #[test]
    fn extract_operators_ignores_unknown_event_kinds() {
        // Forward-compat: an event-kind we don't recognise
        // simply produces no extractions; the renderer falls back
        // to the existing kind/id projection.
        let payload = json!({
            "kind": "FutureEventNotYetMapped",
            "some_other_field": "value",
        });
        let extracted = extract_operators_from_event(&payload);
        assert!(extracted.is_empty());
    }
}
