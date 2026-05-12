//! Prompt-fixture loader for the extended e2e scenario.
//!
//! Reads the reviewable injection payloads from
//! `live-e2e/seed/prompts/injection_payloads.toml` (embedded at
//! compile time via `include_str!`) and exposes a typed view so
//! the injection-task driver can render them into a single
//! prompt and the witness layer can match expected event-kinds
//! per payload.
//!
//! Keeping the payloads in a TOML file (rather than inline
//! string literals) makes them reviewable on a PR without
//! recompiling the kernel.

use serde::Deserialize;

/// Embedded injection payloads. Drift between this constant and
/// the on-disk file would be a build-time mismatch.
pub const INJECTION_PAYLOADS_TOML: &str = include_str!(
    "../../../live-e2e/seed/prompts/injection_payloads.toml"
);

/// Decoded view of `live-e2e/seed/prompts/injection_payloads.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct InjectionPayloadsFile {
    #[serde(rename = "payload")]
    pub payloads: Vec<InjectionPayload>,
}

/// One payload entry in the TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct InjectionPayload {
    pub id:    String,
    pub label: String,
    /// PascalCase event-kind names the witness layer expects to
    /// observe (at least one of) when this payload runs. Empty
    /// list means "no audit-event witness required" (e.g. the
    /// approval-circumvention payload, which produces an
    /// absence-of-event witness).
    #[serde(default)]
    pub expected_event_kinds: Vec<String>,
    pub text: String,
}

/// Decode the embedded payload file. Panics on parse error
/// because the file is committed to the repository.
pub fn load_injection_payloads() -> InjectionPayloadsFile {
    toml::from_str(INJECTION_PAYLOADS_TOML)
        .expect("injection_payloads.toml is valid TOML (embedded fixture drift)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_decode_with_expected_ids() {
        let file = load_injection_payloads();
        let ids: Vec<&str> = file.payloads.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&"egress_exfil"),
            "expected payload id 'egress_exfil' in fixture, got {ids:?}");
        assert!(ids.contains(&"escalation_forgery"));
        assert!(ids.contains(&"approval_circumvention"));
        assert!(ids.contains(&"path_breakout"));
        assert!(file.payloads.len() >= 4);
    }
}
