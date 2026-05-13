// raxis-types::host_preflight — structured payload for the host
// disk-pressure preflight check (INV-HOST-HYGIENE-01).
//
// Wire shape
// ----------
// Carried inside the structured stderr envelope
// `OPERATOR_ATTENTION_REQUIRED HostHygieneDiskPressure {json}`
// emitted by the live-e2e harness preflight before the test
// bails. The JSON body matches `HostPreflightError`. Pinning
// the shape here keeps two call sites in sync:
//
//   * `kernel/tests/extended_e2e_realistic_scenario.rs`'s
//     preflight prints the envelope before panicking.
//   * `xtask/src/hygiene.rs`'s `hygiene-check` subcommand uses
//     the same struct for its diagnostic output.
//
// Scope note: this is a developer-/CI-host signal. It is
// deliberately NOT carried by the kernel's audit chain or the
// operator dashboard — `INV-HOST-HYGIENE-01` is workspace-only
// (a `brew install raxis` operator has no cargo workspace and
// no parent-side aegis-worktrees to sweep) and the audit chain
// stays kernel-scoped for runtime invariants only. See
// `specs/invariants.md §11.11` and `dashboard-hardening.md §5.7`
// for the out-of-scope rationale.
//
// The serde tag is `pressure_kind` so the same stderr envelope
// can grow new variants (e.g. `InodePressure`,
// `MainRepoOverQuota`) without breaking existing parsers.
//
// Crate invariant (lib.rs / INV-CRATE-01): no I/O, no spawning,
// no async — pure data + serde. The `Display` impl renders the
// human-readable form the live-e2e harness panic message AND
// the `cargo test` failure-summary line consume.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Per-volume disk-usage report. Mirrors the shape `df -P` returns
/// AND what `xtask::hygiene::VolumeReport` produces, with `free`
/// pre-rendered to a human string ("64.0GiB") so the harness
/// panic message and CI log consumer do not need to re-derive
/// units.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskVolumeReport {
    /// `df` "Mounted on" column — e.g. `/System/Volumes/Data`,
    /// `/private/tmp`, `/var/folders/zz/xxx`.
    pub mount: String,
    /// Integer percent used (`Capacity` minus the trailing `%`).
    pub used_pct: u32,
    /// Free space pre-rendered to a 1-decimal human-readable
    /// string (e.g. `"64.0GiB"`, `"902MiB"`).
    pub free_human: String,
}

/// Tagged structured error. The JSON wire shape is
/// `{ "pressure_kind": "DiskPressure", "threshold_pct": 90, ... }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "pressure_kind")]
pub enum HostPreflightError {
    /// At least one monitored volume crossed the operator-supplied
    /// `--threshold-pct` (default 90 in the live-e2e preflight).
    DiskPressure {
        /// The threshold the preflight enforced.
        threshold_pct: u32,
        /// Every volume the probe inspected, including ones that
        /// were below the threshold — mirrors `cargo xtask
        /// hygiene-check`'s stderr output. The `Display` impl
        /// surfaces only the over-threshold rows in the
        /// human-readable one-liner; under-threshold entries are
        /// retained in the structured payload for CI / log
        /// consumers that want full context.
        observed_volumes: Vec<DiskVolumeReport>,
        /// Developer-runnable command. Always
        /// `"cargo xtask hygiene"` for the V2.5 implementation.
        remediation_cmd: String,
        /// Optional pointer to the developer recipe.
        docs_url: Option<String>,
    },
}

impl HostPreflightError {
    /// Convenience constructor for `DiskPressure` with the V2.5
    /// defaults (`cargo xtask hygiene` remediation, the operator
    /// recipe URL).
    pub fn disk_pressure(
        threshold_pct: u32,
        observed_volumes: Vec<DiskVolumeReport>,
    ) -> Self {
        Self::DiskPressure {
            threshold_pct,
            observed_volumes,
            remediation_cmd: "cargo xtask hygiene".to_string(),
            docs_url: Some(
                "raxis/guides/operator/18-host-hygiene.md".to_string(),
            ),
        }
    }

    /// Identifier carried in the `OPERATOR_ATTENTION_REQUIRED
    /// <kind> {json}` stderr envelope the live-e2e harness
    /// preflight prints. Pinned to `"HostHygieneDiskPressure"`
    /// so harness / log consumers have a stable filter string;
    /// renaming it is a wire break for those consumers.
    pub const ATTENTION_KIND: &'static str = "HostHygieneDiskPressure";

    /// Render to the JSON form embedded in the stderr envelope.
    /// Pure-data crate convention: no panicking;
    /// `serde_json::to_string` cannot fail for this enum because
    /// every variant is finite and `String`-typed.
    pub fn to_envelope_json(&self) -> String {
        serde_json::to_string(self).expect("HostPreflightError serializes")
    }
}

impl fmt::Display for HostPreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DiskPressure {
                threshold_pct,
                observed_volumes,
                remediation_cmd,
                ..
            } => {
                let over: Vec<&DiskVolumeReport> = observed_volumes
                    .iter()
                    .filter(|v| v.used_pct >= *threshold_pct)
                    .collect();
                if over.is_empty() {
                    write!(
                        f,
                        "Host disk pressure: at least one volume above {threshold_pct}%. \
                         Run `{remediation_cmd}` to remediate."
                    )
                } else {
                    write!(f, "Host disk pressure: ")?;
                    for (i, v) in over.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(
                            f,
                            "{} at {}% (free {})",
                            v.mount, v.used_pct, v.free_human
                        )?;
                    }
                    write!(f, ". Run `{remediation_cmd}` to remediate.")
                }
            }
        }
    }
}

impl std::error::Error for HostPreflightError {}

// ---------------------------------------------------------------------------
// Tests — wire-shape pin + Display rendering
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> HostPreflightError {
        HostPreflightError::disk_pressure(
            90,
            vec![
                DiskVolumeReport {
                    mount: "/System/Volumes/Data".into(),
                    used_pct: 92,
                    free_human: "64.0GiB".into(),
                },
                DiskVolumeReport {
                    mount: "/private/tmp".into(),
                    used_pct: 78,
                    free_human: "199.0GiB".into(),
                },
            ],
        )
    }

    #[test]
    fn json_round_trip_is_byte_identical() {
        let err = fixture();
        let json = err.to_envelope_json();
        let back: HostPreflightError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn json_carries_pressure_kind_tag_for_envelope_consumers() {
        let err = fixture();
        let json = err.to_envelope_json();
        assert!(
            json.contains("\"pressure_kind\":\"DiskPressure\""),
            "JSON tag missing; envelope consumers (harness / CI log scraper) \
             would not match: {json}"
        );
        assert!(json.contains("\"threshold_pct\":90"));
        assert!(json.contains("\"remediation_cmd\":\"cargo xtask hygiene\""));
    }

    #[test]
    fn display_renders_offending_volumes_only() {
        let rendered = format!("{}", fixture());
        assert!(
            rendered.contains("/System/Volumes/Data at 92% (free 64.0GiB)"),
            "Display dropped the over-threshold volume: {rendered}"
        );
        // Under-threshold volume MUST be omitted from the human
        // form (the dashboard renders it as muted context, but
        // the panic / banner title surface only the offenders).
        assert!(
            !rendered.contains("/private/tmp"),
            "Display surfaced an under-threshold volume: {rendered}"
        );
        assert!(
            rendered.contains("Run `cargo xtask hygiene` to remediate"),
            "Display dropped remediation pointer: {rendered}"
        );
    }

    #[test]
    fn attention_kind_is_pinned_for_wire_compat() {
        assert_eq!(
            HostPreflightError::ATTENTION_KIND,
            "HostHygieneDiskPressure",
            "ATTENTION_KIND is the stderr-envelope filter string; \
             changing it is a wire break for the live-e2e harness, \
             terminal users, and CI log scrapers."
        );
    }
}
