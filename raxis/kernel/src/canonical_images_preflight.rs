//! Boot-time canonical VM image manifest preflight (V2 trust model).
//!
//! Normative references:
//!
//! * `planner-harness.md §4.5` (`INV-PLANNER-HARNESS-02`) — Reviewer
//!   image is kernel-canonical; mismatch produces
//!   `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` and a
//!   `SecurityViolationDetected { kind: "ReviewerImageDigestMismatch" }`
//!   audit event.
//! * `planner-harness.md §4.7` (`INV-PLANNER-HARNESS-05`) — same
//!   contract for the Orchestrator image, with the
//!   `OrchestratorImageDigestMismatch` audit kind.
//! * `planner-harness.md §14.4 — Image-build pipeline` — the
//!   manifest-trust model: builder produces signed
//!   `<role>.manifest.toml`, kernel verifies it at boot via
//!   `raxis_canonical_images::verify_canonical_image_via_manifest`.
//! * `system-requirements.md §3` — operator-facing remediation
//!   ("reinstall from a verified source"); this module is the
//!   kernel-side enforcement seam.
//!
//! ## What this module does
//!
//! At boot, the kernel calls
//! [`verify_canonical_images_at_boot`] against the install dir, which
//! for each canonical image:
//!
//! 1. Resolves the .img and the sibling `.manifest.toml`.
//! 2. Calls
//!    `raxis_canonical_images::verify_canonical_image_via_manifest`
//!    against the kernel's compile-time signing-key trust anchor.
//! 3. Surfaces a structured outcome and emits one
//!    `SecurityViolationDetected` audit event per mismatch.
//!
//! Returned outcomes:
//!
//! * `Ok` — manifest signature verifies, manifest's
//!   `image_artefact_sha256` matches the streamed-from-disk .img
//!   bytes, role + kernel-version match. The matching VM-spawn path
//!   may proceed.
//! * `Missing` — the .img file is not on disk yet (early-deployment
//!   case before `raxis doctor canonical-images` runs). Logged as a
//!   warning; activations that need it will fail at
//!   `IsolationBackend::launch` time anyway. Not a boot failure.
//! * `ManifestMissing` — the .img is present but the sibling
//!   `<role>-<kernel_version>.manifest.toml` is not. Logged as a
//!   warning; activations cannot start without the manifest.
//! * `TrustAnchorUnpopulated` — the kernel binary was built before
//!   the signing-key trust anchor was committed
//!   (`EXPECTED_KERNEL_SIGNING_KEY_BYTES` is the all-zero
//!   placeholder). Logged as a warning; not a boot failure.
//!   Once the release pipeline commits the key, this branch becomes
//!   a hard mismatch by construction.
//! * `Tampered` — the .img's streamed SHA-256 disagrees with the
//!   manifest's signed `image_artefact_sha256`. The kernel emits
//!   `SecurityViolationDetected` and refuses to spawn the affected
//!   role's VMs at activation time.
//! * `ManifestRejected` — the manifest could not be loaded, or its
//!   signature/role/kernel-version did not satisfy the kernel's
//!   trust contract. Treated as a tamper case (audit event +
//!   activation refusal).
//!
//! ## Why preflight at boot rather than lazy at activation
//!
//! Preflight surfaces tamper detection in the kernel's startup
//! audit chain, where dashboards already monitor the boot record
//! sequence. A lazy check at first activation would defer the audit
//! event indefinitely on a kernel that never spawns a Reviewer (a
//! plausible scenario for V2 deployments running Executor-only
//! tasks in early adoption). Both seams are wired for V2 GA: this
//! preflight runs at boot, AND `IsolationBackend::launch` re-runs
//! the manifest verification at activation as defense-in-depth.

use std::path::{Path, PathBuf};

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_canonical_images::{
    manifest_path_for_image, verify_canonical_image_via_manifest, CanonicalImageError,
    CanonicalImageKind,
};

/// Outcome of verifying one canonical image at boot under the V2
/// manifest-trust model.
///
/// Returned per image so `main.rs` can render a single human-readable
/// log line summarising the boot's posture, and so integration tests
/// can assert the exact branch taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightOutcome {
    /// Manifest verified + the .img's streamed SHA-256 matched the
    /// manifest's signed `image_artefact_sha256`. The matching VM-spawn
    /// path may proceed.
    Ok {
        /// Image file the kernel verified.
        path: PathBuf,
    },
    /// The .img file was not found at the expected path. Logged as
    /// a warning; activations that need it will fail at
    /// `IsolationBackend::launch` time. Not a boot failure.
    Missing {
        /// The path the kernel attempted to verify.
        path: PathBuf,
    },
    /// The .img is present but the sibling
    /// `<role>-<kernel_version>.manifest.toml` is not. Logged as a
    /// warning; activations cannot start without the manifest.
    ManifestMissing {
        /// Image file path.
        image_path:    PathBuf,
        /// Manifest file path that was missing.
        manifest_path: PathBuf,
    },
    /// The kernel binary's `EXPECTED_KERNEL_SIGNING_KEY_BYTES` is the
    /// all-zero placeholder. Logged as a warning; not a boot failure
    /// (until the release pipeline commits a key, every kernel build
    /// is in this state).
    TrustAnchorUnpopulated {
        /// The path the kernel would have verified.
        path: PathBuf,
    },
    /// The .img's streamed SHA-256 disagreed with the manifest's
    /// signed `image_artefact_sha256`. The kernel will emit
    /// `SecurityViolationDetected` and refuse to spawn the matching
    /// role's VMs at activation time.
    Tampered {
        /// Image file the kernel attempted to verify.
        path:     PathBuf,
        /// Hex-encoded SHA-256 the manifest expected.
        expected: String,
        /// Hex-encoded SHA-256 the kernel observed on disk.
        actual:   String,
    },
    /// The manifest could not be loaded, parsed, or its signature /
    /// role / kernel-version failed the kernel's trust contract.
    /// Audit-emitted and treated as a tamper case for activation.
    ManifestRejected {
        /// Image file path.
        image_path:    PathBuf,
        /// Manifest file path.
        manifest_path: PathBuf,
        /// Human-readable rejection reason (the canonical-image
        /// crate's `Display` for the underlying error).
        reason:        String,
    },
}

/// Resolve the canonical Reviewer image filename for `kernel_version`.
/// Format pinned by `system-requirements.md §1`:
/// `raxis-reviewer-core-<kernel_version>.img`.
pub fn reviewer_image_path(install_dir: &Path, kernel_version: &str) -> PathBuf {
    install_dir.join("images").join(format!(
        "raxis-reviewer-core-{kernel_version}.img"
    ))
}

/// Resolve the canonical Orchestrator image filename for
/// `kernel_version`. Format pinned by `system-requirements.md §1`:
/// `raxis-orchestrator-core-<kernel_version>.img`.
pub fn orchestrator_image_path(install_dir: &Path, kernel_version: &str) -> PathBuf {
    install_dir.join("images").join(format!(
        "raxis-orchestrator-core-{kernel_version}.img"
    ))
}

/// Resolve the canonical Executor-starter image filename for
/// `kernel_version`. Format pinned by `system-requirements.md §1`:
/// `raxis-executor-starter-<kernel_version>.img`.
///
/// **Why a separate path helper.** Executor / Reviewer activations
/// (`v2-deep-spec.md §Steps 21–24`) resolve the canonical guest
/// rootfs at spawn time — keeping the path-template in one place
/// here lets `images/README.md`, the boot-time preflight, and the
/// activation-spawn callsite all share a single source of truth.
/// The Executor-starter is the V2 GA opt-in image; Reviewer
/// activations stay on `raxis-reviewer-core` (Pure-Static Reviewer,
/// `INV-PLANNER-HARNESS-02`).
pub fn executor_starter_image_path(install_dir: &Path, kernel_version: &str) -> PathBuf {
    install_dir.join("images").join(format!(
        "raxis-executor-starter-{kernel_version}.img"
    ))
}

/// Run the canonical-image manifest preflight at boot. Returns one
/// outcome per image (Reviewer first, Orchestrator second) and emits
/// `SecurityViolationDetected` audit events for any mismatch.
///
/// Both image checks run unconditionally (a tampered Orchestrator
/// image and a tampered Reviewer image are independent failure
/// modes; we want both audit events when both happen).
pub fn verify_canonical_images_at_boot(
    install_dir:    &Path,
    kernel_version: &str,
    audit:          &dyn AuditSink,
) -> [(CanonicalImageKind, PreflightOutcome); 2] {
    let reviewer_path     = reviewer_image_path(install_dir, kernel_version);
    let orchestrator_path = orchestrator_image_path(install_dir, kernel_version);

    let reviewer_outcome     = run_one(&reviewer_path,     CanonicalImageKind::Reviewer,     kernel_version, audit);
    let orchestrator_outcome = run_one(&orchestrator_path, CanonicalImageKind::Orchestrator, kernel_version, audit);

    [
        (CanonicalImageKind::Reviewer,     reviewer_outcome),
        (CanonicalImageKind::Orchestrator, orchestrator_outcome),
    ]
}

/// Verify one image's manifest + .img bytes and emit the appropriate
/// audit event on mismatch. Pulled out so the helper is unit-testable
/// without going through `verify_canonical_images_at_boot`'s pair plumbing.
fn run_one(
    image_path:     &Path,
    kind:           CanonicalImageKind,
    kernel_version: &str,
    audit:          &dyn AuditSink,
) -> PreflightOutcome {
    if !image_path.exists() {
        return PreflightOutcome::Missing { path: image_path.to_owned() };
    }
    let manifest_path = manifest_path_for_image(image_path);
    if !manifest_path.exists() {
        return PreflightOutcome::ManifestMissing {
            image_path:    image_path.to_owned(),
            manifest_path,
        };
    }

    match verify_canonical_image_via_manifest(
        image_path,
        &manifest_path,
        kind,
        kernel_version,
    ) {
        Ok(()) => PreflightOutcome::Ok { path: image_path.to_owned() },
        Err(CanonicalImageError::SigningKeyFpNotPopulated) => {
            PreflightOutcome::TrustAnchorUnpopulated { path: image_path.to_owned() }
        }
        Err(CanonicalImageError::DigestMismatch { expected, actual, .. }) => {
            // Audit-after-detect (NOT after a state mutation) — the
            // detection itself IS the recorded fact. Emit failures
            // are logged but never short-circuit the preflight pair:
            // a tampered Reviewer image must not mask a tampered
            // Orchestrator image (or vice versa).
            if let Err(e) = audit.emit(
                AuditEventKind::SecurityViolationDetected {
                    violation_kind: kind.audit_kind().to_owned(),
                    expected:       Some(expected.clone()),
                    actual:         Some(actual.clone()),
                    path:           Some(image_path.display().to_string()),
                },
                None, None, None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"SecurityViolationDetected\",\
                     \"audit_emit_failed\":\"{e}\",\"violation_kind\":\"{}\"}}",
                    kind.audit_kind(),
                );
            }
            PreflightOutcome::Tampered {
                path: image_path.to_owned(),
                expected,
                actual,
            }
        }
        Err(CanonicalImageError::Io { source, .. }) => {
            // I/O reported `not found`-equivalent on a path that
            // `path.exists()` cleared as present — extremely rare
            // (race or symlink-target-vanished). Fall through to
            // `Missing` so the operator sees a single canonical
            // remediation message: "the image file is not present".
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"canonical_image_io_missing\",\
                 \"path\":\"{}\",\"reason\":\"{source}\"}}",
                image_path.display(),
            );
            PreflightOutcome::Missing { path: image_path.to_owned() }
        }
        Err(other) => {
            // Manifest load / parse / signature / role-mismatch /
            // kernel-version-skew. Audit and refuse activation.
            let reason = format!("{other}");
            if let Err(e) = audit.emit(
                AuditEventKind::SecurityViolationDetected {
                    violation_kind: kind.audit_kind().to_owned(),
                    expected:       None,
                    actual:         None,
                    path:           Some(manifest_path.display().to_string()),
                },
                None, None, None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"SecurityViolationDetected\",\
                     \"audit_emit_failed\":\"{e}\",\"violation_kind\":\"{}\"}}",
                    kind.audit_kind(),
                );
            }
            PreflightOutcome::ManifestRejected {
                image_path:    image_path.to_owned(),
                manifest_path,
                reason,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_test_support::FakeAuditSink;
    use std::io::Write;

    /// Path resolution pins the spec's filename format. Drift here
    /// would silently break `raxis doctor canonical-images` and any
    /// air-gapped install that ships images at the documented path.
    #[test]
    fn reviewer_path_matches_system_requirements_layout() {
        let p = reviewer_image_path(Path::new("/usr/local/lib/raxis"), "2.0.0");
        assert_eq!(
            p,
            PathBuf::from("/usr/local/lib/raxis/images/raxis-reviewer-core-2.0.0.img"),
        );
    }

    #[test]
    fn orchestrator_path_matches_system_requirements_layout() {
        let p = orchestrator_image_path(Path::new("/usr/local/lib/raxis"), "2.0.0");
        assert_eq!(
            p,
            PathBuf::from("/usr/local/lib/raxis/images/raxis-orchestrator-core-2.0.0.img"),
        );
    }

    /// On a fresh install (image not present), preflight surfaces
    /// `Missing` and emits NO `SecurityViolationDetected` event.
    /// This is the baseline state of every dev workstation today —
    /// the kernel must boot regardless.
    #[test]
    fn missing_image_is_warning_only_not_audit_event() {
        let tmp   = tempfile::tempdir().unwrap();
        let audit = FakeAuditSink::new();

        let outcomes = verify_canonical_images_at_boot(tmp.path(), "0.0.0-test", &audit);
        match &outcomes[0].1 {
            PreflightOutcome::Missing { .. } => {}
            other => panic!("expected Missing for Reviewer; got {other:?}"),
        }
        match &outcomes[1].1 {
            PreflightOutcome::Missing { .. } => {}
            other => panic!("expected Missing for Orchestrator; got {other:?}"),
        }

        let kinds: Vec<_> = audit.events()
            .iter()
            .map(|e| e.kind.as_str())
            .collect();
        assert!(
            !kinds.contains(&"SecurityViolationDetected"),
            "missing-image case must NOT emit SecurityViolationDetected: {kinds:?}",
        );
    }

    /// .img is on disk but the sibling `.manifest.toml` is not yet
    /// distributed → `ManifestMissing`, no audit event. Pins the
    /// "image is present, manifest not yet shipped" early-deployment
    /// posture (which is the realistic state during V2 cutover before
    /// the release pipeline has produced a manifest).
    #[test]
    fn present_image_without_manifest_surfaces_manifest_missing_warning_only() {
        let tmp   = tempfile::tempdir().unwrap();
        let audit = FakeAuditSink::new();

        let images = tmp.path().join("images");
        std::fs::create_dir_all(&images).unwrap();
        for name in [
            "raxis-reviewer-core-0.0.0-test.img",
            "raxis-orchestrator-core-0.0.0-test.img",
        ] {
            let mut f = std::fs::File::create(images.join(name)).unwrap();
            f.write_all(b"placeholder-content").unwrap();
        }

        let outcomes = verify_canonical_images_at_boot(tmp.path(), "0.0.0-test", &audit);
        for (kind, outcome) in &outcomes {
            assert!(
                matches!(outcome, PreflightOutcome::ManifestMissing { .. }),
                "expected ManifestMissing for {kind:?}; got {outcome:?}",
            );
        }

        let kinds: Vec<_> = audit.events()
            .iter()
            .map(|e| e.kind.as_str())
            .collect();
        assert!(
            !kinds.contains(&"SecurityViolationDetected"),
            "manifest-missing case must NOT emit SecurityViolationDetected: {kinds:?}",
        );
    }

    /// .img + .manifest.toml are both on disk but the kernel's
    /// signing-key trust anchor is the placeholder → `TrustAnchorUnpopulated`
    /// outcome, no audit event. Pins the V2-cutover posture once the
    /// release pipeline starts shipping signed manifests but the
    /// kernel binary has not yet committed the public key.
    #[test]
    fn manifest_present_with_unpopulated_trust_anchor_is_warning_only() {
        let tmp   = tempfile::tempdir().unwrap();
        let audit = FakeAuditSink::new();

        let images = tmp.path().join("images");
        std::fs::create_dir_all(&images).unwrap();
        for stem in [
            "raxis-reviewer-core-0.0.0-test",
            "raxis-orchestrator-core-0.0.0-test",
        ] {
            let mut f = std::fs::File::create(images.join(format!("{stem}.img"))).unwrap();
            f.write_all(b"placeholder-content").unwrap();
            // The manifest contents are irrelevant — the trust-anchor
            // gate trips before we parse the file.
            std::fs::write(
                images.join(format!("{stem}.manifest.toml")),
                "schema_version = 2\n",
            )
            .unwrap();
        }

        let outcomes = verify_canonical_images_at_boot(tmp.path(), "0.0.0-test", &audit);
        for (kind, outcome) in &outcomes {
            assert!(
                matches!(outcome, PreflightOutcome::TrustAnchorUnpopulated { .. }),
                "expected TrustAnchorUnpopulated for {kind:?}; got {outcome:?}",
            );
        }

        let kinds: Vec<_> = audit.events()
            .iter()
            .map(|e| e.kind.as_str())
            .collect();
        assert!(
            !kinds.contains(&"SecurityViolationDetected"),
            "trust-anchor-unpopulated must NOT emit SecurityViolationDetected: {kinds:?}",
        );
    }
}
