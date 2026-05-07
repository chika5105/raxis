//! Boot-time canonical VM image digest preflight.
//!
//! Normative references:
//!
//! * `planner-harness.md §4.5` (`INV-PLANNER-HARNESS-02`) — Reviewer
//!   image digest is kernel-binary-pinned; mismatch produces
//!   `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` and a
//!   `SecurityViolationDetected { kind: "ReviewerImageDigestMismatch" }`
//!   audit event.
//! * `planner-harness.md §4.7` (`INV-PLANNER-HARNESS-05`) — same
//!   contract for the Orchestrator image, with the
//!   `OrchestratorImageDigestMismatch` audit kind.
//! * `system-requirements.md §3` — operator-facing remediation
//!   ("reinstall from a verified source"); this module is the
//!   kernel-side enforcement seam.
//!
//! ## What this module does
//!
//! At boot, the kernel calls
//! [`verify_canonical_images_at_boot`] against the install dir, runs
//! the digest checks, and emits one `SecurityViolationDetected` audit
//! event per mismatch. The function returns a structured outcome
//! per image so `kernel/src/main.rs` can decide whether the boot
//! continues:
//!
//! * `Ok` — the digest matched and the kernel can spawn the VM.
//! * `Missing` — the image file is not on disk yet (early-deployment
//!   case before `raxis doctor canonical-images` runs); the kernel
//!   logs the warning but does NOT exit, because Reviewer / Orchestrator
//!   activations cannot start without the image and will fail-closed
//!   at `IsolationBackend::launch` time anyway. Surfacing the missing
//!   image as a hard boot failure would prevent the kernel from
//!   starting on a fresh installation, which is operator-hostile.
//! * `Tampered` — the digest mismatch is real. The kernel emits
//!   `SecurityViolationDetected` and refuses to spawn the affected
//!   role's VMs at activation time.
//! * `DigestUnpopulated` — the kernel binary was built before the
//!   matching image artefact landed (the all-zero placeholder in
//!   `raxis_canonical_images`). Logged as a warning; not a boot
//!   failure. Once `raxis-image-builder` lands and the kernel build
//!   embeds real digests, this branch becomes a hard mismatch by
//!   construction.
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
//! the digest check at activation as defense-in-depth.

use std::path::{Path, PathBuf};

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_canonical_images::{
    verify_canonical_image, CanonicalImageError, CanonicalImageKind,
};

/// Outcome of verifying one canonical image at boot.
///
/// Returned per image so `main.rs` can render a single human-readable
/// log line summarising the boot's image-digest posture, and so
/// integration tests can assert the exact branch taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightOutcome {
    /// The on-disk image digest matched the kernel's compiled-in
    /// expected value. The matching VM-spawn path may proceed.
    Ok {
        /// Image file the kernel verified.
        path: PathBuf,
    },
    /// The image file was not found at the expected path. Logged as
    /// a warning; activations that need it will fail at
    /// `IsolationBackend::launch` time. Not a boot failure.
    Missing {
        /// The path the kernel attempted to verify.
        path: PathBuf,
    },
    /// The kernel binary's compiled-in expected digest is the
    /// all-zero placeholder. Logged as a warning; not a boot
    /// failure (until `raxis-image-builder` ships, every kernel
    /// build is in this state).
    DigestUnpopulated {
        /// The path the kernel would have verified.
        path: PathBuf,
    },
    /// The digest computed from the on-disk image bytes did not
    /// match the kernel's compiled-in expected digest. The kernel
    /// will emit `SecurityViolationDetected` and refuse to spawn
    /// the matching role's VMs at activation time.
    Tampered {
        /// Image file the kernel attempted to verify.
        path:     PathBuf,
        /// Hex-encoded SHA-256 the kernel expected.
        expected: String,
        /// Hex-encoded SHA-256 the kernel observed on disk.
        actual:   String,
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

/// Run the canonical-image digest preflight at boot. Returns one
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

    let reviewer_outcome     = run_one(&reviewer_path,     CanonicalImageKind::Reviewer,     audit);
    let orchestrator_outcome = run_one(&orchestrator_path, CanonicalImageKind::Orchestrator, audit);

    [
        (CanonicalImageKind::Reviewer,     reviewer_outcome),
        (CanonicalImageKind::Orchestrator, orchestrator_outcome),
    ]
}

/// Verify one image and emit the appropriate audit event on
/// mismatch. Pulled out so the helper is unit-testable without
/// going through `verify_canonical_images_at_boot`'s pair plumbing.
fn run_one(
    path:  &Path,
    kind:  CanonicalImageKind,
    audit: &dyn AuditSink,
) -> PreflightOutcome {
    if !path.exists() {
        return PreflightOutcome::Missing { path: path.to_owned() };
    }
    match verify_canonical_image(path, kind) {
        Ok(()) => PreflightOutcome::Ok { path: path.to_owned() },
        Err(CanonicalImageError::DigestNotPopulated) => {
            PreflightOutcome::DigestUnpopulated { path: path.to_owned() }
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
                    path:           Some(path.display().to_string()),
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
                path: path.to_owned(),
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
                path.display(),
            );
            PreflightOutcome::Missing { path: path.to_owned() }
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

    /// While the kernel binary's `EXPECTED_*_IMAGE_DIGEST` constants
    /// are the all-zero placeholder, an actually-present image
    /// surfaces `DigestUnpopulated` (a warning posture, not an
    /// audit event). Pin this branch so a future
    /// `raxis-image-builder` rollout flipping the constants from
    /// placeholder to real digest is observed in CI as a state
    /// transition.
    #[test]
    fn present_image_with_unpopulated_digest_is_warning_only() {
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
                matches!(outcome, PreflightOutcome::DigestUnpopulated { .. }),
                "expected DigestUnpopulated for {kind:?}; got {outcome:?}",
            );
        }

        let kinds: Vec<_> = audit.events()
            .iter()
            .map(|e| e.kind.as_str())
            .collect();
        assert!(
            !kinds.contains(&"SecurityViolationDetected"),
            "unpopulated-digest case must NOT emit SecurityViolationDetected: {kinds:?}",
        );
    }
}
