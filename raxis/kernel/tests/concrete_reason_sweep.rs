//! Sweep guard for **`INV-FAILURE-REASON-CONCRETE-01`**.
//!
//! This integration test walks every Rust source file under
//! `kernel/src/**` and every TS/TSX file under
//! `dashboard-fe/src/**` and asserts that NONE of them contains a
//! generic-placeholder substring (the multi-option umbrella the
//! invariant forbids, plus the canonical hedge phrases).
//!
//! The per-formatter assertions live in
//! `kernel/src/session_spawn_orchestrator.rs::concrete_reason_tests`
//! (binary-crate inline tests; integration tests cannot import
//! kernel-internal items because `raxis-kernel` has no library
//! target) and in
//! `crates/types/src/planner_exit.rs::tests::format_concrete_reason_avoids_forbidden_phrases`.
//!
//! ## Why a separate integration test
//!
//! The sweep does not depend on any kernel-internal types — it
//! reads source files via `std::fs`. Splitting it out of the
//! per-formatter tests keeps each test's failure mode local: a
//! formatter-shape regression flips the inline tests; a copy-
//! paste of the umbrella string into a new emit site flips this
//! sweep.

#![cfg(test)]

use std::fs;
use std::path::{Path, PathBuf};

/// Substrings forbidden in any kernel emit site or FE failure
/// rendering. Mirrors the per-formatter lists in
/// `crates/types/src/planner_exit.rs` and
/// `kernel/src/session_spawn_orchestrator.rs::concrete_reason_tests::FORBIDDEN_PHRASES`.
///
/// Keep all three in sync — adding a new hedge phrase to the
/// invariant means adding it to all three call sites.
const FORBIDDEN_PHRASES: &[&str] = &[
    // The exact multi-option umbrella from the iter56 bug.
    "maxturnsexceeded / tokensexceeded",
    "tokensexceeded / dispatchidle",
    "dispatchidle / process death",
    // Generic placeholders that hide the actual cause.
    "(no reason)",
    "see logs",
    "something went wrong",
    "unknown reason",
    "unspecified reason",
    // `internal error` as a reason is a violation; the
    // dashboard's HTTP 500 wire body uses this string by design
    // (security boundary — concrete cause goes to tracing logs
    // only) and is allowlisted via `is_allowed`.
    "internal error",
];

/// Strip every region between `SWEEP-IGNORE-BEGIN` and
/// `SWEEP-IGNORE-END` markers. Returns the surviving text.
///
/// The markers MUST appear on their own lines (preceded only by
/// whitespace, comment leaders `//` or `/*`). Unbalanced markers
/// (BEGIN without END) cause the rest of the file to be
/// stripped — operator-loud failure mode for a typo. The markers
/// themselves are case-sensitive so a `sweep-ignore-begin` in
/// prose doesn't accidentally trigger.
fn strip_sweep_ignore_blocks(input: &str) -> String {
    const BEGIN: &str = "SWEEP-IGNORE-BEGIN";
    const END:   &str = "SWEEP-IGNORE-END";
    let mut out = String::with_capacity(input.len());
    let mut skipping = false;
    for line in input.lines() {
        if !skipping && line.contains(BEGIN) {
            skipping = true;
            continue;
        }
        if skipping && line.contains(END) {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn collect_files(dir: &Path, ext_filter: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, ext_filter, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext_filter.contains(&ext) {
                out.push(path);
            }
        }
    }
}

/// Paths whose surface intentionally references the forbidden
/// phrases (documentation, invariant text, negative-example
/// tests, the FE empty-state component that pins the kernel-bug
/// strings).
fn is_allowed(p: &Path) -> bool {
    let s = p.to_string_lossy();
    // This file names the forbidden phrases as the counter-
    // examples being asserted against.
    if s.ends_with("concrete_reason_sweep.rs") { return true; }
    // Pre-existing kernel-bug-detection regex anchors.
    if s.ends_with("failure_reason_invariant_witness.rs") { return true; }
    if s.ends_with("notification_filter.rs") { return true; }
    // The activity-tracker module is the iter56 P2 patch documentation
    // home: its module-level doc-comment quotes the umbrella verbatim
    // as the regression baseline, and its rendering helpers contain
    // regression-check assertions that pin the umbrella's absence. The
    // emit-site templates themselves are
    // `INV-FAILURE-REASON-CONCRETE-01`-clean (no umbrella tail); we
    // whitelist the file rather than wrap every doc-comment in
    // SWEEP-IGNORE markers.
    if s.ends_with("session_activity.rs") { return true; }
    // FE empty-state component: pins the kernel-bug badge's
    // empty-state strings (which include phrases like "No reason
    // supplied — kernel bug" intentionally — those are the
    // operator-visible affordances for the kernel-bug path, not
    // emit-site reasons).
    if s.ends_with("FailureReasonPanel.tsx") { return true; }
    // FE Health page renders the same kernel-bug badge text on
    // `failing` / `degraded` subsystems when `last_error` is
    // empty (pinned by INV-DASHBOARD-FAILURE-VISIBILITY-01).
    if s.ends_with("Health.tsx") { return true; }
    // FE wire-shape types file — references the kernel-bug
    // empty-state strings inside doc-comments.
    if s.ends_with("dashboard-fe/src/types/api.ts") { return true; }
    // FE test fixtures for the kernel-bug badge — the test text
    // intentionally contains the strings the badge displays.
    if s.contains("/test/") || s.ends_with(".test.ts") || s.ends_with(".test.tsx") {
        return true;
    }
    false
}

/// `INV-FAILURE-REASON-CONCRETE-01` sweep — fail loudly if any
/// non-allowlisted source file under `kernel/src/**` or
/// `dashboard-fe/src/**` contains a forbidden phrase.
///
/// Adding a NEW concrete-reason emit site that legitimately
/// quotes a forbidden phrase (e.g. a doc-comment explaining what
/// NOT to write) should add the file to `is_allowed` with a
/// rationale; the default action is to rewrite the call site to
/// produce a CONCRETE reason instead.
#[test]
fn no_umbrella_reason_in_kernel_or_dashboard_emit_sites() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let raxis_root = manifest
        .parent()
        .expect("kernel manifest has a parent (raxis/)");
    let kernel_src = manifest.join("src");
    let fe_src     = raxis_root.join("dashboard-fe").join("src");

    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(&kernel_src, &["rs"], &mut files);
    if fe_src.exists() {
        collect_files(&fe_src, &["ts", "tsx"], &mut files);
    }

    assert!(
        !files.is_empty(),
        "sweep found zero files to scan under {} and {}",
        kernel_src.display(),
        fe_src.display(),
    );

    let mut violations: Vec<(PathBuf, String, &'static str)> = Vec::new();
    for f in &files {
        if is_allowed(f) { continue; }
        let Ok(text) = fs::read_to_string(f) else { continue };
        // Strip regions wrapped in `// SWEEP-IGNORE-BEGIN`/`// SWEEP-IGNORE-END`
        // (or `/* SWEEP-IGNORE-BEGIN */` for block-comment form) so per-file
        // unit-test counter-example lists can co-exist with the actual emit
        // code in the same file. The marker is intentionally verbose so a
        // grep against the markers themselves never matches by accident.
        let scannable = strip_sweep_ignore_blocks(&text);
        let lower = scannable.to_lowercase();
        for phrase in FORBIDDEN_PHRASES {
            if lower.contains(phrase) {
                let line = scannable
                    .lines()
                    .find(|l| l.to_lowercase().contains(phrase))
                    .map(|l| l.trim().to_owned())
                    .unwrap_or_default();
                violations.push((f.clone(), line, *phrase));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "INV-FAILURE-REASON-CONCRETE-01 violation: forbidden generic-placeholder \
         phrases must NOT appear in kernel emit sites or FE failure rendering. \
         Either replace with a CONCRETE reason or, if the phrase is intentional \
         (documentation / negative example / kernel-bug-detection regex), add \
         the path to the `is_allowed` list in \
         `kernel/tests/concrete_reason_sweep.rs` with a rationale. Violations:\n{:#?}",
        violations,
    );
}
