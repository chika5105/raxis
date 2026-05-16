//! Regression net for **`INV-DATA-DIR-WITNESS-SUBDIR-BOOTSTRAPPED-01`** and
//! **`INV-DATA-DIR-LAYOUT-COMPLETE-ON-BOOT-01`**.
//!
//! Three properties pinned here:
//!
//!   1. `<data_dir>/witness/` exists after `ensure_data_dir_layout` —
//!      the iter66 root cause was that genesis (`bootstrap.rs`) never
//!      created `witness/`, so the very first
//!      `IntegrationMerge` gate evaluation panicked
//!      `kernel::witness_index::write_blob_to_disk` with `No such file
//!      or directory (os error 2)`. The boot-time helper closes that
//!      gap; this test pins the closure.
//!
//!   2. Writing a witness blob immediately after boot succeeds — a
//!      direct reproduction of the iter66 failure mode. The helper
//!      synthesises a content-addressed write at
//!      `<data_dir>/witness/<sha256>` exactly the way
//!      `kernel::witness_index::write_blob_to_disk` does, with no
//!      `create_dir_all` of its own. If `ensure_data_dir_layout` ever
//!      regresses on `witness/`, this test panics with the exact same
//!      `ENOENT` the iter66 harness saw.
//!
//!   3. Every entry in `DATA_DIR_SUBDIRS` is present post-boot — the
//!      regression net for `INV-DATA-DIR-LAYOUT-COMPLETE-ON-BOOT-01`.
//!      A future contributor who adds a new per-handler write surface
//!      to the kernel and forgets to update `DATA_DIR_SUBDIRS` either
//!      (a) breaks this test (if they listed the dir in
//!      `DATA_DIR_SUBDIRS` but the helper didn't create it — caught
//!      by sub-test below), or (b) trips a downstream
//!      `No such file or directory` at first write (caught by the
//!      iter66-style witness-write reproduction).
//!
//! ## Why a `#[path]` include rather than a `pub use` import
//!
//! The `raxis-kernel` crate has no library target — every other
//! integration test file in this directory either spawns the kernel
//! binary as a subprocess (e.g. `kernel_signal_shutdown.rs`) or
//! exercises kernel-internal types only through the audit-event +
//! filesystem surface. `data_dir_layout` has zero workspace
//! dependencies (only `std::path::Path` + `std::fs`), so the cleanest
//! path is to include the source file directly with `#[path]`. This
//! keeps the test linked against the SAME `DATA_DIR_SUBDIRS` constant
//! the kernel binary uses — a separate copy in the test would defeat
//! the regression-net purpose.

#![cfg(test)]

#[path = "../src/data_dir_layout.rs"]
mod data_dir_layout;

use std::fs;

use sha2::{Digest, Sha256};
use tempfile::TempDir;

use data_dir_layout::{ensure_data_dir_layout, DATA_DIR_SUBDIRS};

// ────────────────────────────────────────────────────────────────────
// Sub-test 1 — witness/ exists after boot-time bootstrap.
// ────────────────────────────────────────────────────────────────────

/// `INV-DATA-DIR-WITNESS-SUBDIR-BOOTSTRAPPED-01` — the kernel daemon
/// MUST, on every boot, ensure that `<data_dir>/witness/` exists.
#[test]
fn witness_subdir_exists_after_boot_time_bootstrap() {
    let tmp = TempDir::new().expect("tempdir");
    ensure_data_dir_layout(tmp.path()).expect("ensure_data_dir_layout");

    let witness = tmp.path().join("witness");
    assert!(
        witness.is_dir(),
        "INV-DATA-DIR-WITNESS-SUBDIR-BOOTSTRAPPED-01 violated: \
         <data_dir>/witness/ missing after ensure_data_dir_layout \
         (expected at {})",
        witness.display(),
    );
}

// ────────────────────────────────────────────────────────────────────
// Sub-test 2 — direct iter66 reproduction.
// ────────────────────────────────────────────────────────────────────

/// Writing a witness blob immediately after boot MUST succeed.
///
/// This test replicates `kernel::witness_index::write_blob_to_disk`'s
/// on-disk contract: a raw `std::fs::write(<witness_dir>/<sha>, blob)`
/// with no `create_dir_all` of its own. iter66's failure mode was
/// `No such file or directory (os error 2)` at exactly this call site
/// — if `ensure_data_dir_layout` ever regresses on `witness/`, this
/// test reproduces the failure verbatim.
#[test]
fn witness_blob_write_immediately_after_boot_succeeds() {
    let tmp = TempDir::new().expect("tempdir");
    ensure_data_dir_layout(tmp.path()).expect("ensure_data_dir_layout");

    let blob: &[u8] = b"iter66-witness-blob-reproduction-payload";
    let mut h = Sha256::new();
    h.update(blob);
    let sha = hex::encode(h.finalize());

    let witness_dir = tmp.path().join("witness");
    let blob_path = witness_dir.join(&sha);

    // Mirrors `witness_index::write_blob_to_disk`'s line:
    //     std::fs::write(&blob_path, blob)
    fs::write(&blob_path, blob).unwrap_or_else(|e| {
        panic!(
            "iter66 reproduction: writing a witness blob to {} \
             failed with {e}. ensure_data_dir_layout must create \
             <data_dir>/witness/ (INV-DATA-DIR-WITNESS-SUBDIR-BOOTSTRAPPED-01).",
            blob_path.display(),
        )
    });

    let written = fs::read(&blob_path).expect("re-read written blob");
    assert_eq!(
        written, blob,
        "round-trip blob bytes must equal the bytes we wrote",
    );
}

// ────────────────────────────────────────────────────────────────────
// Sub-test 3 — exhaustive canonical-layout regression net.
// ────────────────────────────────────────────────────────────────────

/// `INV-DATA-DIR-LAYOUT-COMPLETE-ON-BOOT-01` — every entry in
/// `DATA_DIR_SUBDIRS` MUST exist on disk after `ensure_data_dir_layout`.
///
/// A future contributor who adds a per-handler write surface and lists
/// it in `DATA_DIR_SUBDIRS` but forgets to update the helper itself
/// will trip this test. (The helper is a simple `for` loop over
/// `DATA_DIR_SUBDIRS`, so the only way to break this property is to
/// special-case some entries with conditional logic — exactly the
/// kind of regression the test exists to catch.)
#[test]
fn canonical_layout_complete_on_boot() {
    let tmp = TempDir::new().expect("tempdir");
    ensure_data_dir_layout(tmp.path()).expect("ensure_data_dir_layout");

    let mut missing: Vec<String> = Vec::new();
    for name in DATA_DIR_SUBDIRS {
        let p = tmp.path().join(name);
        if !p.is_dir() {
            missing.push(format!("{} (path: {})", name, p.display()));
        }
    }
    assert!(
        missing.is_empty(),
        "INV-DATA-DIR-LAYOUT-COMPLETE-ON-BOOT-01 violated: \
         {} canonical subdir(s) missing after \
         ensure_data_dir_layout: {missing:?}",
        missing.len(),
    );

    // Defense in depth: assert the list itself contains the iter66
    // surface. If a future contributor "simplifies" by removing
    // witness/ from the list, this test catches the regression
    // before the harness panics.
    assert!(
        DATA_DIR_SUBDIRS.contains(&"witness"),
        "DATA_DIR_SUBDIRS must include witness/ — see \
         INV-DATA-DIR-WITNESS-SUBDIR-BOOTSTRAPPED-01",
    );
}

// ────────────────────────────────────────────────────────────────────
// Sub-test 4 — bootstrap is idempotent against pre-existing dirs.
// ────────────────────────────────────────────────────────────────────

/// Genesis (`bootstrap.rs`) creates several of the entries in
/// `DATA_DIR_SUBDIRS` already. The boot-time helper MUST be a no-op
/// against a pre-genesis'd data dir so an upgrade path that runs
/// `RAXIS_BOOTSTRAP=1 raxis-kernel` then `raxis-kernel` cannot trip
/// on an already-created subdir.
#[test]
fn ensure_is_idempotent_against_pre_existing_dirs() {
    let tmp = TempDir::new().expect("tempdir");
    // Pre-create a subset of the canonical dirs the way genesis does.
    for name in &["keys", "policy", "audit", "providers", "runtime"] {
        fs::create_dir_all(tmp.path().join(name)).unwrap();
    }
    ensure_data_dir_layout(tmp.path()).expect("first call must accept pre-existing genesis dirs");
    ensure_data_dir_layout(tmp.path()).expect("second call must be a no-op");

    for name in DATA_DIR_SUBDIRS {
        assert!(
            tmp.path().join(name).is_dir(),
            "{name} missing after second idempotent call",
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Sub-test 5 — escalations/ stays out of the canonical layout.
// ────────────────────────────────────────────────────────────────────

/// `escalations/` is intentionally NOT a kernel write surface —
/// escalation rows live in SQLite, pinned by
/// `extended_e2e_concurrent_lifecycle.rs::
/// assert_no_forged_approvals_on_disk`. Listing it in
/// `DATA_DIR_SUBDIRS` would teach operators to expect a directory
/// that should remain absent (or empty if some other process created
/// it). This test pins the deliberate omission so a well-intentioned
/// future PR doesn't promote it into the canonical layout.
#[test]
fn canonical_layout_omits_escalations_by_design() {
    assert!(
        !DATA_DIR_SUBDIRS.contains(&"escalations"),
        "escalations/ MUST stay out of DATA_DIR_SUBDIRS — escalation \
         rows live in SQLite, not on the filesystem (see \
         kernel/tests/extended_e2e_concurrent_lifecycle.rs::\
         assert_no_forged_approvals_on_disk)",
    );
}
