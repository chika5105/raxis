// raxis-test-support — workspace-wide test scaffolding.
//
// This crate is dev-dep-only. It MUST NOT appear in any production
// `[dependencies]` table; doing so would ship `FakeClock` and friends in
// a release binary. The workspace `Cargo.toml` deliberately does NOT add
// it to `[workspace.dependencies]` for that reason — consumers spell out
// the path dependency in their own `[dev-dependencies]`.
//
// ── Enforcement layers (defense in depth) ──────────────────────────────
//
//   Layer 1 (compile-time, this file): every public item is gated on
//     `#[cfg(any(debug_assertions, test))]`. In a release build, the
//     gate is FALSE, so the items disappear and any consumer that
//     references `GitRepo` / `FakeClock` / `mem_store` / `FakeAuditSink`
//     fails to compile with E0432. This makes a misuse like
//     `[dependencies] raxis-test-support = { ... }` followed by
//     `cargo build --release` a hard build failure rather than a
//     silent shipping risk.
//
//   Layer 2 (PR-time, src/workspace_guard.rs): a `#[test]` walks every
//     workspace member's `Cargo.toml` and asserts `raxis-test-support`
//     appears ONLY under `[dev-dependencies]`. Catches the misuse at
//     `cargo test --workspace` (i.e. CI) regardless of build profile.
//
//   Layer 3 (release-build noise, this file): the crate root carries
//     `#![cfg_attr(not(debug_assertions), deprecated)]` so any release
//     build that does manage to depend on this crate emits a clearly
//     worded deprecation warning at every use site.
//
// `cargo test --release` is the one configuration where all three layers
// fire simultaneously: Layer 1 hides the public API, Layer 2 still
// detects the bad dep, and Layer 3 prints the warning. We accept that
// `cargo test --release` of a downstream crate cannot compile against
// `raxis-test-support` — the crate is for tests, and `cargo test`
// without `--release` is the supported path. Benchmarks belong in
// `criterion` benches, not in `tests/`.

#![cfg_attr(
    not(debug_assertions),
    deprecated = "raxis-test-support is dev-dep-only. \
                  If this warning fires in a release build, you have moved \
                  the crate into [dependencies] or [build-dependencies] \
                  somewhere. See specs/v1/philosophy.md §1.6 \
                  `crates/test-support/` for the rationale."
)]
//
// What lives here:
//
//   1. `FakeClock` — settable, thread-safe `raxis_types::Clock` impl.
//      Used by every kernel test that exercises TTL / expiry / cooldown
//      logic and must be deterministic.
//
//   2. `mem_store()` — one-line in-memory `raxis_store::Store` factory
//      so tests don't have to pull in tokio runtime ceremony just to
//      call `Store::open_in_memory()`.
//
//   3. Re-exports of `FakeAuditSink` and `CapturedEvent` from
//      `raxis-audit-tools`, so test crates that already pull in
//      `raxis-test-support` don't also need `raxis-audit-tools` as a
//      separate dev-dep just for the fake sink.
//
//   4. `GitRepo` — a `tempfile::TempDir`-backed real git repository
//      with ergonomic `commit_file`, `commit_files`, `merge_no_ff`,
//      `delete_file_commit` helpers. Auto-cleaned on drop. Used by
//      `kernel::vcs::diff::git_integration` to exercise `kernel::vcs::*`
//      against real `git` subprocess output instead of mocked byte
//      strings.
//
//   5. `AuditDir` — a `tempfile::TempDir`-backed audit directory shaped
//      exactly like a production audit dir (`segment-000.jsonl`).
//      Used by `kernel::recovery::audit_chain_integration` to exercise
//      the full `FileAuditSink` → JSONL → `verify_audit_chain` round
//      trip on the same on-disk artifact, instead of pinning the writer
//      contract and the verifier contract independently in unit tests
//      against synthetic byte strings.
//
//   6. `DiskStore` — a `tempfile::TempDir`-backed file-backed `Store`
//      with `close()` / `reopen()` helpers. Used by
//      `kernel::recovery::disk_store_integration` to exercise WAL
//      semantics, schema-migration-on-existing-DB, and the close-then-
//      reopen-then-`reconcile_tasks` flow, none of which the
//      `:memory:` `Store` exercises (different SQLite mode, no fsync,
//      no file lock).
//
// Why not just put everything in `raxis-audit-tools` / `raxis-store` /
// `raxis-types`?
//   - `FakeClock` is genuinely cross-cutting — the kernel, gateway,
//     and (eventually) provider crates all need to inject clock time
//     into TTL-driven code paths. Putting it in `raxis-types` would
//     bleed `Mutex<i64>` state into a "pure data + serde derives"
//     crate that explicitly forbids state per its module header.
//   - `mem_store()` is one line, but having ONE place for "give me
//     a fresh in-memory Store for a test" prevents call-site drift
//     when (e.g.) we want every test to start with the same set of
//     PRAGMAs warmed up.
//   - `FakeAuditSink` already lives in `raxis-audit-tools` and the
//     re-export here is purely a discoverability / dependency-count
//     convenience.

// ── Layer 1 enforcement — every public item is gated on the
//    "this is a debug or test build" predicate. In a release build of
//    a downstream crate that (incorrectly) takes `raxis-test-support`
//    as a regular dep, none of the items below exist and the consumer
//    fails to compile. The guard test in `workspace_guard.rs` (Layer 2)
//    is what catches the misuse before that point.
#[cfg(any(debug_assertions, test))]
pub mod audit_dir;
#[cfg(any(debug_assertions, test))]
pub mod audit_sink;
#[cfg(any(debug_assertions, test))]
pub mod cert;
#[cfg(any(debug_assertions, test))]
pub mod clock;
#[cfg(any(debug_assertions, test))]
pub mod disk_store;
#[cfg(any(debug_assertions, test))]
pub mod gateway_backend;
#[cfg(any(debug_assertions, test))]
pub mod git_repo;
#[cfg(any(debug_assertions, test))]
pub mod subprocess_isolation;
#[cfg(any(debug_assertions, test))]
mod workspace_guard;

#[cfg(any(debug_assertions, test))]
pub use audit_dir::{AuditDir, GenesisInfo};
#[cfg(any(debug_assertions, test))]
pub use audit_sink::{CapturedEvent, FakeAuditSink};
#[cfg(any(debug_assertions, test))]
pub use cert::{
    ephemeral_cert, ephemeral_cert_with_key, ephemeral_cert_with_opts,
    ephemeral_signing_key, pubkey_hex, stub_cert_for_pubkey, CertOpts,
};
#[cfg(any(debug_assertions, test))]
pub use clock::FakeClock;
#[cfg(any(debug_assertions, test))]
pub use disk_store::DiskStore;
#[cfg(any(debug_assertions, test))]
pub use gateway_backend::MockBackend;
#[cfg(any(debug_assertions, test))]
pub use git_repo::{git_available, GitRepo};
#[cfg(any(debug_assertions, test))]
pub use subprocess_isolation::{SubprocessIsolation, SubprocessSession};

// ---------------------------------------------------------------------------
// mem_store — one-line in-memory Store factory.
//
// Same Layer 1 gate as the other public items: in a release build of
// any consumer that mistakenly takes us as a regular dep, `mem_store`
// does not exist and the consumer fails to compile.
// ---------------------------------------------------------------------------

#[cfg(any(debug_assertions, test))]
use raxis_store::Store;

/// Open a fresh in-memory `raxis_store::Store` with all migrations
/// applied. Panics on failure — this is for tests, where a failed store
/// open is itself a test failure.
///
/// The returned `Store` is fully isolated from any other `mem_store()`
/// call (each one allocates a separate `:memory:` SQLite database), so
/// tests can call this in `#[test]` setup without ordering concerns.
#[cfg(any(debug_assertions, test))]
pub fn mem_store() -> Store {
    Store::open_in_memory()
        .expect("raxis-test-support::mem_store: in-memory Store::open_in_memory failed")
}

// ---------------------------------------------------------------------------
// Smoke tests — keep this crate itself green.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod smoke {
    use super::*;
    use raxis_types::Clock;

    #[test]
    fn mem_store_is_isolated_per_call() {
        // Two independent in-memory stores must not share state.
        let s1 = mem_store();
        let s2 = mem_store();
        assert!(!std::ptr::eq(&s1, &s2),
            "mem_store handed out the same allocation twice");
    }

    #[test]
    fn fake_clock_re_export_implements_clock_trait() {
        let c = FakeClock::at(42);
        assert_eq!(c.now_unix_secs(), 42);
    }

    #[test]
    fn fake_audit_sink_re_export_compiles() {
        let _ = FakeAuditSink::new();
    }
}
