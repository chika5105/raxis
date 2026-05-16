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
//   Layer 1 (PR-time, src/workspace_guard.rs): a `#[test]` walks every
//     workspace member's `Cargo.toml` and asserts `raxis-test-support`
//     appears ONLY under `[dev-dependencies]`. Catches misuse at
//     `cargo test --workspace` (i.e. CI) regardless of build profile.
//     This is the SOLE enforcement mechanism today — it fires in every
//     CI run and pinpoints the offending Cargo.toml.
//
// Historical Layer 2 was a crate-root
// `#![cfg_attr(not(debug_assertions), deprecated = "...")]` that
// emitted a warning at every use site when any consumer compiled this
// crate in release profile. It was retired during the iter67 pipeline
// phase (Sat 2026-05-16) because:
//
//   * The legitimate `cargo build --release --tests`,
//     `cargo build --release --all-targets`, and
//     `cargo clippy --release --all-targets -- -D warnings` workflows
//     all build dev-deps in release profile without the consumer's
//     `cfg(test)` propagating, so the deprecation fired on every test
//     consumer — turning into a fatal error under `-D warnings`.
//   * The lib.rs comment in the original Layer 2 declaration already
//     documented that "the workspace_guard test (now Layer 1) gives
//     strictly stronger guarantees and works in every profile" — i.e.
//     Layer 2 was acknowledged as redundant noise even at the time of
//     its introduction.
//   * No mechanism inside the test-support crate itself can
//     differentiate "dev-dep used by a consumer's test target" from
//     "production dep wired into a release binary" — `cfg(test)` is
//     evaluated per-crate, dev-deps don't see the consumer's test cfg,
//     and there is no `cfg(consumer_is_test)` available.
//
// The workspace_guard test remains the canonical enforcement; it
// asserts every member's `Cargo.toml` lists `raxis-test-support` under
// `[dev-dependencies]` (or not at all) on every CI `cargo test`
// invocation. A stray `[dependencies] raxis-test-support = ...` is
// caught at PR time.

// Historical note: an earlier "Layer 1" pattern (different from the
// current Layer 1 above) gated every public item on
// `#[cfg(any(debug_assertions, test))]` so release builds would fail
// to find the symbols. That broke the legitimate
// `cargo build --release --tests` workflow used by the live-e2e
// pre-build (dev-deps are compiled in release mode without the
// downstream consumer's `cfg(test)` set, so the gate evaluated to
// `false` and the items disappeared from the dep's surface even though
// the consumer's test target legitimately needed them). The
// workspace_guard test (Layer 1 above) gives strictly stronger
// guarantees and works in every profile.
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

// Public surface — kept unconditional so that the legitimate
// `cargo build --release --tests` workflow (used by the live-e2e
// pre-build) sees the items. Misuse — taking `raxis-test-support`
// as a `[dependencies]` / `[build-dependencies]` dep rather than
// `[dev-dependencies]` — is caught by the workspace_guard `#[test]`
// (Layer 1) and the release-build deprecation warning (Layer 2),
// both of which fire regardless of compile profile.
pub mod audit_dir;
pub mod audit_sink;
pub mod cert;
pub mod clock;
pub mod disk_store;
pub mod gateway_backend;
pub mod git_repo;
pub mod subprocess_isolation;
mod workspace_guard;

pub use audit_dir::{AuditDir, GenesisInfo};
pub use audit_sink::{CapturedEvent, FakeAuditSink};
pub use cert::{
    ephemeral_cert, ephemeral_cert_with_key, ephemeral_cert_with_opts, ephemeral_signing_key,
    pubkey_hex, stub_cert_for_pubkey, CertOpts,
};
pub use clock::FakeClock;
pub use disk_store::DiskStore;
pub use gateway_backend::MockBackend;
pub use git_repo::{git_available, GitRepo};
pub use subprocess_isolation::{SubprocessIsolation, SubprocessSession};

// ---------------------------------------------------------------------------
// mem_store — one-line in-memory Store factory.
// ---------------------------------------------------------------------------

use raxis_store::Store;

/// Open a fresh in-memory `raxis_store::Store` with all migrations
/// applied. Panics on failure — this is for tests, where a failed store
/// open is itself a test failure.
///
/// The returned `Store` is fully isolated from any other `mem_store()`
/// call (each one allocates a separate `:memory:` SQLite database), so
/// tests can call this in `#[test]` setup without ordering concerns.
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
        assert!(
            !std::ptr::eq(&s1, &s2),
            "mem_store handed out the same allocation twice"
        );
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
