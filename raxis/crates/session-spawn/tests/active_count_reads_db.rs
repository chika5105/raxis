//! `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01` (iter65) regression
//! suite for [`raxis_session_spawn::SessionSpawnService::active_count`].
//!
//! ## Pathology this guards against
//!
//! Pre-iter65 `active_count` returned `self.sessions.lock().len()` —
//! the in-memory live-handle map. The map was `insert`-ed at
//! `spawn_session` time and `remove`-d at `terminate_session` time,
//! but the production `planner_self_exit` revoke path (the dominant
//! exit class) does NOT call `terminate_session` — it flips
//! `sessions.revoked = 1` directly and returns. Each clean-disconnect
//! exit therefore leaked one entry from the in-memory map; over a
//! 30-minute realistic-scenario run the map pinned at the cap
//! (`current_running == cap == 16`) while the audit chain truthfully
//! showed `alive == 1`. Every subsequent admission rejected with
//! `FailVmConcurrencyAtCap` against an empty audit-truth state.
//!
//! ## What these tests pin
//!
//! * `active_count_with_store_returns_zero_for_all_revoked` — the
//!   audit-truth projection: every row revoked ⇒ count = 0,
//!   regardless of how full the in-memory map happens to be.
//! * `active_count_with_store_counts_unrevoked_rows` — the
//!   audit-truth projection: N un-revoked rows ⇒ count = N.
//! * `active_count_falls_back_to_in_memory_when_no_store` — pre-iter65
//!   fallback for fixtures that never wire a store. Documents the
//!   fallback behaviour; production main + `HandlerContext::new`
//!   always call `with_store`.

use std::sync::Arc;

use raxis_audit_tools::AuditSink;
use raxis_session_spawn::SessionSpawnService;
use raxis_store::{Store, Table};
use raxis_test_support::{FakeAuditSink, SubprocessIsolation};
use rusqlite::params;

/// Insert one `sessions` row with the given `revoked` flag. Mirrors
/// the columns the V2 migration enforces NOT NULL on (the rest are
/// either NULLABLE or carry sensible DEFAULTs); the only invariant
/// the test cares about is `revoked` because that's what
/// `count_unrevoked_sessions` keys on.
fn insert_session_row(conn: &rusqlite::Connection, session_id: &str, revoked: bool) {
    let sessions = Table::Sessions.as_str();
    conn.execute(
        &format!(
            "INSERT INTO {sessions} \
             (session_id, role_id, session_token, lineage_id, \
              fetch_quota, created_at, expires_at, revoked) \
             VALUES (?1, 'planner', ?2, 'lin-test', 0, 100, 9999999999, ?3)"
        ),
        params![
            session_id,
            format!("tok-{session_id}"),
            if revoked { 1 } else { 0 },
        ],
    )
    .expect("seed sessions row");
}

fn build_service(store: Option<Arc<Store>>) -> Arc<SessionSpawnService> {
    let creds_dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(
        raxis_credentials_file::FileCredentialBackend::open_without_uid_check(creds_dir.path()),
    );
    let audit: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());
    let proxy_manager = Arc::new(raxis_credential_proxy_manager::CredentialProxyManager::new(
        Arc::clone(&backend) as _,
        Arc::clone(&audit),
    ));
    let isolation = Arc::new(SubprocessIsolation::new("active-count-test").unwrap());
    // Leak the creds_dir TempDir for the duration of the test —
    // dropping it unlinks the credential backing files which the
    // production proxy code path doesn't care about (we never
    // actually spawn a session here), but the leak keeps the file
    // backend's `open_without_uid_check` invariant satisfied for
    // the entire test wall-clock window.
    std::mem::forget(creds_dir);
    let mut svc = SessionSpawnService::new(isolation as _, proxy_manager, audit);
    if let Some(s) = store {
        svc = svc.with_store(s);
    }
    Arc::new(svc)
}

/// `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01`. After every row
/// has been revoked the count reads zero — regardless of whether
/// the in-memory map is empty (it is, in this test, because we
/// never spawned anything) or full (the iter64 leak surface). The
/// kernel-side cap-admission gate consults THIS value.
#[tokio::test]
async fn active_count_with_store_returns_zero_for_all_revoked() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    {
        let conn = store.lock().await;
        for i in 0..5 {
            insert_session_row(&conn, &format!("s-{i}"), true);
        }
    }
    let svc = build_service(Some(Arc::clone(&store)));
    let count = svc.active_count().await;
    assert_eq!(
        count, 0,
        "INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01: every row \
         revoked ⇒ active_count MUST read zero from the durable \
         sessions table; got {count}",
    );
}

/// `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01`. N un-revoked rows
/// ⇒ `active_count` reports N — the audit-truth projection.
#[tokio::test]
async fn active_count_with_store_counts_unrevoked_rows() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    {
        let conn = store.lock().await;
        for i in 0..3 {
            insert_session_row(&conn, &format!("s-live-{i}"), false);
        }
        for i in 0..7 {
            insert_session_row(&conn, &format!("s-dead-{i}"), true);
        }
    }
    let svc = build_service(Some(Arc::clone(&store)));
    let count = svc.active_count().await;
    assert_eq!(
        count, 3,
        "INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01: 3 un-revoked \
         + 7 revoked rows ⇒ cap-admission count must be 3 (the \
         pre-iter65 in-memory projection would have reported 0 \
         here because we never spawned via the service)",
    );
}

/// `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01`. Regression witness
/// for the iter65 root cause: the `planner_self_exit` revoke path
/// flips `sessions.revoked = 1` without calling `terminate_session`,
/// so the in-memory map keeps the entry forever. The DB-derived
/// projection sees the revoke and the count drops; the in-memory
/// projection would have stayed at the pre-revoke value.
#[tokio::test]
async fn active_count_drops_after_planner_self_exit_revoke_sweep() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    {
        let conn = store.lock().await;
        // Seed 16 live sessions — the iter64 production cap.
        for i in 0..16 {
            insert_session_row(&conn, &format!("s-{i}"), false);
        }
    }
    let svc = build_service(Some(Arc::clone(&store)));
    assert_eq!(svc.active_count().await, 16, "16 live sessions seeded");

    // Simulate the `planner_self_exit` revoke path: flip every
    // row to `revoked = 1` directly via SQL. NO call to
    // `service.terminate_session` (which is the iter65 root
    // cause — the production exit path bypasses it).
    {
        let conn = store.lock().await;
        let sessions = Table::Sessions.as_str();
        conn.execute(&format!("UPDATE {sessions} SET revoked = 1"), [])
            .unwrap();
    }
    let count = svc.active_count().await;
    assert_eq!(
        count, 0,
        "INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01: after the \
         planner_self_exit revoke sweep the cap-admission count \
         MUST collapse to zero (regression witness for the iter64 \
         leak where current_running pinned at 16/16)",
    );
}

/// Pre-iter65 fallback: when no store is wired (legacy unit-test
/// fixtures), `active_count` falls back to `self.sessions.lock().len()`.
/// Documents the fallback so a future refactor that drops the
/// in-memory projection entirely doesn't silently break tests
/// that build `SessionSpawnService::new(...)` without
/// `.with_store(...)`.
#[tokio::test]
async fn active_count_falls_back_to_in_memory_when_no_store() {
    let svc = build_service(None);
    // The fixture spawns nothing, so the in-memory map is empty.
    assert_eq!(
        svc.active_count().await,
        0,
        "fallback path with no store wired: empty in-memory map \
         ⇒ active_count = 0",
    );
}
