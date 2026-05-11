//! Integration tests that drive a real `CredentialProxyManager`
//! against real listeners and assert the wire-level behaviour:
//!
//!   1. After `start_for_session`, the postgres listener accepts a
//!      TCP connection at the loopback addr the manager returned.
//!   2. After at least one connection has been accepted, the
//!      `CredentialProxyStopped` audit event the manager emits at
//!      shutdown carries a non-zero `connections_served` counter.
//!
//! These tests stop short of speaking the postgres wire protocol
//! because the postgres-proxy crate already has dedicated wire
//! tests for that surface; here we only assert that the manager
//! correctly threads the bound listener through to the agent's
//! loopback env.

use std::sync::Arc;
use std::time::Duration;

use raxis_audit_tools::AuditSink;
use raxis_credential_proxy_manager::CredentialProxyManager;
use raxis_credentials::{CredentialBackend, CredentialName};
use raxis_credentials_file::FileCredentialBackend;
use raxis_plan_credentials::{
    PostgresRestrictions, ProxyDecl, TaskCredentialDecl,
};
use raxis_test_support::FakeAuditSink;

#[tokio::test]
async fn postgres_listener_accepts_connection_and_counter_increments_through_shutdown() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let creds_dir = tmp.path().join("credentials");
    std::fs::create_dir_all(&creds_dir).unwrap();
    let pg_path = creds_dir.join("pg-staging.env");
    std::fs::write(&pg_path, b"postgresql://raxis@127.0.0.1:5432/test").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&pg_path, perms).unwrap();
    }

    let backend: Arc<dyn CredentialBackend> =
        Arc::new(FileCredentialBackend::open_without_uid_check(tmp.path()));
    let audit = Arc::new(FakeAuditSink::new());
    let mgr = CredentialProxyManager::new(
        Arc::clone(&backend),
        Arc::clone(&audit) as Arc<dyn AuditSink>,
    );

    let decls = vec![TaskCredentialDecl {
        name:     CredentialName::new("pg-staging"),
        mount_as: "DATABASE_URL".to_owned(),
        proxy:    ProxyDecl::Postgres {
            restrictions: PostgresRestrictions { allow_only_select: false, ..Default::default() },
        },
    }];

    let handles = mgr
        .start_for_session("sess-int-1", "task-int-1", &decls)
        .await
        .expect("start");
    let summary = &handles.started_summaries()[0];

    // Open a real TCP connection to the bound listener. We don't
    // need to drive the postgres handshake — `accept()` increments
    // `connections_served` the moment we land on its accept loop.
    {
        let mut stream = tokio::net::TcpStream::connect(summary.addr)
            .await
            .expect("connect to bound listener");
        // Give the proxy a moment to record the connection in its
        // accept loop. We deliberately avoid sending any bytes so
        // the per-connection task short-circuits without contacting
        // any real postgres backend.
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Drop to close the connection cleanly.
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
    }
    // Yield once so the spawned per-connection task has a chance to
    // run and the counter increment lands.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let report = handles.shutdown().expect("shutdown");
    assert_eq!(report.stopped.len(), 1);
    let pg = &report.stopped[0];
    assert_eq!(pg.proxy_type, "postgres");
    assert!(
        pg.counters.connections_served >= 1,
        "expected connections_served >= 1, got {}",
        pg.counters.connections_served,
    );

    // Stopped audit event carries the same counter.
    let stopped_events: Vec<_> = audit.events()
        .into_iter()
        .filter(|e| e.kind.as_str() == "CredentialProxyStopped")
        .collect();
    assert_eq!(stopped_events.len(), 1);
    let raxis_audit_tools::AuditEventKind::CredentialProxyStopped {
        connections_served, ..
    } = &stopped_events[0].kind else {
        panic!("expected CredentialProxyStopped variant")
    };
    assert!(
        *connections_served >= 1,
        "audit-event counter should match report",
    );
}
