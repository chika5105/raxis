//! Integration test for `SessionSpawnService` exercising the full
//! production wiring against real substrates:
//!
//! * Real `CredentialProxyManager` with a real `FileCredentialBackend`
//!   serving real .env files on disk.
//! * Real `SubprocessIsolation` substrate (test substrate that boots
//!   `/bin/cat` as the "guest").
//! * Real per-session admission listener with a real
//!   `PolicyAdmissionService` over a real `EgressAllowlist`.
//! * Real audit chain (`FakeAuditSink`).
//!
//! The test verifies the full round-trip:
//!   1. spawn_session binds proxies, admission listener, and the VM.
//!   2. Loopback env contains every declared `mount_as`.
//!   3. The admission listener accepts a real bincode-framed
//!      `ProxyAdmissionRequest` and returns the expected verdict.
//!   4. terminate_session shuts the VM, aborts admission, drains
//!      proxies, and emits paired audit events.
//!
//! No mocks. The only fake here is the in-memory audit sink — that's
//! the same fake every other integration test uses, since it's the
//! sink seam itself (audit-tools defines the trait).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use raxis_audit_tools::AuditEventKind;
use raxis_credential_proxy_manager::CredentialProxyManager;
use raxis_credentials::CredentialName;
use raxis_credentials_file::FileCredentialBackend;
use raxis_egress_admission::{EgressAllowlist, PolicyAdmissionService};
use raxis_isolation::{
    EgressTier, ImageBody, ImageKind, ImageSignature, SessionToken, VerifiedImage, VmSpec,
};
use raxis_plan_credentials::{PostgresRestrictions, ProxyDecl, TaskCredentialDecl};
use raxis_session_spawn::{SessionSpawnService, SpawnRequest};
use raxis_test_support::audit_sink::FakeAuditSink;
use raxis_test_support::subprocess_isolation::SubprocessIsolation;
use raxis_tproxy_protocol as tp;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn write_cred_file(dir: &std::path::Path, name: &str, body: &[u8]) {
    let path = dir.join(format!("{}.env", name));
    std::fs::write(&path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn fixture_image() -> VerifiedImage {
    // The subprocess substrate ignores `image` entirely (it boots
    // /bin/cat as the "guest"); we only need a syntactically valid
    // VerifiedImage value to populate the SpawnRequest.
    VerifiedImage {
        kind:      ImageKind::RootfsErofs,
        body:      ImageBody::Path(std::path::PathBuf::from("/dev/null")),
        signature: ImageSignature(b"unsigned-test-image".to_vec()),
        image_id:  "raxis-test-substrate-image".into(),
    }
}

fn fixture_spec() -> VmSpec {
    VmSpec {
        vcpu_count:        1,
        mem_mib:           64,
        egress_tier:       EgressTier::Tier2CredProxy,
        cgroup_quota:      None,
        boot_args:         Vec::new(),
        entrypoint_argv:   Vec::new(),
        session_token:     SessionToken("session-token-spawn-test".into()),
        vsock_cid:         Some(0xC1D_0001),
        virtio_fs_mounts:  Vec::new(),
        // SubprocessIsolation ignores the kernel path; the spec's
        // `linux_kernel_path` doc covers this contract explicitly.
        linux_kernel_path: std::path::PathBuf::new(),
        env:               BTreeMap::new(),
        guest_console_log: None,
    }
}

#[tokio::test]
async fn spawn_session_binds_proxies_admission_and_vm_then_terminates_cleanly() {
    // SAFETY: required by `SubprocessIsolation::new` (test-substrate
    // gate). The same env var is set by every integration test that
    // uses the substrate today, so co-running tests don't conflict.
    unsafe { std::env::set_var("RAXIS_TEST_HARNESS", "1") };

    // --- Real credential backend: file-based with real .env files. -----
    let creds_dir = TempDir::new().unwrap();
    write_cred_file(
        creds_dir.path(),
        "db-staging",
        b"postgresql://raxis@127.0.0.1:5432/test",
    );
    let backend = Arc::new(FileCredentialBackend::open(creds_dir.path()));

    // --- Real audit sink. -----------------------------------------------
    let audit = Arc::new(FakeAuditSink::new());

    // --- Real credential proxy manager. --------------------------------
    let proxy_manager = Arc::new(CredentialProxyManager::new(
        Arc::clone(&backend) as _,
        Arc::clone(&audit) as _,
    ));

    // --- Real isolation substrate (subprocess test substrate). ---------
    let isolation = Arc::new(SubprocessIsolation::new("session-spawn-test").unwrap());

    // --- Service under test. -------------------------------------------
    let service = SessionSpawnService::new(
        isolation as _,
        Arc::clone(&proxy_manager),
        Arc::clone(&audit) as _,
    );

    // --- Build the spawn request. --------------------------------------
    let credentials = vec![TaskCredentialDecl {
        name:     CredentialName::new("db-staging".to_owned()),
        mount_as: "DATABASE_URL".to_owned(),
        proxy:    ProxyDecl::Postgres {
            restrictions: PostgresRestrictions { allow_only_select: true, ..Default::default() },
        },
    }];

    // Real admission service over a real allowlist.
    let allowlist = EgressAllowlist {
        exact_hosts: vec!["api.anthropic.com".into()],
        ..Default::default()
    };
    let admission = Box::new(PolicyAdmissionService::new(allowlist));

    let req = SpawnRequest {
        session_id:        "sess-spawn-1".into(),
        task_id:           Some("task-spawn-1".into()),
        initiative_id:     "init-spawn-1".into(),
        image:             fixture_image(),
        workspace_mounts:  vec![],
        vm_spec:           fixture_spec(),
        credentials,
        admission_service: admission,
    };

    // --- Spawn. ---------------------------------------------------------
    let handle = service.spawn_session(req).await.expect("spawn");
    assert_eq!(handle.session_id, "sess-spawn-1");
    assert_eq!(handle.vsock_cid, Some(0xC1D_0001));

    // The credential proxy URL is in the loopback env under the
    // operator-declared `mount_as` field.
    let pg_url = handle
        .loopback_env
        .get("DATABASE_URL")
        .expect("DATABASE_URL bound");
    assert!(
        pg_url.starts_with("postgresql://raxis@127.0.0.1:"),
        "expected loopback postgres URL, got `{pg_url}`",
    );

    // The service is tracking the live session.
    assert!(service.is_active("sess-spawn-1").await);
    assert_eq!(service.active_count().await, 1);

    // --- Drive a real admission round-trip over the listener. ----------
    // This is what the in-guest `raxis-tproxy` would do over loopback
    // (dev) or vsock (V2 GA) — frame a request, read the response.
    let mut admission_sock =
        tokio::net::TcpStream::connect(handle.admission_loopback)
            .await
            .expect("connect to admission listener");
    let req = tp::ProxyAdmissionRequest {
        connection_id:     1,
        original_dst_ip:   "203.0.113.10".into(),
        original_dst_port: 443,
        host_or_sni:       Some("api.anthropic.com".into()),
        protocol:          tp::AdmissionProtocol::Https,
    };
    let frame = tp::encode_request(&req).expect("encode");
    admission_sock.write_all(&frame).await.expect("write request");

    // Read length-prefixed response.
    let mut len_buf = [0u8; 4];
    admission_sock
        .read_exact(&mut len_buf)
        .await
        .expect("read response length");
    let body_len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    admission_sock
        .read_exact(&mut body)
        .await
        .expect("read response body");
    // Reassemble frame for decode_response (it expects full frame).
    let mut framed = len_buf.to_vec();
    framed.extend_from_slice(&body);
    let (resp, _) = tp::decode_response(&framed).expect("decode");
    match resp {
        tp::ProxyAdmissionResponse::Admit { connection_id } => {
            assert_eq!(connection_id, 1);
        }
        other => panic!("expected Admit; got {other:?}"),
    }

    // --- Terminate. -----------------------------------------------------
    let report = service
        .terminate_session("sess-spawn-1", Duration::from_secs(2))
        .await
        .expect("terminate");
    assert_eq!(report.session_id, "sess-spawn-1");
    assert_eq!(report.credential_proxy_shutdown.stopped.len(), 1);
    let pg = &report.credential_proxy_shutdown.stopped[0];
    assert_eq!(pg.proxy_type, "postgres");
    assert_eq!(pg.credential_name, "db-staging");

    // Service no longer tracks the session.
    assert!(!service.is_active("sess-spawn-1").await);
    assert_eq!(service.active_count().await, 0);

    // --- Audit chain: paired SessionVmSpawned / SessionVmExited. ------
    let events = audit.events();
    assert!(
        events.iter().any(|e| matches!(
            e.kind,
            AuditEventKind::SessionVmSpawned { ref session_id, .. }
            if session_id == "sess-spawn-1"
        )),
        "expected SessionVmSpawned for sess-spawn-1; events: {:?}",
        events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
    );
    assert!(
        events.iter().any(|e| matches!(
            e.kind,
            AuditEventKind::SessionVmExited { ref session_id, .. }
            if session_id == "sess-spawn-1"
        )),
        "expected SessionVmExited for sess-spawn-1; events: {:?}",
        events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
    );
    assert!(
        events.iter().any(|e| matches!(
            e.kind,
            AuditEventKind::CredentialProxyStarted { ref credential_name, .. }
            if credential_name == "db-staging"
        )),
        "expected CredentialProxyStarted for db-staging",
    );
    assert!(
        events.iter().any(|e| matches!(
            e.kind,
            AuditEventKind::CredentialProxyStopped { ref credential_name, .. }
            if credential_name == "db-staging"
        )),
        "expected CredentialProxyStopped for db-staging",
    );

    // Termination ordering: VmSpawned < CredentialProxyStarted (proxy
    // bound after VM spawn announcement is wrong; the spawn service
    // emits proxy_started BEFORE VmSpawned by design — verify that).
    let spawned_idx = events
        .iter()
        .position(|e| matches!(e.kind, AuditEventKind::SessionVmSpawned { .. }))
        .unwrap();
    let proxy_started_idx = events
        .iter()
        .position(|e| matches!(e.kind, AuditEventKind::CredentialProxyStarted { .. }))
        .unwrap();
    assert!(
        proxy_started_idx < spawned_idx,
        "CredentialProxyStarted must precede SessionVmSpawned in the audit chain",
    );

    let exited_idx = events
        .iter()
        .position(|e| matches!(e.kind, AuditEventKind::SessionVmExited { .. }))
        .unwrap();
    let proxy_stopped_idx = events
        .iter()
        .position(|e| matches!(e.kind, AuditEventKind::CredentialProxyStopped { .. }))
        .unwrap();
    assert!(
        exited_idx < proxy_stopped_idx,
        "audit-after-state-mutation: SessionVmExited (Step 1 of teardown — VM shutdown) must precede CredentialProxyStopped (Step 4 — proxy drain)",
    );
}

#[tokio::test]
async fn spawn_session_with_no_credentials_still_binds_admission_listener() {
    unsafe { std::env::set_var("RAXIS_TEST_HARNESS", "1") };

    let creds_dir = TempDir::new().unwrap();
    let backend = Arc::new(FileCredentialBackend::open(creds_dir.path()));
    let audit = Arc::new(FakeAuditSink::new());
    let proxy_manager = Arc::new(CredentialProxyManager::new(
        Arc::clone(&backend) as _,
        Arc::clone(&audit) as _,
    ));
    let isolation = Arc::new(SubprocessIsolation::new("session-spawn-no-creds").unwrap());
    let service = SessionSpawnService::new(
        isolation as _,
        Arc::clone(&proxy_manager),
        Arc::clone(&audit) as _,
    );

    let req = SpawnRequest {
        session_id:        "sess-no-creds-1".into(),
        task_id:           None, // canonical Orchestrator session
        initiative_id:     "init-no-creds-1".into(),
        image:             fixture_image(),
        workspace_mounts:  vec![],
        vm_spec:           fixture_spec(),
        credentials:       vec![], // empty
        admission_service: Box::new(PolicyAdmissionService::new(EgressAllowlist::default())),
    };

    let handle = service.spawn_session(req).await.expect("spawn");
    assert!(handle.loopback_env.is_empty());

    // Admission listener still bound, even with zero credential proxies.
    let _conn = tokio::net::TcpStream::connect(handle.admission_loopback)
        .await
        .expect("admission listener accepts when there are no credential proxies");

    let report = service
        .terminate_session("sess-no-creds-1", Duration::from_secs(2))
        .await
        .expect("terminate");
    assert!(report.credential_proxy_shutdown.stopped.is_empty());
}

#[tokio::test]
async fn double_terminate_returns_session_not_active() {
    unsafe { std::env::set_var("RAXIS_TEST_HARNESS", "1") };

    let creds_dir = TempDir::new().unwrap();
    let backend = Arc::new(FileCredentialBackend::open(creds_dir.path()));
    let audit = Arc::new(FakeAuditSink::new());
    let proxy_manager = Arc::new(CredentialProxyManager::new(
        Arc::clone(&backend) as _,
        Arc::clone(&audit) as _,
    ));
    let isolation = Arc::new(SubprocessIsolation::new("session-spawn-double").unwrap());
    let service = SessionSpawnService::new(
        isolation as _,
        Arc::clone(&proxy_manager),
        Arc::clone(&audit) as _,
    );

    let req = SpawnRequest {
        session_id:        "sess-double-1".into(),
        task_id:           Some("task-double-1".into()),
        initiative_id:     "init-double-1".into(),
        image:             fixture_image(),
        workspace_mounts:  vec![],
        vm_spec:           fixture_spec(),
        credentials:       vec![],
        admission_service: Box::new(PolicyAdmissionService::new(EgressAllowlist::default())),
    };

    let _handle = service.spawn_session(req).await.expect("spawn");
    let _ = service
        .terminate_session("sess-double-1", Duration::from_secs(2))
        .await
        .expect("first terminate");
    let err = service
        .terminate_session("sess-double-1", Duration::from_secs(2))
        .await
        .expect_err("second terminate must error");
    match err {
        raxis_session_spawn::SpawnError::SessionNotActive { session_id } => {
            assert_eq!(session_id, "sess-double-1");
        }
        other => panic!("expected SessionNotActive; got {other:?}"),
    }
}
