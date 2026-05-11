//! `session-spawn` slice — exercise the kernel-side
//! `SessionSpawnService` against real substrates.
//!
//! What this slice proves end-to-end against real bytes on the wire:
//!
//!   1. The composer binds one real per-session credential-proxy
//!      listener (PostgresProxy) on loopback, derived from a real
//!      `.env` credential file resolved through the real
//!      `FileCredentialBackend`.
//!   2. The composer binds one real per-session egress-admission
//!      `tokio::net::TcpListener`, and the `PolicyAdmissionService`
//!      threaded into it answers a real bincode-framed
//!      `ProxyAdmissionRequest` with the correct verdict (Admit
//!      for an allow-listed SNI, Deny for a non-allow-listed SNI).
//!   3. The real `SubprocessIsolation` substrate boots a real child
//!      process (`/bin/cat` as the "guest") with the credential-
//!      proxy loopback URL stamped into its environment via the
//!      composer's `VmSpec.env` plumbing.
//!   4. Termination drives the substrate's `Session::shutdown` →
//!      audit `SessionVmExited` → admission-loop abort → proxies
//!      drain → audit `CredentialProxyStopped` per proxy. The
//!      audit chain landed in the `FakeAuditSink` matches the
//!      spec's fixed ordering.
//!
//! The substrate is `SubprocessIsolation` (the V2 test substrate)
//! because spawning a real Firecracker / Apple-VZ microVM out of a
//! bare `cargo run -p raxis-live-e2e` is infeasible (root, host
//! KVM, canonical image bytes). The substrate satisfies the same
//! `Backend` / `Session` trait with byte-exact identical framing as
//! production substrates per `extensibility-traits.md §3.5`. Every
//! other dependency the slice touches — credential backend,
//! credential-proxy manager, egress-admission service, audit chain,
//! tproxy-protocol bincode frames — is the production crate
//! verbatim.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
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
use raxis_test_support::SubprocessIsolation;
use raxis_tproxy_protocol as tp;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn run() -> Result<()> {
    tracing::info!("slice session-spawn: starting");

    // SAFETY: required by `SubprocessIsolation::new` (test-substrate
    // gate). Same env var every other live-e2e and integration test
    // sets; co-running slices serialise on the substrate's own
    // internal mutex.
    unsafe { std::env::set_var("RAXIS_TEST_HARNESS", "1") };

    // ── Real credential backend with a real .env file. ────────────
    let creds_dir = TempDir::new().context("creds tempdir")?;
    write_cred(creds_dir.path(), "db-live", b"postgresql://raxis@127.0.0.1:5432/test")?;
    let backend = Arc::new(
        FileCredentialBackend::open_without_uid_check(creds_dir.path()),
    );

    // ── Real audit sink. ──────────────────────────────────────────
    let audit = Arc::new(FakeAuditSink::new());

    // ── Real credential-proxy manager + isolation substrate. ─────
    let proxy_manager = Arc::new(CredentialProxyManager::new(
        Arc::clone(&backend) as _,
        Arc::clone(&audit) as _,
    ));
    let isolation = Arc::new(
        SubprocessIsolation::new("live-e2e-session-spawn")
            .map_err(|e| anyhow!("SubprocessIsolation::new: {e:?}"))?,
    );

    // ── Service under test. ──────────────────────────────────────
    let service = SessionSpawnService::new(
        isolation as _,
        Arc::clone(&proxy_manager),
        Arc::clone(&audit) as _,
    );

    let credentials = vec![TaskCredentialDecl {
        name:     CredentialName::new("db-live".to_owned()),
        mount_as: "DATABASE_URL".to_owned(),
        proxy:    ProxyDecl::Postgres {
            restrictions: PostgresRestrictions {
                allow_only_select: true,
                ..Default::default()
            },
        },
    }];

    let allowlist = EgressAllowlist {
        exact_hosts: vec!["api.anthropic.com".into()],
        ..Default::default()
    };

    let req = SpawnRequest {
        session_id:        "live-spawn-1".into(),
        task_id:           Some("live-task-1".into()),
        initiative_id:     "live-init-1".into(),
        image: VerifiedImage {
            kind:      ImageKind::RootfsErofs,
            body:      ImageBody::Path(std::path::PathBuf::from("/dev/null")),
            signature: ImageSignature(b"unsigned-test-image".to_vec()),
            image_id:  "raxis-live-e2e-substrate-image".into(),
        },
        workspace_mounts:  Vec::new(),
        vm_spec: VmSpec {
            vcpu_count:        1,
            mem_mib:           64,
            egress_tier:       EgressTier::Tier2CredProxy,
            cgroup_quota:      None,
            boot_args:         Vec::new(),
            entrypoint_argv:   Vec::new(),
            session_token:     SessionToken("live-session-token".into()),
            vsock_cid:         Some(0xC1D_E2E),
            virtio_fs_mounts:  Vec::new(),
            // SubprocessIsolation ignores the kernel path. The
            // platform-default microVM substrates (AVF / Firecracker)
            // live in the docker-gated full-lifecycle test, not in
            // this slice.
            linux_kernel_path: std::path::PathBuf::new(),
            env:               BTreeMap::new(),
        },
        credentials,
        admission_service: Box::new(PolicyAdmissionService::new(allowlist)),
    };

    // ── Drive spawn. ──────────────────────────────────────────────
    let handle = service
        .spawn_session(req)
        .await
        .map_err(|e| anyhow!("spawn: {e:?}"))?;
    tracing::info!(
        session_id = %handle.session_id,
        admission  = %handle.admission_loopback,
        "spawn succeeded",
    );

    let pg_url = handle
        .loopback_env
        .get("DATABASE_URL")
        .ok_or_else(|| anyhow!("DATABASE_URL was not stamped into loopback env"))?;
    if !pg_url.starts_with("postgresql://raxis@127.0.0.1:") {
        return Err(anyhow!(
            "expected postgres loopback URL; got `{pg_url}`",
        ));
    }
    tracing::info!(database_url = %pg_url, "credential-proxy URL bound");

    // ── Drive a real admission round-trip — Admit. ───────────────
    drive_admission(
        handle.admission_loopback,
        tp::ProxyAdmissionRequest {
            connection_id:     1,
            original_dst_ip:   "203.0.113.10".into(),
            original_dst_port: 443,
            host_or_sni:       Some("api.anthropic.com".into()),
            protocol:          tp::AdmissionProtocol::Https,
        },
        ExpectedVerdict::Admit,
    )
    .await
    .context("admission Admit round-trip")?;

    // ── Drive a real admission round-trip — Deny. ────────────────
    drive_admission(
        handle.admission_loopback,
        tp::ProxyAdmissionRequest {
            connection_id:     2,
            original_dst_ip:   "198.51.100.20".into(),
            original_dst_port: 443,
            host_or_sni:       Some("evil.example.com".into()),
            protocol:          tp::AdmissionProtocol::Https,
        },
        ExpectedVerdict::Deny,
    )
    .await
    .context("admission Deny round-trip")?;

    // ── Tear down. ───────────────────────────────────────────────
    let report = service
        .terminate_session("live-spawn-1", Duration::from_secs(2))
        .await
        .map_err(|e| anyhow!("terminate: {e:?}"))?;
    if report.credential_proxy_shutdown.stopped.len() != 1 {
        return Err(anyhow!(
            "expected exactly 1 stopped proxy; got {}",
            report.credential_proxy_shutdown.stopped.len(),
        ));
    }
    tracing::info!(
        session_id = %report.session_id,
        ?report.exit_status,
        proxies_stopped = report.credential_proxy_shutdown.stopped.len(),
        "terminate succeeded",
    );

    // ── Audit chain ordering check. ──────────────────────────────
    let events = audit.events();
    let kinds: Vec<&'static str> = events.iter().map(|e| e.kind.as_str()).collect();

    let proxy_started_idx = kinds.iter().position(|k| *k == "CredentialProxyStarted")
        .ok_or_else(|| anyhow!("missing CredentialProxyStarted in audit chain"))?;
    let spawned_idx = kinds.iter().position(|k| *k == "SessionVmSpawned")
        .ok_or_else(|| anyhow!("missing SessionVmSpawned in audit chain"))?;
    let exited_idx = kinds.iter().position(|k| *k == "SessionVmExited")
        .ok_or_else(|| anyhow!("missing SessionVmExited in audit chain"))?;
    let proxy_stopped_idx = kinds.iter().position(|k| *k == "CredentialProxyStopped")
        .ok_or_else(|| anyhow!("missing CredentialProxyStopped in audit chain"))?;

    if proxy_started_idx >= spawned_idx {
        return Err(anyhow!(
            "audit-after-state-mutation violated: \
             CredentialProxyStarted (idx={proxy_started_idx}) \
             must precede SessionVmSpawned (idx={spawned_idx}); \
             chain: {kinds:?}",
        ));
    }
    if exited_idx >= proxy_stopped_idx {
        return Err(anyhow!(
            "audit-after-state-mutation violated: \
             SessionVmExited (idx={exited_idx}) must precede \
             CredentialProxyStopped (idx={proxy_stopped_idx}); \
             chain: {kinds:?}",
        ));
    }

    // ── Cardinality: exactly one VmSpawned and exactly one VmExited
    //    paired by session_id. ──────────────────────────────────
    let spawned_session = events.iter().find_map(|e| match &e.kind {
        AuditEventKind::SessionVmSpawned { session_id, .. } => Some(session_id.clone()),
        _ => None,
    });
    let exited_session = events.iter().find_map(|e| match &e.kind {
        AuditEventKind::SessionVmExited { session_id, .. } => Some(session_id.clone()),
        _ => None,
    });
    if spawned_session.as_deref() != Some("live-spawn-1") {
        return Err(anyhow!(
            "SessionVmSpawned session_id mismatch: got {spawned_session:?}",
        ));
    }
    if exited_session.as_deref() != Some("live-spawn-1") {
        return Err(anyhow!(
            "SessionVmExited session_id mismatch: got {exited_session:?}",
        ));
    }

    tracing::info!(
        chain_len = kinds.len(),
        chain     = ?kinds,
        "session-spawn slice OK — full audit chain in expected order",
    );
    Ok(())
}

#[derive(Debug)]
enum ExpectedVerdict {
    Admit,
    Deny,
}

async fn drive_admission(
    addr:     std::net::SocketAddr,
    req:      tp::ProxyAdmissionRequest,
    expected: ExpectedVerdict,
) -> Result<()> {
    let mut sock = tokio::net::TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect to admission listener at {addr}"))?;
    let frame = tp::encode_request(&req).map_err(|e| anyhow!("encode: {e:?}"))?;
    sock.write_all(&frame).await.context("write request")?;

    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await.context("read len")?;
    let body_len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    sock.read_exact(&mut body).await.context("read body")?;
    let mut framed = len_buf.to_vec();
    framed.extend_from_slice(&body);
    let (resp, _) = tp::decode_response(&framed).map_err(|e| anyhow!("decode: {e:?}"))?;

    match (resp, expected) {
        (tp::ProxyAdmissionResponse::Admit { connection_id }, ExpectedVerdict::Admit) => {
            if connection_id != req.connection_id {
                return Err(anyhow!(
                    "admission connection_id mismatch: req={} resp={}",
                    req.connection_id,
                    connection_id,
                ));
            }
            Ok(())
        }
        (tp::ProxyAdmissionResponse::Deny { connection_id, .. }, ExpectedVerdict::Deny) => {
            if connection_id != req.connection_id {
                return Err(anyhow!(
                    "admission connection_id mismatch: req={} resp={}",
                    req.connection_id,
                    connection_id,
                ));
            }
            Ok(())
        }
        (resp, expected) => Err(anyhow!(
            "admission verdict mismatch: expected {expected:?}, got {resp:?}",
        )),
    }
}

fn write_cred(dir: &std::path::Path, name: &str, body: &[u8]) -> Result<()> {
    let path = dir.join(format!("{name}.env"));
    std::fs::write(&path, body).context("write cred file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .context("chmod cred file 0600")?;
    }
    Ok(())
}
