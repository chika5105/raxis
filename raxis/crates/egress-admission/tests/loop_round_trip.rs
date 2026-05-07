//! Integration test: drive `run_admission_loop` against a real
//! `tokio::net::UnixStream` pair (one half is the kernel's reader/
//! writer, the other half plays the in-VM `raxis-tproxy`). This
//! exercises the bincode framing + the audit emission against
//! real bytes, real I/O, no mocks.

use std::sync::Arc;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_egress_admission::{
    run_admission_loop, AdmissionDecision, AdmissionService, AdmissionVerdict, EgressAllowlist,
    PolicyAdmissionService,
};
use raxis_test_support::FakeAuditSink;
use raxis_tproxy_protocol::{
    decode_response, encode_request, AdmissionProtocol, DenyReason, ProxyAdmissionRequest,
    ProxyAdmissionResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_loop_admits_a_real_anthropic_api_request_over_real_unix_socket() {
    let (kernel_side, mut proxy_side) = tokio::net::UnixStream::pair().expect("UnixStream::pair");
    let (kernel_reader, kernel_writer) = kernel_side.into_split();

    let allowlist = EgressAllowlist {
        patterns: vec!["*.anthropic.com".into()],
        ..Default::default()
    };
    let service = Arc::new(PolicyAdmissionService::new(allowlist));
    let audit: Arc<FakeAuditSink> = Arc::new(FakeAuditSink::new());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let session_id = "sess-real-1".to_owned();
    let session_for_loop = session_id.clone();

    let loop_handle = tokio::spawn(async move {
        run_admission_loop(
            kernel_reader,
            kernel_writer,
            service,
            audit_dyn,
            session_for_loop,
        )
        .await
    });

    let req = ProxyAdmissionRequest {
        connection_id:     7,
        original_dst_ip:   "1.2.3.4".into(),
        original_dst_port: 443,
        host_or_sni:       Some("api.anthropic.com".into()),
        protocol:          AdmissionProtocol::Https,
    };
    let req_bytes = encode_request(&req).expect("encode request");
    proxy_side.write_all(&req_bytes).await.expect("write request");

    let mut len_buf = [0u8; 4];
    proxy_side.read_exact(&mut len_buf).await.expect("read response prefix");
    let body_len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    proxy_side.read_exact(&mut body).await.expect("read response body");
    let mut full = Vec::with_capacity(4 + body.len());
    full.extend_from_slice(&len_buf);
    full.extend_from_slice(&body);
    let (resp, _consumed) = decode_response(&full).expect("decode response");
    match resp {
        ProxyAdmissionResponse::Admit { connection_id } => assert_eq!(connection_id, 7),
        other => panic!("expected Admit, got {other:?}"),
    }

    drop(proxy_side);
    let result = loop_handle.await.expect("loop joined");
    result.expect("loop returned cleanly on EOF");

    let events = audit.events();
    assert_eq!(events.len(), 1, "expected 1 audit event, got {events:?}");
    match &events[0].kind {
        AuditEventKind::TransparentProxyAdmitted {
            session_id: sid,
            host_or_sni,
            original_dst_port,
            protocol,
            ..
        } => {
            assert_eq!(sid, &session_id);
            assert_eq!(host_or_sni.as_deref(), Some("api.anthropic.com"));
            assert_eq!(*original_dst_port, 443);
            assert_eq!(protocol, "https");
        }
        other => panic!("expected TransparentProxyAdmitted, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_loop_denies_disallowed_host_and_emits_transparent_proxy_denied() {
    let (kernel_side, mut proxy_side) = tokio::net::UnixStream::pair().expect("pair");
    let (kr, kw) = kernel_side.into_split();

    let service = Arc::new(PolicyAdmissionService::new(EgressAllowlist {
        patterns: vec!["*.allowed.example".into()],
        ..Default::default()
    }));
    let audit: Arc<FakeAuditSink> = Arc::new(FakeAuditSink::new());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let session_id = "sess-deny-1".to_owned();
    let session_for_loop = session_id.clone();

    let loop_handle = tokio::spawn(async move {
        run_admission_loop(kr, kw, service, audit_dyn, session_for_loop).await
    });

    let req = ProxyAdmissionRequest {
        connection_id:     1,
        original_dst_ip:   "9.9.9.9".into(),
        original_dst_port: 443,
        host_or_sni:       Some("evil.example.com".into()),
        protocol:          AdmissionProtocol::Https,
    };
    proxy_side.write_all(&encode_request(&req).unwrap()).await.unwrap();

    let mut len_buf = [0u8; 4];
    proxy_side.read_exact(&mut len_buf).await.unwrap();
    let body_len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    proxy_side.read_exact(&mut body).await.unwrap();
    let mut full = Vec::with_capacity(4 + body.len());
    full.extend_from_slice(&len_buf);
    full.extend_from_slice(&body);
    let (resp, _consumed) = decode_response(&full).unwrap();
    match resp {
        ProxyAdmissionResponse::Deny { connection_id, reason } => {
            assert_eq!(connection_id, 1);
            assert_eq!(reason, DenyReason::HostNotInAllowlist);
        }
        other => panic!("expected Deny, got {other:?}"),
    }

    drop(proxy_side);
    let _ = loop_handle.await.expect("join").expect("loop result");

    let events = audit.events();
    let denial = events
        .iter()
        .find_map(|e| match &e.kind {
            AuditEventKind::TransparentProxyDenied {
                session_id, host_or_sni, reason, protocol, ..
            } => Some((session_id.clone(), host_or_sni.clone(), reason.clone(), protocol.clone())),
            _ => None,
        })
        .expect("TransparentProxyDenied must be emitted");
    assert_eq!(denial.0, session_id);
    assert_eq!(denial.1.as_deref(), Some("evil.example.com"));
    assert_eq!(denial.2, "host_not_in_allowlist");
    assert_eq!(denial.3, "https");
}

/// A scripted-decision service for negative-path coverage: the test
/// queues a sequence of decisions; the service hands them out in
/// FIFO order.
struct ScriptedAdmissionService {
    decisions: std::sync::Mutex<std::collections::VecDeque<AdmissionDecision>>,
}

impl AdmissionService for ScriptedAdmissionService {
    fn admit(
        &self,
        _session_id: &str,
        _request: &ProxyAdmissionRequest,
    ) -> AdmissionDecision {
        self.decisions
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted decisions exhausted")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_loop_pipelines_three_decisions_in_order() {
    let (kernel_side, mut proxy_side) = tokio::net::UnixStream::pair().unwrap();
    let (kr, kw) = kernel_side.into_split();

    let mut decisions = std::collections::VecDeque::new();
    decisions.push_back(AdmissionDecision { connection_id: 1, verdict: AdmissionVerdict::Admit });
    decisions.push_back(AdmissionDecision {
        connection_id: 2,
        verdict: AdmissionVerdict::Deny(DenyReason::ProxyTargetBypass),
    });
    decisions.push_back(AdmissionDecision { connection_id: 3, verdict: AdmissionVerdict::Admit });
    let service = Arc::new(ScriptedAdmissionService {
        decisions: std::sync::Mutex::new(decisions),
    });
    let audit: Arc<FakeAuditSink> = Arc::new(FakeAuditSink::new());
    let audit_dyn: Arc<dyn AuditSink> = audit.clone();
    let session_id = "sess-pipeline-1".to_owned();
    let session_for_loop = session_id.clone();

    let loop_handle = tokio::spawn(async move {
        run_admission_loop(kr, kw, service, audit_dyn, session_for_loop).await
    });

    for cid in 1u64..=3 {
        let req = ProxyAdmissionRequest {
            connection_id:     cid,
            original_dst_ip:   "10.0.0.1".into(),
            original_dst_port: 443,
            host_or_sni:       Some(format!("h{cid}.example.com")),
            protocol:          AdmissionProtocol::Https,
        };
        proxy_side.write_all(&encode_request(&req).unwrap()).await.unwrap();
    }
    proxy_side.flush().await.unwrap();

    let mut got = Vec::new();
    for _ in 0..3 {
        let mut len_buf = [0u8; 4];
        proxy_side.read_exact(&mut len_buf).await.unwrap();
        let body_len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; body_len];
        proxy_side.read_exact(&mut body).await.unwrap();
        let mut full = Vec::with_capacity(4 + body.len());
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&body);
        let (resp, _) = decode_response(&full).unwrap();
        got.push(resp);
    }
    drop(proxy_side);
    let _ = loop_handle.await.unwrap().unwrap();

    match &got[0] {
        ProxyAdmissionResponse::Admit { connection_id } => assert_eq!(*connection_id, 1),
        other => panic!("first response should be Admit(1), got {other:?}"),
    }
    match &got[1] {
        ProxyAdmissionResponse::Deny { connection_id, reason } => {
            assert_eq!(*connection_id, 2);
            assert_eq!(*reason, DenyReason::ProxyTargetBypass);
        }
        other => panic!("second response should be Deny(2), got {other:?}"),
    }
    match &got[2] {
        ProxyAdmissionResponse::Admit { connection_id } => assert_eq!(*connection_id, 3),
        other => panic!("third response should be Admit(3), got {other:?}"),
    }

    assert_eq!(audit.events().len(), 3);
}
