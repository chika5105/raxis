//! Integration test for `FileCredentialBackend` — real I/O against a
//! `tempfile::TempDir`. Drives every conformance contract from
//! `extensibility-traits.md §4.5` plus the file-specific atomicity
//! and mode/uid checks.
//!
//! These tests do NOT touch the kernel — they only exercise the
//! backend in isolation. The kernel's full-boot integration test
//! (`kernel/tests/...`) re-exercises the same code via the real
//! `KernelInstance` harness.

use std::path::PathBuf;
use std::sync::Arc;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_credentials::{
    AuditingBackend, ConsumerIdentity, CredentialBackend, CredentialError, CredentialName,
    CredentialValue, Lease, OperatorId,
};
use raxis_credentials_file::FileCredentialBackend;
use raxis_test_support::FakeAuditSink;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn build_data_dir() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(tmp.path().join("credentials")).unwrap();
    std::fs::create_dir_all(tmp.path().join("providers")).unwrap();
    tmp
}

fn write_cred_0600(data_dir: &std::path::Path, rel: &str, body: &[u8]) -> PathBuf {
    let p = data_dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&p, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&p, perms).unwrap();
    }
    p
}

fn build_audited(data_dir: &std::path::Path) -> (Arc<dyn CredentialBackend>, Arc<FakeAuditSink>) {
    // Tests use `open_without_uid_check` because under some CI
    // sandboxes the test runner's UID does not match the file
    // ownership the test harness writes. The mode check still
    // runs; the uid path is exercised in its own dedicated test.
    let inner: Arc<dyn CredentialBackend> =
        Arc::new(FileCredentialBackend::open_without_uid_check(data_dir));
    let sink = Arc::new(FakeAuditSink::new());
    let dyn_sink: Arc<dyn AuditSink> = sink.clone();
    let with_audit: Arc<dyn CredentialBackend> = Arc::new(AuditingBackend::new(inner, dyn_sink));
    (with_audit, sink)
}

// ---------------------------------------------------------------------------
// Conformance §4.5 rules — re-asserted against the file backend
// ---------------------------------------------------------------------------

#[test]
fn file_backend_resolves_credentials_dot_env_to_byte_exact_value() {
    let dd = build_data_dir();
    write_cred_0600(dd.path(), "credentials/postgres-staging.env", b"hunter2");
    let (backend, audit) = build_audited(dd.path());

    let v = backend
        .resolve(
            &CredentialName::from("postgres-staging"),
            ConsumerIdentity::new("credential_proxy", "sess-1:postgres:5432"),
        )
        .expect("resolve");
    assert_eq!(v.with_bytes(<[u8]>::to_vec), b"hunter2");

    let kinds = audit.event_kinds();
    assert_eq!(
        kinds.iter().filter(|k| **k == "CredentialAccessed").count(),
        1,
        "exactly one CredentialAccessed expected, got {kinds:?}",
    );
}

#[test]
fn file_backend_resolves_provider_dot_toml_under_providers_subtree() {
    let dd = build_data_dir();
    write_cred_0600(
        dd.path(),
        "providers/anthropic-prod.toml",
        b"api_key = \"sk-ant-test\"\nauth_header = \"x-api-key\"\nauth_prefix = \"\"\n",
    );
    let (backend, _audit) = build_audited(dd.path());

    let v = backend
        .resolve(
            &CredentialName::from("providers.anthropic-prod"),
            ConsumerIdentity::new("gateway", "anthropic-prod"),
        )
        .expect("resolve provider");
    assert!(v.as_utf8().unwrap().contains("api_key"));
}

#[test]
fn file_backend_returns_not_found_for_unknown_name() {
    let dd = build_data_dir();
    let (backend, _audit) = build_audited(dd.path());
    let err = backend
        .resolve(
            &CredentialName::from("never-existed"),
            ConsumerIdentity::new("gateway", "x"),
        )
        .unwrap_err();
    assert!(matches!(err, CredentialError::NotFound(_)));
}

#[test]
fn file_backend_rotate_then_resolve_round_trips() {
    let dd = build_data_dir();
    write_cred_0600(dd.path(), "credentials/k.env", b"v0");
    let (backend, _audit) = build_audited(dd.path());

    backend
        .rotate(
            &CredentialName::from("k"),
            CredentialValue::from_bytes(b"v1".to_vec()),
            OperatorId("fp-rotator".to_owned()),
        )
        .expect("rotate v1");
    let v = backend
        .resolve(
            &CredentialName::from("k"),
            ConsumerIdentity::new("operator_cli", "fp-rotator"),
        )
        .unwrap();
    assert_eq!(v.with_bytes(<[u8]>::to_vec), b"v1");
}

#[test]
fn file_backend_rotate_creates_file_with_mode_0600() {
    let dd = build_data_dir();
    let (backend, _audit) = build_audited(dd.path());
    backend
        .rotate(
            &CredentialName::from("freshly-rotated"),
            CredentialValue::from_bytes(b"new-secret".to_vec()),
            OperatorId("fp-rotator".to_owned()),
        )
        .unwrap();

    let p = dd.path().join("credentials/freshly-rotated.env");
    assert!(p.exists(), "rotate should have created {p:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rotate must create files with mode 0600");
    }
    let body = std::fs::read(&p).unwrap();
    assert_eq!(body, b"new-secret");
}

#[test]
fn file_backend_rotate_replaces_existing_value_atomically_no_torn_reads() {
    let dd = build_data_dir();
    let dd_path = dd.path().to_owned();
    write_cred_0600(&dd_path, "credentials/k.env", b"OLD");

    let (backend, _audit) = build_audited(&dd_path);

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..8 {
        let backend = backend.clone();
        let stop = stop.clone();
        readers.push(std::thread::spawn(move || {
            let mut iters = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Acquire) {
                let v = backend
                    .resolve(
                        &CredentialName::from("k"),
                        ConsumerIdentity::new("credential_proxy", "stress"),
                    )
                    .expect("resolve");
                let bytes = v.with_bytes(<[u8]>::to_vec);
                assert!(
                    bytes == b"OLD" || bytes == b"NEW" || bytes == b"NEWER",
                    "torn read observed in file backend: {bytes:?}",
                );
                iters += 1;
            }
            iters
        }));
    }

    let backend_for_rot = backend.clone();
    let rotator = std::thread::spawn(move || {
        let states = [b"OLD".to_vec(), b"NEW".to_vec(), b"NEWER".to_vec()];
        let start = std::time::Instant::now();
        let mut idx = 0usize;
        while start.elapsed() < std::time::Duration::from_millis(250) {
            backend_for_rot
                .rotate(
                    &CredentialName::from("k"),
                    CredentialValue::from_bytes(states[idx].clone()),
                    OperatorId("fp-rot".to_owned()),
                )
                .expect("rotate under contention");
            idx = (idx + 1) % states.len();
        }
    });

    rotator.join().unwrap();
    stop.store(true, std::sync::atomic::Ordering::Release);

    let mut total_reads = 0u64;
    for r in readers {
        total_reads += r.join().unwrap();
    }
    assert!(
        total_reads > 100,
        "expected > 100 reads under contention, got {total_reads}",
    );
}

// ---------------------------------------------------------------------------
// File-specific: mode validation
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn file_backend_rejects_mode_0644_credentials_with_malformed_error() {
    use std::os::unix::fs::PermissionsExt;
    let dd = build_data_dir();
    let p = write_cred_0600(dd.path(), "credentials/leaked.env", b"x");
    // Force the wrong mode after the helper set 0600.
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&p, perms).unwrap();

    let (backend, _audit) = build_audited(dd.path());
    let err = backend
        .resolve(
            &CredentialName::from("leaked"),
            ConsumerIdentity::new("credential_proxy", "x"),
        )
        .unwrap_err();
    match err {
        CredentialError::Malformed { reason, .. } => {
            assert!(reason.contains("mode"), "{reason}");
        }
        other => panic!("expected Malformed for wrong mode, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// File-specific: traversal-name rejection (defence in depth)
// ---------------------------------------------------------------------------

#[test]
fn file_backend_rejects_credential_name_with_path_separator() {
    let dd = build_data_dir();
    let (backend, _audit) = build_audited(dd.path());
    let err = backend
        .resolve(
            &CredentialName::from("a/b"),
            ConsumerIdentity::new("operator_cli", "fp-x"),
        )
        .unwrap_err();
    assert!(matches!(err, CredentialError::Malformed { .. }));
}

#[test]
fn file_backend_rejects_credential_name_with_dot_dot_traversal() {
    let dd = build_data_dir();
    let (backend, _audit) = build_audited(dd.path());
    let err = backend
        .resolve(
            &CredentialName::from("..secrets"),
            ConsumerIdentity::new("operator_cli", "fp-x"),
        )
        .unwrap_err();
    assert!(matches!(err, CredentialError::Malformed { .. }));
}

// ---------------------------------------------------------------------------
// File-specific: exists() agrees with resolve() outcomes
// ---------------------------------------------------------------------------

#[test]
fn file_backend_exists_returns_true_for_well_formed_files() {
    let dd = build_data_dir();
    write_cred_0600(dd.path(), "credentials/here.env", b"value");
    let (backend, _audit) = build_audited(dd.path());
    assert!(backend.exists(&CredentialName::from("here")));
    assert!(!backend.exists(&CredentialName::from("nope")));
}

#[cfg(unix)]
#[test]
fn file_backend_exists_returns_false_for_wrong_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dd = build_data_dir();
    let p = write_cred_0600(dd.path(), "credentials/exposed.env", b"x");
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o600 | 0o004); // world-readable, otherwise 0600
    std::fs::set_permissions(&p, perms).unwrap();
    let (backend, _audit) = build_audited(dd.path());
    assert!(!backend.exists(&CredentialName::from("exposed")));
}

// ---------------------------------------------------------------------------
// File-specific: lease is always Forever
// ---------------------------------------------------------------------------

#[test]
fn file_backend_lease_is_forever_for_any_name() {
    let dd = build_data_dir();
    let backend = FileCredentialBackend::open_without_uid_check(dd.path());
    assert_eq!(
        backend.lease(&CredentialName::from("anything")),
        Lease::Forever,
    );
    assert_eq!(backend.backend_kind(), "file");
}

// ---------------------------------------------------------------------------
// Audit-event payload shape
// ---------------------------------------------------------------------------

#[test]
fn audit_event_payload_records_consumer_kind_and_id_and_backend_kind() {
    let dd = build_data_dir();
    write_cred_0600(dd.path(), "credentials/p.env", b"v");
    let (backend, sink) = build_audited(dd.path());
    let _ = backend
        .resolve(
            &CredentialName::from("p"),
            ConsumerIdentity::new("credential_proxy", "sess-X:postgres:5432"),
        )
        .unwrap();
    let events = sink.events();
    let access = events
        .iter()
        .find_map(|e| match &e.kind {
            AuditEventKind::CredentialAccessed {
                name,
                consumer_kind,
                consumer_id,
                backend_kind,
                success,
            } => Some((
                name.clone(),
                consumer_kind.clone(),
                consumer_id.clone(),
                backend_kind.clone(),
                *success,
            )),
            _ => None,
        })
        .expect("CredentialAccessed");
    assert_eq!(access.0, "p");
    assert_eq!(access.1, "credential_proxy");
    assert_eq!(access.2, "sess-X:postgres:5432");
    assert_eq!(access.3, "file");
    assert!(access.4);
}
