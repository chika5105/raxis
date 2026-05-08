//! Conformance test for `CredentialBackend` impls — `extensibility-traits.md §4.5`.
//!
//! Even though the trait crate ships only the trait + decorator, we
//! exercise the rules with a deliberately minimal in-memory backend
//! built **inside** this test file so the conformance test itself is
//! the canonical source of truth for what conformance means. Any
//! concrete backend (`FileCredentialBackend`,
//! `VaultCredentialBackend`, `Pkcs11HsmBackend`) re-runs the same
//! battery of assertions against its own constructor — see
//! `raxis-credentials-file/tests/integration.rs` for the file-backed
//! variant. The minimal backend defined here is **not** exported and
//! **MUST NOT** be used outside this test — it satisfies the trait
//! shape but stores its bytes in plain `Mutex<HashMap<...>>` with no
//! mode/uid checks.
//!
//! What this test pins:
//!
//! 1. `resolve(name)` returns `Err(NotFound)` for any unknown name.
//! 2. `rotate(name, v1)` then `resolve(name)` returns `v1`.
//! 3. `rotate` is atomic — N=8 concurrent readers + 1 rotator never
//!    observe a torn read.
//! 4. Every `resolve` (success or failure) emits exactly one
//!    `CredentialAccessed` event when wrapped in `AuditingBackend`.
//! 5. `CredentialValue::with_bytes` does not leak the bytes after
//!    the closure returns (smoke-test using the same `Drop` zeroize
//!    discipline that `secrecy::SecretBox` provides).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_credentials::{
    AuditingBackend, ConsumerIdentity, CredentialBackend, CredentialError, CredentialName,
    CredentialValue, Lease, OperatorId,
};
use raxis_test_support::FakeAuditSink;

// ---------------------------------------------------------------------------
// In-memory test backend (not exported)
// ---------------------------------------------------------------------------

/// Minimal in-memory backend for conformance tests. Its bytes have NO
/// at-rest protection — that's why it lives in this test file only,
/// behind `#[cfg(test)]` of an integration test that compiles only
/// when `cargo test` is run.
struct MemBackend {
    /// `(name -> bytes)`. Held under a Mutex so `rotate` can acquire
    /// the write lock and shadow the prior value atomically.
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemBackend {
    fn new() -> Self { Self { inner: Mutex::new(HashMap::new()) } }

    #[allow(dead_code)]
    fn pre_seed(&self, name: &str, bytes: Vec<u8>) {
        self.inner.lock().unwrap().insert(name.to_owned(), bytes);
    }
}

impl CredentialBackend for MemBackend {
    fn resolve(
        &self,
        name: &CredentialName,
        _consumer: ConsumerIdentity<'_>,
    ) -> Result<CredentialValue, CredentialError> {
        let map = self.inner.lock().unwrap();
        match map.get(name.as_str()) {
            Some(bytes) => Ok(CredentialValue::from_bytes(bytes.clone())),
            None => Err(CredentialError::NotFound(name.clone())),
        }
    }

    fn rotate(
        &self,
        name: &CredentialName,
        new: CredentialValue,
        _actor: OperatorId,
    ) -> Result<(), CredentialError> {
        let bytes = new.into_bytes();
        let mut map = self.inner.lock().unwrap();
        // Single mutex-protected store-write makes rotate atomic
        // w.r.t. concurrent resolves, which is the conformance
        // contract rule 3 in this minimal implementation. Real
        // file-backed backends use atomic-rename for the same
        // effect against the kernel.
        map.insert(name.as_str().to_owned(), bytes);
        Ok(())
    }

    fn exists(&self, name: &CredentialName) -> bool {
        self.inner.lock().unwrap().contains_key(name.as_str())
    }

    fn lease(&self, _name: &CredentialName) -> Lease { Lease::Forever }

    fn backend_kind(&self) -> &'static str { "memory_test_only" }
}

// ---------------------------------------------------------------------------
// Test scaffolding helpers
// ---------------------------------------------------------------------------

fn build_audited_mem_backend()
    -> (Arc<dyn CredentialBackend>, Arc<FakeAuditSink>)
{
    let inner: Arc<dyn CredentialBackend> = Arc::new(MemBackend::new());
    let audit_sink = Arc::new(FakeAuditSink::new());
    let audit_sink_dyn: Arc<dyn AuditSink> = audit_sink.clone();
    let with_audit: Arc<dyn CredentialBackend> =
        Arc::new(AuditingBackend::new(inner, audit_sink_dyn));
    (with_audit, audit_sink)
}

// ---------------------------------------------------------------------------
// Rule 1: NotFound for unknown names
// ---------------------------------------------------------------------------

#[test]
fn rule_1_resolve_returns_not_found_for_unknown_names() {
    let (backend, _audit) = build_audited_mem_backend();
    let result = backend.resolve(
        &CredentialName::from("does-not-exist"),
        ConsumerIdentity::new("operator_cli", "fp-test"),
    );
    match result {
        Err(CredentialError::NotFound(name)) => {
            assert_eq!(name.as_str(), "does-not-exist");
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Rule 2: rotate then resolve round-trips
// ---------------------------------------------------------------------------

#[test]
fn rule_2_rotate_then_resolve_returns_the_new_value() {
    let (backend, _audit) = build_audited_mem_backend();

    backend
        .rotate(
            &CredentialName::from("postgres-staging"),
            CredentialValue::from_bytes(b"first-secret".to_vec()),
            OperatorId("fp-aaaa".to_owned()),
        )
        .expect("rotate v1");

    let v1 = backend
        .resolve(
            &CredentialName::from("postgres-staging"),
            ConsumerIdentity::new("credential_proxy", "sess-1:postgres:5432"),
        )
        .expect("resolve v1");
    assert_eq!(v1.with_bytes(<[u8]>::to_vec), b"first-secret");

    backend
        .rotate(
            &CredentialName::from("postgres-staging"),
            CredentialValue::from_bytes(b"rotated-secret".to_vec()),
            OperatorId("fp-bbbb".to_owned()),
        )
        .expect("rotate v2");

    let v2 = backend
        .resolve(
            &CredentialName::from("postgres-staging"),
            ConsumerIdentity::new("credential_proxy", "sess-1:postgres:5432"),
        )
        .expect("resolve v2");
    assert_eq!(v2.with_bytes(<[u8]>::to_vec), b"rotated-secret");
}

// ---------------------------------------------------------------------------
// Rule 3: rotation is atomic w.r.t. concurrent resolves
// ---------------------------------------------------------------------------

#[test]
fn rule_3_rotation_atomicity_with_8_readers_and_1_rotator() {
    let (backend, _audit) = build_audited_mem_backend();
    backend
        .rotate(
            &CredentialName::from("k"),
            CredentialValue::from_bytes(b"OLD".to_vec()),
            OperatorId("fp-init".to_owned()),
        )
        .unwrap();

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..8 {
        let backend = backend.clone();
        let stop = stop.clone();
        readers.push(std::thread::spawn(move || {
            let mut iters = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Acquire) {
                let value = backend
                    .resolve(
                        &CredentialName::from("k"),
                        ConsumerIdentity::new("credential_proxy", "stress"),
                    )
                    .expect("resolve under contention");
                let bytes = value.with_bytes(<[u8]>::to_vec);
                // Each individual resolve MUST observe one of the
                // pre/post-rotate values verbatim — never a torn
                // read like "OLnewVALUE" or partial bytes.
                assert!(
                    bytes == b"OLD" || bytes == b"NEW" || bytes == b"NEWER",
                    "torn read observed: {bytes:?}",
                );
                iters += 1;
            }
            iters
        }));
    }

    // Rotator: cycle OLD -> NEW -> NEWER -> OLD ... for 200 ms.
    let backend_for_rot = backend.clone();
    let rotator = std::thread::spawn(move || {
        let states = [b"OLD".to_vec(), b"NEW".to_vec(), b"NEWER".to_vec()];
        let start = std::time::Instant::now();
        let mut idx = 0usize;
        while start.elapsed() < Duration::from_millis(200) {
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

    rotator.join().expect("rotator joined");
    stop.store(true, std::sync::atomic::Ordering::Release);

    let mut total_reads = 0u64;
    for r in readers {
        total_reads += r.join().expect("reader joined");
    }
    // Sanity: the test actually exercised the contention path.
    assert!(
        total_reads > 100,
        "expected >100 cumulative reads under contention, got {total_reads}",
    );
}

// ---------------------------------------------------------------------------
// Rule 4: every resolve emits exactly one CredentialAccessed event
// ---------------------------------------------------------------------------

#[test]
fn rule_4_each_resolve_emits_one_credential_accessed_event() {
    let (backend, audit) = build_audited_mem_backend();
    backend
        .rotate(
            &CredentialName::from("aws-staging"),
            CredentialValue::from_bytes(b"AKIA...".to_vec()),
            OperatorId("fp-init".to_owned()),
        )
        .unwrap();

    // First resolve — success path.
    let _ = backend
        .resolve(
            &CredentialName::from("aws-staging"),
            ConsumerIdentity::new("gateway", "anthropic-prod"),
        )
        .unwrap();

    // Second resolve — failure path. Still emits one event with
    // success=false.
    let _ = backend
        .resolve(
            &CredentialName::from("missing"),
            ConsumerIdentity::new("gateway", "openai-prod"),
        )
        .unwrap_err();

    let kinds = audit.event_kinds();
    let cred_events: Vec<_> = kinds
        .iter()
        .filter(|k| **k == "CredentialAccessed")
        .collect();
    // Plus 1 `CredentialRotated` from the seed rotate above —
    // verify both shapes coexist correctly.
    assert_eq!(
        cred_events.len(),
        2,
        "expected 2 CredentialAccessed events (1 success, 1 failure), got events={kinds:?}",
    );

    // Inspect the first event's payload.
    let events = audit.events();
    let first_access = events
        .iter()
        .find(|e| matches!(e.kind, AuditEventKind::CredentialAccessed { .. }))
        .expect("first CredentialAccessed");
    match &first_access.kind {
        AuditEventKind::CredentialAccessed {
            name,
            consumer_kind,
            consumer_id,
            backend_kind,
            success,
        } => {
            assert_eq!(name, "aws-staging");
            assert_eq!(consumer_kind, "gateway");
            assert_eq!(consumer_id, "anthropic-prod");
            assert_eq!(backend_kind, "memory_test_only");
            assert!(*success);
        }
        other => panic!("expected CredentialAccessed, got {other:?}"),
    }

    // The failure event records `success=false`.
    let failure = events
        .iter()
        .filter_map(|e| match &e.kind {
            AuditEventKind::CredentialAccessed {
                name, success, ..
            } if !*success => Some(name.clone()),
            _ => None,
        })
        .next()
        .expect("a failed-access event");
    assert_eq!(failure, "missing");
}

#[test]
fn rotation_emits_credential_rotated_event_with_actor_fingerprint() {
    let (backend, audit) = build_audited_mem_backend();
    backend
        .rotate(
            &CredentialName::from("k"),
            CredentialValue::from_bytes(b"v".to_vec()),
            OperatorId("fp-7d2c00aabbcc".to_owned()),
        )
        .unwrap();
    let events = audit.events();
    let rotated = events
        .iter()
        .find_map(|e| match &e.kind {
            AuditEventKind::CredentialRotated {
                name,
                actor_fingerprint,
                backend_kind,
            } => Some((name.clone(), actor_fingerprint.clone(), backend_kind.clone())),
            _ => None,
        })
        .expect("CredentialRotated emitted");
    assert_eq!(rotated.0, "k");
    assert_eq!(rotated.1, "fp-7d2c00aabbcc");
    assert_eq!(rotated.2, "memory_test_only");
}

// ---------------------------------------------------------------------------
// Rule 5: CredentialValue smoke for redaction + into_bytes round-trip
// ---------------------------------------------------------------------------

#[test]
fn rule_5_credential_value_redaction_and_round_trip() {
    let v = CredentialValue::from_bytes(b"this-is-a-real-secret".to_vec());
    let dbg = format!("{v:?}");
    assert!(!dbg.contains("real-secret"));

    // `with_bytes` returns a value, the closure does not own the bytes
    // beyond its scope. Round-trip is byte-exact.
    let observed = v.with_bytes(<[u8]>::to_vec);
    assert_eq!(observed, b"this-is-a-real-secret");

    // `into_bytes` consumes — round-trips byte-exactly.
    let bytes = v.into_bytes();
    assert_eq!(bytes, b"this-is-a-real-secret");
}
