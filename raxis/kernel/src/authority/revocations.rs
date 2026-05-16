// raxis-kernel::authority::revocations — cert-revocation store.
// Normative reference: `specs/v2/key-revocation.md` (full V2 spec)
// and (closeout of what V2.3 actually ships vs.
// what V3 will add).
// V2.3 scope (admission-time gate only):
//   * The store loads `<data_dir>/revocations/<pubkey_hex>.toml` at
//     kernel boot. Each file is one signed `RevocationRecord`.
//   * Every record is structurally validated (correct version tag,
//     hex shape, signature bytes match the canonical input) and the
//     signature is verified against the operator pubkey embedded in
//     the record. Records that fail verification are SKIPPED with a
//     stderr warning so a corrupted record cannot mask a real
//     revocation by also breaking startup.
//   * `lookup(pubkey_hex)` returns the (reason, revoked_at) tuple
//     when the key is revoked. The kernel's `CertEnforcer` calls
//     this from inside `cert_status_with_revocation` to
//     short-circuit cert-status to `Revoked` before computing the
//     four-zone state.
// V3 (deferred):
//   * Confirm that `revoked_by_pubkey_hex` matches a known operator
//     entry in the active policy bundle. V2.3 just verifies the
//     signature is internally consistent (the revocation file was
//     signed by SOME operator key, and the kernel only loads the
//     directory the operator-UID can write to, so the path is gated
//     by the operating-system permission model — but we don't
//     yet cross-check against `policy.toml`).
//   * Live session termination on Compromise revocation
//     (§5.2 step 4 of `key-revocation.md`).
//   * `KernelPush::SessionRevoked` envelope dispatch.
//   * Restart-time reconciliation against `key_trust_state` view.
// Permissions:
//   The directory `<data_dir>/revocations/` is created by the
//   kernel boot path (see `bootstrap.rs`) with mode 0700; revocation
//   files are 0600 — same posture as `<data_dir>/credentials/`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use raxis_crypto::cert::verify_revocation_signature;
use raxis_types::operator_cert::{RevocationReason, RevocationRecord};

/// In-memory snapshot of the revocation directory, populated at
/// kernel boot. Keyed by `subject_pubkey_hex` (lowercase 64-char hex).
/// **Concurrency.** The store is read-only after construction so it
/// requires no internal synchronisation; multiple `enforce` calls
/// can call `lookup` concurrently. A future "live update via
/// `raxis cert revoke` + IPC" path would need to wrap this in
/// `ArcSwap`, but V2.3 ships boot-time-only.
#[derive(Debug, Default, Clone)]
pub struct RevocationStore {
    /// Map of subject_pubkey_hex -> (reason, revoked_at).
    by_pubkey: HashMap<String, (RevocationReason, i64)>,
}

/// Per-record loader outcome surfaced by [`RevocationStore::open`]
/// for forensic diagnostics. The store discards records that fail
/// verification but counts them so kernel boot logs can show the
/// loaded / rejected split. A non-zero `rejected` count indicates
/// a bad revocation file the operator must investigate.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LoadStats {
    pub loaded: usize,
    pub rejected: usize,
}

impl RevocationStore {
    /// Construct an empty store.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load `<data_dir>/revocations/*.toml`. Tolerates a missing
    /// directory (returns an empty store with `LoadStats::default()`
    /// the operator may not have revoked any certs yet).
    /// Records that fail signature verification are SKIPPED with a
    /// stderr warning so a tampered record cannot mask a legitimate
    /// revocation by simply breaking the loader.
    pub fn open(data_dir: &Path) -> (Self, LoadStats) {
        let dir = data_dir.join("revocations");
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return (Self::empty(), LoadStats::default());
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"RevocationStoreOpenFailed\",\
                     \"path\":\"{}\",\"reason\":\"{e}\"}}",
                    dir.display(),
                );
                return (Self::empty(), LoadStats::default());
            }
        };

        let mut store = Self::empty();
        let mut stats = LoadStats::default();
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            match Self::load_record_from(&path) {
                Ok(rec) => {
                    let key = rec.subject_pubkey_hex.clone();
                    store.by_pubkey.insert(key, (rec.reason, rec.revoked_at));
                    stats.loaded += 1;
                }
                Err(e) => {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"RevocationRecordRejected\",\
                         \"path\":\"{}\",\"reason\":\"{e}\"}}",
                        path.display(),
                    );
                    stats.rejected += 1;
                }
            }
        }
        (store, stats)
    }

    /// Lookup a revocation by subject pubkey hex. Returns `None` if
    /// the key is not revoked.
    pub fn lookup(&self, subject_pubkey_hex: &str) -> Option<(RevocationReason, i64)> {
        self.by_pubkey.get(subject_pubkey_hex).copied()
    }

    /// Number of revocation records loaded. Kernel boot logs this
    /// alongside the rejected count for forensic visibility.
    pub fn len(&self) -> usize {
        self.by_pubkey.len()
    }

    /// Whether the store has zero loaded records. Used by tests.
    pub fn is_empty(&self) -> bool {
        self.by_pubkey.is_empty()
    }

    /// Test helper: insert an in-memory record without going
    /// through disk. Behind `#[cfg(test)]` so production code
    /// cannot install records that bypass signature verification.
    #[cfg(test)]
    pub(crate) fn insert_for_tests(
        &mut self,
        subject_pubkey_hex: impl Into<String>,
        reason: RevocationReason,
        revoked_at: i64,
    ) {
        self.by_pubkey
            .insert(subject_pubkey_hex.into(), (reason, revoked_at));
    }

    fn load_record_from(path: &PathBuf) -> Result<RevocationRecord, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
        let text = std::str::from_utf8(&bytes).map_err(|e| format!("utf8: {e}"))?;
        let rec: RevocationRecord = toml::from_str(text).map_err(|e| format!("toml-parse: {e}"))?;
        verify_revocation_signature(&rec).map_err(|e| format!("signature-verify: {e}"))?;
        Ok(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use raxis_crypto::cert::sign_revocation;
    use raxis_types::operator_cert::RevocationRecord;

    fn fixture_signing() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn fixture_pubkey() -> String {
        hex::encode(fixture_signing().verifying_key().to_bytes())
    }

    fn build_record(reason: RevocationReason, when: i64, reference: &str) -> RevocationRecord {
        let pk = fixture_pubkey();
        let sig = sign_revocation(&pk, reason, when, reference, &fixture_signing());
        RevocationRecord {
            subject_pubkey_hex: pk.clone(),
            subject_fingerprint: "00".repeat(16),
            reason,
            revoked_at: when,
            reference: reference.into(),
            revoked_by_pubkey_hex: pk,
            revoked_by_signature_hex: sig,
            signing_input_version: "raxis-cert-revocation/v1".into(),
        }
    }

    #[test]
    fn open_on_missing_directory_returns_empty_store() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, stats) = RevocationStore::open(tmp.path());
        assert!(store.is_empty());
        assert_eq!(
            stats,
            LoadStats {
                loaded: 0,
                rejected: 0
            }
        );
    }

    #[test]
    fn open_loads_well_formed_records_and_rejects_tampered_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let revs = tmp.path().join("revocations");
        std::fs::create_dir_all(&revs).unwrap();

        // Well-formed record.
        let good = build_record(RevocationReason::Compromise, 1_700_000_000, "INC-1");
        std::fs::write(
            revs.join(format!("{}.toml", good.subject_pubkey_hex)),
            toml::to_string(&good).unwrap(),
        )
        .unwrap();

        // Tampered record: change `reason` after signing so the
        // canonical bytes no longer match the embedded signature.
        let mut bad = build_record(RevocationReason::Rotation, 1_700_000_001, "INC-2");
        bad.reason = RevocationReason::Compromise;
        // Different filename so it doesn't collide with `good`.
        std::fs::write(revs.join("bad.toml"), toml::to_string(&bad).unwrap()).unwrap();

        let (store, stats) = RevocationStore::open(tmp.path());
        assert_eq!(stats.loaded, 1, "exactly one well-formed record");
        assert_eq!(stats.rejected, 1, "tampered record must be rejected");
        let hit = store
            .lookup(&good.subject_pubkey_hex)
            .expect("good record loaded");
        assert_eq!(hit.0, RevocationReason::Compromise);
        assert_eq!(hit.1, 1_700_000_000);
    }

    #[test]
    fn lookup_returns_none_for_unknown_pubkey() {
        let store = RevocationStore::empty();
        assert!(store.lookup("aa".repeat(32).as_str()).is_none());
    }
}
