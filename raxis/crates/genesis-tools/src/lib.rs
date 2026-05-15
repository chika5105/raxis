// raxis-genesis-tools — Single source of truth for the on-disk artifacts the
// genesis ceremony emits.
//
// Why this crate exists
// ─────────────────────
// Until this crate landed, the genesis policy.toml had TWO separate emitters:
//
//   - `cli/src/commands/genesis.rs::render_initial_policy_toml`
//     (the operator-facing `raxis genesis` command)
//
//   - `kernel/src/bootstrap.rs::write_genesis_policy`
//     (the kernel's `RAXIS_BOOTSTRAP=1` self-bootstrap path)
//
// They had drifted in five distinct ways, two of which were P0 bugs:
//
//   1. Kernel-side wrote `[sessions] allowed_worktree_roots = []`,
//      which `raxis_policy::PolicyBundle::validate` rejects → kernel
//      could not load its own genesis output.
//
//   2. Kernel-side wrote `[budget.base_cost_per_intent_kind]` keys
//      `MultiBranchCommit` and `PrGateEvaluation`, which are not real
//      `IntentKind` variants. The two real variants the kernel actually
//      looks up at admission time — `CompleteTask` and `ReportFailure` —
//      were absent, so any task of those kinds would fail admission with
//      `BudgetError::UnknownIntentKindCost`.
//
//   3. Kernel-side omitted `[[lanes]]` entirely; CLI-side included a
//      `default` lane.
//
//   4. `display_name` differed (`"operator-1"` vs `"Initial Operator"`).
//
//   5. Whitespace and section ordering differed, producing distinct
//      `policy_sha256` values for the same operator key.
//
// Convergence rules
// ─────────────────
//   - Pure functions: no I/O, no logging, no `SystemTime::now()`. The
//     caller injects every variable input (timestamp, CSPRNG nonce). This
//     keeps the output testable as a deterministic `String` / `Vec<u8>`.
//
//   - Output round-trips through `raxis_policy::load_policy` — pinned by
//     the test at the bottom of `policy_toml.rs`. Any change to either the
//     emitter or the loader that breaks round-trip surfaces immediately.
//
//   - The crate has NO dependency on `raxis-policy` at production build
//     time. The loader is a dev-dep used only for the round-trip test.
//     This keeps the production graph minimal and avoids a circular
//     pressure (loader → bundle → could one day need genesis defaults).
//
// Stability contract
// ──────────────────
// Adding a field to the policy.toml or the genesis audit record is a
// kernel-store / cli-ceremony spec amendment first; the change here just
// reflects the new shape and updates the round-trip / golden tests.

#![forbid(unsafe_code)]

pub mod audit_record;
pub mod policy_toml;

pub use audit_record::{render_genesis_audit_record, GenesisAuditInputs, GENESIS_PREV_SHA256};
pub use policy_toml::{render_genesis_policy_toml, GenesisPolicyInputs, PERMITTED_OPS};

// ---------------------------------------------------------------------------
// Crate-level fingerprint helper
// ---------------------------------------------------------------------------

/// SHA-256[:16] fingerprint of an Ed25519 public key — 16 raw bytes hex-encoded
/// to 32 chars. Matches `kernel-store.md` §2.5.4 and
/// `raxis_policy::loader::operator_pubkey_fingerprint`.
///
/// The genesis ceremony computes two fingerprints from this function: the
/// **operator** fingerprint (used as `[meta] signed_by` and as the operator
/// pubkey filename suffix), and the **authority** fingerprint (embedded in
/// the genesis audit record's `authority_pubkey_fingerprint` field). Both
/// callers go through this single helper so a future change to the slice
/// length or hash function flows to every site at once.
pub fn pubkey_fingerprint(pubkey_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pubkey_bytes);
    hex::encode(&h.finalize()[..16])
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    #[test]
    fn fingerprint_is_thirty_two_hex_chars() {
        let key = [0u8; 32];
        let fp = pubkey_fingerprint(&key);
        assert_eq!(fp.len(), 32, "SHA-256[:16] is 16 bytes = 32 hex chars");
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint must be lowercase hex, got {fp:?}"
        );
    }

    #[test]
    fn distinct_keys_produce_distinct_fingerprints() {
        // Sanity: SHA-256's first 128 bits collision-resist anything we'd
        // realistically test. A bug that hashed an empty slice for both
        // calls would surface as equal fingerprints.
        let fp_a = pubkey_fingerprint(&[0xAAu8; 32]);
        let fp_b = pubkey_fingerprint(&[0xBBu8; 32]);
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let key = [0xC1u8; 32];
        assert_eq!(pubkey_fingerprint(&key), pubkey_fingerprint(&key));
    }
}
