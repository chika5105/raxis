// raxis-genesis-tools::audit_record — render the chain-anchor genesis audit record.
//
// The genesis record is the very first line of `audit/segment-000.jsonl`.
// It carries no prior hash (`prev_sha256` is the all-zeros sentinel) and is
// the structural anchor `recovery::verify_audit_chain` looks for at every
// kernel boot. Until this crate landed, both the kernel-side bootstrap and
// the `AuditDir` test fixture had hand-copied implementations of this
// emitter; this module is the single source.
//
// Production callers pass already-minted CSPRNG bytes via
// `GenesisAuditInputs::nonce_bytes`. The emitter does not call `getrandom`
// directly so callers can:
//   - Inject deterministic bytes in tests (no flake).
//   - Route through their existing `try_random_array` failure handling
//     (kernel: `KernelError::BootstrapFailed`; CLI: `CliError::Crypto`).

use serde_json::json;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 64 zero hex chars = 32 zero bytes hex-encoded — the genesis sentinel for
/// `prev_sha256`. Matches `raxis_audit_tools::AuditWriter::GENESIS_PREV_SHA256`
/// (kept as a string constant rather than a re-export to avoid pulling
/// `raxis-audit-tools` into the production graph of `raxis-genesis-tools`,
/// which would create a circular pressure if audit-tools ever needed
/// genesis defaults).
pub const GENESIS_PREV_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Wire value of the genesis record's `event_kind` field. `recovery::verify_audit_chain`
/// requires the first line of segment-000.jsonl to carry exactly this string;
/// a mismatch is a fail-closed `KernelError::AuditChainBroken`.
pub const GENESIS_EVENT_KIND: &str = "GenesisRecord";

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// Every variable input the genesis audit record depends on.
///
/// All randomness and time-of-day are caller-provided so the emitter is a
/// pure function and tests can produce deterministic output. Production
/// callers source `nonce_bytes` from `raxis_crypto::token::try_random_array`
/// (the same shim used by every other CSPRNG site in the kernel), and
/// `emitted_at_unix_secs` from their `Clock`.
#[derive(Debug, Clone, Copy)]
pub struct GenesisAuditInputs<'a> {
    /// `SHA-256[:16]` of the authority pubkey bytes — 32 hex chars. Use
    /// `super::pubkey_fingerprint` to compute. Embedded in the genesis
    /// record's `authority_pubkey_fingerprint` field; downstream verifiers
    /// (e.g. `recovery::verify_audit_chain`) treat this as the chain's
    /// trusted-signer commitment.
    pub authority_pubkey_fingerprint: &'a str,
    /// Caller-minted CSPRNG bytes for the genesis nonce. Spec
    /// (`kernel-store.md` §2.5.5 `audit-genesis-nonce`) requires "at least
    /// 256 bits of entropy"; we accept exactly 64 bytes (= 512 bits, leaving
    /// headroom). A length other than 64 panics — callers that source bytes
    /// from `try_random_array::<64>()` always satisfy this.
    pub nonce_bytes: &'a [u8],
    /// Unix-seconds timestamp written into `emitted_at`. Caller-injected for
    /// determinism (see crate-level docstring rationale).
    pub emitted_at_unix_secs: u64,
    /// UUID for the `event_id` field. Caller-injected so tests can use a
    /// fixed UUID for golden output assertions; production callers mint a
    /// fresh `Uuid::new_v4().to_string()` per genesis record.
    pub event_id: &'a str,
}

// ---------------------------------------------------------------------------
// Emitter
// ---------------------------------------------------------------------------

/// Build the genesis audit record as a JSON line ending in `\n`.
///
/// Returns `String` (already newline-terminated) so the caller can append
/// directly to `audit/segment-000.jsonl` without re-framing. Pure function;
/// no I/O.
///
/// # Panics
///
/// Panics if `inputs.nonce_bytes.len() != 64`. Production callers use
/// `try_random_array::<64>()` which always satisfies this; in tests it
/// pins the spec invariant that the nonce carries ≥ 256 bits of entropy
/// (we mint 512).
pub fn render_genesis_audit_record(inputs: GenesisAuditInputs<'_>) -> String {
    assert_eq!(
        inputs.nonce_bytes.len(),
        64,
        "render_genesis_audit_record: nonce_bytes must be exactly 64 bytes \
         (512 bits, with 256-bit headroom over the spec minimum); got {} bytes",
        inputs.nonce_bytes.len(),
    );

    let genesis_nonce = hex::encode(inputs.nonce_bytes);

    // Field set is fixed by `kernel-core.md` §2.2 bootstrap.rs entry. Keep
    // the order stable for human readability; serde_json sorts keys
    // alphabetically anyway, but the macro's order matches the spec text.
    let record = json!({
        "seq":                          0,
        "event_id":                     inputs.event_id,
        "event_kind":                   GENESIS_EVENT_KIND,
        "prev_sha256":                  GENESIS_PREV_SHA256,
        "genesis_nonce":                genesis_nonce,
        "authority_pubkey_fingerprint": inputs.authority_pubkey_fingerprint,
        "emitted_at":                   inputs.emitted_at_unix_secs,
    });

    // `serde_json::to_string` is infallible for `serde_json::Value`. We
    // unwrap with a panic message that names the function so a future
    // refactor that swaps the input type for one with a fallible Serialize
    // surfaces clearly in the panic.
    let mut line = serde_json::to_string(&record)
        .expect("render_genesis_audit_record: serde_json::Value serialise is infallible");
    line.push('\n');
    line
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_inputs<'a>() -> GenesisAuditInputs<'a> {
        GenesisAuditInputs {
            authority_pubkey_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeef",
            nonce_bytes: &[0xC1u8; 64],
            emitted_at_unix_secs: 1_700_000_000,
            event_id: "00000000-0000-4000-8000-000000000000",
        }
    }

    // ── Shape / spec invariants ─────────────────────────────────────────────

    #[test]
    fn line_ends_with_newline() {
        // segment-000.jsonl is JSONL — recovery::verify_audit_chain reads
        // line-by-line. Missing newline = subsequent appends would land on
        // the same line and corrupt the chain.
        let line = render_genesis_audit_record(fixed_inputs());
        assert!(
            line.ends_with('\n'),
            "genesis audit line must end with `\\n`, got {line:?}"
        );
    }

    #[test]
    fn line_parses_as_json_with_every_required_field() {
        // Pin the field set so a future emitter that drops or renames a
        // field surfaces here, not at the next kernel recovery.
        let line = render_genesis_audit_record(fixed_inputs());
        let v: serde_json::Value =
            serde_json::from_str(line.trim_end()).expect("line must be valid JSON");
        for required in [
            "seq",
            "event_id",
            "event_kind",
            "prev_sha256",
            "genesis_nonce",
            "authority_pubkey_fingerprint",
            "emitted_at",
        ] {
            assert!(
                v.get(required).is_some(),
                "required field {required:?} missing from genesis record: {v:?}"
            );
        }
    }

    #[test]
    fn seq_is_integer_zero() {
        // Pin the type AND value: `recovery::verify_audit_chain` rejects
        // both `seq != 0` and `seq: "0"` (string-typed). A bug that
        // serialised seq as a string would round-trip through serde but
        // break the verifier.
        let line = render_genesis_audit_record(fixed_inputs());
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["seq"], serde_json::json!(0));
        assert!(
            v["seq"].is_i64() || v["seq"].is_u64(),
            "seq must be a JSON number, got {:?}",
            v["seq"]
        );
    }

    #[test]
    fn event_kind_is_exactly_genesis_record() {
        // verify_audit_chain rejects any other value. Hardcoded exact
        // match — case-sensitive.
        let line = render_genesis_audit_record(fixed_inputs());
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["event_kind"], "GenesisRecord");
    }

    #[test]
    fn prev_sha256_is_64_zeros() {
        // The all-zeros sentinel is what AuditWriter::GENESIS_PREV_SHA256
        // chains against. Any other value would cause the first
        // post-genesis record to fail prev_hash verification.
        let line = render_genesis_audit_record(fixed_inputs());
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["prev_sha256"], "0".repeat(64));
    }

    #[test]
    fn genesis_nonce_is_128_hex_chars() {
        // 64 bytes hex-encoded = 128 chars. Spec floor is 256 bits = 64 hex
        // chars; we mint 512 bits = 128 hex chars for headroom.
        let line = render_genesis_audit_record(fixed_inputs());
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        let nonce = v["genesis_nonce"].as_str().expect("nonce is string");
        assert_eq!(nonce.len(), 128, "genesis_nonce must be 128 hex chars");
        assert!(
            nonce.chars().all(|c| c.is_ascii_hexdigit()),
            "genesis_nonce must be lowercase hex"
        );
    }

    #[test]
    fn authority_fingerprint_appears_verbatim() {
        // Pin that the caller-supplied fingerprint is the one that lands
        // — no re-hashing or re-encoding happens inside the emitter.
        let inputs = GenesisAuditInputs {
            authority_pubkey_fingerprint: "feed1234feed1234feed1234feed1234",
            ..fixed_inputs()
        };
        let line = render_genesis_audit_record(inputs);
        assert!(
            line.contains("feed1234feed1234feed1234feed1234"),
            "fingerprint not found verbatim in: {line}"
        );
    }

    #[test]
    fn output_is_byte_deterministic_for_fixed_inputs() {
        // Same property test as the policy emitter: same inputs ⇒ same bytes.
        let a = render_genesis_audit_record(fixed_inputs());
        let b = render_genesis_audit_record(fixed_inputs());
        assert_eq!(a, b, "audit-record emitter must be byte-deterministic");
    }

    // ── Negative cases ─────────────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "nonce_bytes must be exactly 64 bytes")]
    fn short_nonce_panics() {
        // Failing fast at emit time gives a clearer error than letting a
        // 32-byte nonce ship in production with 256-bit (not 512-bit)
        // entropy. The spec floor is met either way (256 ≥ 256), but
        // every existing call site mints 64 bytes via
        // `try_random_array::<64>()`, so a 32-byte slice can only come
        // from a programming mistake worth surfacing.
        let inputs = GenesisAuditInputs {
            nonce_bytes: &[0u8; 32],
            ..fixed_inputs()
        };
        let _ = render_genesis_audit_record(inputs);
    }

    #[test]
    #[should_panic(expected = "nonce_bytes must be exactly 64 bytes")]
    fn long_nonce_also_panics() {
        let inputs = GenesisAuditInputs {
            nonce_bytes: &[0u8; 128],
            ..fixed_inputs()
        };
        let _ = render_genesis_audit_record(inputs);
    }
}
