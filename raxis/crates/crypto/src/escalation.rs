// raxis-crypto::escalation — ApproveEscalation signing-input construction.
//
// Normative reference: kernel-store.md §2.5.5 "Escalation approval on the
// operator socket" and kernel-core.md §2.3 `handle_approve_escalation`.
//
// The operator signs the canonical bytes returned by
// `approval_scope_signing_input` with their private key; the kernel
// reconstructs the same bytes here and calls `verify::verify_ed25519` to
// authenticate the approval.
//
// Why text rather than a binary discriminant + length-prefixed format like
// `delegation_signing_input`?
//
//   The escalation signing domain has only four fields, none of which can
//   contain pipe characters in practice (`escalation_id` is a UUIDv4,
//   `capability_class` is a `CapabilityClass` enum variant name,
//   `max_uses` and `valid_for_seconds` are integers). A pipe-separated
//   text format is therefore unambiguous AND ergonomically debuggable
//   from a tcpdump trace, matching the existing `approval_signing_input`
//   format used by `authority::approval`. The kernel-CLI contract is
//   pinned by `tests::canonical_signing_input_byte_layout` in this
//   module — both halves go through THIS function, drift breaks the
//   test.

/// Construct the canonical signing input for an `ApproveEscalation`
/// operator request.
///
/// Format (UTF-8, ASCII pipe separators):
///
/// ```text
/// approval|<escalation_id>|<capability_class>|<max_uses>|<valid_for_seconds>
/// ```
///
/// `escalation_id` is taken VERBATIM from the wire — no case folding,
/// no whitespace trimming. The CLI MUST sign the exact bytes it puts on
/// the wire.
///
/// Returns the raw bytes; the caller signs / verifies with
/// `verify::verify_ed25519` directly. Unlike `delegation_signing_input`
/// (which wraps in a SHA-256 because the canonical bytes are
/// variable-length and binary), this returns the bytes themselves —
/// they're already short enough for Ed25519's internal SHA-512 to
/// handle as the message in one shot.
pub fn approval_scope_signing_input(
    escalation_id:     &str,
    capability_class:  &str,
    max_uses:          i64,
    valid_for_seconds: u64,
) -> Vec<u8> {
    format!(
        "approval|{escalation_id}|{capability_class}|{max_uses}|{valid_for_seconds}"
    ).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_signing_input_byte_layout() {
        let bytes = approval_scope_signing_input("esc-abc", "WriteSecrets", 3, 1800);
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            "approval|esc-abc|WriteSecrets|3|1800",
        );
    }

    #[test]
    fn signing_input_uses_escalation_id_verbatim() {
        // Pin: no normalization. Operators sign the exact wire bytes.
        let bytes = approval_scope_signing_input("Esc With Spaces", "WriteCode", 1, 60);
        assert!(std::str::from_utf8(&bytes).unwrap()
                .starts_with("approval|Esc With Spaces|"));
    }

    #[test]
    fn signing_input_changes_on_any_field_change() {
        // Sanity guard: a one-bit change in any input field must produce
        // a different canonical byte string. Otherwise the kernel-CLI
        // contract is too coarse.
        let base = approval_scope_signing_input("e1", "Cap", 1, 10);
        assert_ne!(base, approval_scope_signing_input("e2", "Cap", 1, 10));
        assert_ne!(base, approval_scope_signing_input("e1", "Other", 1, 10));
        assert_ne!(base, approval_scope_signing_input("e1", "Cap", 2, 10));
        assert_ne!(base, approval_scope_signing_input("e1", "Cap", 1, 11));
    }
}
