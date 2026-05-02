// raxis-kernel::authority — Trust engine: sessions, delegations, tokens, keys, approvals.
//
// Normative reference: kernel-core.md §2.3 Authority Subsystem.
//
// This is the kernel's designated importer of raxis-crypto. No other kernel
// module may import raxis-crypto directly (except raxis-audit-tools, which is
// a separate crate). cargo deny enforces this per-crate.
//
// Public API (the only functions callable by other kernel modules):
//
//   Session lifecycle:
//     create_session, get_session, revoke_session, update_sequence_number
//
//   Delegation management:
//     check_capability, record_capability_use, list_delegations,
//     mark_stale_on_epoch_advance, grant_delegation
//
//   Verifier run tokens:
//     issue_verifier_token, validate_verifier_token, consume_verifier_token
//
//   Key operations:
//     verify_hmac, sign_audit_record, authority_pubkey_fingerprint
//
//   Approval tokens:
//     validate_approval_token, revoke_approval

pub mod keys;
pub mod session;
pub mod delegation;
pub mod verifier_token;
pub mod approval;

// Re-export the public API surface per kernel-core.md §2.3 authority/mod.rs.
pub use delegation::{
    check_capability, record_capability_use, list_delegations, mark_stale_on_epoch_advance,
    grant_delegation,
};
pub use session::{
    accept_envelope_and_advance_sequence, create_session, get_session, revoke_session,
    update_sequence_number, EnvelopeReplayReason,
};
pub use verifier_token::{issue_verifier_token, validate_verifier_token, consume_verifier_token};
pub use keys::{verify_hmac, sign_audit_record, authority_pubkey_fingerprint, KeyRegistry, load_key_registry};
pub use approval::{validate_approval_token, revoke_approval};
