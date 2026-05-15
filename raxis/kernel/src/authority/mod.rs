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

pub mod approval;
pub mod cert_check;
pub mod delegation;
pub mod dispatch_matrix;
pub mod escalation;
pub mod keys;
pub mod revocations;
pub mod session;
pub mod verifier_token;

// Re-export the public API surface per kernel-core.md §2.3 authority/mod.rs.
pub use dispatch_matrix::evaluate_dispatch;
#[cfg(test)]
pub use keys::sign_audit_record;
pub use keys::{authority_pubkey_fingerprint, load_key_registry};
