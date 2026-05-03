// raxis-policy — policy artifact loading, parsing, and accessor API.
//
// Normative references:
//   - kernel-core.md §2.2 startup step 3 (policy load and verification)
//   - kernel-core.md §2.3 policy_manager.rs (epoch advance)
//   - kernel-core.md §2.3 Escalation FSM (escalation_policy fields)
//   - kernel-store.md §2.5.3 (plan signing key lookup via operator_entry)
//   - kernel-store.md §2.5.4 (key inventory — authority_pubkey, quality_pubkey)
//   - kernel-store.md §2.5.5 (operator entries, permitted_ops)
//
// This crate is pure sync — no tokio dependency. Policy is loaded once at
// startup, validated, and placed behind an ArcSwap in the kernel binary.
// The kernel binary owns the ArcSwap<PolicyBundle>; this crate exposes the
// parsing and accessor API only.

pub mod bundle;
pub mod error;
pub mod loader;

pub use bundle::{
    GatewaySection, OperatorEntry, PolicyBundle, ProviderEntry,
    MAX_DATA_FETCH_TIMEOUT_MS, MAX_INFERENCE_TIMEOUT_MS, MAX_RESPONSE_BYTES_CEILING,
};

#[cfg(any(debug_assertions, test))]
pub use bundle::EscalationPolicyForTests;
pub use error::PolicyError;
pub use loader::load_policy;
