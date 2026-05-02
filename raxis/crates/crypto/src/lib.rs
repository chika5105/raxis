// raxis-crypto — Ed25519 signing, SHA-256 hashing, and token generation.
//
// Normative reference:
//   - kernel-store.md §2.5.3 (plan artifact signing domain)
//   - kernel-store.md §2.5.4 (key inventory; four key families)
//   - kernel-store.md §2.5.5 (operator challenge-response; GrantDelegation
//     signing domain — byte-exact canonical concatenation)
//
// Crate rules (philosophy.md §1.5):
//   - No I/O, no SQLite, no tokio.
//   - All functions are pure (input → output); callers manage key lifecycle.
//   - Raw private key bytes are never stored in types exported from this crate.

pub mod delegation;
pub mod plan;
pub mod token;
pub mod verify;

pub use verify::{CryptoError, verify_ed25519};
