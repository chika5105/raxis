//! Planner system-prompt assembly (T1.8 / kernel-core.md §2.3 prompt/).
//!
//! # Role
//!
//! This subsystem builds the **static scaffold** of the planner's
//! system prompt — the portion derived from kernel-known facts (policy
//! epoch, session identity, delegation summary, initiative context) —
//! and concatenates it with the canonical [`planner-api.md`] body
//! that defines the IPC contract the planner must obey.
//!
//! The prompt is **assembled by the kernel and signed by the epoch**.
//! The planner cannot modify it; it receives the rendered string as
//! its system-prompt prefix at session start (and on every inference
//! round — there is no caching, see kernel-core.md §2.3 step 6).
//!
//! # What this module is NOT
//!
//! * It does **not** spawn the planner process. The planner is
//!   "model-side participant — not a binary in the repository"
//!   ([`peripherals.md §3.1`]). The kernel only listens on
//!   `<data_dir>/sockets/planner.sock` for connections from a planner
//!   the operator has spawned externally; this module's output is
//!   what that planner gets handed by its host runner.
//! * It does **not** generate natural language. Every block is
//!   templated from typed values; there are no free-form strings.
//!
//! # Layout
//!
//! ```text
//! prompt/
//! ├── mod.rs            // this file: re-exports + AssembledPrompt
//! ├── assembler.rs      // assemble(session_id, ctx) → AssembledPrompt
//! └── epoch_binding.rs  // session_prompt_valid + invalidation
//! ```
//!
//! [`planner-api.md`]: https://github.com/raxis/specs/v1/planner-api.md
//! [`peripherals.md §3.1`]: https://github.com/raxis/specs/v1/peripherals.md

pub mod assembler;
pub mod epoch_binding;

// The re-exports below are part of the kernel's internal API for v1
// — `policy_manager` will call `mark_all_prompts_invalid` once the
// prompt path is wired into the planner socket handler in v1.1.
// Until then these re-exports surface the public types/functions for
// integrators (the planner-socket handler is the only intended
// caller). `allow(unused_imports)` keeps the kernel build clean
// without inviting drift.
#[allow(unused_imports)]
pub use assembler::{assemble, AssembledPrompt, PromptCtx, PromptError};
#[allow(unused_imports)]
pub use epoch_binding::{
    invalidate_session_prompts, mark_all_prompts_invalid, session_prompt_valid, EpochBinding,
};
