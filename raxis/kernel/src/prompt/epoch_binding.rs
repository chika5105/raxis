//! Session-scoped epoch validity tracker for assembled prompts
//! (kernel-core.md §2.3 `prompt/epoch_binding.rs`).
//!
//! # Purpose
//!
//! When the policy epoch advances, every assembled prompt's
//! `constraint_block` (and possibly `capability_block`) is now stale.
//! The spec contract is:
//!
//! * `policy_manager::advance_epoch` calls
//!   [`mark_all_prompts_invalid`].
//! * On the next `assemble()` call for a given session,
//!   [`session_prompt_valid`] returns `false`, which causes the
//!   assembler to log `AuditEventKind::PromptReassembled { reason:
//!   EpochAdvance }` and clear the flag. The actual reassembly was
//!   going to happen anyway (no cache), but the audit trail records
//!   that "this round's prompt was rebuilt because of an epoch
//!   advance" rather than "as part of the normal per-round rebuild".
//!
//! # v1 implementation choice — in-memory tracker
//!
//! kernel-core.md §2.3 specifies a `prompt_epoch_valid` column on the
//! sessions table. v1 ships an **in-memory `RwLock<HashSet<SessionId>>`**
//! instead, for two reasons:
//!
//! 1. The flag is not data-correctness load-bearing. The spec itself
//!    notes (line 1216) that "there is no in-memory or store-resident
//!    cached prompt object to invalidate." — assembly is stateless.
//!    The flag is purely a diagnostic ("did an epoch advance get
//!    missed between rounds?").
//! 2. Adding a new column requires a schema migration (kernel-store.md
//!    §2.5.1). v1 already has a long migration backlog; deferring the
//!    column to v1.1 keeps the migration count down and the audit
//!    trail unchanged.
//!
//! The persistence-backed implementation will land alongside the
//! sessions-table migration in v1.1 — at which point the public API
//! here does not change; only the storage backend swaps.

use std::collections::HashSet;
use std::sync::RwLock;

use raxis_types::SessionId;

/// In-memory shared state. Sessions present in the inner set have
/// `prompt_epoch_valid = false`; absent sessions are valid. Wrapped in
/// `RwLock` because the read path (every assembly call) is far hotter
/// than the write path (every epoch advance).
#[derive(Debug, Default)]
pub struct EpochBinding {
    invalidated: RwLock<HashSet<SessionId>>,
}

impl EpochBinding {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the session's prompt is still epoch-valid
    /// (i.e. NOT in the invalidated set).
    pub fn session_prompt_valid(&self, session_id: &SessionId) -> bool {
        self.invalidated
            .read()
            .map(|guard| !guard.contains(session_id))
            .unwrap_or(true)
    }

    /// Mark a single session as invalidated.
    pub fn invalidate(&self, session_id: &SessionId) {
        if let Ok(mut guard) = self.invalidated.write() {
            guard.insert(session_id.clone());
        }
    }

    /// Mark every session whose id is in `active_sessions` as
    /// invalidated. Returns the count of newly-marked sessions
    /// (excludes sessions that were already invalidated).
    ///
    /// Why we take the active-session list as input rather than
    /// scanning a global registry: the kernel's authority subsystem
    /// owns the set of active sessions; this module is intentionally
    /// dependency-light. `policy_manager::advance_epoch` reads the
    /// active sessions once and passes them in.
    pub fn mark_all_invalid(&self, active_sessions: &[SessionId]) -> usize {
        let mut guard = match self.invalidated.write() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        let mut newly = 0usize;
        for sid in active_sessions {
            if guard.insert(sid.clone()) {
                newly += 1;
            }
        }
        newly
    }

    /// Clear the invalidated flag for a session. Called by the
    /// assembler immediately after it logs `PromptReassembled` so
    /// subsequent rounds don't re-log the same epoch advance.
    pub fn clear(&self, session_id: &SessionId) {
        if let Ok(mut guard) = self.invalidated.write() {
            guard.remove(session_id);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Free-function shims matching the spec signature (kernel-core.md
// §2.3 `prompt/epoch_binding.rs`). These accept an `&EpochBinding`
// by reference so call sites that already hold one don't have to
// reach into the struct directly. The shims are thin and exist so
// the public API matches what the spec dictates word-for-word.
// ────────────────────────────────────────────────────────────────────

pub fn session_prompt_valid(session_id: &SessionId, binding: &EpochBinding) -> bool {
    binding.session_prompt_valid(session_id)
}

pub fn invalidate_session_prompts(session_id: &SessionId, binding: &EpochBinding) {
    binding.invalidate(session_id);
}

pub fn mark_all_prompts_invalid(active_sessions: &[SessionId], binding: &EpochBinding) -> usize {
    binding.mark_all_invalid(active_sessions)
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_binding_treats_every_session_as_valid() {
        let b = EpochBinding::new();
        let sid = SessionId::new_v4();
        assert!(b.session_prompt_valid(&sid));
    }

    #[test]
    fn invalidate_then_check_returns_false() {
        let b = EpochBinding::new();
        let sid = SessionId::new_v4();
        b.invalidate(&sid);
        assert!(!b.session_prompt_valid(&sid));
    }

    #[test]
    fn clear_removes_invalidated_flag() {
        let b = EpochBinding::new();
        let sid = SessionId::new_v4();
        b.invalidate(&sid);
        assert!(!b.session_prompt_valid(&sid));
        b.clear(&sid);
        assert!(b.session_prompt_valid(&sid));
    }

    #[test]
    fn mark_all_invalid_marks_each_session_once() {
        let b = EpochBinding::new();
        let sids: Vec<_> = (0..3).map(|_| SessionId::new_v4()).collect();
        let n = b.mark_all_invalid(&sids);
        assert_eq!(n, 3);
        // Re-marking the same sessions returns 0 newly-marked.
        let n = b.mark_all_invalid(&sids);
        assert_eq!(n, 0);
        for sid in &sids {
            assert!(!b.session_prompt_valid(sid));
        }
    }

    #[test]
    fn invalidation_is_per_session_isolated() {
        let b = EpochBinding::new();
        let s1 = SessionId::new_v4();
        let s2 = SessionId::new_v4();
        b.invalidate(&s1);
        assert!(!b.session_prompt_valid(&s1));
        assert!(b.session_prompt_valid(&s2));
    }

    #[test]
    fn free_function_shims_delegate_to_binding() {
        let b = EpochBinding::new();
        let s1 = SessionId::new_v4();
        let s2 = SessionId::new_v4();
        invalidate_session_prompts(&s1, &b);
        assert!(!session_prompt_valid(&s1, &b));
        assert!(session_prompt_valid(&s2, &b));
        let n = mark_all_prompts_invalid(&[s1.clone(), s2.clone()], &b);
        // s1 was already invalidated; only s2 is newly marked.
        assert_eq!(n, 1);
    }
}
