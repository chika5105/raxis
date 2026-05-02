// raxis-kernel::vcs — VCS subsystem re-exports.
//
// Normative reference: kernel-core.md §2.3 `src/vcs/mod.rs`.

pub mod diff;
pub use diff::{touched_paths, is_ancestor, rev_parse_parent, topology_check, compute};
