// raxis-cli::commands — All CLI subcommand implementations.
//
// Sub-modules are split into two families:
//
//   * "Mutating / ceremony" commands — talk to the kernel over
//     operator.sock with a typed OperatorRequest.
//
//   * "Read-only" commands — never touch operator.sock. They open
//     `<data_dir>/runtime/heartbeat.json` and a read-only
//     `kernel.db` handle (`raxis_store::open_ro`) and render a
//     report. cli-readonly.md §5.5 catalogues them.
//
// Audit-chain integrity verification lives exclusively in
// [`crate::commands::verify_chain`] (the canonical, multi-segment,
// library-backed implementation).  The historical V1 single-segment
// `audit verify` shim was removed: keeping two CLI surfaces that
// "verify the chain" violates the no-duplicate-action invariant.

pub mod auth;
pub mod budget;
pub mod cert;
pub mod credential;
pub mod delegation;
pub mod doctor;
pub mod epoch;
pub mod escalation;
pub mod escalations;
pub mod explain;
pub mod genesis;
pub mod inbox;
pub mod initiative;
pub mod initiative_show;
pub mod initiatives;
pub mod inspect;
pub mod kernel;
pub mod log;
pub mod operator;
pub mod plan;
pub mod plan_fmt;
pub mod plan_init;
pub mod plan_validate;
pub mod policy;
pub mod policy_diff;
pub mod policy_show;
pub mod providers;
pub mod queue;
pub mod session;
pub mod sessions;
pub mod setup;
pub mod status;
pub mod submit;
pub mod task;
pub mod top;
pub mod verifiers;
pub mod verify_chain;
pub mod witnesses;
