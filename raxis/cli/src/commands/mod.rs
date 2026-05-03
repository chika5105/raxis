// raxis-cli::commands — All CLI subcommand implementations.
//
// Sub-modules are split into two families:
//
//   * "Mutating / ceremony" commands — talk to the kernel over
//     operator.sock with a typed OperatorRequest. (`audit verify`
//     is local-only but lives in the same family for historical
//     reasons.)
//
//   * "Read-only" commands — never touch operator.sock. They open
//     `<data_dir>/runtime/heartbeat.json` and a read-only
//     `kernel.db` handle (`raxis_store::open_ro`) and render a
//     report. cli-readonly.md §5.5 catalogues them.

pub mod audit;
pub mod delegation;
pub mod epoch;
pub mod escalation;
pub mod escalations;
pub mod genesis;
pub mod initiative;
pub mod inspect;
pub mod log;
pub mod plan;
pub mod policy;
pub mod queue;
pub mod session;
pub mod sessions;
pub mod status;
pub mod task;
pub mod verify_chain;
