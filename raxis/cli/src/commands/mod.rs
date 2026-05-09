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
pub mod inspect_initiative;
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
pub mod queue;
pub mod session;
pub mod sessions;
pub mod status;
pub mod submit;
pub mod task;
pub mod top;
pub mod verifiers;
pub mod verify_chain;
pub mod witnesses;
