// raxis-cli::commands::initiative — initiative abort.
//
// Normative reference: cli-ceremony.md §4.1 `initiative abort`.

use raxis_types::operator_wire::OperatorRequest;

use crate::commands::plan::{handle_response, open_conn, to_wire};
use crate::errors::CliError;
use crate::GlobalFlags;

pub fn run_abort(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let initiative_id = args.first().ok_or_else(|| {
        CliError::Usage("initiative abort requires <initiative_id>".to_owned())
    })?;

    let (mut conn, fingerprint) = open_conn(flags)?;
    let req = OperatorRequest::AbortInitiative {
        initiative_id: initiative_id.clone(),
        aborted_by:    fingerprint,
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |_| {
        println!("Initiative {initiative_id} aborted. All non-terminal tasks cancelled.");
    })
}
