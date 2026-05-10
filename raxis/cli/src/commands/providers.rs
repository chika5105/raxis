//! `raxis providers` — circuit-breaker observability and operator reset.
//!
//! Normative reference: provider-failure-handling.md §6.6.
//!
//! # Subcommands
//!
//! * `raxis providers status [--json]` — read-only listing of every
//!   `(provider, model)` circuit breaker row in `kernel.db`.
//! * `raxis providers reset <provider> [<model>] [--json]` — manual
//!   operator override that forces the breaker(s) to `Closed`.
//!
//! Both operate on the `provider_circuit_state` table (migration 15).
//! `status` is fully read-only (no kernel IPC); `reset` mutates the
//! table directly (the kernel reads it lazily on the next dispatch).
//!
//! # Exit codes
//!
//! | Code | Meaning                                |
//! |------|----------------------------------------|
//! | `0`  | Success (status rendered / reset done). |
//! | `1`  | Error opening kernel.db or parsing args.|

use raxis_store::{open_ro, SqliteCircuitStore};

use crate::errors::CliError;
use crate::GlobalFlags;

// ────────────────────────────────────────────────────────────────────
// `raxis providers status [--json]`
// ────────────────────────────────────────────────────────────────────

/// Read-only listing of all circuit breaker rows.
pub fn run_status(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_status_args(args)?;
    let db_path = flags.data_dir().join("kernel.db");

    // Open read-only first to check if the table exists.
    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ).map_err(|e| CliError::Usage(format!(
        "cannot open kernel.db at {}: {e}", db_path.display()
    )))?;

    let store = SqliteCircuitStore::new(conn);
    let rows = store.list_all();

    if opts.json {
        let json_rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "provider":             &r.provider,
                    "model":                &r.model,
                    "state":                &r.state,
                    "consecutive_failures": r.consecutive_failures,
                    "last_failure_kind":    &r.last_failure_kind,
                    "last_failure_http_code": r.last_failure_http_code,
                    "opened_at_ms":         r.opened_at_ms,
                    "open_expires_at_ms":   r.open_expires_at_ms,
                    "half_open_inflight":   r.half_open_inflight != 0,
                    "last_success_at_ms":   r.last_success_at_ms,
                    "last_state_change_at_ms": r.last_state_change_at_ms,
                })
            })
            .collect();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let _ = serde_json::to_writer_pretty(&mut out, &json_rows);
        use std::io::Write;
        let _ = writeln!(out);
    } else {
        render_status_human(&rows);
    }

    Ok(())
}

fn render_status_human(rows: &[raxis_store::CircuitRowSqlite]) {
    if rows.is_empty() {
        println!("No circuit breaker state recorded (all providers are Closed/default).");
        return;
    }

    // Header.
    println!(
        "{:<16} {:<28} {:<10} {:>8}  {:<14} {:<12}",
        "PROVIDER", "MODEL", "STATE", "FAILURES", "LAST_FAILURE", "CHANGED_AT"
    );
    println!("{}", "-".repeat(92));

    for r in rows {
        let changed = format_epoch_ms(r.last_state_change_at_ms);
        let failure_kind = r
            .last_failure_kind
            .as_deref()
            .unwrap_or("-");
        let state_display = match r.state.as_str() {
            "Open" => "\x1b[31mOpen\x1b[0m",      // red
            "HalfOpen" => "\x1b[33mHalfOpen\x1b[0m", // yellow
            _ => "Closed",
        };
        println!(
            "{:<16} {:<28} {:<10} {:>8}  {:<14} {:<12}",
            truncate(&r.provider, 16),
            truncate(&r.model, 28),
            state_display,
            r.consecutive_failures,
            truncate(failure_kind, 14),
            changed,
        );
    }

    // Summary line.
    let open_count = rows.iter().filter(|r| r.state == "Open").count();
    let half_open_count = rows.iter().filter(|r| r.state == "HalfOpen").count();
    println!();
    println!(
        "{} provider(s) tracked. {} Open, {} HalfOpen.",
        rows.len(),
        open_count,
        half_open_count,
    );

    if open_count > 0 {
        println!();
        println!("  Hint: use `raxis providers reset <provider> [<model>]` to force a breaker Closed.");
    }
}

// ────────────────────────────────────────────────────────────────────
// `raxis providers reset <provider> [<model>] [--json]`
// ────────────────────────────────────────────────────────────────────

/// Manual operator reset — force one or all (provider, model) breakers
/// to Closed.
pub fn run_reset(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_reset_args(args)?;
    let db_path = flags.data_dir().join("kernel.db");

    let conn = rusqlite::Connection::open(
        &db_path,
    ).map_err(|e| CliError::Usage(format!(
        "cannot open kernel.db at {}: {e}", db_path.display()
    )))?;

    let store = SqliteCircuitStore::new(conn);

    // If a specific model is provided, reset just that one.
    // Otherwise, reset all models for the given provider.
    let transitions: Vec<(raxis_store::CircuitRowSqlite, Option<raxis_store::CircuitTransition>)>;

    if let Some(ref model) = opts.model {
        let result = store.manual_reset(&opts.provider, model);
        transitions = vec![result];
    } else {
        // List all rows for this provider and reset each one.
        let all = store.list_all();
        let provider_rows: Vec<_> = all
            .into_iter()
            .filter(|r| r.provider == opts.provider)
            .collect();

        if provider_rows.is_empty() {
            if opts.json {
                println!("[]");
            } else {
                println!(
                    "No circuit breaker state found for provider \"{}\". Nothing to reset.",
                    opts.provider,
                );
            }
            return Ok(());
        }

        transitions = provider_rows
            .iter()
            .map(|r| store.manual_reset(&r.provider, &r.model))
            .collect();
    }

    if opts.json {
        let json_out: Vec<serde_json::Value> = transitions
            .iter()
            .map(|(row, transition)| {
                serde_json::json!({
                    "provider": &row.provider,
                    "model": &row.model,
                    "state": &row.state,
                    "previous_state": transition.as_ref().map(|t| &t.from_state),
                    "reset": transition.is_some(),
                })
            })
            .collect();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let _ = serde_json::to_writer_pretty(&mut out, &json_out);
        use std::io::Write;
        let _ = writeln!(out);
    } else {
        for (row, transition) in &transitions {
            if let Some(t) = transition {
                println!(
                    "Reset {}/{}: {} → Closed",
                    row.provider, row.model, t.from_state,
                );
            } else {
                println!(
                    "{}/{}: already Closed (no-op)",
                    row.provider, row.model,
                );
            }
        }
    }

    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct StatusOpts {
    json: bool,
}

fn parse_status_args(args: &[String]) -> Result<StatusOpts, CliError> {
    let mut opts = StatusOpts::default();
    for arg in args {
        match arg.as_str() {
            "--json" => opts.json = true,
            "-h" | "--help" => {
                print_status_help();
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown providers status flag: {other:?} (try --json or --help)"
                )));
            }
        }
    }
    Ok(opts)
}

#[derive(Debug)]
struct ResetOpts {
    provider: String,
    model: Option<String>,
    json: bool,
}

fn parse_reset_args(args: &[String]) -> Result<ResetOpts, CliError> {
    let mut provider: Option<String> = None;
    let mut model: Option<String> = None;
    let mut json = false;
    let mut positional_count = 0;

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                print_reset_help();
                std::process::exit(0);
            }
            s if s.starts_with('-') => {
                return Err(CliError::Usage(format!(
                    "unknown providers reset flag: {s:?}"
                )));
            }
            _ => {
                positional_count += 1;
                match positional_count {
                    1 => provider = Some(arg.clone()),
                    2 => model = Some(arg.clone()),
                    _ => {
                        return Err(CliError::Usage(
                            "too many positional arguments for providers reset \
                             (expected: <provider> [<model>])"
                                .to_owned(),
                        ));
                    }
                }
            }
        }
    }

    let provider = provider.ok_or_else(|| {
        CliError::Usage(
            "providers reset requires a <provider> argument\n\
             usage: raxis providers reset <provider> [<model>] [--json]"
                .to_owned(),
        )
    })?;

    Ok(ResetOpts {
        provider,
        model,
        json,
    })
}

// ────────────────────────────────────────────────────────────────────
// Help
// ────────────────────────────────────────────────────────────────────

fn print_status_help() {
    println!(
        "raxis providers status — circuit breaker observability\n\
         \n\
         USAGE:\n\
         \traxis providers status [--json]\n\
         \n\
         FLAGS:\n\
         \t--json    Emit JSON array instead of human table.\n\
         \n\
         Lists every (provider, model) pair with recorded circuit breaker\n\
         state. Providers with no failures (default Closed) are omitted.\n\
         \n\
         Reads kernel.db read-only. No kernel IPC required."
    );
}

fn print_reset_help() {
    println!(
        "raxis providers reset — manual circuit breaker operator override\n\
         \n\
         USAGE:\n\
         \traxis providers reset <provider> [<model>] [--json]\n\
         \n\
         ARGUMENTS:\n\
         \t<provider>   Provider name (e.g. \"anthropic\", \"openai\").\n\
         \t<model>      Optional model name. If omitted, resets ALL models\n\
         \t             for the given provider.\n\
         \n\
         FLAGS:\n\
         \t--json    Emit JSON output instead of human text.\n\
         \n\
         Forces the circuit breaker to Closed for the specified (provider,\n\
         model) pair. The kernel reads the state lazily on the next\n\
         dispatch, so the reset takes effect immediately.\n\
         \n\
         Writes to kernel.db directly. No kernel IPC required."
    );
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn format_epoch_ms(ms: i64) -> String {
    if ms == 0 {
        return "-".to_owned();
    }
    // Render as ISO-8601 UTC short form (HH:MM:SS) for compact table display.
    let secs = ms / 1000;
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let s = secs % 60;
    format!("{hours:02}:{minutes:02}:{s:02}Z")
}
