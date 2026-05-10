//! Boot banner printed to stderr when the kernel starts.
//!
//! The ASCII art is rendered with ANSI colors:
//!   - White (bold) for the R letterform
//!   - Cyan for the diagonal axis stroke
//!   - Dim white for the "REFERENCE MONITOR FOR AI" subtitle
//!
//! The banner is deliberately compact (11 lines) to fit within
//! a 24-row terminal without pushing important boot diagnostics
//! off-screen.

/// Print the RAXIS boot banner to stderr.
///
/// Uses ANSI escape codes for color. The caller should check
/// `atty::is(atty::Stream::Stderr)` if they want to suppress
/// colors when piped to a file — but the kernel's stderr is
/// always a terminal in practice (systemd journals preserve
/// ANSI, and `journalctl --output=cat` strips them).
pub fn print_boot_banner() {
    // ANSI codes.
    const BOLD_WHITE: &str = "\x1b[1;97m";
    const CYAN: &str = "\x1b[1;36m";
    const DIM: &str = "\x1b[2;37m";
    const RESET: &str = "\x1b[0m";

    let banner = format!(
        r#"
{BOLD_WHITE}  ██████╗  {CYAN}  ╱{BOLD_WHITE}            
  ██╔══██╗{CYAN} ╱ {BOLD_WHITE}            
  ██████╔╝{CYAN}╱  {BOLD_WHITE}            
  ██╔══██╗{CYAN}╲  {BOLD_WHITE}            
  ██║  ██║{CYAN} ╲ {BOLD_WHITE}            
  ╚═╝  ╚═╝{CYAN}  ╲{BOLD_WHITE}            
{RESET}
{BOLD_WHITE}  R A X I S{RESET}  {DIM}v{version}{RESET}
  {DIM}Reference Monitor for AI{RESET}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
    eprint!("{banner}");
}

/// Compact single-line banner for structured-log mode
/// (`RAXIS_LOG_FORMAT=json`). Emits a JSON object instead of
/// ASCII art.
pub fn print_boot_banner_json() {
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"KernelBoot\",\"version\":\"{}\"}}",
        env!("CARGO_PKG_VERSION"),
    );
}
