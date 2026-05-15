//! Boot banner printed to stderr when the kernel starts.
//!
//! Two-line plaintext identity confirmation — version + tagline.
//! The previous ASCII-art rendering of the RAXIS logo was removed
//! in favour of this compact, scrollback-friendly form so that
//! diagnostics emitted in the first few hundred milliseconds of
//! boot remain visible without the operator having to scroll up
//! past 50+ lines of art.
//!
//! Structured-log deployments (`RAXIS_LOG_FORMAT=json`) emit a
//! single-line JSON object instead — see
//! [`print_boot_banner_json`].

/// Print the RAXIS boot banner to stderr.
///
/// Two short lines: `R A X I S vX.Y.Z` (bold) and the tagline
/// (dim). ANSI escape codes are emitted unconditionally; modern
/// terminals (Cursor, VS Code, iTerm2, Terminal.app, Ghostty,
/// Kitty, Alacritty) render them, and any TTY that does not
/// degrades gracefully (the version + tagline text is still
/// readable, just uncoloured).
pub fn print_boot_banner() {
    const BOLD_WHITE: &str = "\x1b[1;97m";
    const DIM: &str = "\x1b[2;37m";
    const RESET: &str = "\x1b[0m";

    eprintln!(
        "{BOLD_WHITE}R A X I S{RESET}  {DIM}v{}{RESET}",
        env!("CARGO_PKG_VERSION"),
    );
    eprintln!("{DIM}Reference Monitor for AI{RESET}");
    eprintln!();
}

/// Compact single-line banner for structured-log mode
/// (`RAXIS_LOG_FORMAT=json`). Emits a JSON object instead of
/// human-readable text so log shippers + the `raxis status`
/// parser get a stable wire shape.
pub fn print_boot_banner_json() {
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"KernelBoot\",\"version\":\"{}\"}}",
        env!("CARGO_PKG_VERSION"),
    );
}
