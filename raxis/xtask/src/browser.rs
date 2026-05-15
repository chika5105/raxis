//! Host-browser dispatch: open a URL in the best-available
//! browser for the current host environment.
//!
//! # Why this exists
//!
//! `cargo xtask observability up` (and the live-e2e Tier-3
//! reporter, mirrored at `kernel/tests/common/browser.rs`) needs
//! to open Grafana / Prometheus / dashboard-autologin URLs at end
//! of run. A naive `open(1)` / `xdg-open(1)` hands the URL to the
//! system default browser, which on a developer host means the
//! user's normal Chrome / Safari / Firefox window. That works,
//! but operators running Cursor with `Glass` layout asked for the
//! URL to appear inside Cursor's in-IDE browser pane (the
//! "Simple Browser" VS Code surface that Cursor exposes via the
//! `cursor --open-url <url>` flag inherited from upstream VS Code).
//!
//! This module encapsulates the dispatch:
//!
//!   1. Honour the explicit `RAXIS_E2E_BROWSER` env override
//!      (`cursor`, `system`, `none`).
//!   2. Auto-detect Cursor via `TERM_PROGRAM` + `CURSOR_*` /
//!      `VSCODE_IPC_HOOK` env vars.
//!   3. If Cursor — invoke the `cursor` CLI from `$PATH` or from
//!      the canonical macOS app bundle path `/Applications/
//!      Cursor.app/Contents/Resources/app/bin/cursor`. The CLI
//!      inherits `--open-url <url>` from upstream VS Code.
//!   4. If that fails (or the host is not Cursor) — fall back to
//!      the OS default (`open` on macOS, `xdg-open` /
//!      `gnome-open` / `kde-open` / `wslview` on Linux).
//!   5. If every opener fails — print the URL on stdout so the
//!      operator can copy-paste, and return [`OpenOutcome::Printed`].
//!
//! The module never panics and never returns an `Err` for an
//! operator-recoverable condition (missing CLI, headless host,
//! SSH); the caller's contract is `let _ = open_in_best_browser(url)`.
//!
//! # Tests
//!
//! `detect_host_environment` is covered by unit tests that snapshot
//! `std::env` and assert each branch fires correctly. The shelling
//! out to `cursor` / `open` / `xdg-open` is not unit-tested (it
//! would require a fake binary on PATH); the integration story is
//! the operator running `cargo xtask observability up` on their
//! host and seeing the URL land in the right surface.

use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Operator-recognised host environments for URL opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEnvironment {
    /// Running under Cursor's integrated terminal. The agent or
    /// operator wants URLs to surface in Cursor's in-IDE browser
    /// pane (Simple Browser, controlled by `cursor --open-url`).
    Cursor,
    /// Anything else — desktop terminal, SSH session, CI shell.
    /// URLs go to the OS default browser.
    SystemDefault,
}

/// Explicit operator override read from `RAXIS_E2E_BROWSER`.
/// Higher precedence than auto-detection: an operator running a
/// scripted pipeline (CI, SSH-with-display, headless container)
/// can force a deterministic mode without relying on the env
/// `TERM_PROGRAM` heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserPreference {
    /// Auto-detect from `TERM_PROGRAM` / `CURSOR_*` env vars.
    Auto,
    /// Force the Cursor-CLI path; on failure falls back to
    /// system default.
    ForceCursor,
    /// Force system default; never invoke `cursor`.
    ForceSystem,
    /// Suppress opening entirely; the URL is still printed to
    /// stdout via [`OpenOutcome::Printed`].
    None,
}

/// Result of an open attempt. Surfaced to callers so the caller
/// can render a one-liner like "opened in Cursor / opened in
/// system / printed URL only" without re-doing the detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenOutcome {
    /// Spawned `cursor --open-url <url>` successfully.
    Cursor,
    /// Spawned the OS default opener (`open` / `xdg-open` /
    /// `gnome-open` / `kde-open` / `wslview`).
    System { opener: String },
    /// `RAXIS_E2E_BROWSER=none` — suppressed.
    Suppressed,
    /// Could not invoke any opener; URL was printed to stdout.
    Printed,
}

/// Read the explicit `RAXIS_E2E_BROWSER` env override.
///
/// Recognised values (case-insensitive): `cursor`, `system`,
/// `none`. Anything else (including unset) returns
/// [`BrowserPreference::Auto`].
pub fn preference_from_env() -> BrowserPreference {
    match std::env::var("RAXIS_E2E_BROWSER")
        .ok()
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("cursor") => BrowserPreference::ForceCursor,
        Some("system") => BrowserPreference::ForceSystem,
        Some("none") => BrowserPreference::None,
        _ => BrowserPreference::Auto,
    }
}

/// Detect the host environment from process env vars.
///
/// Priority signals:
///   1. `TERM_PROGRAM=cursor` (case-insensitive) — primary signal
///      that Cursor's integrated terminal is the parent process.
///   2. `CURSOR_TRACE_ID` set — Cursor's agent context.
///   3. `CURSOR_LAYOUT` set — Glass layout marker.
///   4. `VSCODE_IPC_HOOK` containing `/Cursor/` — Cursor's IPC
///      socket path (distinct from upstream VSCode's
///      `/Code/`-rooted path).
///
/// VSCode (`TERM_PROGRAM=vscode`) is treated as system-default —
/// the user's Cursor-specific ask is the primary target; VSCode
/// users would need to use `RAXIS_E2E_BROWSER=cursor` explicitly
/// if they want the same in-IDE behaviour (their `code --open-url`
/// shape is identical to Cursor's so the same dispatch would work).
pub fn detect_host_environment() -> HostEnvironment {
    if std::env::var("TERM_PROGRAM")
        .map(|v| v.eq_ignore_ascii_case("cursor"))
        .unwrap_or(false)
    {
        return HostEnvironment::Cursor;
    }
    if std::env::var("CURSOR_TRACE_ID").is_ok() {
        return HostEnvironment::Cursor;
    }
    if std::env::var("CURSOR_LAYOUT").is_ok() {
        return HostEnvironment::Cursor;
    }
    if let Ok(hook) = std::env::var("VSCODE_IPC_HOOK") {
        if hook.contains("/Cursor/") {
            return HostEnvironment::Cursor;
        }
    }
    HostEnvironment::SystemDefault
}

/// Open `url` in the best-available browser for the current host.
///
/// Honours `RAXIS_E2E_BROWSER` (`cursor`, `system`, `none`); falls
/// back to auto-detection from `TERM_PROGRAM` and the `CURSOR_*`
/// env-var family.
///
/// Never panics. Never returns an `Err` for an
/// operator-recoverable condition: an unavailable opener
/// surfaces as [`OpenOutcome::Printed`] with the URL on stdout.
pub fn open_in_best_browser(url: &str) -> OpenOutcome {
    let pref = preference_from_env();
    match pref {
        BrowserPreference::None => {
            // Print the URL to stdout so the operator can still
            // copy-paste; the suppress flag is a "don't focus my
            // window" hint, not a "don't tell me the URL" hint.
            eprintln!("    (RAXIS_E2E_BROWSER=none) {url}");
            return OpenOutcome::Suppressed;
        }
        BrowserPreference::ForceCursor => {
            if let Some(outcome) = try_cursor(url) {
                return outcome;
            }
            // Fall through to system default on cursor-CLI failure.
            eprintln!(
                "    (RAXIS_E2E_BROWSER=cursor) cursor CLI unavailable; \
                 falling back to system default browser"
            );
            return try_system(url).unwrap_or_else(|| print_url(url));
        }
        BrowserPreference::ForceSystem => {
            return try_system(url).unwrap_or_else(|| print_url(url));
        }
        BrowserPreference::Auto => {}
    }
    match detect_host_environment() {
        HostEnvironment::Cursor => {
            if let Some(outcome) = try_cursor(url) {
                return outcome;
            }
            eprintln!(
                "    note: install Cursor CLI \
                 ('Cursor → Shell Command: Install \"cursor\" command in PATH') \
                 to open in the in-IDE browser next time; \
                 falling back to system default browser"
            );
            try_system(url).unwrap_or_else(|| print_url(url))
        }
        HostEnvironment::SystemDefault => try_system(url).unwrap_or_else(|| print_url(url)),
    }
}

/// Find a `cursor` CLI on `$PATH` or in the canonical Cursor.app
/// install location on macOS. Returns `None` when no candidate
/// exists.
pub fn cursor_cli_path() -> Option<PathBuf> {
    if let Some(p) = which::find("cursor") {
        return Some(p);
    }
    // macOS app-bundle fallback. Cursor's "Install cursor command
    // in PATH" command-palette action symlinks
    // `/usr/local/bin/cursor` → this path; users who never ran
    // that action still have the binary at the bundled path.
    if cfg!(target_os = "macos") {
        let bundled = PathBuf::from("/Applications/Cursor.app/Contents/Resources/app/bin/cursor");
        if bundled.exists() {
            return Some(bundled);
        }
    }
    // Linux: common install paths from the official `.deb` /
    // AppImage installs. Keep this list short and obvious; do not
    // walk `$HOME` looking for AppImage extractions.
    if cfg!(target_os = "linux") {
        for candidate in [
            "/usr/share/cursor/cursor",
            "/usr/share/cursor/bin/cursor",
            "/opt/cursor/cursor",
            "/opt/cursor/bin/cursor",
        ] {
            let p = PathBuf::from(candidate);
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

fn try_cursor(url: &str) -> Option<OpenOutcome> {
    let bin = cursor_cli_path()?;
    let status = Command::new(&bin)
        .args(["--open-url", url])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if status.success() {
        eprintln!("    opened in Cursor: {url}");
        Some(OpenOutcome::Cursor)
    } else {
        None
    }
}

fn try_system(url: &str) -> Option<OpenOutcome> {
    // Per-OS preferred opener; fall through every candidate so a
    // Linux without `xdg-open` (a stripped container, an Alpine
    // shell) still gets a shot via `gnome-open` / `kde-open` /
    // `wslview`. macOS' `open(1)` is the only candidate on Darwin
    // — every macOS install ships it.
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &["open"]
    } else if cfg!(target_os = "linux") {
        &["xdg-open", "gnome-open", "kde-open", "wslview"]
    } else if cfg!(target_os = "windows") {
        // Windows: `cmd /C start "" <url>`. We special-case below
        // by returning a tuple via `try_windows`; keep this branch
        // short.
        return try_windows(url);
    } else {
        &["xdg-open"]
    };
    for opener in candidates {
        let spawn = Command::new(opener)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if spawn.is_ok() {
            eprintln!("    opened in system browser via `{opener}`: {url}");
            return Some(OpenOutcome::System {
                opener: (*opener).to_string(),
            });
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn try_windows(url: &str) -> Option<OpenOutcome> {
    // `cmd /C start "" <url>` — the empty `""` is the window
    // title that `start` consumes; without it the URL would be
    // parsed as the title and a blank `cmd` window would pop up.
    let status = Command::new("cmd")
        .args(["/C", "start", "", url])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if status.success() {
        eprintln!("    opened in system browser via `cmd /C start`: {url}");
        Some(OpenOutcome::System {
            opener: "cmd /C start".into(),
        })
    } else {
        None
    }
}

#[cfg(not(target_os = "windows"))]
fn try_windows(_url: &str) -> Option<OpenOutcome> {
    None
}

fn print_url(url: &str) -> OpenOutcome {
    eprintln!("    (no URL opener available — paste manually) {url}");
    OpenOutcome::Printed
}

// Tiny stand-in for `which::which` so we don't pull a third-party
// crate for a one-call need. Walks `$PATH` and returns the first
// hit that's executable.
mod which {
    use std::path::PathBuf;

    pub fn find(bin: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(bin);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    #[cfg(unix)]
    fn is_executable(p: &std::path::Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(p) {
            Ok(m) if m.is_file() => m.permissions().mode() & 0o111 != 0,
            _ => false,
        }
    }

    #[cfg(not(unix))]
    fn is_executable(p: &std::path::Path) -> bool {
        p.is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test sets / unsets env vars on the process; we
    /// serialise via this mutex so parallel test execution doesn't
    /// shuffle env underneath one another. The mutex is module-
    /// local because env state is process-global and there is no
    /// scoped equivalent for `std::env::set_var`.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn snapshot_and_clear() -> Vec<(String, Option<String>)> {
        let keys = [
            "TERM_PROGRAM",
            "CURSOR_TRACE_ID",
            "CURSOR_LAYOUT",
            "VSCODE_IPC_HOOK",
            "RAXIS_E2E_BROWSER",
        ];
        let snap: Vec<_> = keys
            .iter()
            .map(|k| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        for (k, _) in &snap {
            std::env::remove_var(k);
        }
        snap
    }

    fn restore(snap: Vec<(String, Option<String>)>) {
        for (k, v) in snap {
            match v {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
    }

    #[test]
    fn detect_cursor_via_term_program() {
        let _guard = env_guard();
        let snap = snapshot_and_clear();
        std::env::set_var("TERM_PROGRAM", "cursor");
        assert_eq!(detect_host_environment(), HostEnvironment::Cursor);
        std::env::set_var("TERM_PROGRAM", "Cursor");
        assert_eq!(detect_host_environment(), HostEnvironment::Cursor);
        std::env::set_var("TERM_PROGRAM", "CURSOR");
        assert_eq!(detect_host_environment(), HostEnvironment::Cursor);
        restore(snap);
    }

    #[test]
    fn detect_cursor_via_cursor_layout() {
        let _guard = env_guard();
        let snap = snapshot_and_clear();
        std::env::set_var("CURSOR_LAYOUT", "glass");
        assert_eq!(detect_host_environment(), HostEnvironment::Cursor);
        restore(snap);
    }

    #[test]
    fn detect_cursor_via_vscode_ipc_hook() {
        let _guard = env_guard();
        let snap = snapshot_and_clear();
        std::env::set_var(
            "VSCODE_IPC_HOOK",
            "/Users/me/Library/Application Support/Cursor/3.3.-main.sock",
        );
        assert_eq!(detect_host_environment(), HostEnvironment::Cursor);
        restore(snap);
    }

    #[test]
    fn detect_vscode_falls_through_to_system_default() {
        let _guard = env_guard();
        let snap = snapshot_and_clear();
        std::env::set_var("TERM_PROGRAM", "vscode");
        std::env::set_var(
            "VSCODE_IPC_HOOK",
            "/Users/me/Library/Application Support/Code/main.sock",
        );
        assert_eq!(detect_host_environment(), HostEnvironment::SystemDefault);
        restore(snap);
    }

    #[test]
    fn detect_plain_terminal_falls_through_to_system_default() {
        let _guard = env_guard();
        let snap = snapshot_and_clear();
        assert_eq!(detect_host_environment(), HostEnvironment::SystemDefault);
        restore(snap);
    }

    #[test]
    fn preference_env_force_cursor() {
        let _guard = env_guard();
        let snap = snapshot_and_clear();
        std::env::set_var("RAXIS_E2E_BROWSER", "cursor");
        assert_eq!(preference_from_env(), BrowserPreference::ForceCursor);
        std::env::set_var("RAXIS_E2E_BROWSER", "CURSOR");
        assert_eq!(preference_from_env(), BrowserPreference::ForceCursor);
        restore(snap);
    }

    #[test]
    fn preference_env_force_system() {
        let _guard = env_guard();
        let snap = snapshot_and_clear();
        std::env::set_var("RAXIS_E2E_BROWSER", "system");
        assert_eq!(preference_from_env(), BrowserPreference::ForceSystem);
        restore(snap);
    }

    #[test]
    fn preference_env_none_suppresses() {
        let _guard = env_guard();
        let snap = snapshot_and_clear();
        std::env::set_var("RAXIS_E2E_BROWSER", "none");
        assert_eq!(preference_from_env(), BrowserPreference::None);
        restore(snap);
    }

    #[test]
    fn preference_env_unknown_falls_through_to_auto() {
        let _guard = env_guard();
        let snap = snapshot_and_clear();
        std::env::set_var("RAXIS_E2E_BROWSER", "edge");
        assert_eq!(preference_from_env(), BrowserPreference::Auto);
        std::env::remove_var("RAXIS_E2E_BROWSER");
        assert_eq!(preference_from_env(), BrowserPreference::Auto);
        restore(snap);
    }

    #[test]
    fn open_with_none_returns_suppressed_without_spawning() {
        let _guard = env_guard();
        let snap = snapshot_and_clear();
        std::env::set_var("RAXIS_E2E_BROWSER", "none");
        let outcome = open_in_best_browser("http://example.invalid/");
        assert_eq!(outcome, OpenOutcome::Suppressed);
        restore(snap);
    }
}
