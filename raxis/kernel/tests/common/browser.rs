//! Host-browser dispatch for URLs printed by the live-e2e
//! harnesses. Mirrors `raxis/xtask/src/browser.rs` shape so the
//! `cargo xtask observability` and `cargo test
//! --test extended_e2e_realistic_scenario` surfaces both honour
//! the same operator-facing semantics:
//!
//!   * `RAXIS_E2E_BROWSER=cursor` — force the Cursor CLI path.
//!   * `RAXIS_E2E_BROWSER=system` — force the OS default browser.
//!   * `RAXIS_E2E_BROWSER=none`   — suppress, just print the URL.
//!   * Otherwise — auto-detect Cursor via `TERM_PROGRAM` /
//!     `CURSOR_*` / `VSCODE_IPC_HOOK`.
//!
//! We deliberately duplicate the helper instead of pulling
//! `xtask` into the kernel-test build graph (xtask depends on
//! every workspace producer crate; adding it as a dev-dep would
//! grow `cargo test -p raxis-kernel` compile-time substantially).
//! The unit tests in BOTH modules pin the env-var shape so a
//! future change to one path that doesn't apply to the other
//! is caught by `cargo test`.
//!
//! ## Coordination with `common::dashboard::spawn_url_opener`
//!
//! The dashboard-autologin URL path used to call
//! `common::dashboard::spawn_url_opener` directly (`open` /
//! `xdg-open`). That helper now delegates to
//! [`open_in_best_browser`] so the dashboard URL benefits from
//! the same Cursor-in-IDE-browser dispatch as the new
//! observability URL block.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Operator-recognised host environments for URL opening. See
/// `xtask::browser::HostEnvironment` for the canonical surface;
/// this mirror exists so the kernel-test crate doesn't depend on
/// `xtask`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEnvironment {
    Cursor,
    SystemDefault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserPreference {
    Auto,
    ForceCursor,
    ForceSystem,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenOutcome {
    Cursor,
    System { opener: String },
    Suppressed,
    Printed,
}

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

/// Open `url` in the best-available browser. Never panics; never
/// returns an error from the harness perspective — an
/// operator-unfriendly host (no opener available) surfaces as
/// [`OpenOutcome::Printed`] with the URL on stderr.
pub fn open_in_best_browser(url: &str) -> OpenOutcome {
    let pref = preference_from_env();
    match pref {
        BrowserPreference::None => {
            eprintln!("    (RAXIS_E2E_BROWSER=none) {url}");
            return OpenOutcome::Suppressed;
        }
        BrowserPreference::ForceCursor => {
            if let Some(o) = try_cursor(url) {
                return o;
            }
            eprintln!(
                "    (RAXIS_E2E_BROWSER=cursor) cursor CLI unavailable; \
                 falling back to system default"
            );
            return try_system(url).unwrap_or_else(|| print_only(url));
        }
        BrowserPreference::ForceSystem => {
            return try_system(url).unwrap_or_else(|| print_only(url));
        }
        BrowserPreference::Auto => {}
    }
    match detect_host_environment() {
        HostEnvironment::Cursor => {
            if let Some(o) = try_cursor(url) {
                return o;
            }
            eprintln!(
                "    note: install Cursor CLI \
                 ('Cursor → Shell Command: Install \"cursor\" command in PATH') \
                 to open in the in-IDE browser next time; \
                 falling back to system default browser"
            );
            try_system(url).unwrap_or_else(|| print_only(url))
        }
        HostEnvironment::SystemDefault => try_system(url).unwrap_or_else(|| print_only(url)),
    }
}

pub fn cursor_cli_path() -> Option<PathBuf> {
    if let Some(p) = find_on_path("cursor") {
        return Some(p);
    }
    if cfg!(target_os = "macos") {
        let bundled = PathBuf::from("/Applications/Cursor.app/Contents/Resources/app/bin/cursor");
        if bundled.exists() {
            return Some(bundled);
        }
    }
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
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &["open"]
    } else if cfg!(target_os = "linux") {
        &["xdg-open", "gnome-open", "kde-open", "wslview"]
    } else if cfg!(target_os = "windows") {
        return try_windows(url);
    } else {
        &["xdg-open"]
    };
    for opener in candidates {
        let spawned = Command::new(opener)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if spawned.is_ok() {
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

fn print_only(url: &str) -> OpenOutcome {
    eprintln!("    (no URL opener available — paste manually) {url}");
    OpenOutcome::Printed
}

fn find_on_path(bin: &str) -> Option<PathBuf> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let _g = env_guard();
        let s = snapshot_and_clear();
        std::env::set_var("TERM_PROGRAM", "cursor");
        assert_eq!(detect_host_environment(), HostEnvironment::Cursor);
        std::env::set_var("TERM_PROGRAM", "Cursor");
        assert_eq!(detect_host_environment(), HostEnvironment::Cursor);
        restore(s);
    }

    #[test]
    fn detect_cursor_via_cursor_layout() {
        let _g = env_guard();
        let s = snapshot_and_clear();
        std::env::set_var("CURSOR_LAYOUT", "glass");
        assert_eq!(detect_host_environment(), HostEnvironment::Cursor);
        restore(s);
    }

    #[test]
    fn detect_cursor_via_vscode_ipc_hook_cursor_path() {
        let _g = env_guard();
        let s = snapshot_and_clear();
        std::env::set_var(
            "VSCODE_IPC_HOOK",
            "/Users/me/Library/Application Support/Cursor/3.3.-main.sock",
        );
        assert_eq!(detect_host_environment(), HostEnvironment::Cursor);
        restore(s);
    }

    #[test]
    fn detect_vscode_falls_through_to_system_default() {
        let _g = env_guard();
        let s = snapshot_and_clear();
        std::env::set_var("TERM_PROGRAM", "vscode");
        std::env::set_var(
            "VSCODE_IPC_HOOK",
            "/Users/me/Library/Application Support/Code/main.sock",
        );
        assert_eq!(detect_host_environment(), HostEnvironment::SystemDefault);
        restore(s);
    }

    #[test]
    fn preference_env_recognises_all_three_values() {
        let _g = env_guard();
        let s = snapshot_and_clear();
        std::env::set_var("RAXIS_E2E_BROWSER", "cursor");
        assert_eq!(preference_from_env(), BrowserPreference::ForceCursor);
        std::env::set_var("RAXIS_E2E_BROWSER", "system");
        assert_eq!(preference_from_env(), BrowserPreference::ForceSystem);
        std::env::set_var("RAXIS_E2E_BROWSER", "none");
        assert_eq!(preference_from_env(), BrowserPreference::None);
        std::env::set_var("RAXIS_E2E_BROWSER", "edge");
        assert_eq!(preference_from_env(), BrowserPreference::Auto);
        std::env::remove_var("RAXIS_E2E_BROWSER");
        assert_eq!(preference_from_env(), BrowserPreference::Auto);
        restore(s);
    }

    #[test]
    fn open_with_none_returns_suppressed() {
        let _g = env_guard();
        let s = snapshot_and_clear();
        std::env::set_var("RAXIS_E2E_BROWSER", "none");
        assert_eq!(
            open_in_best_browser("http://example.invalid/"),
            OpenOutcome::Suppressed
        );
        restore(s);
    }
}
