// raxis-supervisor::log — JSON-line stderr logger.
//
// Normative reference: `self-healing-supervisor.md §4.7`.
//
// The supervisor's stderr log is forensic evidence, not the
// authoritative audit trail. Operators tail
// `<data_dir>/supervisor.stderr.log` to reconstruct supervisor-
// side decisions; the kernel's audit chain
// (`KernelDeadlockDetected` / `KernelRestartInitiated` /
// `KernelRestartCompleted` / `KernelRestartHaltedCircuitOpen`)
// remains the authoritative record.
//
// **Format.** One JSON object per line, no trailing whitespace,
// `\n`-terminated. Fields:
//
//   * `ts`     — RFC3339 wallclock (chrono::Utc)
//   * `level`  — `"info"` / `"warn"` / `"error"`
//   * `event`  — PascalCase event name (matches the kernel's
//                 audit-event names where applicable)
//   * other event-specific fields appended as JSON values
//
// **Why we duplicate the writer.** The supervisor crate
// intentionally has no dependency on `raxis-runtime` /
// `raxis-observability` — it must be buildable + runnable even
// if the kernel observability stack is mid-refactor. ~50 LOC of
// `serde_json::to_string + writeln!` is cheaper than coupling
// the supervisor to the kernel's logging stack.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;

/// Stderr-log filename per `self-healing-supervisor.md §4.7`.
pub const LOG_FILENAME: &str = "supervisor.stderr.log";

/// JSON-line logger. Owns its own writer + mutex so a single
/// instance can be shared across the supervisor's tasks without
/// interleaving lines.
#[derive(Debug)]
pub struct SupervisorLog {
    path:   PathBuf,
    writer: Mutex<std::fs::File>,
}

impl SupervisorLog {
    /// Open / create the log file in append mode. The file is
    /// kept open for the supervisor's entire lifetime; rotation
    /// is the operator's responsibility (logrotate, etc.).
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(LOG_FILENAME);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path,
            writer: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Emit one JSON-line record. Best-effort — write failures
    /// (disk-full, EROFS) fall back to a `eprintln!` mirror so
    /// the operator running the supervisor in the foreground
    /// still sees the line.
    pub fn emit<T: Serialize>(&self, level: &str, event: &str, payload: &T) {
        let now = chrono::Utc::now().to_rfc3339();
        let mut obj = serde_json::Map::new();
        obj.insert("ts".to_owned(), serde_json::Value::String(now));
        obj.insert(
            "level".to_owned(),
            serde_json::Value::String(level.to_owned()),
        );
        obj.insert(
            "event".to_owned(),
            serde_json::Value::String(event.to_owned()),
        );
        if let Ok(serde_json::Value::Object(payload_map)) = serde_json::to_value(payload) {
            for (k, v) in payload_map {
                obj.insert(k, v);
            }
        }
        let line = match serde_json::to_string(&serde_json::Value::Object(obj)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"supervisor_log_serialize_failed\",\
                     \"reason\":\"{e}\"}}"
                );
                return;
            }
        };
        if let Ok(mut guard) = self.writer.lock() {
            if let Err(e) = writeln!(*guard, "{line}") {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"supervisor_log_write_failed\",\
                     \"reason\":\"{e}\"}}"
                );
                eprintln!("{line}");
            }
        } else {
            eprintln!("{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn open_creates_file_in_data_dir() {
        let dir = tempdir().unwrap();
        let log = SupervisorLog::open(dir.path()).expect("open");
        assert_eq!(log.path(), dir.path().join(LOG_FILENAME));
        assert!(log.path().exists());
    }

    #[test]
    fn emit_appends_a_json_line_with_event_payload() {
        let dir = tempdir().unwrap();
        let log = SupervisorLog::open(dir.path()).unwrap();
        log.emit(
            "info",
            "supervisor_started",
            &serde_json::json!({ "supervisor_pid": 12345 }),
        );
        log.emit(
            "warn",
            "circuit_breaker_tripped",
            &serde_json::json!({ "attempts_in_window": 4, "window_secs": 60 }),
        );
        let contents = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "supervisor_started");
        assert_eq!(first["level"], "info");
        assert_eq!(first["supervisor_pid"], 12345);
        assert!(first["ts"].is_string());
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["event"], "circuit_breaker_tripped");
        assert_eq!(second["attempts_in_window"], 4);
    }
}
