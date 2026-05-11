//! Tiny `/healthz` HTTP endpoint.
//!
//! Spec: `v3/otel-observability.md §12.5`.
//!
//! ## Why hand-rolled?
//!
//! The pusher already pulls in `tokio` + `reqwest` (for outbound
//! OTLP). Adding a server framework like `axum` or `hyper-util` for
//! a single endpoint that returns a 1-KiB JSON body would balloon
//! compile time and binary size for no real value. The endpoint
//! handles exactly two HTTP/1.1 verbs (`GET /healthz` → 200 with
//! body, anything else → 404) and never sees more than one
//! concurrent request from `raxis doctor`.
//!
//! The server lives behind a `tokio::sync::watch::Sender<HealthSnapshot>`
//! the main loop publishes to after every export attempt.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Snapshot the main loop publishes after each export attempt.
#[derive(Debug, Clone, Serialize, Default)]
pub struct HealthSnapshot {
    /// `"ok"` when the most recent export succeeded; `"degraded"`
    /// after the first failure; `"failing"` after `consecutive_failures
    /// >= max_attempts`.
    pub status: String,
    /// Wallclock at most recent export attempt (success OR failure).
    pub last_export_attempt_unix: i64,
    /// Wallclock at most recent successful export.
    pub last_export_success_unix: i64,
    /// Number of consecutive failures since the last success.
    pub consecutive_failures: u32,
    /// Total spans exported across the lifetime of this pusher.
    pub spans_exported_total: u64,
    /// Total metrics exported across the lifetime of this pusher.
    pub metrics_exported_total: u64,
    /// Total batches dropped after exhausting retries.
    pub spans_dropped_total: u64,
    /// Distance (segments) between the cursor's current segment
    /// and the kernel's currently-active segment, summed across
    /// streams.
    pub cursor_lag_segments: u64,
}

impl HealthSnapshot {
    /// Initial snapshot for a freshly-booted pusher.
    pub fn initial() -> Self {
        Self {
            status: "starting".to_owned(),
            ..Self::default()
        }
    }
}

/// Spawn the `/healthz` listener on `127.0.0.1:port`.
///
/// Returns a [`tokio::sync::watch::Sender`] the main loop uses to
/// publish snapshots. The listener task is cancelled when the
/// returned [`tokio::task::JoinHandle`] is dropped.
pub async fn spawn(
    port:    u16,
    initial: HealthSnapshot,
) -> std::io::Result<HealthHandle> {
    let (tx, rx) = watch::channel(initial);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let bound_port = listener.local_addr()?.port();
    let rx_clone = rx.clone();
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _peer)) => {
                    let snapshot = rx_clone.borrow().clone();
                    let _ = handle_connection(&mut stream, snapshot).await;
                }
                Err(e) => {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"otel_pusher_health_accept_failed\",\
                          \"reason\":\"{e}\"}}"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(HealthHandle {
        snapshot:   tx,
        port:       bound_port,
        _listener:  Arc::new(handle),
    })
}

/// Handle to a running health server.
#[derive(Clone)]
pub struct HealthHandle {
    /// Sender side of the watch channel; main loop publishes
    /// snapshots through it.
    pub snapshot: watch::Sender<HealthSnapshot>,
    /// Bound port (useful when the operator passed `port = 0` for
    /// auto-allocation in tests).
    pub port:     u16,
    /// Listener task handle; cloning the handle keeps the task
    /// alive for as long as any clone exists. Underscored to
    /// make the "kept-alive ref-count" semantics explicit.
    _listener:    Arc<tokio::task::JoinHandle<()>>,
}

impl HealthHandle {
    /// Update the snapshot. Cheap; the watch channel only wakes
    /// pending receivers.
    pub fn publish(&self, s: HealthSnapshot) {
        let _ = self.snapshot.send(s);
    }
}

async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    snap:   HealthSnapshot,
) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let mut request = Vec::with_capacity(256);
    let mut total = 0;
    // We don't care about the body; the request line is enough.
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 { break; }
        request.extend_from_slice(&buf[..n]);
        total += n;
        if request.windows(4).any(|w| w == b"\r\n\r\n") || total >= 16 * 1024 {
            break;
        }
    }
    let body_str = std::str::from_utf8(&request).unwrap_or("");
    let first_line = body_str.lines().next().unwrap_or("");
    if first_line.starts_with("GET /healthz") {
        let body = serde_json::to_string(&snap).unwrap_or_else(|_| "{}".into());
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        stream.write_all(resp.as_bytes()).await?;
    } else {
        let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(resp).await?;
    }
    let _ = stream.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::io::Write;
    use std::net::TcpStream;

    #[tokio::test]
    async fn healthz_returns_snapshot_json() {
        let h = spawn(0, HealthSnapshot::initial()).await.unwrap();
        h.publish(HealthSnapshot {
            status: "ok".to_owned(),
            last_export_success_unix: 100,
            spans_exported_total: 42,
            ..HealthSnapshot::default()
        });
        let port = h.port;
        let body = tokio::task::spawn_blocking(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let mut buf = String::new();
            s.read_to_string(&mut buf).unwrap();
            buf
        }).await.unwrap();
        assert!(body.contains("HTTP/1.1 200 OK"));
        assert!(body.contains("\"status\":\"ok\""));
        assert!(body.contains("\"spans_exported_total\":42"));
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let h = spawn(0, HealthSnapshot::initial()).await.unwrap();
        let port = h.port;
        let body = tokio::task::spawn_blocking(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(b"GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let mut buf = String::new();
            s.read_to_string(&mut buf).unwrap();
            buf
        }).await.unwrap();
        assert!(body.contains("HTTP/1.1 404"));
    }
}
