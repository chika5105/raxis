// raxis-ipc::frame — async read/write for the 4-byte LE length-prefix framing.
//
// Normative reference: specs/v1/peripherals.md §3 opening normative note.
//
// Frame format:
//   [4 bytes: u32 little-endian body length] [N bytes: bincode-encoded body]
//   The 4-byte prefix encodes N (body byte count); it is NOT included in N.
//
// Codec: bincode::config::standard() — varint integers, LE byte order,
//   no field names. Implementations MUST NOT use config::legacy().
//
// Maximum frame body size: 64 MiB (64 * 1024 * 1024 bytes). Any frame
// announcing a body larger than this is rejected with FrameError::TooLarge.
// The 16 MiB gateway response limit is enforced separately in the gateway
// handler; the frame layer allows up to 64 MiB to leave headroom for future
// message types while still bounding memory allocation on malformed input.

use bincode::config::standard;
use raxis_observability::{redact, MetricName, ObservabilityHub};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum allowed body byte count. Frames announcing more are rejected.
pub const MAX_FRAME_BODY_BYTES: u32 = 64 * 1024 * 1024; // 64 MiB

// ---------------------------------------------------------------------------
// iter61 — `INV-OBSERVABILITY-DATAPLANE-LATENCY-05` per-stage histograms.
// ---------------------------------------------------------------------------
//
// Closed lexicon of bincode-IPC frame stages, mirrored from
// `kernel/src/observability.rs::IPC_FRAME_STAGES`. Adding a stage
// here MUST be paired with a matching wire-up in `write_frame` /
// `read_frame`.
const IPC_FRAME_STAGE_ENCODE: &str = "encode";
const IPC_FRAME_STAGE_WRITE: &str = "write";
const IPC_FRAME_STAGE_READ: &str = "read";
const IPC_FRAME_STAGE_DECODE: &str = "decode";

/// Process-global `ObservabilityHub` handle the four stage-emit
/// helpers consult on every frame. Mirrors the shape of
/// `raxis-worktree-provision`'s opt-in observability seam — set
/// once at kernel boot via [`set_global_observability_hub`], unset
/// by default so kernel-less CLI tools, planner-side fixtures, and
/// the standalone bincode round-trip tests pay zero per-frame
/// overhead.
static OBSERVABILITY_HUB: OnceLock<Arc<ObservabilityHub>> = OnceLock::new();

/// Wire the process-global observability hub the framing layer
/// emits `raxis.kernel.substrate.ipc.frame.stage.duration` samples
/// to. Idempotent — a second call is a no-op (the `OnceLock::set`
/// returns `Err`, which we discard so re-entrant test boots don't
/// panic).
pub fn set_global_observability_hub(hub: Arc<ObservabilityHub>) {
    let _ = OBSERVABILITY_HUB.set(hub);
}

/// Emit one `raxis.kernel.substrate.ipc.frame.stage.duration`
/// histogram observation tagged with `stage` + `outcome`. The
/// `role` and `message_kind` labels collapse to `"unknown"` here
/// because the framing layer is generic over `T`; richer per-call
/// tagging stays at the kernel substrate IPC dispatcher seam
/// (`KernelSubstrateIpcRoundtrip`), which already pivots the
/// end-to-end RTT histogram by the static `(role, message_kind)`
/// closed lexicon. Hub-disabled fast path early-returns on the
/// `OnceLock::get()` arm — zero per-frame overhead.
fn record_frame_stage(stage: &str, outcome: &str, duration_ms: i64) {
    let Some(hub) = OBSERVABILITY_HUB.get() else {
        return;
    };
    if !hub.enabled() {
        return;
    }
    let labels = redact::attrs([
        ("role", "unknown"),
        ("message_kind", "unknown"),
        ("stage", stage),
        ("outcome", outcome),
    ]);
    hub.record_histogram(
        MetricName::IpcFrameStageDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

// ---------------------------------------------------------------------------
// FrameError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error reading/writing frame: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame body of {0} bytes exceeds maximum {MAX_FRAME_BODY_BYTES}")]
    TooLarge(u32),

    #[error("bincode encode error: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("bincode decode error: {0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("connection closed cleanly (EOF on length prefix)")]
    Eof,
}

// ---------------------------------------------------------------------------
// write_frame<T>
//
// Serialises `msg` with bincode::config::standard(), prepends the 4-byte LE
// body length, and writes both to `writer`. Flushes after writing.
// ---------------------------------------------------------------------------

/// Encode `msg` to bincode and write it as a length-prefixed frame.
///
/// # Wire layout
/// ```text
/// ┌──────────────────────────────┬──────────────────────┐
/// │  body_len: u32 little-endian │  body: [u8; body_len]│
/// └──────────────────────────────┴──────────────────────┘
/// ```
pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    // INV-OBSERVABILITY-DATAPLANE-LATENCY-05 stage 1 — `encode`.
    // Times the bincode serialise. Both arms emit so the dashboard
    // can rank a slow encode (large `IntegrationMergeCompleted`
    // payload) separately from a slow disk write.
    let encode_started = Instant::now();
    let body = match bincode::serde::encode_to_vec(msg, standard()) {
        Ok(b) => {
            record_frame_stage(
                IPC_FRAME_STAGE_ENCODE,
                "ok",
                encode_started.elapsed().as_millis() as i64,
            );
            b
        }
        Err(e) => {
            record_frame_stage(
                IPC_FRAME_STAGE_ENCODE,
                "error",
                encode_started.elapsed().as_millis() as i64,
            );
            return Err(FrameError::Encode(e));
        }
    };

    let body_len = body.len() as u32;
    if body_len > MAX_FRAME_BODY_BYTES {
        return Err(FrameError::TooLarge(body_len));
    }

    // INV-OBSERVABILITY-DATAPLANE-LATENCY-05 stage 2 — `write`.
    // Times the prefix + body + flush. Both arms emit so a slow
    // peer's TCP back-pressure surfaces as an error-tagged sample.
    let write_started = Instant::now();
    let write_result = async {
        writer.write_all(&body_len.to_le_bytes()).await?;
        writer.write_all(&body).await?;
        writer.flush().await?;
        Ok::<(), std::io::Error>(())
    }
    .await;
    match write_result {
        Ok(()) => {
            record_frame_stage(
                IPC_FRAME_STAGE_WRITE,
                "ok",
                write_started.elapsed().as_millis() as i64,
            );
            Ok(())
        }
        Err(e) => {
            record_frame_stage(
                IPC_FRAME_STAGE_WRITE,
                "error",
                write_started.elapsed().as_millis() as i64,
            );
            Err(FrameError::Io(e))
        }
    }
}

// ---------------------------------------------------------------------------
// read_frame<T>
//
// Reads a 4-byte LE length prefix, allocates a buffer of that many bytes,
// fills it, then decodes the bincode payload into T.
// ---------------------------------------------------------------------------

/// Read a length-prefixed frame from `reader` and decode it as `T`.
///
/// Returns `FrameError::Eof` on a clean EOF while reading the length prefix
/// (i.e. the remote peer closed the connection between messages). Any other
/// EOF mid-frame is an `io::Error` (UnexpectedEof).
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    // INV-OBSERVABILITY-DATAPLANE-LATENCY-05 stage 3 — `read`.
    // Times the prefix + body fill, including the head-of-frame
    // EOF detection. Both arms emit so a slow peer (or a stuck
    // socket) surfaces as an error-tagged sample.
    let read_started = Instant::now();
    let read_result = async {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Clean EOF between frames — peer closed the connection.
                return Err(FrameError::Eof);
            }
            Err(e) => return Err(FrameError::Io(e)),
        }

        let body_len = u32::from_le_bytes(len_buf);
        if body_len > MAX_FRAME_BODY_BYTES {
            return Err(FrameError::TooLarge(body_len));
        }

        let mut body = vec![0u8; body_len as usize];
        reader.read_exact(&mut body).await?;
        Ok(body)
    }
    .await;
    let body = match read_result {
        Ok(b) => {
            record_frame_stage(
                IPC_FRAME_STAGE_READ,
                "ok",
                read_started.elapsed().as_millis() as i64,
            );
            b
        }
        Err(e) => {
            // EOF on a clean disconnect counts as `ok` — the
            // dashboard's bottleneck pivot is interested in the
            // error rate of mid-frame failures, not the polite
            // peer-closed signal that's normal at process exit.
            let outcome = match &e {
                FrameError::Eof => "ok",
                _ => "error",
            };
            record_frame_stage(
                IPC_FRAME_STAGE_READ,
                outcome,
                read_started.elapsed().as_millis() as i64,
            );
            return Err(e);
        }
    };

    // INV-OBSERVABILITY-DATAPLANE-LATENCY-05 stage 4 — `decode`.
    // Times the bincode deserialise. Both arms emit so a wire-
    // protocol mismatch (planner emitting a stale variant) lights
    // up the error histogram.
    let decode_started = Instant::now();
    match bincode::serde::decode_from_slice(&body, standard()) {
        Ok((msg, _consumed)) => {
            record_frame_stage(
                IPC_FRAME_STAGE_DECODE,
                "ok",
                decode_started.elapsed().as_millis() as i64,
            );
            Ok(msg)
        }
        Err(e) => {
            record_frame_stage(
                IPC_FRAME_STAGE_DECODE,
                "error",
                decode_started.elapsed().as_millis() as i64,
            );
            Err(FrameError::Decode(e))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tokio::io::duplex;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Ping {
        id: u64,
        payload: String,
    }

    #[tokio::test]
    async fn round_trip_single_frame() {
        let msg = Ping {
            id: 42,
            payload: "hello raxis".to_owned(),
        };

        let (mut client, mut server) = duplex(4096);

        write_frame(&mut client, &msg).await.unwrap();
        let received: Ping = read_frame(&mut server).await.unwrap();

        assert_eq!(msg, received);
    }

    #[tokio::test]
    async fn round_trip_multiple_frames() {
        let msgs: Vec<Ping> = (0..5)
            .map(|i| Ping {
                id: i,
                payload: format!("msg-{}", i),
            })
            .collect();

        let (mut client, mut server) = duplex(65536);

        for m in &msgs {
            write_frame(&mut client, m).await.unwrap();
        }
        drop(client); // signal EOF after all frames written

        for expected in &msgs {
            let got: Ping = read_frame(&mut server).await.unwrap();
            assert_eq!(expected, &got);
        }

        // Next read should return Eof cleanly.
        let result: Result<Ping, _> = read_frame(&mut server).await;
        assert!(matches!(result, Err(FrameError::Eof)));
    }

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let (mut client, mut server) = duplex(16);

        // Manually write a frame claiming MAX+1 bytes.
        let fake_len: u32 = MAX_FRAME_BODY_BYTES + 1;
        client.write_all(&fake_len.to_le_bytes()).await.unwrap();

        let result: Result<Ping, _> = read_frame(&mut server).await;
        assert!(matches!(result, Err(FrameError::TooLarge(_))));
    }

    // ------------------------------------------------------------------
    // INV-OBSERVABILITY-DATAPLANE-LATENCY-05 — per-stage histogram
    // witnesses (encode / write / read / decode).
    // ------------------------------------------------------------------
    //
    // The framing layer's hub handle lives in a process-global
    // `OnceLock` (mirrored from `raxis-worktree-provision`).
    // `OnceLock::set` is one-shot, so the witness exercises the
    // disabled-path / happy-path / error-path arms in one test
    // under a process-local serial guard.

    fn obs_serial_guard() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        match LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    // The `obs_serial_guard()` MutexGuard is held across awaits
    // for this witness's entire body — that's the point: every
    // other observability-touching test in this binary funnels
    // through the same lock so no two of them race the global
    // `OnceLock`-backed hub. The clippy lint is fired purely
    // because the std::sync::Mutex API doesn't yield across the
    // await — but this test is single-threaded inside one
    // tokio runtime, so deadlocking is not possible. The
    // attribute is targeted at exactly this witness rather than
    // suppressing it crate-wide.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn frame_stage_histograms_cover_encode_write_read_decode() {
        use raxis_observability::{
            exporter::{InMemoryExporter, ObservabilityExporter},
            AttrValue, DataPoint, HubConfig, MetricName, ObservabilityHub,
        };

        let _g = obs_serial_guard();

        // ── Witness #3 — hub-disabled fast path. The
        //    `OBSERVABILITY_HUB` global is empty before any test
        //    touches `set_global_observability_hub`. We capture the
        //    "before" state here, run a frame round-trip, and
        //    confirm no panic + the global stays empty.
        if OBSERVABILITY_HUB.get().is_none() {
            let msg = Ping {
                id: 1,
                payload: "inert".to_owned(),
            };
            let (mut c, mut s) = duplex(4096);
            write_frame(&mut c, &msg).await.unwrap();
            let _: Ping = read_frame(&mut s).await.unwrap();
            assert!(
                OBSERVABILITY_HUB.get().is_none(),
                "the global hub must remain unset after a hub-disabled round-trip"
            );
        }

        // ── Witness #1 — wire the hub and assert all four stages
        //    emit on a successful round-trip in the documented
        //    encode → write → read → decode order.
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled: true,
            sample_rate: 1.0,
            max_queue_depth: 1024,
            max_attrs_per_span: 32,
            max_events_per_span: 16,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            Arc::clone(&exp) as Arc<dyn ObservabilityExporter>,
        ));
        set_global_observability_hub(Arc::clone(&hub));

        let msg = Ping {
            id: 7,
            payload: "happy".to_owned(),
        };
        let (mut c, mut s) = duplex(4096);
        write_frame(&mut c, &msg).await.unwrap();
        let _: Ping = read_frame(&mut s).await.unwrap();
        hub.flush();

        let stage_counts: std::collections::BTreeMap<(String, String), u64> = exp
            .metrics()
            .into_iter()
            .filter(|m| m.name == MetricName::IpcFrameStageDuration)
            .filter_map(|m| {
                let count = match m.datapoint {
                    DataPoint::Histo { count, .. } => count,
                    _ => return None,
                };
                let s = |key: &str| match m.labels.get(key) {
                    Some(AttrValue::Str(s)) => s.clone(),
                    _ => String::new(),
                };
                Some(((s("stage"), s("outcome")), count))
            })
            .fold(std::collections::BTreeMap::new(), |mut acc, (k, v)| {
                *acc.entry(k).or_default() += v;
                acc
            });
        for stage in ["encode", "write", "read", "decode"] {
            let key = (stage.to_owned(), "ok".to_owned());
            assert!(
                stage_counts.get(&key).copied().unwrap_or(0) >= 1,
                "expected ≥1 ok sample for stage {stage:?}; got {stage_counts:#?}",
            );
        }

        // ── Witness #2 — error-path arm. A bogus length-prefix
        //    that exceeds the cap surfaces `FrameError::TooLarge`
        //    from the `read` stage; the per-stage histogram MUST
        //    NOT silently swallow this — the dashboard's error
        //    histogram is the operator's "wire-protocol regression"
        //    signal. (TooLarge fast-paths inside the read closure
        //    so it lands as a `read` outcome=error sample.)
        let (mut bad_c, mut bad_s) = duplex(16);
        let fake_len: u32 = MAX_FRAME_BODY_BYTES + 1;
        bad_c.write_all(&fake_len.to_le_bytes()).await.unwrap();
        let result: Result<Ping, _> = read_frame(&mut bad_s).await;
        assert!(matches!(result, Err(FrameError::TooLarge(_))));
        hub.flush();

        let any_read_error = exp.metrics().iter().any(|m| {
            m.name == MetricName::IpcFrameStageDuration
                && matches!(m.labels.get("stage"), Some(AttrValue::Str(s)) if s == "read")
                && matches!(m.labels.get("outcome"), Some(AttrValue::Str(s)) if s == "error")
        });
        assert!(
            any_read_error,
            "expected at least one (stage=read, outcome=error) sample on TooLarge"
        );
    }
}
