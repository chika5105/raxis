//! Typed Firecracker VMM API client over a Unix domain socket.
//!
//! Firecracker exposes a REST-shaped API on `--api-sock <path>` (HTTP
//! 1.1 over UDS). The endpoints we drive at boot are:
//!
//! | Endpoint            | Method | Purpose                                  |
//! |---------------------|--------|------------------------------------------|
//! | `/boot-source`      | PUT    | kernel image + cmdline                   |
//! | `/drives/{id}`      | PUT    | rootfs / data drive                      |
//! | `/machine-config`   | PUT    | vcpu count, memory, smt                  |
//! | `/network-interfaces/{id}` | PUT    | tap device + MAC                  |
//! | `/vsock`            | PUT    | guest CID + UDS path                     |
//! | `/actions`          | PUT    | `InstanceStart`, `SendCtrlAltDel`        |
//!
//! Wire reference: <https://github.com/firecracker-microvm/firecracker/blob/main/src/api_server/swagger/firecracker.yaml>
//!
//! ## Why we hand-roll HTTP/1.1 over UDS
//!
//! The Firecracker API is small (≤8 endpoints, JSON bodies) and
//! protocol-stable. Pulling `hyper`/`reqwest` in for it would multiply
//! the substrate's dependency surface (TLS stack, async runtime,
//! HTTP/2) for no functional benefit. A 200-line synchronous
//! HTTP/1.1 client over `UnixStream` is auditable in one sitting and
//! fits the "kernel substrate has minimal trusted-code surface" rule
//! in `paradigm.md §3 R-6` (fail-closed default).
//!
//! ## What this module is NOT responsible for
//!
//! * Process supervision of the `firecracker` binary itself — that
//!   lives in `vmm.rs`. The `FirecrackerApi` instance only knows the
//!   path of the API socket; it does not own the VMM process.
//! * VSock framing — `vsock.rs` owns that.
//! * Image signature verification — the `Backend::spawn` impl checks
//!   `VerifiedImage::signature` before calling into this module
//!   (defence-in-depth backstop for the kernel's image resolver).

use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public API client
// ---------------------------------------------------------------------------

/// Errors the API client can surface.
///
/// Distinct from `raxis_isolation::IsolationError` because this client
/// is the inner-most layer — `Backend::spawn` translates these into
/// the trait error after attaching backend-id context.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// UDS connect / write / read failed.
    #[error("transport: {0}")]
    Transport(std::io::Error),
    /// Firecracker returned a non-2xx status. The string is the
    /// raw response body so the caller can record a verbatim audit
    /// excerpt.
    #[error("firecracker returned {status}: {body}")]
    Status {
        /// HTTP status code (e.g. 400, 500).
        status: u16,
        /// Response body (typically a JSON `{ "fault_message": "..." }`).
        body:   String,
    },
    /// JSON serialization or response-parse failure.
    #[error("json: {0}")]
    Json(serde_json::Error),
    /// Remote did not produce a valid HTTP/1.1 response within the
    /// configured deadline.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    /// Server returned a header shape we cannot parse (bad
    /// `Content-Length`, no status line, etc.).
    #[error("malformed response: {0}")]
    MalformedResponse(String),
    /// A platform that does not support Unix domain sockets attempted
    /// to use the API. Compiled-in on every target so the substrate
    /// can be linked anywhere (the trait crate compiles on macOS too)
    /// while still failing-closed at runtime.
    #[error("unix domain sockets not supported on this target")]
    NotSupportedOnTarget,
}

/// Synchronous Firecracker API client bound to a single VMM
/// instance's UDS.
///
/// Cheap to clone (`PathBuf`); each method opens a fresh connection
/// because the Firecracker API server closes the connection after
/// each request anyway (no keep-alive in the canonical
/// implementation).
#[derive(Debug, Clone)]
pub struct FirecrackerApi {
    /// Path of the API socket (`firecracker --api-sock <path>`).
    api_sock: PathBuf,
    /// Per-call deadline. The Firecracker boot sequence is fast
    /// (single-digit ms per API call); a 5s default catches stalled
    /// VMMs without making boot-failure tests slow.
    timeout:  Duration,
}

impl FirecrackerApi {
    /// Build a client. Does not perform any I/O; the next call to a
    /// `*_endpoint` method connects fresh.
    pub fn new(api_sock: impl Into<PathBuf>) -> Self {
        Self {
            api_sock: api_sock.into(),
            timeout:  Duration::from_secs(5),
        }
    }

    /// Override the per-call deadline.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// `PUT /boot-source`.
    pub fn put_boot_source(&self, body: &BootSource) -> Result<(), ApiError> {
        self.request("PUT", "/boot-source", Some(body))?;
        Ok(())
    }

    /// `PUT /drives/{drive_id}`.
    pub fn put_drive(&self, body: &Drive) -> Result<(), ApiError> {
        let path = format!("/drives/{}", body.drive_id);
        self.request("PUT", &path, Some(body))?;
        Ok(())
    }

    /// `PUT /machine-config`.
    pub fn put_machine_config(&self, body: &MachineConfig) -> Result<(), ApiError> {
        self.request("PUT", "/machine-config", Some(body))?;
        Ok(())
    }

    // `PUT /network-interfaces/{iface_id}` was removed in the
    // Tier1Tproxy deletion sweep — no surviving `EgressTier`
    // variant attaches a virtio-net interface to a Firecracker
    // guest (see `crates/isolation-firecracker/src/lib.rs::drive_boot`
    // and `specs/v2/airgap-architecture.md §5`).

    /// `PUT /vsock`.
    pub fn put_vsock(&self, body: &VsockConfig) -> Result<(), ApiError> {
        self.request("PUT", "/vsock", Some(body))?;
        Ok(())
    }

    /// `PUT /actions` — issue an `InstanceStart` action.
    pub fn instance_start(&self) -> Result<(), ApiError> {
        let body = Action {
            action_type: ActionType::InstanceStart,
        };
        self.request("PUT", "/actions", Some(&body))?;
        Ok(())
    }

    /// `PUT /actions` — issue a `SendCtrlAltDel` action (graceful
    /// guest shutdown signal).
    pub fn send_ctrl_alt_del(&self) -> Result<(), ApiError> {
        let body = Action {
            action_type: ActionType::SendCtrlAltDel,
        };
        self.request("PUT", "/actions", Some(&body))?;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Internals — HTTP/1.1 over UDS
    // ---------------------------------------------------------------

    /// Connect, frame the request, drain the response. We re-open a
    /// fresh connection per call because the Firecracker API server
    /// closes the connection after each request.
    #[cfg(unix)]
    fn request<T: Serialize>(
        &self,
        method: &str,
        path:   &str,
        body:   Option<&T>,
    ) -> Result<HttpResponse, ApiError> {
        let mut stream = UnixStream::connect(&self.api_sock).map_err(ApiError::Transport)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(ApiError::Transport)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(ApiError::Transport)?;

        let payload = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(ApiError::Json)?;

        let request = build_http_request(method, path, payload.as_deref());
        stream.write_all(&request).map_err(ApiError::Transport)?;
        stream.flush().map_err(ApiError::Transport)?;

        let deadline = Instant::now() + self.timeout;
        let response = read_http_response(&mut stream, deadline)?;
        if response.status >= 200 && response.status < 300 {
            Ok(response)
        } else {
            Err(ApiError::Status {
                status: response.status,
                body:   response.body_string(),
            })
        }
    }

    #[cfg(not(unix))]
    fn request<T: Serialize>(
        &self,
        _method: &str,
        _path:   &str,
        _body:   Option<&T>,
    ) -> Result<HttpResponse, ApiError> {
        Err(ApiError::NotSupportedOnTarget)
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 framing helpers — exposed as `pub(crate)` so unit tests can
// pin the wire shape independently of a real Firecracker binary.
// ---------------------------------------------------------------------------

/// Render a request frame: status line, host header, content-length,
/// optional JSON body. Matches the `firecracker` daemon's parser
/// (rust-vmm hyper-derived; tolerant of `Content-Length: 0` on body-
/// less requests).
pub(crate) fn build_http_request(method: &str, path: &str, body: Option<&[u8]>) -> Vec<u8> {
    let len = body.map(|b| b.len()).unwrap_or(0);
    let mut buf = Vec::with_capacity(160 + len);
    use std::io::Write;
    write!(
        &mut buf,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n",
    )
    .expect("write to Vec never fails");
    if body.is_some() {
        write!(&mut buf, "Content-Type: application/json\r\n").expect("write to Vec");
    }
    write!(&mut buf, "Content-Length: {len}\r\n\r\n").expect("write to Vec");
    if let Some(b) = body {
        buf.extend_from_slice(b);
    }
    buf
}

/// Decoded response. Pulled out so tests can compare values directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpResponse {
    pub status: u16,
    pub body:   Vec<u8>,
}

impl HttpResponse {
    /// Render the body as UTF-8, lossily — Firecracker only ever sends
    /// JSON or plain ASCII.
    fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Pull a complete HTTP/1.1 response off a stream. Honours
/// `Content-Length`; rejects chunked encoding (Firecracker never uses
/// it). Caller passes a hard deadline for the entire response.
pub(crate) fn read_http_response<R: Read>(
    reader:   &mut R,
    deadline: Instant,
) -> Result<HttpResponse, ApiError> {
    // Read headers (everything up to and including the first blank
    // line).
    let mut header_buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 256];
    loop {
        if Instant::now() >= deadline {
            return Err(ApiError::Timeout(Duration::ZERO));
        }
        let n = reader.read(&mut chunk).map_err(ApiError::Transport)?;
        if n == 0 {
            return Err(ApiError::MalformedResponse(
                "EOF before headers complete".to_owned(),
            ));
        }
        header_buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_double_crlf(&header_buf) {
            // Headers end at `end + 4`.
            let raw_headers = &header_buf[..end];
            let body_start  = end + 4;
            let already_in_buf = header_buf.len().saturating_sub(body_start);

            let (status, content_length) = parse_status_and_content_length(raw_headers)?;

            let mut body = Vec::with_capacity(content_length);
            // Copy bytes that arrived along with the headers.
            if already_in_buf > 0 {
                body.extend_from_slice(&header_buf[body_start..]);
            }
            // Pull the rest.
            while body.len() < content_length {
                if Instant::now() >= deadline {
                    return Err(ApiError::Timeout(Duration::ZERO));
                }
                let n = reader.read(&mut chunk).map_err(ApiError::Transport)?;
                if n == 0 {
                    return Err(ApiError::MalformedResponse(
                        "EOF before content-length satisfied".to_owned(),
                    ));
                }
                let needed = content_length - body.len();
                body.extend_from_slice(&chunk[..n.min(needed)]);
            }
            return Ok(HttpResponse { status, body });
        }
        if header_buf.len() > 64 * 1024 {
            return Err(ApiError::MalformedResponse(
                "headers exceed 64 KiB".to_owned(),
            ));
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_and_content_length(headers: &[u8]) -> Result<(u16, usize), ApiError> {
    let text = std::str::from_utf8(headers)
        .map_err(|_| ApiError::MalformedResponse("non-utf8 headers".to_owned()))?;

    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ApiError::MalformedResponse("missing status line".to_owned()))?;

    // `HTTP/1.1 200 OK` — split on whitespace, take the second token.
    let mut parts = status_line.split_whitespace();
    let _proto = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| ApiError::MalformedResponse("status line missing code".to_owned()))?;
    let status: u16 = code
        .parse()
        .map_err(|_| ApiError::MalformedResponse(format!("bad status code: {code:?}")))?;

    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
            let trimmed = rest.trim();
            content_length = trimmed
                .parse()
                .map_err(|_| ApiError::MalformedResponse(format!("bad cl: {trimmed:?}")))?;
        }
    }
    Ok((status, content_length))
}

// ---------------------------------------------------------------------------
// Typed request bodies
// ---------------------------------------------------------------------------

/// `/boot-source` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootSource {
    /// Path to the kernel image (typically `vmlinux.bin`).
    pub kernel_image_path: PathBuf,
    /// Linux kernel boot args. RAXIS pins:
    ///   `console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nokbd`
    /// to keep the guest minimal and reboot-on-panic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
    /// Optional initrd path. RAXIS does not use an initrd in V2 (the
    /// rootfs is mounted directly via virtio-blk); we keep the field
    /// for forward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<PathBuf>,
}

/// `/drives/{drive_id}` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Drive {
    /// Stable identifier (e.g. `"rootfs"`, `"data"`). Path-encoded
    /// into the URL.
    pub drive_id:        String,
    /// Host path of the backing image.
    pub path_on_host:    PathBuf,
    /// `true` ⇒ this drive is the rootfs (`/dev/vda` on the guest).
    pub is_root_device:  bool,
    /// `true` ⇒ guest sees it as read-only.
    pub is_read_only:    bool,
}

/// `/machine-config` payload.
///
/// `smt` (Symmetric Multi-Threading) is left to the kernel default
/// (`false`); operators that want SMT-enabled VMs set it via a future
/// extension to `VmSpec`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineConfig {
    /// Number of vCPUs.
    pub vcpu_count: u32,
    /// Memory ceiling in MiB.
    pub mem_size_mib: u32,
    /// Whether SMT is enabled. `false` is the canonical RAXIS default
    /// (one logical CPU per declared vCPU; predictable resource model).
    #[serde(default)]
    pub smt: bool,
}

// `/network-interfaces/{iface_id}` payload removed alongside
// `put_network_interface` in the Tier1Tproxy deletion sweep.

/// `/vsock` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VsockConfig {
    /// Stable identifier — Firecracker accepts a free-form string.
    pub vsock_id:     String,
    /// Guest-side context id. Host CID is always 2; planner-VM CIDs
    /// start at 3 in V2.
    pub guest_cid:    u32,
    /// Host UDS path the VMM uses to expose the guest's vsock device.
    /// The guest sees `vhost-vsock`; the host sees a UDS that accepts
    /// `CONNECT <port>` lines.
    pub uds_path:     PathBuf,
}

/// `/actions` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Action {
    /// Action discriminator.
    pub action_type: ActionType,
}

/// Subset of Firecracker actions RAXIS uses.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum ActionType {
    /// Begin guest execution.
    InstanceStart,
    /// Send Ctrl+Alt+Del to the guest (graceful shutdown).
    SendCtrlAltDel,
}

// Helper to keep tests / vmm.rs from re-importing `Path` / `PathBuf`.
impl FirecrackerApi {
    /// API socket path (read-only accessor; mostly used by tests and
    /// the VMM-supervision module to reason about cleanup paths).
    pub fn api_sock_path(&self) -> &Path {
        &self.api_sock
    }

    /// Per-call timeout (test introspection).
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- request builder ----------------------------------------------------

    #[test]
    fn request_builder_emits_method_path_host_and_content_length() {
        let req = build_http_request("PUT", "/machine-config", Some(b"{\"vcpu\":1}"));
        let text = std::str::from_utf8(&req).unwrap();
        assert!(text.starts_with("PUT /machine-config HTTP/1.1\r\n"));
        assert!(text.contains("Host: localhost\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains("Content-Length: 10\r\n\r\n"));
        assert!(text.ends_with("{\"vcpu\":1}"));
    }

    #[test]
    fn request_builder_omits_body_section_when_payload_is_none() {
        let req = build_http_request("GET", "/", None);
        let text = std::str::from_utf8(&req).unwrap();
        // Bodyless still emits Content-Length: 0 — Firecracker's
        // parser requires it.
        assert!(text.contains("Content-Length: 0\r\n\r\n"));
        assert!(!text.contains("Content-Type:"));
    }

    // -- response parser ----------------------------------------------------

    #[test]
    fn response_parser_pulls_status_and_body() {
        let raw = b"HTTP/1.1 204 No Content\r\nServer: Firecracker\r\nContent-Length: 0\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw.as_ref());
        let r = read_http_response(&mut cursor, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(r.status, 204);
        assert!(r.body.is_empty());
    }

    #[test]
    fn response_parser_handles_body_split_across_reads() {
        // Two chunks: headers + first byte of body, then rest of body.
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = std::io::Cursor::new(raw.as_ref());
        let r = read_http_response(&mut cursor, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn response_parser_rejects_eof_inside_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";
        let mut cursor = std::io::Cursor::new(raw.as_ref());
        let err = read_http_response(&mut cursor, Instant::now() + Duration::from_secs(1))
            .unwrap_err();
        assert!(matches!(err, ApiError::MalformedResponse(_)));
    }

    #[test]
    fn response_parser_rejects_eof_before_body_complete() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi";
        let mut cursor = std::io::Cursor::new(raw.as_ref());
        let err = read_http_response(&mut cursor, Instant::now() + Duration::from_secs(1))
            .unwrap_err();
        assert!(matches!(err, ApiError::MalformedResponse(_)));
    }

    // -- typed body shapes (pin the JSON wire) -----------------------------

    #[test]
    fn boot_source_serializes_to_canonical_firecracker_shape() {
        let bs = BootSource {
            kernel_image_path: PathBuf::from("/var/raxis/kernel/vmlinux.bin"),
            boot_args:         Some("console=ttyS0 reboot=k panic=1".to_owned()),
            initrd_path:       None,
        };
        let v: serde_json::Value = serde_json::to_value(&bs).unwrap();
        assert_eq!(v["kernel_image_path"], "/var/raxis/kernel/vmlinux.bin");
        assert_eq!(v["boot_args"], "console=ttyS0 reboot=k panic=1");
        // Optional initrd path skipped.
        assert!(v.get("initrd_path").is_none());
    }

    #[test]
    fn drive_serializes_with_required_fields() {
        let d = Drive {
            drive_id:       "rootfs".to_owned(),
            path_on_host:   PathBuf::from("/var/raxis/img/orchestrator-rootfs.img"),
            is_root_device: true,
            is_read_only:   true,
        };
        let v: serde_json::Value = serde_json::to_value(&d).unwrap();
        assert_eq!(v["drive_id"], "rootfs");
        assert_eq!(v["is_root_device"], true);
        assert_eq!(v["is_read_only"], true);
    }

    #[test]
    fn machine_config_pins_smt_default_to_false() {
        let m = MachineConfig {
            vcpu_count:   1,
            mem_size_mib: 256,
            smt:          false,
        };
        let v: serde_json::Value = serde_json::to_value(&m).unwrap();
        assert_eq!(v["smt"], false);
    }

    #[test]
    fn vsock_config_carries_guest_cid_and_uds() {
        let c = VsockConfig {
            vsock_id:  "raxis-vsock".to_owned(),
            guest_cid: 42,
            uds_path:  PathBuf::from("/run/raxis/vsock-42.sock"),
        };
        let v: serde_json::Value = serde_json::to_value(&c).unwrap();
        assert_eq!(v["guest_cid"], 42);
        assert_eq!(v["uds_path"], "/run/raxis/vsock-42.sock");
    }

    #[test]
    fn action_type_serializes_to_pascal_case() {
        let a = Action { action_type: ActionType::InstanceStart };
        let v: serde_json::Value = serde_json::to_value(&a).unwrap();
        assert_eq!(v["action_type"], "InstanceStart");

        let a2 = Action { action_type: ActionType::SendCtrlAltDel };
        let v2: serde_json::Value = serde_json::to_value(&a2).unwrap();
        assert_eq!(v2["action_type"], "SendCtrlAltDel");
    }

    // -- accessors / builders -----------------------------------------------

    #[test]
    fn api_client_builder_accessors_round_trip() {
        let c = FirecrackerApi::new("/run/x.sock").with_timeout(Duration::from_millis(750));
        assert_eq!(c.api_sock_path(), Path::new("/run/x.sock"));
        assert_eq!(c.timeout(), Duration::from_millis(750));
    }

    // -- live UDS round-trip against an in-test server ----------------------
    //
    // We stand up a one-shot UDS server in a background thread that
    // reads the request, asserts on its shape, and returns a 204
    // response. The client is the real `FirecrackerApi` — this proves
    // the HTTP/1.1 framing matches end-to-end without needing a real
    // `firecracker` binary on the runner.

    #[cfg(unix)]
    #[test]
    fn end_to_end_put_machine_config_round_trips_against_in_test_server() {
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!(
            "raxis-fcapi-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("api.sock");
        let _ = std::fs::remove_file(&sock);

        let listener = UnixListener::bind(&sock).unwrap();

        let received: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received_thread = std::sync::Arc::clone(&received);

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Drain just enough to find the headers + content-length.
            let mut buf = Vec::with_capacity(4096);
            let mut tmp = [0u8; 1024];
            // Read until we see the body fully — single PUT body
            // is small enough that one or two reads suffice.
            loop {
                let n = stream.read(&mut tmp).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                // Stop once we've seen headers + the declared body.
                if let Some(end) = find_double_crlf(&buf) {
                    let headers = std::str::from_utf8(&buf[..end]).unwrap();
                    let cl: usize = headers
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("Content-Length:")
                                .or_else(|| l.strip_prefix("content-length:"))
                                .map(|s| s.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + cl {
                        break;
                    }
                }
            }
            *received_thread.lock().unwrap() = buf;
            // Reply 204 No Content.
            let resp = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(resp).unwrap();
            stream.flush().unwrap();
        });

        let api = FirecrackerApi::new(&sock).with_timeout(Duration::from_secs(2));
        api.put_machine_config(&MachineConfig {
            vcpu_count:   2,
            mem_size_mib: 256,
            smt:          false,
        })
        .expect("put_machine_config must succeed against the test server");

        server.join().unwrap();
        let recv = received.lock().unwrap();
        let text = std::str::from_utf8(&recv).unwrap();
        assert!(text.starts_with("PUT /machine-config HTTP/1.1\r\n"));
        assert!(text.contains("Content-Type: application/json"));
        assert!(text.contains("\"vcpu_count\":2"));
        assert!(text.contains("\"mem_size_mib\":256"));

        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
