//! `raxis-tproxy` — in-VM transparent egress proxy (Path A3 / Mediated only).
//!
//! Normative reference: `specs/v2/airgap-architecture.md §3`.
//!
//! # What this crate provides
//!
//! Three layers, in increasing platform-specificity:
//!
//! 1. **`peek` module** — reads bytes from the agent-side socket
//!    until either a TLS ClientHello (HTTPS) or a complete HTTP/1.1
//!    request preamble (HTTP) is buffered. Pure async I/O over any
//!    `AsyncRead + AsyncWrite`; cross-platform. Tests run on the
//!    macOS build host with no special privileges.
//!
//! 2. **`a3` module** — Path A3 admission round-trip
//!    (`IpcMessage`-framed over vsock) and the 48-byte tunnel
//!    handshake. Cross-platform; tests use `tokio::io::duplex`.
//!
//! 3. **`linux` module** — Linux-only glue: listening on TCP :3129,
//!    reading `SO_ORIGINAL_DST` after iptables REDIRECT, dialing
//!    the kernel over `AF_VSOCK` for admission + tunnel splice.
//!    Guarded by `cfg(target_os = "linux")`; on macOS the symbols
//!    don't exist and the module is empty. Production VM image is
//!    built with `cargo build --target x86_64-unknown-linux-musl
//!    --release -p raxis-tproxy`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod a3;
pub mod loopback_forwarder;
pub mod peek;

#[cfg(target_os = "linux")]
pub mod linux;

// Path A3 in-guest DNS stub forwarder (UDP+TCP :53 → kernel
// vsock). Linux-only at runtime because the production stub binds
// `127.0.0.1:53` inside the guest namespace and the kernel
// admission channel is `AF_VSOCK`. Tests for the pure-DNS-protocol
// codec live in `a3::dns_stub::tests` and run cross-platform.
#[cfg(target_os = "linux")]
pub mod dns_stub;
