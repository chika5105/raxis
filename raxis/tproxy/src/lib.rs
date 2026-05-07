//! `raxis-tproxy` — in-VM Tier 1 transparent egress proxy.
//!
//! Normative reference: `specs/v2/vm-network-isolation.md §3`.
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
//! 2. **`shuttle` module** — bidirectional byte-shuttle between the
//!    agent socket and the kernel-tunnel socket once the kernel
//!    admits the connection. Uses `tokio::io::copy_bidirectional`,
//!    which is portable.
//!
//! 3. **`linux` module** — Linux-only glue: listening on TCP :3129,
//!    reading `SO_ORIGINAL_DST` after iptables REDIRECT, talking to
//!    the kernel over `AF_VSOCK`. Guarded by `cfg(target_os =
//!    "linux")`; on macOS the symbols don't exist and the module is
//!    empty. Production VM image is built with
//!    `cargo build --target x86_64-unknown-linux-musl --release -p
//!    raxis-tproxy`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod peek;
pub mod shuttle;

#[cfg(target_os = "linux")]
pub mod linux;
