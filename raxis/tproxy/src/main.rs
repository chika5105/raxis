//! `raxis-tproxy` binary entry point.
//!
//! Linux-only at runtime — on macOS the binary still compiles
//! (so `cargo check --workspace` is clean on a developer's
//! laptop) but `main()` aborts with a clear error.
//!
//! Environment variables consumed:
//!   * `RAXIS_TPROXY_KERNEL_TCP` — TCP `host:port` of the
//!     kernel admission service. Used during dev bring-up
//!     before the kernel substrate exposes vsock.

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("raxis-tproxy: cannot construct tokio runtime: {e}");
                return std::process::ExitCode::from(64);
            }
        };
        rt.block_on(async {
            let kernel_tcp = match std::env::var("RAXIS_TPROXY_KERNEL_TCP") {
                Ok(v) => v,
                Err(_) => {
                    eprintln!(
                        "raxis-tproxy: RAXIS_TPROXY_KERNEL_TCP not set \
                         (V2 GA will use vsock; this binary is dev-bring-up only)"
                    );
                    return std::process::ExitCode::from(64);
                }
            };
            let addr: std::net::SocketAddr = match kernel_tcp.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("raxis-tproxy: RAXIS_TPROXY_KERNEL_TCP parse failed: {e}");
                    return std::process::ExitCode::from(64);
                }
            };
            let listener = match raxis_tproxy::linux::bind_default_listener().await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("raxis-tproxy: bind 0.0.0.0:3129 failed: {e}");
                    return std::process::ExitCode::from(64);
                }
            };
            let kernel = raxis_tproxy::linux::KernelChannel::Tcp(addr);
            if let Err(e) = raxis_tproxy::linux::accept_loop(listener, kernel).await {
                eprintln!("raxis-tproxy: accept loop terminated: {e}");
                return std::process::ExitCode::from(64);
            }
            std::process::ExitCode::from(0)
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "raxis-tproxy is Linux-only at runtime (uses SO_ORIGINAL_DST + AF_VSOCK). \
             For macOS host-side dev work the integration tests exercise the same \
             admission path through `tokio::net::UnixStream::pair()`. \
             Build for the in-VM target with `cargo build --target \
             x86_64-unknown-linux-musl --release -p raxis-tproxy`."
        );
        std::process::ExitCode::from(64)
    }
}
