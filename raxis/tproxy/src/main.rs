//! `raxis-tproxy` binary entry point.
//!
//! Linux-only at runtime — on macOS the binary still compiles
//! (so `cargo check --workspace` is clean on a developer's
//! laptop) but `main()` aborts with a clear error.
//!
//! Environment variables consumed:
//!   * `RAXIS_TPROXY_KERNEL_TCP` — TCP `host:port` of the
//!     kernel admission service. Used during dev bring-up
//!     before the kernel substrate exposes vsock. **Optional**
//!     once the credential-proxy vsock-loopback path is the only
//!     thing the binary needs to provide; absent ⇒ skip the
//!     egress-admission accept loop and run as a pure
//!     credential-loopback forwarder.
//!   * `RAXIS_VSOCK_LOOPBACK_PLAN` — comma-separated
//!     `<vsock_port>:<guest_loopback_port>` pairs identifying
//!     the per-session credential-proxy fan-out the in-VM
//!     forwarder must wire up. See `raxis-vsock-loopback` for
//!     the wire format. Absent ⇒ no forwarding (the session
//!     declared no credentials).

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
            // Stage 1 — bring up the credential-proxy vsock
            // loopback forwarder. This is the substrate fix for
            // INV-CRED-PROXY-VM-REACHABILITY-01: stock
            // `127.0.0.1:<port>` URLs in the agent's environment
            // resolve to host-side credential proxies via
            // per-VM AF_VSOCK fan-out. Failure here is fatal —
            // a session that declared credentials cannot
            // proceed if the forwarder cannot bind.
            match raxis_tproxy::loopback_forwarder::loopback_plan_from_env() {
                Ok(Some(plan)) => {
                    eprintln!(
                        "raxis-tproxy: vsock-loopback forwarder enabled \
                         ({} entries) — INV-CRED-PROXY-VM-REACHABILITY-01",
                        plan.len()
                    );
                    if let Err(e) =
                        raxis_tproxy::loopback_forwarder::spawn_forwarder(&plan).await
                    {
                        eprintln!("raxis-tproxy: vsock-loopback forwarder bind failed: {e}");
                        return std::process::ExitCode::from(64);
                    }
                }
                Ok(None) => {
                    eprintln!(
                        "raxis-tproxy: vsock-loopback forwarder skipped \
                         (RAXIS_VSOCK_LOOPBACK_PLAN unset/empty — session \
                         declared no credentials)"
                    );
                }
                Err(e) => {
                    eprintln!("raxis-tproxy: malformed RAXIS_VSOCK_LOOPBACK_PLAN: {e}");
                    return std::process::ExitCode::from(64);
                }
            }

            // Stage 2 — bring up the egress-admission accept
            // loop iff the kernel-tcp dev fallback is wired.
            // V2 GA will replace this with a vsock channel; for
            // now we keep the existing dev path optional so a
            // session that only needs credential proxies (no
            // SNI-allowlisted egress) still spawns a usable
            // tproxy binary.
            match std::env::var("RAXIS_TPROXY_KERNEL_TCP") {
                Ok(kernel_tcp) => {
                    let addr: std::net::SocketAddr = match kernel_tcp.parse() {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!(
                                "raxis-tproxy: RAXIS_TPROXY_KERNEL_TCP parse failed: {e}"
                            );
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
                    if let Err(e) =
                        raxis_tproxy::linux::accept_loop(listener, kernel).await
                    {
                        eprintln!("raxis-tproxy: accept loop terminated: {e}");
                        return std::process::ExitCode::from(64);
                    }
                    std::process::ExitCode::from(0)
                }
                Err(_) => {
                    eprintln!(
                        "raxis-tproxy: RAXIS_TPROXY_KERNEL_TCP unset — \
                         egress-admission disabled, running as pure \
                         credential-loopback forwarder"
                    );
                    // Park forever — the spawned forwarder tasks
                    // are running on the same runtime.
                    std::future::pending::<()>().await;
                    std::process::ExitCode::from(0)
                }
            }
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
