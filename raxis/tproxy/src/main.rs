//! `raxis-tproxy` binary entry point.
//!
//! Linux-only at runtime — on macOS the binary still compiles
//! (so `cargo check --workspace` is clean on a developer's
//! laptop) but `main()` aborts with a clear error.
//!
//! The standalone binary's role under Mediated egress is the
//! credential-loopback forwarder. The egress-admission accept
//! loop (Path A3 / `accept_loop_a3`) is driven by the
//! `planner-executor` binary instead, where the per-session
//! token + vsock CID/ports are already in scope.
//!
//! Environment variables consumed:
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
            // Bring up the credential-proxy vsock loopback
            // forwarder. This is the substrate fix for
            // INV-CRED-PROXY-VM-REACHABILITY-01: stock
            // `127.0.0.1:<port>` URLs in the agent's environment
            // resolve to host-side credential proxies via per-VM
            // AF_VSOCK fan-out. Failure here is fatal — a
            // session that declared credentials cannot proceed
            // if the forwarder cannot bind.
            match raxis_tproxy::loopback_forwarder::loopback_plan_from_env() {
                Ok(Some(plan)) => {
                    eprintln!(
                        "raxis-tproxy: vsock-loopback forwarder enabled \
                         ({} entries) — INV-CRED-PROXY-VM-REACHABILITY-01",
                        plan.len()
                    );
                    if let Err(e) = raxis_tproxy::loopback_forwarder::spawn_forwarder(&plan).await {
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

            // Park forever — the spawned forwarder tasks are
            // running on the same runtime. The egress-admission
            // accept loop (Path A3) is owned by planner-executor,
            // not this binary.
            std::future::pending::<()>().await;
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
