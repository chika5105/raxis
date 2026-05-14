//! `raxis-executor` — guest-side planner-harness binary for the
//! [`Role::Executor`](raxis_planner_core::Role::Executor) role.
//!
//! See `raxis-planner-orchestrator/src/main.rs` for the full
//! lifecycle commentary; the executor binary differs only in:
//!
//!   * argv contract:
//!     `--task-id <ID> --initiative-id <ID>` (both required).
//!   * compile-time tool-registry features
//!     (`raxis-planner-core/executor`).
//!   * egress tier the kernel pre-stamps on the VM
//!     (`Mediated` per `raxis-kernel::session_spawn_orchestrator`).
//!
//! V2.4 lifecycle: the driver delegates to
//! [`raxis_planner_core::run_role_session`] which runs the full
//! dispatch loop end-to-end when `RAXIS_PLANNER_TASK_PROMPT` is
//! set. Otherwise the binary parks on signal exactly like the V2.3
//! scaffold.

use raxis_planner_core::{
    ensure_cargo_offline_default, hydrate_from_proc_cmdline, init_pid1_a3_egress,
    init_pid1_filesystem, mount_workspace_shares, park_on_signal, render_boot_log,
    run_role_session, shutdown_or_exit, BootContext, CargoOfflineDefaultOutcome, DriverError,
    DriverOutcome, HydrationOutcome, MountStatus, PlannerError, Role, WorkspaceMountOutcome,
};

fn main() -> ! {
    // Step 1: when running as PID 1 inside a Linux initramfs,
    // mount /proc, /sys, /dev, /tmp before any other I/O. See
    // `raxis-planner-core::guest_init` for the full rationale.
    // No-op on the host (PID ≠ 1) and on macOS.
    init_pid1_filesystem();

    // Step 2: pre-runtime cmdline-env hydration. See
    // `raxis-planner-orchestrator/src/main.rs` for the full
    // rationale; the AVF substrate folds `VmSpec::env` into a
    // `raxis.envb64=<base64>` cmdline token because there is no
    // `Command::env` analogue at the AVF surface. Other substrates
    // are no-ops.
    let hydration = hydrate_from_proc_cmdline();
    log_hydration_outcome(&hydration);

    // Step 3: mount any VirtioFS workspace shares the substrate
    // declared via `RAXIS_VIRTIOFS_MOUNTS`. The executor role
    // mounts `/workspace` (its task-scoped worktree) RW for
    // git/build/test tools to read/write. See
    // `raxis-planner-orchestrator/src/main.rs::main` for the full
    // rationale.
    let mount_outcome = mount_workspace_shares();
    log_workspace_mount_outcome(&mount_outcome);

    // Step 3a: default `CARGO_NET_OFFLINE=true` for every
    // `BashTool`-spawned `cargo` invocation the executor's LLM
    // dispatches. The realistic-scenario seed's `rust-crate/
    // Cargo.toml` declares no third-party deps, so `cargo fmt
    // --check` + `cargo clippy --all-targets -- -D warnings`
    // succeed offline; defaulting `--offline` mode here defends
    // against a future seed dep accidentally introducing a
    // registry probe against the canonical empty per-session
    // egress allowlist (`INV-EXECUTOR-IMAGE-RUST-OFFLINE-01`,
    // `INV-EXECUTOR-EGRESS-OFFLINE-FIRST-01`). MUST run BEFORE
    // the tokio runtime is constructed below — the helper's
    // `unsafe { set_var }` call is single-threaded contract per
    // Rust 2024, and any worker thread spawn would invalidate
    // that. Operator override is preserved (the helper only
    // sets when the variable is unset/empty); see the helper's
    // docstring for the precedence contract.
    log_cargo_offline_default_outcome(&ensure_cargo_offline_default());

    // Step 3b: Path A3 — install the in-guest egress chokepoint
    // (disable IPv6 via sysfs, point `/etc/resolv.conf` at the
    // in-guest DNS stub, install iptables REDIRECT chains for
    // outbound TCP and UDP/53). After the Tier1Tproxy deletion
    // every executor / orchestrator VM boots at
    // `EgressTier::Mediated`, so the chokepoint is installed
    // unconditionally on Linux PID 1 — the previous
    // `RAXIS_AIRGAP_A3=1` env-var gate was removed.
    init_pid1_a3_egress();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime construction must not fail at executor boot");
    let exit_code = runtime.block_on(async_main());
    // See `raxis-planner-orchestrator/src/main.rs` for the full
    // rationale: PID 1 must `reboot(POWER_OFF)` instead of plain
    // `process::exit` so the substrate observes a clean
    // `SessionVmExited` event. `shutdown_or_exit` no-ops to
    // `process::exit(code)` when not PID 1.
    shutdown_or_exit(exit_code)
}

async fn async_main() -> u8 {
    if let Err(code) = activate_vsock_loopback_forwarder().await {
        return code;
    }
    // Path A3 — spawn the in-guest tproxy + DNS stub. After the
    // Tier1Tproxy deletion the kernel always stamps the executor
    // VM at `EgressTier::Mediated`, so the chokepoint is
    // unconditionally active; the previous `RAXIS_AIRGAP_A3=1`
    // env-var gate was removed in the same sweep.
    if let Err(code) = activate_airgap_a3_chokepoint().await {
        return code;
    }
    match run().await {
        Ok(())  => 0,
        Err(e)  => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-boot-error\",\
                  \"role\":\"executor\",\"message\":{:?}}}",
                e.to_string(),
            );
            e.exit_code() as u8
        }
    }
}

/// Env var that names the kernel CID the in-guest tproxy /
/// DNS-stub dial when admission is mediated over AF_VSOCK.
/// Defaults to `VMADDR_CID_HOST` (2) which is the only value
/// the AVF / Firecracker substrates expose.
const A3_HOST_CID_ENV:        &str = "RAXIS_AIRGAP_A3_HOST_CID";
/// Env var that names the kernel-side admission listener port.
/// Defaults to a stable canonical port — `kernel/src/main.rs`
/// binds the same one when the A3 feature is active.
const A3_ADMISSION_PORT_ENV:  &str = "RAXIS_AIRGAP_A3_ADMISSION_PORT";
/// Env var that names the kernel-side byte-tunnel listener port.
const A3_TUNNEL_PORT_ENV:     &str = "RAXIS_AIRGAP_A3_TUNNEL_PORT";

/// Default kernel admission port (`spec §3.1`).
const DEFAULT_ADMISSION_PORT: u32 = 5380;
/// Default kernel tunnel port (`spec §4`).
const DEFAULT_TUNNEL_PORT:    u32 = 5381;
/// Default host CID — `VMADDR_CID_HOST` (2).
const DEFAULT_HOST_CID:       u32 = 2;

/// Bring up the in-guest tproxy listener and DNS stub when Path
/// A3 is active. The accept loop runs on the same tokio runtime
/// as the executor dispatcher so a single failure mode (process
/// exit) cleanly tears both halves down.
async fn activate_airgap_a3_chokepoint() -> Result<(), u8> {
    let session_token = match std::env::var("RAXIS_SESSION_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"airgap-a3-chokepoint\",\
                  \"role\":\"executor\",\"outcome\":\"missing-session-token\",\
                  \"reason\":\"RAXIS_SESSION_TOKEN required for A3 admission auth\"}}"
            );
            return Err(64);
        }
    };
    let host_cid       = env_u32_or(A3_HOST_CID_ENV,        DEFAULT_HOST_CID);
    let admission_port = env_u32_or(A3_ADMISSION_PORT_ENV,  DEFAULT_ADMISSION_PORT);
    let tunnel_port    = env_u32_or(A3_TUNNEL_PORT_ENV,     DEFAULT_TUNNEL_PORT);

    #[cfg(target_os = "linux")]
    {
        use raxis_tproxy::linux::{accept_loop_a3, bind_default_listener};
        let listener = match bind_default_listener().await {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"airgap-a3-chokepoint\",\
                      \"role\":\"executor\",\"outcome\":\"bind-failed\",\
                      \"reason\":{:?}}}",
                    e.to_string(),
                );
                return Err(64);
            }
        };
        let token_for_loop = session_token.clone();
        tokio::spawn(async move {
            let res = accept_loop_a3(
                listener,
                host_cid,
                admission_port,
                tunnel_port,
                token_for_loop,
            )
            .await;
            if let Err(e) = res {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"airgap-a3-chokepoint\",\
                      \"role\":\"executor\",\"outcome\":\"accept-loop-exit\",\
                      \"reason\":{:?}}}",
                    e.to_string(),
                );
            }
        });
        let token_for_dns = session_token.clone();
        tokio::spawn(async move {
            let res = raxis_tproxy::dns_stub::run_dns_stub(
                host_cid,
                admission_port,
                token_for_dns,
            )
            .await;
            if let Err(e) = res {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"airgap-a3-chokepoint\",\
                      \"role\":\"executor\",\"outcome\":\"dns-stub-exit\",\
                      \"reason\":{:?}}}",
                    e.to_string(),
                );
            }
        });
        eprintln!(
            "{{\"level\":\"info\",\"step\":\"airgap-a3-chokepoint\",\
              \"role\":\"executor\",\"outcome\":\"activated\",\
              \"host_cid\":{host_cid},\"admission_port\":{admission_port},\
              \"tunnel_port\":{tunnel_port}}}"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (host_cid, admission_port, tunnel_port, session_token);
        eprintln!(
            "{{\"level\":\"warn\",\"step\":\"airgap-a3-chokepoint\",\
              \"role\":\"executor\",\"outcome\":\"skipped-non-linux\",\
              \"reason\":\"AF_VSOCK is Linux-only; A3 chokepoint disabled\"}}"
        );
        Ok(())
    }
}

fn env_u32_or(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default)
}

/// Bring up the in-guest TCP→AF_VSOCK fan-out for the
/// credential-proxy URLs the kernel substrate stamped into the
/// executor's environment (`INV-CRED-PROXY-VM-REACHABILITY-01`).
///
/// Behaviour:
/// * `RAXIS_VSOCK_LOOPBACK_PLAN` unset / empty → skip silently
///   (the kernel did not request any credential proxies for this
///   session, e.g. an executor task with `[[tasks.credentials]]
///   = []`).
/// * Plan present and well-formed → bind one
///   `127.0.0.1:<guest_loopback_port>` listener per entry and
///   spawn the splice loop on the same tokio runtime that drives
///   the dispatch loop. Returns once every bind has succeeded so
///   any failure is observed by the caller before the agent's
///   first tool fires.
/// * Plan present but malformed, or any bind fails → fail-closed:
///   exit with the planner's "isolation diagnostic" exit code so
///   the substrate observes a clean `SessionVmExited` and the
///   kernel surfaces a structured error rather than the
///   downstream `error connecting to server` cascade an
///   un-forwarded loopback would produce. The executor canonical
///   rootfs ships only this binary, so silently swallowing the
///   failure here would strand every credential-bearing task in
///   the same opaque cascade `8a26540` was meant to fix.
async fn activate_vsock_loopback_forwarder() -> Result<(), u8> {
    use raxis_tproxy::loopback_forwarder;
    match loopback_forwarder::loopback_plan_from_env() {
        Ok(None) => {
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"vsock-loopback-forwarder\",\
                  \"role\":\"executor\",\"outcome\":\"skipped\",\
                  \"reason\":\"RAXIS_VSOCK_LOOPBACK_PLAN unset or empty\"}}"
            );
            Ok(())
        }
        Ok(Some(plan)) => match loopback_forwarder::spawn_forwarder(&plan).await {
            Ok(()) => {
                eprintln!(
                    "{{\"level\":\"info\",\"step\":\"vsock-loopback-forwarder\",\
                      \"role\":\"executor\",\"outcome\":\"activated\",\
                      \"entries\":{}}}",
                    plan.len(),
                );
                Ok(())
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"vsock-loopback-forwarder\",\
                      \"role\":\"executor\",\"outcome\":\"bind-failed\",\
                      \"reason\":{:?}}}",
                    e.to_string(),
                );
                Err(64)
            }
        },
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"vsock-loopback-forwarder\",\
                  \"role\":\"executor\",\"outcome\":\"plan-decode-failed\",\
                  \"reason\":{:?}}}",
                e.to_string(),
            );
            Err(64)
        }
    }
}

fn log_hydration_outcome(outcome: &HydrationOutcome) {
    match outcome {
        HydrationOutcome::NoProcCmdline { reason } => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"executor\",\"outcome\":\"no-proc-cmdline\",\
              \"reason\":{:?}}}",
            reason,
        ),
        HydrationOutcome::NoEnvToken => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"executor\",\"outcome\":\"no-env-token\"}}"
        ),
        HydrationOutcome::BadEnvToken { reason } => eprintln!(
            "{{\"level\":\"warn\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"executor\",\"outcome\":\"bad-env-token\",\
              \"reason\":{:?}}}",
            reason,
        ),
        HydrationOutcome::Hydrated { applied, skipped_already_set } => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"executor\",\"outcome\":\"hydrated\",\
              \"applied\":{applied},\"skipped_already_set\":{skipped_already_set}}}"
        ),
    }
}

async fn run() -> Result<(), PlannerError> {
    let ctx = BootContext::from_process(Role::Executor)?;
    eprintln!("{}", render_boot_log(&ctx));

    let outcome = run_role_session(ctx.role, ctx.args.clone(), ctx.env.clone())
        .await
        .map_err(driver_to_planner_error)?;

    match outcome {
        DriverOutcome::Scaffold => {
            park_on_signal().await;
            Ok(())
        }
        DriverOutcome::Completed { tool_name } => {
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"planner-completed\",\
                  \"role\":\"executor\",\"terminal_tool\":{:?}}}",
                tool_name,
            );
            Ok(())
        }
        DriverOutcome::Idle { final_text } => {
            // Executor must always pick a terminal tool
            // (`task_complete` / `single_commit` / `report_failure`).
            // An Idle outcome means the model gave up without
            // submitting either, which the kernel surfaces as a
            // structured failure.
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"planner-idle\",\
                  \"role\":\"executor\",\"final_text_len\":{len}}}",
                len = final_text.len(),
            );
            Err(PlannerError::DispatchIdle)
        }
        DriverOutcome::MaxTurnsExceeded { turns } => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-max-turns\",\
                  \"role\":\"executor\",\"turns\":{turns}}}",
            );
            Err(PlannerError::MaxTurnsExceeded { turns })
        }
        DriverOutcome::TokensExceeded { which, ceiling } => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-tokens-exceeded\",\
                  \"role\":\"executor\",\"which\":{:?},\"ceiling\":{ceiling}}}",
                which,
            );
            Err(PlannerError::TokensExceeded { which, ceiling })
        }
    }
}

fn driver_to_planner_error(e: DriverError) -> PlannerError {
    PlannerError::DriverFailure(e.to_string())
}

/// Emit one structured JSON line summarising the
/// `CARGO_NET_OFFLINE` env-default action taken at PID-1 boot.
/// The post-mortem audit-chain replay uses this line to prove
/// whether the executor's `cargo` invocations defaulted to
/// offline OR inherited an operator-set value
/// (`INV-EXECUTOR-IMAGE-RUST-OFFLINE-01`).
fn log_cargo_offline_default_outcome(outcome: &CargoOfflineDefaultOutcome) {
    match outcome {
        CargoOfflineDefaultOutcome::DefaultedToOffline => eprintln!(
            "{{\"level\":\"info\",\"step\":\"cargo-net-offline-default\",\
              \"role\":\"executor\",\"event\":\"defaulted\",\"value\":\"true\"}}"
        ),
        CargoOfflineDefaultOutcome::PreservedExisting { value } => eprintln!(
            "{{\"level\":\"info\",\"step\":\"cargo-net-offline-default\",\
              \"role\":\"executor\",\"event\":\"preserved_existing\",\
              \"value\":{:?}}}",
            value,
        ),
    }
}

fn log_workspace_mount_outcome(outcome: &WorkspaceMountOutcome) {
    match outcome {
        WorkspaceMountOutcome::NoEnvVar => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-virtiofs-mount\",\
              \"role\":\"executor\",\"outcome\":\"no-env-var\"}}"
        ),
        WorkspaceMountOutcome::BadEnvVar { reason, attempts } => eprintln!(
            "{{\"level\":\"warn\",\"step\":\"planner-virtiofs-mount\",\
              \"role\":\"executor\",\"outcome\":\"bad-env-var\",\
              \"reason\":{:?},\"attempts\":{}}}",
            reason,
            attempts.len(),
        ),
        WorkspaceMountOutcome::Mounted { attempts } => {
            for attempt in attempts {
                let (status_str, reason): (&str, Option<&str>) = match &attempt.status {
                    MountStatus::Ok      => ("ok", None),
                    MountStatus::Already => ("already", None),
                    MountStatus::Failed { reason } => ("failed", Some(reason.as_str())),
                };
                match reason {
                    Some(r) => eprintln!(
                        "{{\"level\":\"warn\",\"step\":\"planner-virtiofs-mount\",\
                          \"role\":\"executor\",\"outcome\":{:?},\
                          \"tag\":{:?},\"guest_path\":{:?},\"read_only\":{},\
                          \"reason\":{:?}}}",
                        status_str,
                        attempt.spec.tag,
                        attempt.spec.guest_path,
                        attempt.spec.read_only,
                        r,
                    ),
                    None => eprintln!(
                        "{{\"level\":\"info\",\"step\":\"planner-virtiofs-mount\",\
                          \"role\":\"executor\",\"outcome\":{:?},\
                          \"tag\":{:?},\"guest_path\":{:?},\"read_only\":{}}}",
                        status_str,
                        attempt.spec.tag,
                        attempt.spec.guest_path,
                        attempt.spec.read_only,
                    ),
                }
            }
        }
    }
}
