//! `raxis-executor` — guest-side planner-harness binary for the
//! [`raxis_planner_core::Role::Executor`] role.
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
//! dispatch loop end-to-end when the kernel-stamped prompt contract
//! is present, and fails closed when it is not.

use raxis_planner_core::{
    enforce_pid1_or_abort, ensure_executor_rustup_env_defaults, harden_guest_for_agent,
    hydrate_from_proc_cmdline, init_pid1_a3_egress, init_pid1_filesystem, mount_workspace_shares,
    render_boot_log, run_role_session, scrub_sensitive_env_for_agent, shutdown_or_exit,
    BootContext, DriverError, DriverOutcome, HydrationOutcome, MountStatus, PlannerError, Role,
    RustupEnvDefaultOutcome, WorkspaceMountOutcome,
};

fn main() -> ! {
    // Step 0: `INV-PLANNER-PID1-ONLY-EXEC-01` — refuse to start
    // when the binary is invoked as a child process inside an
    // already-running microVM. The contract is "PID 1 of a
    // microVM"; any other invocation is a jailbreak vector (a
    // curious or adversarial in-VM agent re-execing the
    // executor binary to inherit the parent's kernel transport and
    // port bindings). See the helper docstring + the
    // `iter72-dep-fetch-jailbreak` postmortem for context.
    enforce_pid1_or_abort();

    // Step 1: when running as PID 1 inside a Linux initramfs,
    // mount /proc, /sys, /dev, /tmp before any other I/O. See
    // `raxis-planner-core::guest_init` for the full rationale.
    // No-op on the host (PID ≠ 1) and on macOS.
    init_pid1_filesystem();

    // Step 2: pre-runtime cmdline-env hydration. See
    // `raxis-planner-orchestrator/src/main.rs` for the full
    // rationale; the microVM substrates fold `VmSpec::env` into a
    // `raxis.envb64=<base64>` cmdline token because there is no
    // `Command::env` analogue at the VM boot surface. Subprocess
    // isolation is a no-op.
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

    // Step 3a: point rustup/cargo at the baked executor-starter
    // homes. AVF can boot PID 1 with HOME=/, which makes rustup
    // shims look under `/.rustup` even though the image installed
    // stable under `/root/.rustup`.
    log_rustup_env_default_outcome(&ensure_executor_rustup_env_defaults());

    // Step 3b: Path A3 — install the in-guest egress chokepoint
    // (disable IPv6 via sysfs, point `/etc/resolv.conf` at the
    // in-guest DNS stub, install iptables REDIRECT chains for
    // outbound TCP and UDP/53). After the Tier1Tproxy deletion
    // every executor / orchestrator VM boots at
    // `EgressTier::Mediated`, so the chokepoint is installed
    // unconditionally on Linux PID 1 — the previous
    // `RAXIS_AIRGAP_A3=1` env-var gate was removed.
    init_pid1_a3_egress();

    // Step 3c: `INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01` —
    // last-line hardening against an in-VM LLM agent reading
    // kernel-stamped secrets, re-executing the planner binary,
    // or powering off the VM out-of-band. See the helper's
    // docstring for the full taxonomy and
    // `specs/v3/guest-agent-jailbreak-defense.md` for the
    // attack-vector replay log. MUST run BEFORE the tokio
    // runtime spins up so the procfs bind mounts and
    // `prctl(PR_*)` flags are inherited by every worker thread.
    harden_guest_for_agent();

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
    // Note: `scrub_sensitive_env_for_agent` is invoked INSIDE
    // `run()` immediately after `BootContext::from_process` has
    // captured the safe session id. Scrubbing here (before `run()`
    // runs `from_process`) would starve the BootContext constructor
    // of the env vars it needs to initialise the per-task kernel
    // transport handshake.
    match run().await {
        Ok(()) => 0,
        Err(e) => {
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
const A3_HOST_CID_ENV: &str = "RAXIS_AIRGAP_A3_HOST_CID";
/// Env var that names the kernel-side admission listener port.
/// Defaults to a stable canonical port — `kernel/src/main.rs`
/// binds the same one when the A3 feature is active.
const A3_ADMISSION_PORT_ENV: &str = "RAXIS_AIRGAP_A3_ADMISSION_PORT";
/// Env var that names the kernel-side byte-tunnel listener port.
const A3_TUNNEL_PORT_ENV: &str = "RAXIS_AIRGAP_A3_TUNNEL_PORT";

/// Default kernel admission port (`spec §3.1`).
const DEFAULT_ADMISSION_PORT: u32 = 5380;
/// Default kernel tunnel port (`spec §4`).
const DEFAULT_TUNNEL_PORT: u32 = 5381;
/// Default host CID — `VMADDR_CID_HOST` (2).
const DEFAULT_HOST_CID: u32 = 2;

/// Bring up the in-guest tproxy listener and DNS stub when Path
/// A3 is active. The accept loop runs on the same tokio runtime
/// as the executor dispatcher so a single failure mode (process
/// exit) cleanly tears both halves down.
async fn activate_airgap_a3_chokepoint() -> Result<(), u8> {
    let host_cid = env_u32_or(A3_HOST_CID_ENV, DEFAULT_HOST_CID);
    let admission_port = env_u32_or(A3_ADMISSION_PORT_ENV, DEFAULT_ADMISSION_PORT);
    let tunnel_port = env_u32_or(A3_TUNNEL_PORT_ENV, DEFAULT_TUNNEL_PORT);

    #[cfg(target_os = "linux")]
    {
        use raxis_tproxy::linux::{accept_loop_a3, bind_default_listener};
        // Bind the tproxy chokepoint synchronously before logging
        // "activated" so the boot-log ordering pins the actual
        // listener-ready instant.
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
        // Bind the DNS stub synchronously BEFORE returning from
        // the activation function. Iter72 forensics showed the
        // previous code spawned `run_dns_stub` directly and let
        // `tokio::spawn` return immediately; the bind ran inside
        // the spawn body, so the agent's first
        // `bash -lc 'python3 ... http.client.HTTPSConnection'`
        // could fire before `UdpSocket::bind("127.0.0.1:53")` had
        // run. Symptom: `gaierror: [Errno -3] Temporary failure in
        // name resolution` followed by a 30-turn diagnostic spiral
        // (replay file `specs/v3/guest-agent-jailbreak-replay-iter72.md`
        // turns 1-7).
        let dns_listeners = match raxis_tproxy::dns_stub::bind_dns_stub().await {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"airgap-a3-chokepoint\",\
                      \"role\":\"executor\",\"outcome\":\"dns-bind-failed\",\
                      \"reason\":{:?}}}",
                    e.to_string(),
                );
                return Err(64);
            }
        };
        let (dns_udp_addr, dns_tcp_addr) = dns_listeners.bound_addrs();
        tokio::spawn(async move {
            let res = accept_loop_a3(listener, host_cid, admission_port, tunnel_port).await;
            if let Err(e) = res {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"airgap-a3-chokepoint\",\
                      \"role\":\"executor\",\"outcome\":\"accept-loop-exit\",\
                      \"reason\":{:?}}}",
                    e.to_string(),
                );
            }
        });
        tokio::spawn(async move {
            let res =
                raxis_tproxy::dns_stub::serve_dns_stub(dns_listeners, host_cid, admission_port)
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
              \"tunnel_port\":{tunnel_port},\
              \"dns_udp\":\"{dns_udp_addr}\",\"dns_tcp\":\"{dns_tcp_addr}\"}}"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (host_cid, admission_port, tunnel_port);
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
        HydrationOutcome::Hydrated {
            applied,
            skipped_already_set,
        } => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"executor\",\"outcome\":\"hydrated\",\
              \"applied\":{applied},\"skipped_already_set\":{skipped_already_set}}}"
        ),
    }
}

async fn run() -> Result<(), PlannerError> {
    let ctx = BootContext::from_process(Role::Executor)?;
    eprintln!("{}", render_boot_log(&ctx));

    // `INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01` — scrub the
    // sensitive env vars from the process environment after
    // `BootContext::from_process` has captured the safe session id.
    // The A3 tasks authenticate by host-owned session binding, not
    // guest bearer material. The scrubber also keeps an in-process
    // snapshot for the driver; `run_role_session` reduces that
    // snapshot to a fixed runtime allowlist, while the first
    // `BashTool` / `SubprocessTool` child process inherits the
    // scrubbed env via `Command::spawn`.
    scrub_sensitive_env_for_agent();

    let outcome = run_role_session(ctx.role, ctx.args.clone(), ctx.env.clone())
        .await
        .map_err(driver_to_planner_error)?;

    match outcome {
        DriverOutcome::Scaffold => Err(PlannerError::DriverFailure(
            "driver returned retired Scaffold outcome; prompt contract was not stamped".to_owned(),
        )),
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

fn log_rustup_env_default_outcome(outcome: &RustupEnvDefaultOutcome) {
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"executor-rustup-env-defaults\",\
          \"role\":\"executor\",\"defaulted\":{:?},\"preserved\":{:?}}}",
        outcome.defaulted, outcome.preserved,
    );
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
                    MountStatus::Ok => ("ok", None),
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
