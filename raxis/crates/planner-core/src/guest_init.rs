//! `guest_init` — mount the essential virtual filesystems when the
//! planner binary is executed as PID 1 inside a Linux microVM.
//!
//! ## Why this exists
//!
//! Under the AVF and Firecracker substrates the canonical image is
//! a `cpio.gz` initramfs whose `/init` entry **is** the planner
//! binary (per `cargo xtask images dev-stage`). The Linux kernel
//! `execve(/init)` after unpacking the initramfs into rootfs and
//! does **not** mount `/proc`, `/sys`, or `/dev` — that is the
//! responsibility of `/init` itself, which on a typical
//! distribution is a userland init system (systemd, busybox-init,
//! …). When `/init` is a single statically-linked binary, the
//! binary must do it.
//!
//! Concretely: without `/proc` mounted the planner cannot read
//! `/proc/cmdline`, which is the channel the AVF substrate uses to
//! propagate the kernel-stamped env (`raxis.envb64=…`) — see
//! `crate::cmdline_env`. Skip the mount and you ship the planner
//! into the dispatch loop with no `RAXIS_KERNEL_VSOCK_LISTEN_PORT`,
//! no `RAXIS_SESSION_TOKEN`, and no `RAXIS_PLANNER_TASK_PROMPT`,
//! which surfaces from the host as the AVF vsock CONNECT failing
//! with `Connection reset by peer` (the planner panics and PID 1
//! exits, which makes the kernel reboot per `panic=1`).
//!
//! ## What this module mounts
//!
//! Only the minimum required for V2 GA:
//!
//!   * `/proc` (procfs) — needed for `/proc/cmdline` (env
//!     hydration) and for `tokio` to size the worker pool against
//!     `/proc/cpuinfo`.
//!   * `/sys` (sysfs) — needed for `tokio-vsock`'s socket
//!     creation paths to read `/sys/class/misc/vsock/dev`.
//!   * `/dev` (devtmpfs) — needed so `/dev/null`, `/dev/random`,
//!     `/dev/vsock` actually exist. The kernel populates devtmpfs
//!     automatically once mounted.
//!   * `/tmp` (tmpfs) — needed by the planner's tool subsystem
//!     (the `domain-git` crate writes worktrees there).
//!
//! Each mount is idempotent: `EBUSY` from the `mount(2)` syscall
//! (target already mounted) is treated as success so a substrate
//! that pre-mounts (e.g. a future Firecracker MMDS variant) does
//! not break.
//!
//! ## When this is invoked
//!
//! Only when `std::process::id() == 1`. A planner running under
//! `SubprocessIsolation` on the host (PID ≠ 1) skips this
//! entirely — the host already has `/proc` etc.
//!
//! ## Failure mode
//!
//! Each individual mount failure is logged on stderr but does NOT
//! panic. The next phase (`crate::cmdline_env::hydrate_*`) will
//! observe the missing `/proc/cmdline` and the dispatch driver
//! will surface the absent env vars as a normal `KernelSocketMissing`
//! / `BadBaseUrl` error — those are diagnostically richer than a
//! mount panic from PID 1.

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::io;

    /// One filesystem to mount.
    struct MountPlan {
        target:  &'static str,
        fs_type: &'static str,
        flags:   libc::c_ulong,
    }

    /// Canonical mount table for V2 GA. Order matters: `/dev` is
    /// mounted last so `/dev/null` becoming available cannot hide
    /// an earlier mount failure on stderr.
    const PLAN: &[MountPlan] = &[
        MountPlan {
            target:  "/proc",
            fs_type: "proc",
            // procfs default flags: nodev, noexec, nosuid (kernel
            // sets these automatically for procfs even without
            // explicit flags, but we set them so older kernels
            // behave consistently).
            flags:   libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID,
        },
        MountPlan {
            target:  "/sys",
            fs_type: "sysfs",
            flags:   libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID,
        },
        MountPlan {
            target:  "/tmp",
            fs_type: "tmpfs",
            flags:   libc::MS_NODEV | libc::MS_NOSUID,
        },
        MountPlan {
            target:  "/dev",
            fs_type: "devtmpfs",
            flags:   libc::MS_NOSUID,
        },
    ];

    /// Mount the canonical filesystems and ensure the target
    /// directories exist (initramfs may not include them by
    /// default; `cargo xtask images dev-stage` creates them but a
    /// hand-rolled rootfs may not).
    pub(super) fn mount_pid1_essentials() {
        for plan in PLAN {
            // `mkdir -p` first — the initramfs may have shipped
            // empty mount points, but if the rootfs builder forgot
            // any we recover here.
            if let Err(e) = std::fs::create_dir_all(plan.target) {
                eprintln!(
                    "{{\"level\":\"warn\",\"step\":\"guest-init\",\
                      \"event\":\"mkdir_failed\",\"target\":{:?},\
                      \"err\":{:?}}}",
                    plan.target, e.to_string(),
                );
                continue;
            }
            match try_mount(plan.target, plan.fs_type, plan.flags) {
                Ok(()) => eprintln!(
                    "{{\"level\":\"info\",\"step\":\"guest-init\",\
                      \"event\":\"mount_ok\",\"target\":{:?},\
                      \"fs_type\":{:?}}}",
                    plan.target, plan.fs_type,
                ),
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                    // Already mounted by an earlier substrate hook
                    // — treat as success.
                    eprintln!(
                        "{{\"level\":\"info\",\"step\":\"guest-init\",\
                          \"event\":\"mount_already\",\"target\":{:?}}}",
                        plan.target,
                    );
                }
                Err(e) => eprintln!(
                    "{{\"level\":\"warn\",\"step\":\"guest-init\",\
                      \"event\":\"mount_failed\",\"target\":{:?},\
                      \"fs_type\":{:?},\"err\":{:?}}}",
                    plan.target, plan.fs_type, e.to_string(),
                ),
            }
        }

        // After devtmpfs is mounted, /dev/console becomes the kernel
        // console (whatever `console=…` cmdline arg routed). When
        // the kernel `execve`s our `/init` from an initramfs that
        // lacked a static `/dev/console` node, fds 0/1/2 are NOT
        // hooked up to anything (the kernel's `init_post()` only
        // sets them up if `/dev/console` already existed at exec
        // time). Without this redirection the planner's `eprintln`
        // / `tracing` output goes nowhere — which means panic
        // backtraces, mount errors, env hydration errors, and the
        // dispatch-loop diagnostics all silently disappear, leaving
        // the host with nothing but a vsock RST.
        //
        // Open `/dev/console` ourselves and `dup2` it onto fd 0/1/2
        // so the rest of the planner can use the standard streams
        // and have them land on the substrate's serial-console
        // attachment (host file under `data_dir/guests/<id>/console.log`
        // for AVF; pipe to firecracker's `boot_args` console for
        // Firecracker).
        redirect_stdio_to_console();
    }

    /// Open `/dev/console` and dup it onto fd 0/1/2. Idempotent and
    /// silently no-op if the console node is missing — the planner
    /// has no recovery path beyond logging anyway, and we cannot
    /// log without a console.
    fn redirect_stdio_to_console() {
        // Opening /dev/console requires devtmpfs to have been
        // mounted by [`mount_pid1_essentials`]; if a future caller
        // skips that, the open fails and we silently retain the
        // pre-existing (probably empty) stdio.
        let path = CString::new("/dev/console").expect("static path is NUL-free");
        // `O_WRONLY` keeps the kernel from blocking if no reader is
        // attached on the console; the console driver always
        // accepts writes regardless of opener mode.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NOCTTY) };
        if fd < 0 {
            // Re-attempt with O_RDWR in case the device demands it
            // for some substrate (Firecracker's `serial::Stdio`
            // wraps a duplex pipe and rejects O_WRONLY-only).
            let fd_rw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
            if fd_rw < 0 {
                eprintln!(
                    "{{\"level\":\"warn\",\"step\":\"guest-init\",\
                      \"event\":\"open_console_failed\",\
                      \"errno\":{}}}",
                    io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(-1),
                );
                return;
            }
            dup_onto_stdio(fd_rw);
            return;
        }
        dup_onto_stdio(fd);
    }

    /// `dup2` `fd` onto fd 0/1/2 then close `fd`. Logs (best-effort
    /// — once stdio is hooked up the eprintln will reach the
    /// substrate-side console log) on each dup outcome so we can
    /// diagnose where redirection failed without a `strace`.
    fn dup_onto_stdio(fd: libc::c_int) {
        for target in [0, 1, 2] {
            // Skip a noop dup (in the unlikely case the kernel
            // already had us pointing at the console).
            if target == fd {
                continue;
            }
            let rc = unsafe { libc::dup2(fd, target) };
            if rc < 0 {
                eprintln!(
                    "{{\"level\":\"warn\",\"step\":\"guest-init\",\
                      \"event\":\"dup2_failed\",\"target\":{},\
                      \"errno\":{}}}",
                    target,
                    io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(-1),
                );
            }
        }
        // Best-effort close of the original fd — dup2 already
        // gave us 0/1/2 with the same backing console.
        if fd > 2 {
            unsafe {
                libc::close(fd);
            }
        }
        // Now that stdio points at /dev/console, emit a single
        // marker so the host-side console.log unambiguously
        // identifies a successful boot of `/init` (PID 1) and the
        // version string. Anything before this point is invisible
        // to the host.
        eprintln!(
            "{{\"level\":\"info\",\"step\":\"guest-init\",\
              \"event\":\"stdio_attached_to_console\",\
              \"version\":{:?}}}",
            env!("CARGO_PKG_VERSION"),
        );
    }

    fn try_mount(target: &str, fs_type: &str, flags: libc::c_ulong) -> io::Result<()> {
        // SAFETY: `target` and `fs_type` are static `&str`, copied
        // into freshly-allocated `CString`s here; the resulting
        // pointers live for the duration of the mount(2) call. We
        // pass `null` for `source` and `data` because procfs /
        // sysfs / devtmpfs / tmpfs all ignore them.
        let target_c = CString::new(target).expect("static target has no NUL bytes");
        let fs_c     = CString::new(fs_type).expect("static fs_type has no NUL bytes");
        let rc = unsafe {
            libc::mount(
                std::ptr::null(),
                target_c.as_ptr(),
                fs_c.as_ptr(),
                flags,
                std::ptr::null(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Mount one VirtioFS share inside the guest. Equivalent to
    /// `mount -t virtiofs <tag> <guest_path>` (read/write) or
    /// `mount -t virtiofs -o ro <tag> <guest_path>` (read-only).
    pub(super) fn try_mount_virtiofs(
        tag:        &str,
        guest_path: &str,
        read_only:  bool,
    ) -> io::Result<()> {
        let source_c = CString::new(tag)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let target_c = CString::new(guest_path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let fs_c = CString::new("virtiofs")
            .expect("static fs_type has no NUL bytes");
        // VirtioFS does not need a `data` parameter for the basic
        // case; mount options like `cache=…` would be supplied
        // here. The kernel's virtiofs driver pulls cache mode
        // from the device descriptor by default.
        let mut flags: libc::c_ulong = libc::MS_NOSUID | libc::MS_NODEV;
        if read_only {
            flags |= libc::MS_RDONLY;
        }
        let rc = unsafe {
            libc::mount(
                source_c.as_ptr(),
                target_c.as_ptr(),
                fs_c.as_ptr(),
                flags,
                std::ptr::null(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Mount `/proc`, `/sys`, `/dev`, `/tmp` if and only if this
/// process is PID 1 on Linux. No-op everywhere else (subprocess
/// substrate on the host, macOS dev workflows, …).
///
/// MUST be called BEFORE [`crate::cmdline_env::hydrate_from_proc_cmdline`]
/// so the env hydrator can actually read `/proc/cmdline`.
pub fn init_pid1_filesystem() {
    #[cfg(target_os = "linux")]
    {
        if std::process::id() == 1 {
            linux::mount_pid1_essentials();
        }
    }
    // Non-Linux + non-PID-1 path: deliberate no-op.
}

// ---------------------------------------------------------------------------
// VirtioFS workspace-share mounts
// ---------------------------------------------------------------------------

/// Environment variable the AVF / Firecracker substrates use to
/// hand the guest the list of `WorkspaceMount`s the host has wired
/// in via VirtioFS. Comma-separated entries of the form
/// `<tag>:<guest_path>:<rw|ro>`. Empty / unset ⇒ no shares to
/// mount (the substrate did not declare any workspace mounts).
///
/// Wire shape (single entry):
///
/// ```text
/// <tag>:<guest_path>:<mode>
///   tag        — VirtioFS tag, must match the substrate's
///                `AvfVirtioFsShare.tag` byte-for-byte.
///                Convention: `<guest_path>` with the leading
///                `/` stripped and any internal `/` rewritten to
///                `_` (e.g. `/workspace` ⇒ `workspace`,
///                `/raxis/foo` ⇒ `raxis_foo`).
///   guest_path — absolute path inside the guest where the share
///                is mounted (must start with `/`).
///   mode       — `ro` (`MountMode::ReadOnly`) or `rw`
///                (`MountMode::ReadWrite`).
/// ```
///
/// We deliberately do NOT route this through `raxis.envb64=` (the
/// catch-all base64 channel) because the substrate already needs
/// the per-mount tag/path/mode to surface the AVF
/// `VZVirtioFileSystemDeviceConfiguration` in
/// `crates/isolation-apple-vz/src/config.rs::translate`; the guest
/// must observe the exact same triple to issue the correct
/// `mount(2)` syscall. Pinning the env-var name here keeps the
/// host/guest contract single-channel.
pub const VIRTIOFS_MOUNTS_ENV: &str = "RAXIS_VIRTIOFS_MOUNTS";

/// One parsed VirtioFS share spec extracted from
/// [`VIRTIOFS_MOUNTS_ENV`]. The host-side substrate (AVF /
/// Firecracker) already validated `host_path` and the
/// `MountMode`; the guest only sees the post-validation triple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioFsMountSpec {
    /// VirtioFS tag — must match the host-side
    /// `AvfVirtioFsShare.tag`. Used as the `source` argument to
    /// `mount(2)`.
    pub tag: String,
    /// Absolute guest path the share is mounted at (the `/init`
    /// process performs `mkdir -p` before mounting).
    pub guest_path: String,
    /// `true` ⇒ mount the share read-only (`MS_RDONLY`).
    pub read_only: bool,
}

/// Outcome of parsing [`VIRTIOFS_MOUNTS_ENV`] and attempting each
/// mount. Aggregated and logged by the planner main entry-points
/// so the kernel-side scraper can correlate a guest-side mount
/// failure to the host-side substrate event.
#[derive(Clone, Debug)]
pub enum WorkspaceMountOutcome {
    /// `RAXIS_VIRTIOFS_MOUNTS` was unset or empty — the substrate
    /// did not wire any workspace shares, the guest has nothing to
    /// mount.
    NoEnvVar,
    /// The env var existed but at least one entry was malformed.
    /// The guest still attempts to mount the well-formed entries
    /// (defence-in-depth: a typo in one entry must not strand a
    /// healthy share).
    BadEnvVar {
        /// Operator-facing diagnostic for why a token was rejected.
        reason: String,
        /// The well-formed entries we still attempted to mount.
        attempts: Vec<MountAttempt>,
    },
    /// All entries parsed cleanly; per-attempt status is in
    /// `attempts`.
    Mounted {
        /// One [`MountAttempt`] per parsed [`VirtioFsMountSpec`].
        attempts: Vec<MountAttempt>,
    },
}

/// Per-share mount attempt + outcome.
#[derive(Clone, Debug)]
pub struct MountAttempt {
    /// The parsed share specification we tried to mount.
    pub spec: VirtioFsMountSpec,
    /// Whether the `mount(2)` syscall succeeded, treated EBUSY as
    /// success (already-mounted), or failed.
    pub status: MountStatus,
}

/// Discriminant for a single per-share mount outcome.
#[derive(Clone, Debug)]
pub enum MountStatus {
    /// `mount(2)` returned 0 — the share is now visible at
    /// `spec.guest_path`.
    Ok,
    /// `mount(2)` returned `EBUSY` (`spec.guest_path` was already
    /// mounted by an earlier substrate hook). Treated as success
    /// for idempotency.
    Already,
    /// `mount(2)` failed (or `mkdir -p` of the target failed
    /// upstream). The reason is the operator-facing `io::Error`
    /// message; the guest continues to try the remaining shares.
    Failed {
        /// Operator-facing diagnostic for why this mount failed.
        reason: String,
    },
}

/// Parse one comma-separated `RAXIS_VIRTIOFS_MOUNTS` payload into
/// [`VirtioFsMountSpec`]s + the index of the first malformed
/// token (if any).
pub fn parse_virtiofs_mounts(
    raw: &str,
) -> (Vec<VirtioFsMountSpec>, Option<String>) {
    let mut out: Vec<VirtioFsMountSpec> = Vec::new();
    let mut bad: Option<String> = None;
    for (idx, raw_entry) in raw.split(',').enumerate() {
        let entry = raw_entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.split(':');
        let tag = match parts.next() {
            Some(t) if !t.is_empty() => t.to_owned(),
            _ => {
                if bad.is_none() {
                    bad = Some(format!(
                        "entry {idx}: missing or empty <tag> field"
                    ));
                }
                continue;
            }
        };
        let guest_path = match parts.next() {
            Some(p) if p.starts_with('/') => p.to_owned(),
            Some(p) => {
                if bad.is_none() {
                    bad = Some(format!(
                        "entry {idx}: <guest_path> must be absolute (got {p:?})"
                    ));
                }
                continue;
            }
            None => {
                if bad.is_none() {
                    bad = Some(format!(
                        "entry {idx}: missing <guest_path> field"
                    ));
                }
                continue;
            }
        };
        let mode = match parts.next() {
            Some("ro") => true,
            Some("rw") => false,
            Some(other) => {
                if bad.is_none() {
                    bad = Some(format!(
                        "entry {idx}: <mode> must be 'ro' or 'rw' (got {other:?})"
                    ));
                }
                continue;
            }
            None => {
                if bad.is_none() {
                    bad = Some(format!(
                        "entry {idx}: missing <mode> field"
                    ));
                }
                continue;
            }
        };
        if parts.next().is_some() && bad.is_none() {
            bad = Some(format!(
                "entry {idx}: too many ':' separated fields"
            ));
            // Still accept the spec — extra fields are tolerated
            // for forward-compatibility, but flagged.
        }
        out.push(VirtioFsMountSpec {
            tag,
            guest_path,
            read_only: mode,
        });
    }
    (out, bad)
}

/// Read [`VIRTIOFS_MOUNTS_ENV`] and mount every declared VirtioFS
/// share. No-op on non-Linux. Each mount is best-effort: a single
/// failed share does not abort the others.
///
/// MUST be invoked AFTER [`init_pid1_filesystem`] (which mounts
/// `/proc`/`/sys`/`/dev`/`/tmp`) AND AFTER
/// [`crate::cmdline_env::hydrate_from_proc_cmdline`] (which copies
/// the env from `/proc/cmdline` into the process env). Otherwise
/// the env var is invisible.
pub fn mount_workspace_shares() -> WorkspaceMountOutcome {
    let raw = match std::env::var(VIRTIOFS_MOUNTS_ENV) {
        Ok(v) if !v.is_empty() => v,
        _ => return WorkspaceMountOutcome::NoEnvVar,
    };
    let (specs, bad) = parse_virtiofs_mounts(&raw);
    let mut attempts: Vec<MountAttempt> = Vec::with_capacity(specs.len());
    for spec in specs {
        let status = mount_one(&spec);
        attempts.push(MountAttempt { spec, status });
    }
    match bad {
        Some(reason) => WorkspaceMountOutcome::BadEnvVar { reason, attempts },
        None => WorkspaceMountOutcome::Mounted { attempts },
    }
}

#[cfg(target_os = "linux")]
fn mount_one(spec: &VirtioFsMountSpec) -> MountStatus {
    if let Err(e) = std::fs::create_dir_all(&spec.guest_path) {
        return MountStatus::Failed {
            reason: format!(
                "mkdir -p {target}: {e}",
                target = spec.guest_path,
            ),
        };
    }
    match linux::try_mount_virtiofs(&spec.tag, &spec.guest_path, spec.read_only) {
        Ok(()) => MountStatus::Ok,
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => MountStatus::Already,
        Err(e) => MountStatus::Failed { reason: e.to_string() },
    }
}

#[cfg(not(target_os = "linux"))]
fn mount_one(_spec: &VirtioFsMountSpec) -> MountStatus {
    // Non-Linux dev hosts have no `mount(2)` for virtiofs; the
    // planner does not run as PID 1 there anyway.
    MountStatus::Failed {
        reason: "mount_workspace_shares is a no-op on non-Linux".to_owned(),
    }
}

/// **Cleanly power off the microVM after the planner main exits.**
///
/// Linux treats PID 1 exit as a fatal kernel event ("Attempted to
/// kill init!") and triggers an automatic reboot per the kernel's
/// `panic=…` cmdline argument. AVF substrates observe the reboot
/// rather than a clean stop, which keeps the per-session VM alive
/// in a zombie loop:
///
///   1. planner main returns SUCCESS
///   2. process-1 exits → kernel panic → kernel auto-reboots
///   3. AVF re-runs `/init`, planner-boot fires again
///   4. New planner instance binds vsock and blocks on accept(),
///      but the kernel-side `drive_planner_stream` task has
///      already returned EOF and there is no re-bridge
///   5. The host sees an indefinitely-running session with a
///      planner that never advances — wedging the lifecycle
///
/// Issuing `reboot(LINUX_REBOOT_CMD_POWER_OFF)` from PID 1 instead
/// performs an orderly hypervisor shutdown. The substrate observes
/// `SessionVmExited` cleanly, the kernel emits the audit row, and
/// the lifecycle proceeds (e.g. spawning the next sub-task or
/// re-spawning the orchestrator on the next DAG edge — see
/// `kernel/src/initiatives/lifecycle.rs::respawn_orchestrator_after_*`).
///
/// Behaviour:
/// * **PID 1 on Linux:** flushes stdio, then issues
///   `LINUX_REBOOT_CMD_POWER_OFF` via `libc::reboot`. The function
///   does not return on success (the kernel halts the VM). On
///   failure we fall through to `exit(code)` so the substrate at
///   least sees a process exit.
/// * **PID ≠ 1 or non-Linux:** `std::process::exit(code)` —
///   subprocess substrate on the host where exit-code propagation
///   is the host's `Command::status()` contract.
///
/// `code` is the kernel-visible exit code per `planner-harness.md
/// §14.6` ("planner exit codes"). Cross-substrate the meaning is:
/// 0 = clean terminal-tool firing, non-zero = structured failure.
pub fn shutdown_or_exit(code: u8) -> ! {
    // Best-effort flush so the last `planner-completed` /
    // `planner-boot-error` line lands on the substrate's console
    // log before we cut the VM. Both writers are line-buffered on
    // a serial console, but explicit flushing is cheap insurance
    // against a panic backtrace getting clipped mid-line.
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    #[cfg(target_os = "linux")]
    {
        if std::process::id() == 1 {
            // Emit one structured line so a post-mortem can
            // unambiguously distinguish a clean halt from a panic
            // (the kernel-panic path is silent past `do_exit`).
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"guest-init\",\
                  \"event\":\"shutdown_power_off\",\"exit_code\":{code}}}"
            );
            // SAFETY: `libc::reboot` is the canonical syscall wrapper
            // for `reboot(2)`. From PID 1 with `LINUX_REBOOT_CMD_POWER_OFF`
            // it never returns on success; the VM halts and the
            // hypervisor observes a clean exit. On error (e.g. the
            // kernel was built without CONFIG_REBOOT_VECTOR) we fall
            // through to the std::process::exit path so the substrate
            // still sees a process exit code.
            let rc = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
            // Reaching this line means reboot(2) returned non-zero —
            // log it and fall through to a regular exit so we do not
            // leave the planner process hanging.
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(-1);
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-init\",\
                  \"event\":\"shutdown_power_off_failed\",\
                  \"rc\":{rc},\"errno\":{errno}}}"
            );
        }
    }

    std::process::exit(code as i32)
}
