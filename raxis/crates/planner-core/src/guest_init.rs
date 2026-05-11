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
