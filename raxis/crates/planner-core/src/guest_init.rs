//! `guest_init` — mount the essential virtual filesystems when the
//! planner binary is executed as PID 1 inside a Linux microVM.
//!
//! ## Why this exists
//!
//! Under the AVF and Firecracker substrates the canonical image is
//! a `cpio.gz` initramfs whose `/init` entry **is** the planner
//! binary (per `cargo xtask images bake`). The Linux kernel
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
//! no `RAXIS_SESSION_ID`, and no `RAXIS_PLANNER_TASK_PROMPT`,
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
        target: &'static str,
        fs_type: &'static str,
        flags: libc::c_ulong,
    }

    /// Canonical mount table for V2 GA. Order matters: `/dev` is
    /// mounted last so `/dev/null` becoming available cannot hide
    /// an earlier mount failure on stderr.
    const PLAN: &[MountPlan] = &[
        MountPlan {
            target: "/proc",
            fs_type: "proc",
            // procfs default flags: nodev, noexec, nosuid (kernel
            // sets these automatically for procfs even without
            // explicit flags, but we set them so older kernels
            // behave consistently).
            flags: libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID,
        },
        MountPlan {
            target: "/sys",
            fs_type: "sysfs",
            flags: libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID,
        },
        MountPlan {
            target: "/tmp",
            fs_type: "tmpfs",
            flags: libc::MS_NODEV | libc::MS_NOSUID,
        },
        MountPlan {
            target: "/dev",
            fs_type: "devtmpfs",
            flags: libc::MS_NOSUID,
        },
    ];

    /// Mount the canonical filesystems and ensure the target
    /// directories exist (initramfs may not include them by
    /// default; `cargo xtask images bake` creates them but a
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
                    plan.target,
                    e.to_string(),
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
                    plan.target,
                    plan.fs_type,
                    e.to_string(),
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
        // `tracing` output goes nowhere — which means panic
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

        // Bring up the loopback interface (`lo`). The Linux kernel
        // ships every interface in the `DOWN + !RUNNING` state at
        // boot; until we explicitly issue `ip link set lo up` the
        // 127.0.0.0/8 address space has no usable backing device
        // and any `bind(127.0.0.1:N)` returns `EADDRNOTAVAIL`
        // (Linux errno 99 — "Cannot assign requested address").
        //
        // Three callsites depend on `lo` being up inside the
        // executor VM:
        //   * `raxis_tproxy::loopback_forwarder::spawn_forwarder` —
        //     binds `127.0.0.1:<guest_loopback_port>` for every
        //     credential proxy. Without `lo` up the executor task
        //     fails with the same `EADDRNOTAVAIL` cascade that the
        //     substrate-loopback fix `8a26540` was meant to remove.
        //   * tools that loopback-spawn a sidecar service (none today,
        //     but the contract is symmetric with a non-virtualised
        //     dev host where `lo` is always up).
        //   * future planner-side health checks that dial
        //     `127.0.0.1:<port>` to probe their own listeners.
        //
        // Failure here is logged but does NOT abort: a substrate
        // that pre-brings-up `lo` (a future Firecracker variant
        // that ships an MMDS-stage netlink hook, for example) MUST
        // not be broken by a duplicate set-flags call. The `lo`
        // interface tolerates idempotent `IFF_UP | IFF_RUNNING`
        // sets — the second call returns success without churning
        // the routing table.
        bring_up_loopback();
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
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1),
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
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1),
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

    /// Bring up the loopback interface (`lo`) inside the guest.
    ///
    /// Equivalent to `ip link set lo up` / `ifconfig lo up` but
    /// done via direct `ioctl(SIOCSIFFLAGS)` so the in-VM rootfs
    /// does not need to ship `iproute2` or `net-tools` — neither
    /// is in the executor canonical image (`planner-core/Cargo.toml`
    /// lines 51-58 confirm the rootfs is planner-binary-only).
    ///
    /// Pure-libc implementation — no extra crate deps. Idempotent:
    /// reading the current flags first means a substrate that
    /// pre-brings-up `lo` reports `iface_already_up` instead of
    /// re-issuing the set.
    pub(super) fn bring_up_loopback() {
        // SAFETY: every libc call below operates on values whose
        // lifetimes are bounded by this function. The `ifreq`
        // struct is zeroed before we write the interface name, the
        // socket fd is closed unconditionally on every exit path,
        // and `ioctl` is invoked with the canonical SIOC* request
        // codes documented in `netdevice(7)`.
        #[allow(unsafe_code)]
        unsafe {
            // `socket(AF_INET, SOCK_DGRAM, 0)` — the canonical
            // "control plane" socket every netdevice ioctl is
            // dispatched against. We pick AF_INET (not AF_PACKET)
            // because it's available on the leanest kernel configs;
            // SIOCSIFFLAGS does not actually read or write any IP
            // packets, the socket is just the dispatch handle.
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock < 0 {
                eprintln!(
                    "{{\"level\":\"warn\",\"step\":\"guest-init\",\
                      \"event\":\"loopback_socket_failed\",\
                      \"errno\":{}}}",
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                );
                return;
            }

            let mut ifr: libc::ifreq = std::mem::zeroed();
            // Copy "lo" into ifr_name (NUL-terminated). `ifr_name`
            // is `[c_char; IFNAMSIZ]`; "lo" plus a NUL fits in
            // 3 bytes which is well under the 16-byte cap.
            let name = b"lo\0";
            for (i, &byte) in name.iter().enumerate() {
                ifr.ifr_name[i] = byte as libc::c_char;
            }

            // Read current flags via SIOCGIFFLAGS. The libc `ioctl`
            // request constants for AF_INET netdevice ioctls are
            // typed as `u64` on aarch64-musl; the syscall takes
            // `Ioctl` (currently `c_ulong`/`i32` depending on
            // libc version + target). We round-trip via `c_ulong`
            // so the cast is platform-correct on every target the
            // planner ships to.
            if libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::c_ulong as _, &mut ifr) < 0 {
                eprintln!(
                    "{{\"level\":\"warn\",\"step\":\"guest-init\",\
                      \"event\":\"loopback_ioctl_get_failed\",\
                      \"errno\":{}}}",
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                );
                libc::close(sock);
                return;
            }

            // `ifreq` is a C union: the flags live at
            // `ifr_ifru.ifru_flags` (i16). On Linux's libc binding
            // the union is exposed via the `ifr_ifru` field with
            // typed accessors; we read/write the flags slot
            // directly through the union to keep this dependency-
            // free of any helper crate.
            let cur_flags = ifr.ifr_ifru.ifru_flags;
            let want = cur_flags | (libc::IFF_UP as i16) | (libc::IFF_RUNNING as i16);
            if cur_flags == want {
                eprintln!(
                    "{{\"level\":\"info\",\"step\":\"guest-init\",\
                      \"event\":\"loopback_already_up\"}}"
                );
                libc::close(sock);
                return;
            }
            ifr.ifr_ifru.ifru_flags = want;

            if libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::c_ulong as _, &ifr) < 0 {
                eprintln!(
                    "{{\"level\":\"warn\",\"step\":\"guest-init\",\
                      \"event\":\"loopback_ioctl_set_failed\",\
                      \"errno\":{}}}",
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                );
                libc::close(sock);
                return;
            }
            libc::close(sock);
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"guest-init\",\
                  \"event\":\"loopback_up\"}}"
            );
        }
    }

    fn try_mount(target: &str, fs_type: &str, flags: libc::c_ulong) -> io::Result<()> {
        // SAFETY: `target` and `fs_type` are static `&str`, copied
        // into freshly-allocated `CString`s here; the resulting
        // pointers live for the duration of the mount(2) call. We
        // pass `null` for `source` and `data` because procfs /
        // sysfs / devtmpfs / tmpfs all ignore them.
        let target_c = CString::new(target).expect("static target has no NUL bytes");
        let fs_c = CString::new(fs_type).expect("static fs_type has no NUL bytes");
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

    /// Mount one substrate-declared filesystem inside the guest.
    /// For AVF this is `mount -t virtiofs <tag> <guest_path>`.
    /// For Firecracker this is
    /// `mount -t ext4 /dev/vdX <guest_path>` over a kernel-owned
    /// workspace block image.
    pub(super) fn try_mount_filesystem(
        source: &str,
        guest_path: &str,
        fs_type: &str,
        read_only: bool,
    ) -> io::Result<()> {
        let source_c =
            CString::new(source).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let target_c =
            CString::new(guest_path).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let fs_c =
            CString::new(fs_type).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
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

/// `INV-PLANNER-PID1-ONLY-EXEC-01` — exit code emitted by
/// [`enforce_pid1_or_abort`] when the binary is invoked outside
/// PID 1 on Linux. Chosen distinct from every documented planner
/// exit (0 = clean, 1 = generic error, 2 = misuse, 64 =
/// `BOOT_ERR_ISOLATION_UNAVAILABLE`, 78 =
/// `BOOT_ERR_CONFIG`) so an operator scanning `dmesg` /
/// substrate logs can tell at a glance that the binary refused
/// to start because the agent (LLM) re-exec'd it from inside a
/// VM.
pub const PID1_ENFORCEMENT_EXIT_CODE: u8 = 126;

/// `INV-PLANNER-PID1-ONLY-EXEC-01` — refuse to start when this
/// binary is invoked outside PID 1 on Linux.
///
/// ## Why this exists
///
/// Inside a Raxis microVM the planner binary is wired as `/init`
/// (PID 1). After PID 1 boots, the binary remains on disk at
/// `/usr/local/bin/raxis-{executor,orchestrator,reviewer}`,
/// reachable through `$PATH` from the agent's bash tool. In
/// iter72 forensics we observed the executor's Claude agent
/// running `bash -lc "raxis-executor --help"` while diagnosing a
/// `dep-fetch-evidence` DNS failure — the agent had no malicious
/// intent, but a child invocation of the executor binary inside
/// its own VM IS a jailbreak vector:
///
/// 1. The child process inherits the parent's environment,
///    including `RAXIS_PLANNER_TASK_PROMPT_PATH` and
///    `RAXIS_KERNEL_VSOCK_LISTEN_PORT`. It can confuse the
///    kernel-side planner IPC flow by reusing the parent's
///    transport hints until the parent's session is revoked.
/// 2. The child can read the parent's `/proc/<parent_pid>/cmdline`
///    to learn the parent's per-task arguments (initiative id,
///    task id) and impersonate the parent's identity at the
///    kernel-side dispatch matrix.
/// 3. The child's port-binding attempts (vsock loopback forwarder
///    on the credential-proxy port; airgap A3 chokepoint on port
///    3129) collide with the parent's, which manifests at the
///    host as a stalled VM — exactly the kind of stall the
///    iter72 idle watchdog catches *after* the damage is done.
///
/// The cleanest defense is to refuse to start in the first place:
/// the planner binary contract is "PID 1 of a microVM". Any
/// invocation that violates the contract is rejected with a
/// distinctive exit code and a structured stderr breadcrumb that
/// surfaces in the in-VM console log, so a post-mortem replay
/// can correlate the jailbreak attempt against the agent's
/// tool-use audit chain.
///
/// ## Scope of the check
///
/// **Linux only.** On macOS the binaries are not executed
/// directly (they cross-compile to aarch64-linux for the
/// microVM); the unit tests in `raxis-planner-core` exercise the
/// library surface, not these `main()`s. On Linux outside the
/// substrate the binary is genuinely useless (no `RAXIS_*` env,
/// no kernel UDS, no canonical image), so refusing to start
/// loses nothing the operator could legitimately want.
///
/// ## Override (test-only)
///
/// Setting `RAXIS_PLANNER_PID1_ENFORCEMENT_BYPASS=1` skips the
/// check. This exists so a host-mode `SubprocessIsolation`
/// fixture (used by some legacy kernel tests that drive the
/// planner as a child process rather than a real microVM) can
/// continue to function. The bypass is logged loudly so a
/// production operator who flips it by mistake sees the warning
/// in the kernel stderr stream.
///
/// ## Behaviour
///
/// * Linux + PID 1 + bypass-unset: return `Ok(())`. Normal flow.
/// * Linux + PID 1 + bypass-set: log warning, return `Ok(())`.
/// * Linux + PID ≠ 1 + bypass-unset: log structured stderr,
///   exit with [`PID1_ENFORCEMENT_EXIT_CODE`] (`126`). Does
///   not return.
/// * Linux + PID ≠ 1 + bypass-set: log warning, return `Ok(())`.
/// * Non-Linux: return `Ok(())` (no-op).
pub fn enforce_pid1_or_abort() {
    #[cfg(target_os = "linux")]
    {
        let bypass = std::env::var("RAXIS_PLANNER_PID1_ENFORCEMENT_BYPASS")
            .map(|v| v == "1")
            .unwrap_or(false);
        let pid = std::process::id();
        if pid == 1 {
            // Normal flow; nothing to log.
            return;
        }
        if bypass {
            eprintln!(
                "{{\"level\":\"warn\",\
                 \"event\":\"planner_pid1_enforcement_bypassed\",\
                 \"pid\":{pid},\
                 \"reason\":\"RAXIS_PLANNER_PID1_ENFORCEMENT_BYPASS=1; \
                 this should ONLY be set by legacy host-mode \
                 SubprocessIsolation fixtures. Production microVMs \
                 must NEVER set this.\"}}"
            );
            return;
        }
        // Determine the binary's argv[0] for the structured
        // breadcrumb so a forensic replay can identify which of
        // the three planner binaries the agent re-exec'd.
        let argv0 = std::env::args()
            .next()
            .unwrap_or_else(|| "<unknown>".to_owned());
        // Capture parent pid for jailbreak-attribution chains —
        // PPID is the in-VM agent's shell (or the agent's process
        // tree root) and lets the operator correlate the attempt
        // against the agent's bash tool-use audit chain.
        let ppid = std::os::unix::process::parent_id();
        eprintln!(
            "{{\"level\":\"error\",\
             \"event\":\"planner_pid1_enforcement_violation\",\
             \"pid\":{pid},\
             \"ppid\":{ppid},\
             \"argv0\":\"{argv0}\",\
             \"exit_code\":{exit_code},\
             \"invariant\":\"INV-PLANNER-PID1-ONLY-EXEC-01\",\
             \"reason\":\"raxis-planner binaries MUST run only as \
             PID 1 of a microVM. This invocation is a child process \
             — likely an LLM-driven re-exec from within an executor \
             VM. Aborting to prevent session-token reuse and \
             port-binding collisions. See \
             specs/v2/planner-ipc-idle-watchdog.md \
             §1.1 + specs/v2/planner-harness.md for the \
             jailbreak taxonomy.\"}}",
            pid = pid,
            ppid = ppid,
            argv0 = argv0,
            exit_code = PID1_ENFORCEMENT_EXIT_CODE,
        );
        std::process::exit(PID1_ENFORCEMENT_EXIT_CODE as i32);
    }
    #[cfg(not(target_os = "linux"))]
    {
        // No-op on macOS / Windows. The planner binaries never
        // run natively on these hosts — they cross-compile to
        // aarch64-linux for the microVM.
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
            // iter73 regression: the Linux kernel hands /init only
            // `HOME=/ TERM=linux` from the AVF substrate boot-args
            // and the cmdline-env token does not carry PATH either.
            // Musl libc's `execvp` then falls back to a default
            // search path of `/usr/local/bin:/bin:/usr/bin` — which
            // does NOT include `/usr/sbin`, where Debian ships
            // nft, ip, sysctl, etc., and does NOT include
            // `/root/.cargo/bin`, where the executor starter image
            // installs Rust via rustup. Bare-name `Command::new("X")`
            // calls would silently miss those binaries.
            // Synthesising a defensive PATH here is cheap (one
            // `set_var`), idempotent, and short-circuits any future
            // bare-name spawn that lands inside the agent VM. The
            // operator-supplied env still wins via `set_var`'s
            // last-writer semantics — `hydrate_from_proc_cmdline`
            // runs AFTER this and will overwrite PATH if the
            // kernel-stamped cmdline carries one.
            // SAFETY: PID 1 is single-threaded at this point
            // (tokio runtime has not been built yet). Setting an
            // env var here is therefore unsynchronised but
            // race-free.
            if std::env::var_os("PATH").is_none() {
                unsafe {
                    std::env::set_var(
                        "PATH",
                        "/root/.cargo/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    );
                }
                eprintln!(
                    "{{\"level\":\"info\",\"step\":\"guest-init\",\
                     \"event\":\"pid1_default_path_set\",\
                     \"value\":\"/root/.cargo/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"}}"
                );
            }
        }
    }
    // Non-Linux + non-PID-1 path: deliberate no-op.
}

// ---------------------------------------------------------------------------
// Path A3 egress chokepoint setup
// ---------------------------------------------------------------------------

/// Env var consumed by [`init_pid1_a3_egress`] to size the
/// nftables REDIRECT chain that catches outbound TCP from agent
/// processes. Default `3129` matches
/// `raxis_tproxy::linux::bind_default_listener`.
pub const A3_TPROXY_PORT_ENV: &str = "RAXIS_AIRGAP_A3_TPROXY_PORT";

/// Default in-guest port the nftables REDIRECT chain forwards
/// outbound TCP to. Mirrors `raxis_tproxy::linux::bind_default_listener`.
pub const A3_DEFAULT_TPROXY_PORT: u16 = 3129;

/// Install the in-guest egress chokepoint when the calling process
/// is PID 1 on Linux.
///
/// After the Tier1Tproxy deletion (TODO
/// `tier1-deletion-fold-into-cleanup-sweep`) every executor /
/// orchestrator VM boots at `EgressTier::Mediated`, so the
/// chokepoint is installed unconditionally on Linux PID 1 — the
/// previous `RAXIS_AIRGAP_A3=1` env-var gate was removed in the
/// same sweep. (Non-Linux platforms and non-PID-1 callers remain
/// no-ops.)
///
/// Steps:
///   1. Disable IPv6 entirely (sysfs writes to
///      `/proc/sys/net/ipv6/conf/{all,default,lo}/disable_ipv6`).
///      The substrate refuses to provision a NIC under
///      `raxis_isolation::EgressTier::Mediated`, so the guest
///      has no IPv6 interface to begin with, but defence in
///      depth: a future substrate that exposes an IPv6
///      auto-configured device cannot leak via SLAAC.
///   2. Write `/etc/resolv.conf` so the libc resolver dispatches
///      every `getaddrinfo` through `127.0.0.1:53` — i.e. the
///      in-guest DNS stub that fans queries out over vsock to
///      the kernel-side resolver.
///   3. Configure loopback routing sysctls for local transparent
///      NAT. The route below intentionally makes non-local peers
///      traverse `lo` before nftables redirects them; the reverse
///      path can therefore look martian to stock IPv4 checks unless
///      local routing is explicitly enabled and reverse-path
///      filtering is disabled for the no-NIC guest.
///   4. Install a loopback-backed IPv4 default route. The A3 guest
///      has no NIC by design; without a default route Linux can
///      return `ENETUNREACH` before the `nat OUTPUT` hook sees the
///      socket and redirects it to the in-guest tproxy.
///   5. Install native nftables `nat OUTPUT` REDIRECT rules to send
///      outbound TCP to the local tproxy listener
///      (`127.0.0.1:<tproxy_port>`). UDP port 53 is REDIRECTed
///      to the local DNS stub on port 53. The canonical path uses
///      native nftables (`nft -f -`) instead of the xtables
///      compatibility frontend, which removes the iptables-nft
///      extension mismatch that showed up in live e2e.
///
/// Failures on any individual step are logged but non-fatal:
/// the kernel-side admission listener is the load-bearing
/// chokepoint (`INV-NETISO-A3-VSOCK-CHOKEPOINT-01`) and refuses
/// every connection that arrives from a guest with no admission
/// token. A botched nftables install therefore degrades to
/// "guest cannot reach the network at all" rather than "guest
/// has bypassed the chokepoint".
pub fn init_pid1_a3_egress() {
    #[cfg(target_os = "linux")]
    {
        if std::process::id() != 1 {
            return;
        }
        let tproxy_port = std::env::var(A3_TPROXY_PORT_ENV)
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(A3_DEFAULT_TPROXY_PORT);
        linux_a3::disable_ipv6_via_sysfs();
        linux_a3::write_resolv_conf_for_stub();
        linux_a3::configure_loopback_transparent_egress_sysctls();
        linux_a3::install_loopback_default_route();
        linux_a3::install_nftables_redirect(tproxy_port);
    }
}

// ---------------------------------------------------------------------------
// Guest hardening — `INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01`
// ---------------------------------------------------------------------------

/// Canonical in-guest paths that hold the planner binary across
/// every substrate. Hidden by [`harden_guest_for_agent`] so an
/// in-VM agent's `bash -lc "cat <path>"` returns an empty file
/// instead of the planner executable. The list is comprehensive
/// rather than minimal because the canonical image builder
/// (`cargo xtask images bake`) emits a copy at `/init` AND a
/// PATH-resolvable copy under `/usr/local/bin/` — masking only one
/// would leave the other readable.
pub const PLANNER_BINARY_PATHS_TO_MASK: &[&str] = &[
    "/init",
    "/usr/local/bin/raxis-executor",
    "/usr/local/bin/raxis-orchestrator",
    "/usr/local/bin/raxis-reviewer",
    "/usr/local/bin/raxis-verifier-no-secrets",
];

/// Env vars that MUST be removed from the process environment
/// BEFORE the agent's `BashTool` /
/// [`crate::custom_tools::SubprocessTool`] is allowed to spawn a
/// child. Most are secrets or kernel transport handles; a few are
/// routing, KSB/tool-sidecar, or runtime-control knobs whose presence
/// would mislead the model about the VM's actual task-level
/// capabilities. The planner PID 1 keeps a process-local snapshot for
/// legitimate post-scrub reads; spawned children inherit only
/// `std::env`, where these keys are gone. `RAXIS_SESSION_ID` is
/// captured into `BootEnv` before scrub; `RAXIS_SESSION_TOKEN`
/// remains in this list as a defense-in-depth guard for stale or
/// third-party images, but the supported kernel spawn path no longer
/// exposes it to the guest.
pub const SENSITIVE_ENV_VARS_TO_SCRUB: &[&str] =
    raxis_types::planner_env::AGENT_SUBPROCESS_SCRUBBED_ENV_VARS;

/// `INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01` — last-line
/// post-PID-1-boot defenses against an in-VM LLM agent reading
/// kernel-stamped secrets, re-executing the planner binary, or
/// powering off the VM out-of-band.
///
/// ## Why this exists
///
/// `enforce_pid1_or_abort` (iter72) closed the most obvious
/// vector — a child `raxis-executor` re-exec inheriting the
/// parent's vsock-listener bindings — but the surrounding
/// surface is wider:
///
///   1. **`/proc/cmdline` exposes the kernel-stamped
///      `raxis.envb64=<base64>` envelope.** `cat /proc/cmdline` is
///      not gated by uid; the agent can decode the base64 to
///      recover transport hints, task prompt paths, and other
///      kernel-controlled metadata. Mitigation: bind-mount
///      `/dev/null` over `/proc/cmdline` so reads return EOF
///      regardless of uid. PID 1 has already hydrated its env
///      from the cmdline before this function runs, so masking is
///      lossless for the legitimate path.
///   2. **`/proc/1/environ` echoes the hydrated env.** Same uid
///      check as everywhere in `/proc/<pid>/`, so a root-uid
///      `bash` child can read PID 1's environ block. Mitigation:
///      `prctl(PR_SET_DUMPABLE, 0)` strips the readable bit on
///      `/proc/1/{environ,maps,cmdline,...}` for anything but
///      `CAP_SYS_PTRACE` callers. Combined with the cap-set drop
///      below, this defangs the env-read vector.
///   3. **`/init` and `/usr/local/bin/raxis-*` are world-readable.**
///      Even though `enforce_pid1_or_abort` refuses re-exec, the
///      agent can `cat /init` to read the binary, learn protocol
///      constants, or transmit it for offline analysis.
///      Mitigation: bind-mount `/dev/null` over every canonical
///      planner-binary path. The running PID 1 holds the inode
///      open via its in-kernel exe descriptor, so masking the
///      filesystem path has no effect on the executing process —
///      only on subsequent `open(/init)` calls.
///   4. **`reboot(LINUX_REBOOT_CMD_*)` is a `CAP_SYS_BOOT`
///      operation.** A root-uid `bash` child can shutdown the VM
///      out of band, which the substrate observes as a clean
///      power-off and the kernel synthesises as
///      "executor VM exited via clean EOF without a
///      `PlannerExitNotice`" — a stealth abort. Mitigation: drop
///      `CAP_SYS_BOOT` from the bounding set via
///      `prctl(PR_CAPBSET_DROP, …)`. PID 1 itself does not need
///      `CAP_SYS_BOOT` after this point because
///      [`shutdown_or_exit`] is the only legitimate caller and it
///      runs BEFORE `harden_guest_for_agent`'s effects matter
///      (the planner's `main` runs `shutdown_or_exit` after the
///      dispatch loop returns; we drop the cap as part of the
///      pre-dispatch hardening sweep, which means PID 1 itself
///      can no longer call `reboot(2)`). To keep the clean-exit
///      path working we therefore drop the cap LAST, AFTER the
///      bounding-set drop, only from the BOUNDING SET — the
///      effective + permitted set retains the cap so PID 1 can
///      still issue the power-off, but every `execve` (which the
///      bounding set is consulted on) strips it from the child.
///      Net effect: PID 1 keeps `reboot()`, agent children
///      cannot acquire `CAP_SYS_BOOT`, no path lets the agent
///      shutdown the VM.
///   5. **`prctl(PR_SET_NO_NEW_PRIVS, 1)` defangs setuid binaries
///      transitively.** If the canonical executor rootfs ever
///      ships a setuid binary by accident (today it doesn't), the
///      agent could exec it to acquire host-uid privileges; this
///      flag is inherited across `execve` and prevents any future
///      `setuid` bit from elevating privileges.
///
/// ## Where this runs
///
/// Called from each planner-binary `main` between
/// `init_pid1_a3_egress` (which installs the nftables REDIRECT
/// chain that the in-guest tproxy depends on) and the tokio
/// runtime construction. Subsequent agent-tool subprocess spawns
/// inherit:
///   * the cmdline / environ mask from the procfs bind mounts,
///   * the binary mask from the planner-binary bind mounts,
///   * the `NO_NEW_PRIVS` flag and the
///     `CAP_SYS_BOOT`-stripped bounding set (per-execve).
///
/// Every step is best-effort + logged. A substrate that pre-
/// enforces any of these (a future Firecracker variant could ship
/// procfs already bind-mounted, for example) returns `EBUSY` /
/// `EEXIST`, which we treat as success.
///
/// ## When this is a no-op
///
/// PID ≠ 1 on Linux: the SubprocessIsolation host-mode fixture
/// runs the planner as a normal subprocess, where these mounts
/// would either fail (no `CAP_SYS_ADMIN` outside a user namespace)
/// or actively harm the host. Skipping under PID ≠ 1 keeps the
/// fixture working.
///
/// Non-Linux: macOS dev workstations build the workspace but
/// never run a planner binary natively; the function is a no-op.
pub fn harden_guest_for_agent() {
    #[cfg(target_os = "linux")]
    {
        if std::process::id() != 1 {
            return;
        }
        linux_harden::mask_proc_cmdline();
        linux_harden::set_pid1_undumpable();
        linux_harden::mask_planner_binaries(PLANNER_BINARY_PATHS_TO_MASK);
        linux_harden::drop_cap_sys_boot_from_bounding_set();
        linux_harden::set_no_new_privs();
    }
}

/// `INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01` — second-stage
/// scrub that runs AFTER each in-guest listener has read its
/// transport hints. Removes
/// [`SENSITIVE_ENV_VARS_TO_SCRUB`] from the process environment
/// so subsequent agent-tool subprocess spawns
/// (`BashTool::execute` → `tokio::process::Command::new("bash")`
/// or `SubprocessTool::execute` → `Command::new(argv0)`) cannot
/// inherit them.
///
/// MUST run AFTER:
///   * `hydrate_from_proc_cmdline` (which writes the env from the
///     cmdline token into the process env), AND
///   * the in-guest tproxy / DNS stub spawn (they authenticate via
///     host-owned session binding, so no guest bearer token is
///     needed).
///
/// Idempotent: removing an already-unset variable is a no-op at
/// the libc layer. Logged via one structured stderr line per
/// scrubbed key for audit-replay.
///
/// ## Safety
///
/// Calls `std::env::remove_var`, which is `unsafe` under Rust
/// 2024 due to multi-threaded env-mutation semantics. The caller
/// MUST invoke this BEFORE the agent's first tool dispatch fires.
/// All current call sites
/// (`raxis-planner-{executor,orchestrator,reviewer}/src/main.rs`)
/// run this on the tokio runtime's main task, AFTER the
/// listener-spawning tasks are kicked off but BEFORE the dispatch
/// loop accepts any model-driven tool call. The agent's tools
/// `tokio::process::Command::spawn` call observes the post-scrub
/// env snapshot.
pub fn scrub_sensitive_env_for_agent() {
    let mut scrubbed = 0u32;
    let mut already_unset = 0u32;
    let mut snapshot: std::collections::BTreeMap<&'static str, String> =
        std::collections::BTreeMap::new();
    for &key in SENSITIVE_ENV_VARS_TO_SCRUB {
        match std::env::var(key) {
            Ok(v) => {
                // Snapshot BEFORE removal so in-process readers
                // (specifically `driver::run_role_session`, which
                // reads `RAXIS_KERNEL_VSOCK_LISTEN_PORT`,
                // `RAXIS_PLANNER_TASK_PROMPT[_PATH]`, and
                // safe transport/task env after this scrub fires)
                // can still resolve the value via
                // `read_scrubbed_env_snapshot`. The snapshot is
                // process-local memory — an agent's `bash`
                // subprocess cannot reach it because it inherits
                // via `Command::spawn` from `std::env`, which is
                // the surface this function strips. See iter73
                // regression note in
                // `specs/v3/guest-agent-jailbreak-defense.md`.
                snapshot.insert(key, v);
                // SAFETY: documented contract — the caller invokes
                // this on the main task before the agent's tool
                // dispatch spawns any child. The tokio runtime
                // worker pool may exist by this point, but no
                // worker is concurrently mutating env. The only
                // writer before this point is
                // `cmdline_env::apply_*` during pre-runtime
                // hydration; this one runs synchronously between
                // listener-spawn and dispatch-loop-entry.
                unsafe {
                    std::env::remove_var(key);
                }
                scrubbed += 1;
            }
            Err(_) => {
                already_unset += 1;
            }
        }
    }
    // Idempotency: a second call is a no-op against std::env (vars
    // already removed) and MUST NOT overwrite an earlier snapshot
    // with an empty one. `get_or_init` preserves the first writer.
    let _ = SCRUBBED_ENV_SNAPSHOT.get_or_init(|| snapshot);
    eprintln!(
        "{{\"level\":\"info\",\"step\":\"guest-harden\",\
         \"event\":\"sensitive_env_scrubbed\",\
         \"scrubbed\":{scrubbed},\"already_unset\":{already_unset},\
         \"invariant\":\"INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01\"}}"
    );
}

/// In-process snapshot of the values
/// [`scrub_sensitive_env_for_agent`] removed from `std::env`.
///
/// Populated exactly once, on the first scrub call. Subsequent
/// scrub calls are no-ops against this snapshot
/// (`OnceLock::get_or_init`).
static SCRUBBED_ENV_SNAPSHOT: std::sync::OnceLock<
    std::collections::BTreeMap<&'static str, String>,
> = std::sync::OnceLock::new();

/// Read-side accessor for the scrubbed-env snapshot. Returns
/// `Some(value)` if `key` was in [`SENSITIVE_ENV_VARS_TO_SCRUB`]
/// and was present in `std::env` at the moment
/// [`scrub_sensitive_env_for_agent`] ran. Returns `None` otherwise
/// (variable absent at scrub time, scrub not yet called, or key
/// not in the scrub list).
///
/// This intentionally does NOT fall back to `std::env::var` — the
/// caller is responsible for that fallback so the scrub-vs-read
/// ordering is auditable at the call site.
///
/// ## Why this exists
///
/// iter73 regression: `scrub_sensitive_env_for_agent` was placed
/// before `run_role_session` in the planner-role `main`s under the
/// belief that `BootContext::from_process` had already consumed
/// every env var the planner needed. That belief was wrong —
/// `BootContext::env` only captures `RAXIS_SESSION_ID`, while
/// `run_role_session_with_env_fn` reads
/// `RAXIS_KERNEL_VSOCK_LISTEN_PORT`,
/// `RAXIS_PLANNER_TASK_PROMPT[_PATH]`, and several other vars from
/// `std::env::var` via its env-reader closure. The scrub therefore
/// blanked the very vars `run_role_session` needed, the prompt
/// resolved to `None`, the driver returned `DriverOutcome::Scaffold`,
/// the planner entered `park_on_signal().await`, and the kernel's
/// vsock CONNECT timed out because no listener ever bound.
///
/// The fix preserves the security property — `std::env` is still
/// scrubbed, so the agent's `bash` subprocess (spawned via
/// `tokio::process::Command::spawn`, which inherits from
/// `std::env`) STILL cannot see sensitive transport/control vars
/// while restoring in-process readability for
/// post-scrub planner-driver code that legitimately needs the
/// values. The snapshot lives in Rust-process memory and is not
/// reachable from a spawned child.
pub fn read_scrubbed_env_snapshot(key: &str) -> Option<String> {
    SCRUBBED_ENV_SNAPSHOT
        .get()
        .and_then(|m| m.get(key))
        .cloned()
}

#[cfg(target_os = "linux")]
mod linux_harden {
    use std::ffi::CString;
    use std::io;

    /// Bind-mount `/dev/null` over `/proc/cmdline` so any reader
    /// (including the agent's `bash -lc "cat /proc/cmdline"`)
    /// observes an empty file instead of the kernel-stamped
    /// `raxis.envb64=…` token. PID 1 has already hydrated its
    /// env BEFORE this runs, so masking the filesystem view is
    /// lossless for the legitimate path.
    pub(super) fn mask_proc_cmdline() {
        match bind_mount_dev_null_over("/proc/cmdline") {
            Ok(()) => eprintln!(
                "{{\"level\":\"info\",\"step\":\"guest-harden\",\
                 \"event\":\"proc_cmdline_masked\"}}"
            ),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => eprintln!(
                "{{\"level\":\"info\",\"step\":\"guest-harden\",\
                 \"event\":\"proc_cmdline_already_masked\"}}"
            ),
            Err(e) => eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-harden\",\
                 \"event\":\"proc_cmdline_mask_failed\",\
                 \"errno\":{}}}",
                e.raw_os_error().unwrap_or(-1),
            ),
        }
    }

    /// `prctl(PR_SET_DUMPABLE, 0)` — strip the readable bit on
    /// `/proc/1/environ`, `/proc/1/maps`, `/proc/1/cmdline`,
    /// `/proc/1/auxv`, `/proc/1/io`, etc. for callers without
    /// `CAP_SYS_PTRACE`. Default value (1, `SUID_DUMP_USER`) is
    /// what lets a same-uid `bash` child read PID 1's environ.
    /// Setting to 0 (`SUID_DUMP_DISABLE`) chmods the per-pid
    /// procfs entries `0500 root:root`, defeating the read.
    ///
    /// The flag is also inherited across `fork` /
    /// `clone`, so every child the planner spawns from PID 1
    /// inherits the same protection — which means the agent's
    /// `bash` tool cannot read its OWN `/proc/self/environ`
    /// (where the still-hydrated env vars would otherwise leak).
    pub(super) fn set_pid1_undumpable() {
        // `SUID_DUMP_DISABLE` = `0` per `<linux/sched/coredump.h>`
        // (also surfaced as `libc::SUID_DUMP_DISABLE` on glibc
        // targets, but absent in `libc` for `aarch64-unknown-linux-musl`
        // — the canonical executor target. Use the raw value so the
        // helper compiles across every supported Linux target.)
        const SUID_DUMP_DISABLE: libc::c_ulong = 0;
        // SAFETY: `prctl` is a thin wrapper around the
        // `prctl(2)` syscall; `PR_SET_DUMPABLE` is stable in
        // `libc::PR_SET_DUMPABLE`.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, SUID_DUMP_DISABLE, 0, 0, 0) };
        if rc == 0 {
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"guest-harden\",\
                 \"event\":\"pr_set_dumpable_disabled\"}}"
            );
        } else {
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-harden\",\
                 \"event\":\"pr_set_dumpable_failed\",\
                 \"errno\":{}}}",
                io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            );
        }
    }

    /// Bind-mount `/dev/null` over every path in `paths`.
    /// `cat /init` returns nothing; `cat /usr/local/bin/raxis-*`
    /// returns nothing. The running planner is unaffected: its
    /// in-kernel exe descriptor (`/proc/1/exe`) references the
    /// inode the kernel exec'd, which the bind mount does not
    /// touch.
    ///
    /// We do not `unlink(2)` the binary because a future
    /// substrate that pre-bind-mounts an immutable rootfs would
    /// reject unlinks; bind-mounting `/dev/null` is the
    /// minimum-side-effect operation that works everywhere.
    ///
    /// Each missing target (path does not exist) is logged but
    /// not treated as failure — the canonical image only ships
    /// the planner-role binary that corresponds to the active
    /// VM, so 2 of the 5 paths in `paths` are always absent.
    pub(super) fn mask_planner_binaries(paths: &[&str]) {
        let mut masked = 0u32;
        let mut already = 0u32;
        let mut missing = 0u32;
        let mut errors = 0u32;
        for path in paths {
            if !std::path::Path::new(path).exists() {
                missing += 1;
                continue;
            }
            match bind_mount_dev_null_over(path) {
                Ok(()) => masked += 1,
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                    already += 1;
                }
                Err(_) => {
                    errors += 1;
                }
            }
        }
        eprintln!(
            "{{\"level\":\"info\",\"step\":\"guest-harden\",\
             \"event\":\"planner_binaries_masked\",\
             \"masked\":{masked},\"already\":{already},\
             \"missing\":{missing},\"errors\":{errors}}}"
        );
    }

    /// `prctl(PR_CAPBSET_DROP, CAP_SYS_BOOT)` — strip the
    /// `CAP_SYS_BOOT` bit from the BOUNDING SET so it cannot be
    /// re-acquired across `execve`. PID 1's effective set still
    /// carries the cap (so [`super::shutdown_or_exit`] continues
    /// to power-off the VM cleanly on terminal exit), but any
    /// `execve` triggered by the agent's bash tool runs with the
    /// bounding-set-intersected capability set — i.e. no
    /// `CAP_SYS_BOOT`, so an agent `bash -c "reboot"` (or any
    /// equivalent `reboot(2)` syscall from an agent child)
    /// returns EPERM.
    pub(super) fn drop_cap_sys_boot_from_bounding_set() {
        // `CAP_SYS_BOOT` = `22` per `<linux/capability.h>`
        // (`#define CAP_SYS_BOOT 22`). Not surfaced as a named
        // constant in `libc` for `aarch64-unknown-linux-musl` —
        // the canonical executor target — so use the raw value
        // so the helper compiles across every supported Linux
        // target. The kernel-side enum is ABI-frozen; the
        // numeric value is the contract.
        const CAP_SYS_BOOT: libc::c_ulong = 22;
        // SAFETY: `prctl` with `PR_CAPBSET_DROP` is a thin
        // wrapper around the prctl(2) syscall; the constant
        // `PR_CAPBSET_DROP` is stable in `libc::PR_CAPBSET_DROP`.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, CAP_SYS_BOOT, 0, 0, 0) };
        if rc == 0 {
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"guest-harden\",\
                 \"event\":\"cap_sys_boot_dropped_from_bounding_set\"}}"
            );
        } else {
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-harden\",\
                 \"event\":\"cap_sys_boot_drop_failed\",\
                 \"errno\":{}}}",
                io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            );
        }
    }

    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)` — once set, the kernel
    /// guarantees that no subsequent `execve(2)` (in this
    /// process or any descendant) can grant privileges that
    /// were not held at the time of the prctl. Defangs any
    /// future setuid binary inadvertently shipped in the
    /// canonical image: the agent can `exec` it, but the suid
    /// bit is ignored.
    pub(super) fn set_no_new_privs() {
        // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` is
        // documented stable since Linux 3.5. The flag is inherited
        // across `fork`/`clone`/`execve`; once set it cannot be
        // unset.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) };
        if rc == 0 {
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"guest-harden\",\
                 \"event\":\"pr_set_no_new_privs_enabled\"}}"
            );
        } else {
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-harden\",\
                 \"event\":\"pr_set_no_new_privs_failed\",\
                 \"errno\":{}}}",
                io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            );
        }
    }

    /// Issue `mount("/dev/null", target, NULL, MS_BIND, NULL)`.
    /// On success any subsequent `open(target, O_RDONLY)` returns
    /// EOF on first read; existing fds opened before the mount
    /// keep their original view.
    fn bind_mount_dev_null_over(target: &str) -> io::Result<()> {
        let source = CString::new("/dev/null").expect("static path has no NUL");
        let target_c =
            CString::new(target).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // `mount(2)` requires the `data` arg to be `NULL` for
        // bind mounts; `flags = MS_BIND`.
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
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

#[cfg(target_os = "linux")]
mod linux_a3 {
    use std::fs::OpenOptions;
    use std::io::Write as _;

    /// Hard-disable IPv6 on every interface (incl. future
    /// auto-configured ones) via the `disable_ipv6` sysfs knob.
    pub(super) fn disable_ipv6_via_sysfs() {
        for scope in ["all", "default", "lo"] {
            let path = format!("/proc/sys/net/ipv6/conf/{scope}/disable_ipv6");
            match OpenOptions::new().write(true).open(&path) {
                Ok(mut f) => {
                    if let Err(e) = f.write_all(b"1") {
                        eprintln!(
                            "{{\"level\":\"warn\",\"step\":\"guest-init-a3\",\
                              \"event\":\"ipv6_disable_write_failed\",\
                              \"path\":{path:?},\"err\":{:?}}}",
                            e.to_string(),
                        );
                    } else {
                        eprintln!(
                            "{{\"level\":\"info\",\"step\":\"guest-init-a3\",\
                              \"event\":\"ipv6_disabled\",\"scope\":{scope:?}}}"
                        );
                    }
                }
                Err(e) => {
                    // sysfs path missing ⇒ kernel was built without
                    // IPv6 support (CONFIG_IPV6=n). Already safe.
                    eprintln!(
                        "{{\"level\":\"info\",\"step\":\"guest-init-a3\",\
                          \"event\":\"ipv6_sysfs_unavailable\",\
                          \"path\":{path:?},\"err\":{:?}}}",
                        e.to_string(),
                    );
                }
            }
        }
    }

    /// Point the libc resolver at the in-guest stub on
    /// `127.0.0.1:53`. The stub binds at PID-1 setup time inside
    /// the planner-executor entry point.
    pub(super) fn write_resolv_conf_for_stub() {
        // glibc and musl both treat `nameserver 127.0.0.1` as the
        // sole resolver target when no `search` / `options` lines
        // are present. The stub forwarder is the dispatcher to
        // the kernel-side resolver via vsock.
        let contents: &[u8] = b"# raxis managed DNS.\n\
              nameserver 127.0.0.1\n\
              options single-request-reopen timeout:5 attempts:2\n";
        // `/etc` may or may not exist in the canonical executor
        // rootfs; `mkdir -p` is cheap.
        if let Err(e) = std::fs::create_dir_all("/etc") {
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-init-a3\",\
                  \"event\":\"resolv_mkdir_failed\",\"err\":{:?}}}",
                e.to_string(),
            );
            return;
        }
        if let Err(e) = std::fs::write("/etc/resolv.conf", contents) {
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-init-a3\",\
                  \"event\":\"resolv_write_failed\",\"err\":{:?}}}",
                e.to_string(),
            );
            return;
        }
        eprintln!(
            "{{\"level\":\"info\",\"step\":\"guest-init-a3\",\
              \"event\":\"resolv_conf_pointed_at_stub\"}}"
        );
    }

    /// Make Linux accept the deliberately unusual no-NIC routing
    /// shape used by A3 transparent egress.
    ///
    /// `install_loopback_default_route` below sends otherwise
    /// unroutable IPv4 destinations through `lo` so the local
    /// `nat OUTPUT` hook can REDIRECT them to the in-guest tproxy.
    /// The reverse direction of that NATed local TCP flow can
    /// carry non-loopback peer addresses over `lo`; stock martian
    /// checks and reverse-path filtering are allowed to reject that
    /// traffic. In an A3 guest there is no external interface to
    /// spoof through, so these knobs widen only the internal
    /// loopback path that nftables immediately redirects into the
    /// kernel-mediated tunnel.
    pub(super) fn configure_loopback_transparent_egress_sysctls() {
        let mut ok = 0u32;
        let mut failed = 0u32;
        for (path, value) in LOOPBACK_TRANSPARENT_EGRESS_SYSCTLS {
            match std::fs::write(path, format!("{value}\n")) {
                Ok(()) => ok += 1,
                Err(e) => {
                    failed += 1;
                    eprintln!(
                        "{{\"level\":\"warn\",\"step\":\"guest-init-a3\",\
                          \"event\":\"loopback_transparent_egress_sysctl_failed\",\
                          \"path\":{path:?},\"value\":{value:?},\"err\":{:?}}}",
                        e.to_string(),
                    );
                }
            }
        }
        eprintln!(
            "{{\"level\":\"info\",\"step\":\"guest-init-a3\",\
              \"event\":\"loopback_transparent_egress_sysctls_configured\",\
              \"ok\":{ok},\"failed\":{failed}}}"
        );
    }

    pub(super) const LOOPBACK_TRANSPARENT_EGRESS_SYSCTLS: &[(&str, &str)] = &[
        ("/proc/sys/net/ipv4/conf/all/accept_local", "1"),
        ("/proc/sys/net/ipv4/conf/all/route_localnet", "1"),
        ("/proc/sys/net/ipv4/conf/all/rp_filter", "0"),
        ("/proc/sys/net/ipv4/conf/default/accept_local", "1"),
        ("/proc/sys/net/ipv4/conf/default/route_localnet", "1"),
        ("/proc/sys/net/ipv4/conf/default/rp_filter", "0"),
        ("/proc/sys/net/ipv4/conf/lo/accept_local", "1"),
        ("/proc/sys/net/ipv4/conf/lo/route_localnet", "1"),
        ("/proc/sys/net/ipv4/conf/lo/rp_filter", "0"),
    ];

    /// Route otherwise-unroutable IPv4 destinations through `lo`
    /// so Linux reaches the `nat OUTPUT` hook and nftables can
    /// REDIRECT the socket to the in-guest tproxy.
    ///
    /// This does not grant network access by itself: the guest still
    /// has no NIC, and the tproxy opens the upstream through the
    /// kernel-side A3 tunnel only after admission. The nft ruleset
    /// separately exempts real loopback destinations (`127.0.0.0/8`)
    /// so credential-proxy loopback ports and in-VM control sockets
    /// are not captured.
    pub(super) fn install_loopback_default_route() {
        let binaries: &[&str] = &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip", "ip"];
        let mut installed_any = false;
        for binary in binaries {
            match run_ip_route_replace_default_lo(binary) {
                Ok(()) => {
                    installed_any = true;
                    eprintln!(
                        "{{\"level\":\"info\",\"step\":\"guest-init-a3\",\
                          \"event\":\"loopback_default_route_installed\",\
                          \"binary\":{binary:?}}}"
                    );
                    break;
                }
                Err(RouteInstallError::Missing { reason }) => {
                    eprintln!(
                        "{{\"level\":\"info\",\"step\":\"guest-init-a3\",\
                          \"event\":\"ip_binary_missing\",\
                          \"binary\":{binary:?},\"err\":{reason:?}}}"
                    );
                }
                Err(RouteInstallError::Failed { reason }) => {
                    eprintln!(
                        "{{\"level\":\"warn\",\"step\":\"guest-init-a3\",\
                          \"event\":\"loopback_default_route_candidate_failed\",\
                          \"binary\":{binary:?},\"err\":{reason:?}}}"
                    );
                }
            }
        }
        if !installed_any {
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-init-a3\",\
                  \"event\":\"loopback_default_route_failed\",\
                  \"note\":\"egress will fail closed — the guest has no NIC, \
                  and Linux may reject outbound connects before nftables \
                  can redirect them to the in-guest tproxy\"}}"
            );
        }
    }

    /// Shell out to native `nft` to install the A3 REDIRECT chain.
    ///
    /// We deliberately avoid the iptables compatibility frontends:
    /// the live-e2e failure mode was an xtables REDIRECT extension
    /// mismatch even though the kernel had nftables core support.
    /// Native nftables keeps the userspace/kernel contract aligned
    /// with the Kconfig fragment validated during bake.
    pub(super) fn install_nftables_redirect(tproxy_port: u16) {
        let ruleset = nft_redirect_ruleset(tproxy_port);
        let binaries: &[&str] = &[
            "/usr/sbin/nft",
            "/sbin/nft",
            "/usr/bin/nft",
            "/bin/nft",
            "nft",
        ];
        let mut installed_any = false;
        for binary in binaries {
            match run_nft_ruleset(binary, &ruleset) {
                Ok(()) => {
                    installed_any = true;
                    eprintln!(
                        "{{\"level\":\"info\",\"step\":\"guest-init-a3\",\
                          \"event\":\"nftables_redirect_installed\",\
                          \"binary\":{binary:?},\"tproxy_port\":{tproxy_port}}}"
                    );
                    break;
                }
                Err(NftInstallError::Missing { reason }) => {
                    eprintln!(
                        "{{\"level\":\"info\",\"step\":\"guest-init-a3\",\
                          \"event\":\"nft_binary_missing\",\
                          \"binary\":{binary:?},\"err\":{reason:?}}}"
                    );
                }
                Err(NftInstallError::Failed { reason }) => {
                    eprintln!(
                        "{{\"level\":\"warn\",\"step\":\"guest-init-a3\",\
                          \"event\":\"nftables_install_candidate_failed\",\
                          \"binary\":{binary:?},\"err\":{reason:?}}}"
                    );
                }
            }
        }
        if !installed_any {
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-init-a3\",\
                  \"event\":\"nftables_install_failed\",\
                  \"note\":\"egress will fail closed — substrate has no NIC \
                  and the in-guest tproxy listener is unreachable from \
                  agent processes without the nftables REDIRECT chain\"}}"
            );
        }
    }

    pub(super) fn nft_redirect_ruleset(tproxy_port: u16) -> String {
        // Use the IPv4 family, not `inet`: the staged guest kernel
        // validates `CONFIG_NF_TABLES_IPV4=y` and disables IPv6 for
        // A3, while `CONFIG_NF_TABLES_INET` is optional on older
        // kernels. Targeting `inet` makes native `nft` fail with
        // `Operation not supported` even when IPv4 NAT/REDIRECT is
        // correctly available.
        format!(
            r#"table ip raxis_a3 {{
  chain output {{
    type nat hook output priority -100; policy accept;
    ip daddr 127.0.0.0/8 return
    ip protocol tcp redirect to :{tproxy_port}
    udp dport 53 redirect to :53
  }}
}}
"#
        )
    }

    enum NftInstallError {
        Missing { reason: String },
        Failed { reason: String },
    }

    enum RouteInstallError {
        Missing { reason: String },
        Failed { reason: String },
    }

    fn run_ip_route_replace_default_lo(binary: &str) -> Result<(), RouteInstallError> {
        let output = std::process::Command::new(binary)
            .args(["-4", "route", "replace", "default", "dev", "lo"])
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    RouteInstallError::Missing {
                        reason: e.to_string(),
                    }
                } else {
                    RouteInstallError::Failed {
                        reason: e.to_string(),
                    }
                }
            })?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            Err(RouteInstallError::Failed {
                reason: if stderr.is_empty() {
                    format!("exit {:?}", output.status.code())
                } else {
                    format!("exit {:?}: {stderr}", output.status.code())
                },
            })
        }
    }

    fn run_nft_ruleset(binary: &str, ruleset: &str) -> Result<(), NftInstallError> {
        let mut child = std::process::Command::new(binary)
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    NftInstallError::Missing {
                        reason: e.to_string(),
                    }
                } else {
                    NftInstallError::Failed {
                        reason: e.to_string(),
                    }
                }
            })?;
        match child.stdin.take() {
            Some(mut stdin) => {
                if let Err(e) = stdin.write_all(ruleset.as_bytes()) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(NftInstallError::Failed {
                        reason: format!("stdin write failed: {e}"),
                    });
                }
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(NftInstallError::Failed {
                    reason: "stdin unavailable".to_owned(),
                });
            }
        }
        let status = child.wait().map_err(|e| NftInstallError::Failed {
            reason: format!("wait failed: {e}"),
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(NftInstallError::Failed {
                reason: format!("exit {:?}", status.code()),
            })
        }
    }
}

#[cfg(test)]
mod tests_a3 {
    use super::*;

    #[test]
    fn a3_env_vars_pinned() {
        // Pin the surviving env-var names. The `RAXIS_AIRGAP_A3=1`
        // ACTIVE-toggle env var (`A3_ACTIVE_ENV`) and the
        // `airgap_a3_active()` helper were removed in the
        // Tier1Tproxy deletion sweep — Mediated is unconditional
        // for executor / orchestrator VMs, so the toggle no longer
        // has a purpose. The per-port discovery env vars
        // (`RAXIS_AIRGAP_A3_TPROXY_PORT`, plus the
        // `RAXIS_AIRGAP_A3_{HOST_CID,ADMISSION_PORT,TUNNEL_PORT}`
        // constants in `planner-executor::main`) survive because
        // the kernel still needs to communicate per-session vsock
        // port assignments to the guest.
        assert_eq!(A3_TPROXY_PORT_ENV, "RAXIS_AIRGAP_A3_TPROXY_PORT");
        assert_eq!(A3_DEFAULT_TPROXY_PORT, 3129);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a3_nft_ruleset_redirects_tcp_and_dns_while_preserving_loopback() {
        let ruleset = linux_a3::nft_redirect_ruleset(3129);
        assert!(ruleset.contains("table ip raxis_a3"));
        assert!(ruleset.contains("type nat hook output priority -100"));
        assert!(ruleset.contains("ip daddr 127.0.0.0/8 return"));
        assert!(ruleset.contains("ip protocol tcp redirect to :3129"));
        assert!(ruleset.contains("udp dport 53 redirect to :53"));
        assert!(!ruleset.contains("oifname \"lo\" return"));
        assert!(!ruleset.contains("iptables"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a3_loopback_transparent_egress_sysctls_pin_martian_relaxation() {
        let sysctls = linux_a3::LOOPBACK_TRANSPARENT_EGRESS_SYSCTLS;
        assert!(sysctls.contains(&("/proc/sys/net/ipv4/conf/all/route_localnet", "1")));
        assert!(sysctls.contains(&("/proc/sys/net/ipv4/conf/lo/route_localnet", "1")));
        assert!(sysctls.contains(&("/proc/sys/net/ipv4/conf/all/accept_local", "1")));
        assert!(sysctls.contains(&("/proc/sys/net/ipv4/conf/lo/accept_local", "1")));
        assert!(sysctls.contains(&("/proc/sys/net/ipv4/conf/all/rp_filter", "0")));
        assert!(sysctls.contains(&("/proc/sys/net/ipv4/conf/lo/rp_filter", "0")));
    }
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

/// Environment variable the Firecracker substrate uses when it
/// exposes workspace mounts as pre-attached virtio-blk ext4 images.
/// Comma-separated entries of the form
/// `<device_path>:<guest_path>:<rw|ro>:<fs_type>`, for example
/// `/dev/vda:/workspace:rw:ext4`.
pub const BLOCK_MOUNTS_ENV: &str = "RAXIS_BLOCK_MOUNTS";

/// One parsed workspace share spec extracted from a substrate mount
/// declaration. AVF declares VirtioFS tags; Firecracker declares
/// virtio-blk device paths. The host-side substrate already validated
/// `host_path` and the `MountMode`; the guest only sees the
/// post-validation mount triple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioFsMountSpec {
    /// Mount source. For AVF this is the host-side
    /// `AvfVirtioFsShare.tag`; for Firecracker it is the block-device
    /// path such as `/dev/vda`. Used as the `source` argument to
    /// `mount(2)`.
    pub tag: String,
    /// Absolute guest path the share is mounted at (the `/init`
    /// process performs `mkdir -p` before mounting).
    pub guest_path: String,
    /// `true` ⇒ mount the share read-only (`MS_RDONLY`).
    pub read_only: bool,
    /// Filesystem type passed to `mount(2)`.
    pub fs_type: String,
}

/// Outcome of parsing the substrate's workspace-mount env and
/// attempting each mount. Aggregated and logged by the planner main
/// entry-points so the kernel-side scraper can correlate a guest-side
/// mount failure to the host-side substrate event.
#[derive(Clone, Debug)]
pub enum WorkspaceMountOutcome {
    /// Both workspace mount env vars were unset or empty — the
    /// substrate did not wire any workspace shares, the guest has
    /// nothing to mount.
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
        /// One [`MountAttempt`] per parsed workspace mount spec.
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
pub fn parse_virtiofs_mounts(raw: &str) -> (Vec<VirtioFsMountSpec>, Option<String>) {
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
                    bad = Some(format!("entry {idx}: missing or empty <tag> field"));
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
                    bad = Some(format!("entry {idx}: missing <guest_path> field"));
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
                    bad = Some(format!("entry {idx}: missing <mode> field"));
                }
                continue;
            }
        };
        if parts.next().is_some() && bad.is_none() {
            bad = Some(format!("entry {idx}: too many ':' separated fields"));
            // Still accept the spec — extra fields are tolerated
            // for forward-compatibility, but flagged.
        }
        out.push(VirtioFsMountSpec {
            tag,
            guest_path,
            read_only: mode,
            fs_type: "virtiofs".to_owned(),
        });
    }
    (out, bad)
}

/// Parse one comma-separated `RAXIS_BLOCK_MOUNTS` payload into
/// mount specs. Firecracker uses this for ext4 workspace images
/// attached as virtio-blk devices.
pub fn parse_block_mounts(raw: &str) -> (Vec<VirtioFsMountSpec>, Option<String>) {
    let mut out: Vec<VirtioFsMountSpec> = Vec::new();
    let mut bad: Option<String> = None;
    for (idx, raw_entry) in raw.split(',').enumerate() {
        let entry = raw_entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.split(':');
        let source = match parts.next() {
            Some(t) if t.starts_with("/dev/") => t.to_owned(),
            Some(t) => {
                if bad.is_none() {
                    bad = Some(format!(
                        "entry {idx}: <device_path> must start with /dev/ (got {t:?})"
                    ));
                }
                continue;
            }
            None => {
                if bad.is_none() {
                    bad = Some(format!("entry {idx}: missing <device_path> field"));
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
                    bad = Some(format!("entry {idx}: missing <guest_path> field"));
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
                    bad = Some(format!("entry {idx}: missing <mode> field"));
                }
                continue;
            }
        };
        let fs_type = match parts.next() {
            Some("ext4") => "ext4".to_owned(),
            Some(other) => {
                if bad.is_none() {
                    bad = Some(format!(
                        "entry {idx}: <fs_type> must be 'ext4' (got {other:?})"
                    ));
                }
                continue;
            }
            None => {
                if bad.is_none() {
                    bad = Some(format!("entry {idx}: missing <fs_type> field"));
                }
                continue;
            }
        };
        if parts.next().is_some() && bad.is_none() {
            bad = Some(format!("entry {idx}: too many ':' separated fields"));
        }
        out.push(VirtioFsMountSpec {
            tag: source,
            guest_path,
            read_only: mode,
            fs_type,
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
    let mut specs = Vec::new();
    let mut bad: Option<String> = None;

    if let Ok(raw) = std::env::var(VIRTIOFS_MOUNTS_ENV) {
        if !raw.is_empty() {
            let (mut parsed, parse_bad) = parse_virtiofs_mounts(&raw);
            specs.append(&mut parsed);
            bad = bad.or(parse_bad.map(|e| format!("{VIRTIOFS_MOUNTS_ENV}: {e}")));
        }
    }

    if let Ok(raw) = std::env::var(BLOCK_MOUNTS_ENV) {
        if !raw.is_empty() {
            let (mut parsed, parse_bad) = parse_block_mounts(&raw);
            specs.append(&mut parsed);
            bad = bad.or(parse_bad.map(|e| format!("{BLOCK_MOUNTS_ENV}: {e}")));
        }
    }

    if specs.is_empty() && bad.is_none() {
        return WorkspaceMountOutcome::NoEnvVar;
    }

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
            reason: format!("mkdir -p {target}: {e}", target = spec.guest_path,),
        };
    }
    for attempt in 0..40 {
        match linux::try_mount_filesystem(
            &spec.tag,
            &spec.guest_path,
            &spec.fs_type,
            spec.read_only,
        ) {
            Ok(()) => return MountStatus::Ok,
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => return MountStatus::Already,
            Err(e)
                if spec.tag.starts_with("/dev/")
                    && matches!(
                        e.raw_os_error(),
                        Some(code) if code == libc::ENOENT || code == libc::ENODEV
                    )
                    && attempt < 39 =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                return MountStatus::Failed {
                    reason: e.to_string(),
                };
            }
        }
    }
    MountStatus::Failed {
        reason: "mount retry loop exhausted".to_owned(),
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

#[cfg(test)]
mod workspace_mount_parse_tests {
    use super::*;

    #[test]
    fn parse_block_mounts_accepts_ext4_devices() {
        let (specs, bad) =
            parse_block_mounts("/dev/vda:/workspace:rw:ext4,/dev/vdb:/raxis-meta:ro:ext4");
        assert!(bad.is_none(), "unexpected parse error: {bad:?}");
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].tag, "/dev/vda");
        assert_eq!(specs[0].guest_path, "/workspace");
        assert!(!specs[0].read_only);
        assert_eq!(specs[0].fs_type, "ext4");
        assert_eq!(specs[1].tag, "/dev/vdb");
        assert!(specs[1].read_only);
    }

    #[test]
    fn parse_block_mounts_rejects_non_device_source() {
        let (specs, bad) = parse_block_mounts("workspace:/workspace:rw:ext4");
        assert!(specs.is_empty());
        assert!(bad
            .as_deref()
            .unwrap_or_default()
            .contains("must start with /dev/"));
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
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-init\",\
                  \"event\":\"shutdown_power_off_failed\",\
                  \"rc\":{rc},\"errno\":{errno}}}"
            );
        }
    }

    std::process::exit(code as i32)
}

// ---------------------------------------------------------------------------
// Executor Rust toolchain defaults
// ---------------------------------------------------------------------------

/// Rustup/cargo env defaults for the executor starter image.
///
/// AVF boots PID 1 with `HOME=/` on some host/kernel combinations.
/// Rustup then looks under `/.rustup` even though the starter image
/// installs the stable toolchain under `/root/.rustup`, producing
/// the misleading runtime error "no default toolchain configured".
/// These defaults make the baked toolchain discoverable without
/// requiring every executor prompt to know rustup internals.
pub const EXECUTOR_HOME_ENV: &str = "HOME";
/// Rustup home baked by `images/executor-starter/Containerfile`.
pub const EXECUTOR_RUSTUP_HOME_ENV: &str = "RUSTUP_HOME";
/// Cargo home baked by `images/executor-starter/Containerfile`.
pub const EXECUTOR_CARGO_HOME_ENV: &str = "CARGO_HOME";
/// Rustup selector used by shims when no default file is visible.
pub const EXECUTOR_RUSTUP_TOOLCHAIN_ENV: &str = "RUSTUP_TOOLCHAIN";

const EXECUTOR_HOME_DEFAULT: &str = "/root";
const EXECUTOR_RUSTUP_HOME_DEFAULT: &str = "/root/.rustup";
const EXECUTOR_CARGO_HOME_DEFAULT: &str = "/root/.cargo";
const EXECUTOR_RUSTUP_TOOLCHAIN_DEFAULT: &str = "1.85.1";

/// Install executor Rust toolchain environment defaults before
/// any shell tool can spawn `cargo`, `rustfmt`, or `clippy`.
pub fn ensure_executor_rustup_env_defaults() -> RustupEnvDefaultOutcome {
    let mut defaulted: Vec<&'static str> = Vec::new();
    let mut preserved: Vec<&'static str> = Vec::new();
    for (key, value) in [
        (EXECUTOR_HOME_ENV, EXECUTOR_HOME_DEFAULT),
        (EXECUTOR_RUSTUP_HOME_ENV, EXECUTOR_RUSTUP_HOME_DEFAULT),
        (EXECUTOR_CARGO_HOME_ENV, EXECUTOR_CARGO_HOME_DEFAULT),
        (
            EXECUTOR_RUSTUP_TOOLCHAIN_ENV,
            EXECUTOR_RUSTUP_TOOLCHAIN_DEFAULT,
        ),
    ] {
        match std::env::var(key) {
            Ok(v) if !v.is_empty() => preserved.push(key),
            _ => {
                // SAFETY: executor main calls this before building
                // the tokio runtime, so no worker thread can race on
                // process env.
                unsafe {
                    std::env::set_var(key, value);
                }
                defaulted.push(key);
            }
        }
    }
    RustupEnvDefaultOutcome {
        defaulted,
        preserved,
    }
}

/// Outcome of [`ensure_executor_rustup_env_defaults`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustupEnvDefaultOutcome {
    /// Env vars this helper installed.
    pub defaulted: Vec<&'static str>,
    /// Env vars already set by the substrate/operator.
    pub preserved: Vec<&'static str>,
}

#[cfg(test)]
mod rustup_env_default_tests {
    use super::*;
    use std::sync::Mutex;

    fn with_env_snapshot<F: FnOnce()>(f: F) {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let keys = [
            EXECUTOR_HOME_ENV,
            EXECUTOR_RUSTUP_HOME_ENV,
            EXECUTOR_CARGO_HOME_ENV,
            EXECUTOR_RUSTUP_TOOLCHAIN_ENV,
        ];
        let prev: Vec<(&str, Option<String>)> =
            keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        // SAFETY: serialised via the static mutex.
        unsafe {
            for key in keys {
                std::env::remove_var(key);
            }
        }
        f();
        // SAFETY: serialised via the static mutex.
        unsafe {
            for (key, value) in prev {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn ensure_executor_rustup_env_defaults_sets_baked_paths_when_absent() {
        with_env_snapshot(|| {
            let outcome = ensure_executor_rustup_env_defaults();
            assert_eq!(
                outcome.defaulted,
                vec![
                    EXECUTOR_HOME_ENV,
                    EXECUTOR_RUSTUP_HOME_ENV,
                    EXECUTOR_CARGO_HOME_ENV,
                    EXECUTOR_RUSTUP_TOOLCHAIN_ENV
                ]
            );
            assert_eq!(std::env::var(EXECUTOR_HOME_ENV).unwrap(), "/root");
            assert_eq!(
                std::env::var(EXECUTOR_RUSTUP_HOME_ENV).unwrap(),
                "/root/.rustup"
            );
            assert_eq!(
                std::env::var(EXECUTOR_CARGO_HOME_ENV).unwrap(),
                "/root/.cargo"
            );
            assert_eq!(
                std::env::var(EXECUTOR_RUSTUP_TOOLCHAIN_ENV).unwrap(),
                "1.85.1"
            );
        });
    }

    #[test]
    fn ensure_executor_rustup_env_defaults_preserves_operator_values() {
        with_env_snapshot(|| {
            // SAFETY: serialised via `with_env_snapshot`.
            unsafe {
                std::env::set_var(EXECUTOR_HOME_ENV, "/custom-home");
                std::env::set_var(EXECUTOR_RUSTUP_HOME_ENV, "/custom-rustup");
                std::env::set_var(EXECUTOR_CARGO_HOME_ENV, "/custom-cargo");
                std::env::set_var(EXECUTOR_RUSTUP_TOOLCHAIN_ENV, "1.85.0");
            }
            let outcome = ensure_executor_rustup_env_defaults();
            assert!(outcome.defaulted.is_empty());
            assert_eq!(std::env::var(EXECUTOR_HOME_ENV).unwrap(), "/custom-home");
            assert_eq!(
                std::env::var(EXECUTOR_RUSTUP_TOOLCHAIN_ENV).unwrap(),
                "1.85.0"
            );
        });
    }
}

/// `INV-PLANNER-PID1-ONLY-EXEC-01` — unit tests for
/// [`enforce_pid1_or_abort`]. Cannot exercise the abort path
/// directly (would terminate the test runner), but cover the
/// no-op branches and the bypass surface.
#[cfg(test)]
mod pid1_enforcement_tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialise env mutations across tests (matches the
    /// pattern used by the other env-mutating tests in this file.
    fn with_bypass_env<F: FnOnce()>(f: F) {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        const KEY: &str = "RAXIS_PLANNER_PID1_ENFORCEMENT_BYPASS";
        let prev = std::env::var(KEY).ok();
        // SAFETY: serialised via the static mutex; no other test
        // in this module touches the variable concurrently.
        unsafe {
            std::env::remove_var(KEY);
        }
        f();
        // SAFETY: see above.
        unsafe {
            match prev {
                Some(v) => std::env::set_var(KEY, v),
                None => std::env::remove_var(KEY),
            }
        }
    }

    /// On macOS / Windows the helper is a no-op regardless of
    /// PID — the planner binaries cross-compile to
    /// aarch64-linux for the microVM and are not executed
    /// natively on the host. Test runners on macOS calling the
    /// helper MUST NOT abort.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn enforce_pid1_or_abort_is_noop_on_non_linux() {
        with_bypass_env(|| {
            // No assertion needed — the call returning without
            // aborting is itself the witness.
            enforce_pid1_or_abort();
        });
    }

    /// On Linux + PID ≠ 1 + bypass set, the helper MUST NOT
    /// abort. This is the SubprocessIsolation contract: the
    /// fixture sets the bypass before exec'ing the planner
    /// binary so legacy host-mode tests continue to function.
    #[cfg(target_os = "linux")]
    #[test]
    fn enforce_pid1_or_abort_respects_bypass_outside_pid1() {
        with_bypass_env(|| {
            // The test runner is unlikely to be PID 1; set the
            // bypass and assert the call returns without
            // exiting the process.
            // SAFETY: serialised via with_bypass_env's mutex.
            unsafe {
                std::env::set_var("RAXIS_PLANNER_PID1_ENFORCEMENT_BYPASS", "1");
            }
            enforce_pid1_or_abort();
            // If we reach here the call returned cleanly. Pass.
        });
    }

    /// The advertised exit code is the operator-facing
    /// breadcrumb; pin it so a future refactor cannot silently
    /// alter the visible signal.
    #[test]
    fn pid1_enforcement_exit_code_is_126() {
        assert_eq!(PID1_ENFORCEMENT_EXIT_CODE, 126);
    }
}

/// `INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01` — unit tests
/// pinning the operator-visible defense lists. The actual mount
/// / prctl side-effects cannot be exercised from a unit test
/// (the test runner is not PID 1 and lacks `CAP_SYS_ADMIN`); we
/// pin the visible interface so a future refactor cannot
/// silently drop a defense.
#[cfg(test)]
mod guest_harden_tests {
    use super::*;

    /// Pin the canonical planner-binary path list so a future
    /// refactor (renaming a binary, adding a fourth role) MUST
    /// land a paired update here. The agent's exfiltration surface
    /// grows in lock-step with the set of binaries the canonical
    /// image ships; an out-of-band rename would silently widen
    /// the surface.
    #[test]
    fn planner_binary_paths_to_mask_pinned() {
        assert_eq!(
            PLANNER_BINARY_PATHS_TO_MASK,
            &[
                "/init",
                "/usr/local/bin/raxis-executor",
                "/usr/local/bin/raxis-orchestrator",
                "/usr/local/bin/raxis-reviewer",
                "/usr/local/bin/raxis-verifier-no-secrets",
            ],
            "PLANNER_BINARY_PATHS_TO_MASK is the exfiltration surface; \
             any change must be paired with a spec update in \
             specs/v3/guest-agent-jailbreak-defense.md §2.3"
        );
    }

    /// Pin the scrub list. Every entry is a kernel-stamped value
    /// or runtime-control knob an agent's `bash -lc 'env'` could
    /// otherwise recover or misinterpret. A future env addition
    /// that holds a secret or changes apparent capability posture
    /// MUST land here in the same commit.
    #[test]
    fn sensitive_env_vars_to_scrub_pinned() {
        assert_eq!(
            SENSITIVE_ENV_VARS_TO_SCRUB,
            raxis_types::planner_env::AGENT_SUBPROCESS_SCRUBBED_ENV_VARS,
            "SENSITIVE_ENV_VARS_TO_SCRUB is the agent token/capability \
             recovery surface; any change must be paired with a spec \
             update in specs/v3/guest-agent-jailbreak-defense.md §2.6"
        );
        assert!(SENSITIVE_ENV_VARS_TO_SCRUB.contains(&"RAXIS_MODEL_CHAIN"));
        assert!(SENSITIVE_ENV_VARS_TO_SCRUB.contains(&"RAXIS_MODEL_ID"));
        assert!(SENSITIVE_ENV_VARS_TO_SCRUB.contains(&"RAXIS_VM_IMAGE_ORIGIN"));
        assert!(SENSITIVE_ENV_VARS_TO_SCRUB.contains(&"RAXIS_VM_IMAGE_DIGEST"));
        assert!(SENSITIVE_ENV_VARS_TO_SCRUB.contains(&"RAXIS_PLANNER_SESSION_ROLE"));
        assert!(SENSITIVE_ENV_VARS_TO_SCRUB.contains(&"RAXIS_PLANNER_KSB_PATH"));
        assert!(SENSITIVE_ENV_VARS_TO_SCRUB.contains(&"RAXIS_PLANNER_CUSTOM_TOOLS_PATH"));
        assert!(SENSITIVE_ENV_VARS_TO_SCRUB.contains(&"RAXIS_PLANNER_SIDECAR_HMAC_SECRET"));
    }

    /// `RAXIS_SESSION_ID` is scrubbed from child-process env after
    /// `BootEnv` captures it. Tool dispatch keeps audit attribution
    /// through `ToolContext`, not by asking bash/custom tools to read
    /// identity metadata from their environment.
    #[test]
    fn session_id_is_scrubbed_after_bootenv_capture() {
        assert!(
            SENSITIVE_ENV_VARS_TO_SCRUB.contains(&"RAXIS_SESSION_ID"),
            "RAXIS_SESSION_ID is planner-process metadata, not an \
             agent-tool env contract. BootEnv captures it before scrub."
        );
    }

    /// On non-Linux + PID ≠ 1 the helper is a no-op: it MUST NOT
    /// abort the test runner or panic. This is the parity the
    /// other PID-1-gated helpers in this module honour.
    #[test]
    fn harden_guest_for_agent_is_noop_on_non_pid1_or_non_linux() {
        // No assertion needed — the call returning without
        // exiting / panicking is itself the witness. On macOS
        // dev workstations the function falls through the
        // `cfg(target_os = "linux")` gate; on Linux test runners
        // PID is ≠ 1 so the PID-1 gate inside also falls
        // through.
        harden_guest_for_agent();
    }

    /// `scrub_sensitive_env_for_agent` MUST be safe to call when
    /// the env vars are already unset (the legitimate path
    /// after a second invocation, or the dev workflow where the
    /// host process never had them set). The function logs each
    /// case as `already_unset` but does not return an error.
    #[test]
    fn scrub_sensitive_env_for_agent_is_idempotent_when_already_unset() {
        // Snapshot+restore so the test does not bleed env into
        // sibling tests in the same process.
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let snapshot: Vec<(String, Option<String>)> = SENSITIVE_ENV_VARS_TO_SCRUB
            .iter()
            .map(|k| ((*k).to_owned(), std::env::var(k).ok()))
            .collect();
        // SAFETY: serialised via the static mutex.
        for (k, _) in &snapshot {
            unsafe {
                std::env::remove_var(k);
            }
        }
        scrub_sensitive_env_for_agent();
        scrub_sensitive_env_for_agent(); // idempotent second pass
                                         // Restore.
                                         // SAFETY: serialised via the static mutex.
        for (k, v) in snapshot {
            unsafe {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }
}
