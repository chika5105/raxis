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
                    io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(-1),
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
                    io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(-1),
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
            let want = cur_flags
                | (libc::IFF_UP as i16)
                | (libc::IFF_RUNNING as i16);
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
                    io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(-1),
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
// Path A3 egress chokepoint setup
// ---------------------------------------------------------------------------

/// Env var consumed by [`init_pid1_a3_egress`] to size the
/// iptables REDIRECT chain that catches outbound TCP from agent
/// processes. Default `3129` matches
/// `raxis_tproxy::linux::bind_default_listener`.
pub const A3_TPROXY_PORT_ENV: &str = "RAXIS_AIRGAP_A3_TPROXY_PORT";

/// Default in-guest port the iptables REDIRECT chain forwards
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
///      [`raxis_isolation::EgressTier::Mediated`], so the guest
///      has no IPv6 interface to begin with, but defence in
///      depth: a future substrate that exposes an IPv6
///      auto-configured device cannot leak via SLAAC.
///   2. Write `/etc/resolv.conf` so the libc resolver dispatches
///      every `getaddrinfo` through `127.0.0.1:53` — i.e. the
///      in-guest DNS stub that fans queries out over vsock to
///      the kernel-side resolver.
///   3. Install `iptables -t nat OUTPUT` REDIRECT rules to send
///      outbound TCP to the local tproxy listener
///      (`127.0.0.1:<tproxy_port>`). UDP port 53 is REDIRECTed
///      to the local DNS stub on port 53.
///
/// Failures on any individual step are logged but non-fatal:
/// the kernel-side admission listener is the load-bearing
/// chokepoint (`INV-NETISO-A3-VSOCK-CHOKEPOINT-01`) and refuses
/// every connection that arrives from a guest with no admission
/// token. A botched iptables install therefore degrades to
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
        linux_a3::install_iptables_redirect(tproxy_port);
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
        let contents: &[u8] =
            b"# raxis Path A3 universal airgap -- kernel-mediated DNS.\n\
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

    /// Shell out to `iptables` (`iptables-nft` or
    /// `iptables-legacy`, whichever is on PATH) to install the
    /// A3 REDIRECT chain. We try each binary candidate in turn
    /// because the canonical executor rootfs may ship either —
    /// the `images/executor-starter/Containerfile` is the
    /// authoritative source of truth.
    pub(super) fn install_iptables_redirect(tproxy_port: u16) {
        // RULES — applied in order. Each rule is a list of argv
        // tokens; empty list = end of rules.
        //
        // 1. Skip the cred-proxy loopback range (already on
        //    127.0.0.1, which is INPUT not OUTPUT — we let it
        //    through unconditionally).
        // 2. REDIRECT outbound TCP (any dest, any port) to the
        //    in-guest tproxy listener.
        // 3. REDIRECT outbound UDP port 53 (DNS) to the in-guest
        //    DNS stub on port 53.
        let tproxy_port_s = tproxy_port.to_string();
        let rules: Vec<Vec<&str>> = vec![
            // Don't REDIRECT traffic that is already loopback —
            // the cred-proxy loopback forwarder and the DNS stub
            // both bind 127.0.0.1.
            vec![
                "-t", "nat", "-A", "OUTPUT",
                "-o", "lo", "-j", "RETURN",
            ],
            // Default-deny REJECT-as-RST equivalent is implicit:
            // anything that doesn't hit one of the REDIRECT rules
            // below has no upstream NIC anyway (substrate gave us
            // EgressTier::Mediated), so connect(2) returns
            // ENETUNREACH / EHOSTUNREACH which surfaces to the
            // agent's libc as a clean failure.
            vec![
                "-t", "nat", "-A", "OUTPUT",
                "-p", "tcp", "!", "-d", "127.0.0.1/32",
                "-j", "REDIRECT", "--to-port", &tproxy_port_s,
            ],
            vec![
                "-t", "nat", "-A", "OUTPUT",
                "-p", "udp", "--dport", "53",
                "!", "-d", "127.0.0.1/32",
                "-j", "REDIRECT", "--to-port", "53",
            ],
        ];

        let binaries: &[&str] = &["iptables-nft", "iptables"];
        let mut installed_any = false;
        for binary in binaries {
            let mut ok = true;
            for argv in &rules {
                let status = std::process::Command::new(binary)
                    .args(argv)
                    .status();
                match status {
                    Ok(s) if s.success() => {}
                    Ok(s) => {
                        eprintln!(
                            "{{\"level\":\"warn\",\"step\":\"guest-init-a3\",\
                              \"event\":\"iptables_rule_failed\",\
                              \"binary\":{binary:?},\"argv\":{argv:?},\
                              \"exit\":{:?}}}",
                            s.code(),
                        );
                        ok = false;
                        break;
                    }
                    Err(e) => {
                        eprintln!(
                            "{{\"level\":\"info\",\"step\":\"guest-init-a3\",\
                              \"event\":\"iptables_binary_missing\",\
                              \"binary\":{binary:?},\"err\":{:?}}}",
                            e.to_string(),
                        );
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                installed_any = true;
                eprintln!(
                    "{{\"level\":\"info\",\"step\":\"guest-init-a3\",\
                      \"event\":\"iptables_redirect_installed\",\
                      \"binary\":{binary:?},\"tproxy_port\":{tproxy_port}}}"
                );
                break;
            }
        }
        if !installed_any {
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"guest-init-a3\",\
                  \"event\":\"iptables_install_failed\",\
                  \"note\":\"egress will fail closed — substrate has no NIC \
                  and the in-guest tproxy listener is unreachable from \
                  agent processes without the REDIRECT chain\"}}"
            );
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
        assert_eq!(A3_TPROXY_PORT_ENV,   "RAXIS_AIRGAP_A3_TPROXY_PORT");
        assert_eq!(A3_DEFAULT_TPROXY_PORT, 3129);
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

// ---------------------------------------------------------------------------
// Cargo-offline default (`INV-EXECUTOR-IMAGE-RUST-OFFLINE-01`)
// ---------------------------------------------------------------------------

/// Env var the executor planner-core sets at PID-1 boot so every
/// `BashTool`-spawned `cargo` invocation defaults to offline mode.
///
/// The realistic-scenario seed's `rust-crate/Cargo.toml` declares
/// no third-party dependencies, so `cargo fmt --check` + `cargo
/// clippy --all-targets -- -D warnings` succeed without any
/// `index.crates.io` probe. Defaulting `CARGO_NET_OFFLINE=true`
/// short-circuits cargo's first-invocation registry-index refresh
/// — which would otherwise hit the canonical empty per-session
/// egress allowlist (`INV-EXECUTOR-EGRESS-OFFLINE-FIRST-01`),
/// retry the resolver for the registry-fetch timeout window, and
/// surface a flaky `failed to download` error rather than the
/// crisp `no matching package … found (lock file only)` shape
/// `--offline` produces.
///
/// The two sibling lint-toolchain invariants
/// (`INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-{PYTHON,JS}-01`, canonical
/// home `v2/planner-harness.md §10.6`) bake their per-language
/// deps directly into the executor-starter rootfs at image-build
/// time. This invariant covers the Rust half of the same
/// offline-first surface for the realistic-scenario plan
/// (`raxis/kernel/tests/extended_e2e_support/plan_realistic.rs`):
/// the seed's `rust-crate/` has no third-party deps so there's
/// nothing to bake, and the env-default is the load-bearing
/// guard against a future seed dep accidentally introducing a
/// registry probe.
pub const CARGO_OFFLINE_ENV: &str = "CARGO_NET_OFFLINE";

/// Set [`CARGO_OFFLINE_ENV`] = `"true"` in the current process env
/// IF AND ONLY IF the operator has not already set it (any
/// non-empty value wins; an explicit `CARGO_NET_OFFLINE=false`
/// stays in force). The executor planner-core invokes this once
/// during PID-1 boot, BEFORE the tokio runtime spawns any worker
/// thread, so the `unsafe { set_var }` call is single-threaded
/// per Rust 2024's env-mutation contract.
///
/// Returns the action taken so the caller can log it (and a
/// post-mortem audit-chain replay can prove which branch fired
/// for each session).
pub fn ensure_cargo_offline_default() -> CargoOfflineDefaultOutcome {
    match std::env::var(CARGO_OFFLINE_ENV) {
        Ok(v) if !v.is_empty() => {
            CargoOfflineDefaultOutcome::PreservedExisting { value: v }
        }
        _ => {
            // SAFETY: `set_var` is unsafe-by-Rust-2024 because of
            // multi-threaded access semantics. This call runs
            // from the planner's PID-1 main BEFORE the tokio
            // runtime spawns any worker threads (the call site
            // in planner-executor sits between
            // `mount_workspace_shares()` and the
            // `tokio::runtime::Builder::new_multi_thread()`
            // construction), so there is no concurrent env
            // reader/writer. The whole point of running this
            // before runtime construction is to ensure the
            // single-threaded contract holds.
            unsafe {
                std::env::set_var(CARGO_OFFLINE_ENV, "true");
            }
            CargoOfflineDefaultOutcome::DefaultedToOffline
        }
    }
}

/// Outcome of [`ensure_cargo_offline_default`]. Logged by the
/// caller so a post-mortem can prove whether the executor's
/// `cargo` invocations defaulted to offline OR inherited an
/// operator-set value.
#[derive(Clone, Debug)]
pub enum CargoOfflineDefaultOutcome {
    /// The env var was unset / empty when the helper ran; the
    /// helper set it to `"true"`.
    DefaultedToOffline,
    /// The env var was already set; the helper preserved the
    /// existing value.
    PreservedExisting {
        /// The value the operator pre-set.
        value: String,
    },
}

#[cfg(test)]
mod cargo_offline_default_tests {
    use super::*;
    use std::sync::Mutex;

    /// Helper: snapshot/restore the env var around a test that
    /// mutates it. Tests in the same process can race on env
    /// mutation, so we serialise via a process-wide mutex around
    /// the snapshot/restore pair.
    fn with_env_snapshot<F: FnOnce()>(key: &str, f: F) {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var(key).ok();
        // SAFETY: holding the static mutex serialises every test
        // in this module against any other test in this module
        // that touches the same env key.
        unsafe { std::env::remove_var(key); }
        f();
        // SAFETY: see above.
        unsafe {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None    => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn ensure_cargo_offline_default_sets_when_absent() {
        with_env_snapshot(CARGO_OFFLINE_ENV, || {
            let outcome = ensure_cargo_offline_default();
            assert!(matches!(outcome, CargoOfflineDefaultOutcome::DefaultedToOffline));
            assert_eq!(std::env::var(CARGO_OFFLINE_ENV).unwrap(), "true");
        });
    }

    #[test]
    fn ensure_cargo_offline_default_preserves_existing_truthy_value() {
        with_env_snapshot(CARGO_OFFLINE_ENV, || {
            // SAFETY: serialised via `with_env_snapshot`'s mutex.
            unsafe { std::env::set_var(CARGO_OFFLINE_ENV, "true"); }
            let outcome = ensure_cargo_offline_default();
            match outcome {
                CargoOfflineDefaultOutcome::PreservedExisting { value } => {
                    assert_eq!(value, "true");
                }
                other => panic!("expected PreservedExisting, got {other:?}"),
            }
        });
    }

    #[test]
    fn ensure_cargo_offline_default_preserves_explicit_falsy_value() {
        // Operator override: `CARGO_NET_OFFLINE=false` MUST win
        // over the planner default. This is the load-bearing
        // precedence contract — an operator who explicitly opts
        // back into online cargo (e.g. a starter image embedded
        // inside a tier-3 BYO workflow that genuinely needs the
        // registry index) needs the planner to respect that
        // choice.
        with_env_snapshot(CARGO_OFFLINE_ENV, || {
            // SAFETY: serialised via `with_env_snapshot`'s mutex.
            unsafe { std::env::set_var(CARGO_OFFLINE_ENV, "false"); }
            let outcome = ensure_cargo_offline_default();
            match outcome {
                CargoOfflineDefaultOutcome::PreservedExisting { value } => {
                    assert_eq!(value, "false");
                }
                other => panic!("expected PreservedExisting, got {other:?}"),
            }
            assert_eq!(std::env::var(CARGO_OFFLINE_ENV).unwrap(), "false");
        });
    }

    #[test]
    fn ensure_cargo_offline_default_treats_empty_as_unset() {
        // Pin: an empty-string env var is treated as "unset" so
        // an operator who exported the variable without a value
        // still gets the default. This matches cargo's own
        // env-handling: cargo treats `CARGO_NET_OFFLINE=` (empty)
        // as "no preference set".
        with_env_snapshot(CARGO_OFFLINE_ENV, || {
            // SAFETY: serialised via `with_env_snapshot`'s mutex.
            unsafe { std::env::set_var(CARGO_OFFLINE_ENV, ""); }
            let outcome = ensure_cargo_offline_default();
            assert!(matches!(outcome, CargoOfflineDefaultOutcome::DefaultedToOffline));
            assert_eq!(std::env::var(CARGO_OFFLINE_ENV).unwrap(), "true");
        });
    }
}
