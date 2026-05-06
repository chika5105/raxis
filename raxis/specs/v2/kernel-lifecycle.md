# RAXIS V2 — Kernel Process Lifecycle and Daemonization

> **Status:** V2 Specified
> **Cross-references:**
> - `specs/invariants.md` — INV-04 (audit chain integrity)
> - `specs/v2/key-revocation.md §7` — termination signal categories (`Immediate` vs `Graceful`); the kernel itself is always `Graceful` (operators never `KeyCompromised` the kernel host)
> - `specs/v2/host-capacity.md §7.6` — `AuditWriteImpossible` halt behavior; this spec specifies how that halt is surfaced to operators when the kernel runs detached from a terminal
> - `specs/v2/integration-merge.md §11` — three-phase transactional pattern; daemonized kernel restarts must complete the same recovery protocol on startup
> - `specs/v2/planner-harness.md §5.6` — In-VM background-process cleanup sweep on `SessionPausing` (referenced by §7.1 below)
> - `specs/v2/planner-harness.md §10.2` — Linux 5.14+ VM guest kernel requirement (provides `cgroup.kill` for the universal reap at hypervisor stop)
> - `specs/v2/verifier-processes.md §4.4` — Verifier-VM teardown sequence (host-side cgroup cleanup; verifier-cgroup orphan sweep on kernel restart per §10.2)
> - `specs/v2/extensibility-traits.md §6` — `OperatorTransport` trait; the operator-socket bind described in §3 (kernel start) and the implementation checklist in §13 delegate to `Arc<dyn OperatorTransport>::bind` (V2 default `UnixSocketTransport`). Future transports (mTLS gRPC for RAXIS Cloud, serial relay for air-gapped) plug in here without changing the lifecycle states/signals/recovery flows in this spec.
> - `specs/v2/extensibility-traits.md §9` — boot composition order; the kernel's `main.rs` constructs `AuditSink → CredentialBackend → InferenceRouter → IsolationBackend → DomainAdapter → OperatorTransport` in that exact order before entering `accept_loop`.

---

## 1. The Problem

By default, `raxis kernel start` runs in the foreground: it occupies the operator's terminal, prints status to stdout, blocks the shell until terminated, and dies when the terminal is closed. This is correct behavior for development, testing, and one-off operations — the operator wants to see what's happening and stop the kernel with `^C`.

For production use, foreground operation is hostile to operators:

- The kernel must be running 24/7 (it's the control plane for everything else); a closed SSH session or terminal hang kills it.
- Manually re-starting the kernel after every reboot, login, or accidental termination is operationally toilsome.
- Operators end up writing their own `systemd` unit files or `launchd` plists, with varying quality and inconsistent restart behavior. This produces a fragmented operational experience: every deployment has subtly different daemonization.
- A kernel crash should be invisible to most operators (the supervisor restarts it); they need to be paged only for repeated crash loops or capacity halts that the supervisor cannot recover from.

V2 specifies first-class daemonization as a CLI flag. With `--daemon`, the kernel installs itself as a native platform service (systemd user unit on Linux, launchd user agent on macOS), starts in the background, returns the operator's shell immediately, and auto-starts on subsequent logins. Without the flag, behavior is unchanged — foreground, terminal-bound, ^C-stoppable.

This spec answers: "how do I get the kernel to run all the time without thinking about it?", "how do I see what it's doing when it's not in my shell?", "how do I stop or restart it cleanly?", and "what happens when it crashes?"

---

## 2. Architecture: Two Modes, One Binary

The kernel binary is identical in both modes; the mode is determined by command-line flags at start time.

| Mode | Invoked via | Process behavior | Lifetime | Auto-restart on crash |
|---|---|---|---|---|
| **Foreground** | `raxis kernel start` | Blocks shell; stdout/stderr go to terminal; ^C → SIGINT → graceful shutdown | Until terminal closed or signal received | No |
| **Daemon (user)** | `raxis kernel start --daemon` | Forks via platform supervisor; detached from terminal; returns immediately | Until explicitly stopped, logout, or shutdown | Yes (supervisor-managed; bounded backoff) |
| **Daemon (system)** | `sudo raxis kernel start --daemon --system` | Same as Daemon (user) but runs as `raxis` system user; persists across logouts | Until explicitly stopped or machine shutdown | Yes (supervisor-managed; bounded backoff) |

The kernel itself does not implement daemonization (no `fork()`-and-detach, no manual log redirection, no PID file management beyond a single sanity check). Daemonization is delegated to the operating system's native service supervisor:

- **Linux:** `systemd` user units (`~/.config/systemd/user/raxis-kernel.service`) for user mode; `systemd` system units (`/etc/systemd/system/raxis-kernel.service`) for system mode.
- **macOS:** `launchd` user agents (`~/Library/LaunchAgents/dev.raxis.kernel.plist`) for user mode; `launchd` daemons (`/Library/LaunchDaemons/dev.raxis.kernel.plist`) for system mode.
- **Windows:** Not supported in V2. The kernel's existing platform requirements (VirtIO/Firecracker on Linux, Apple Virtualization.framework on macOS) already exclude Windows; daemonization on Windows is V3+ if the kernel itself ever lands there.

Per `INV-LIFECYCLE-03`, V2 does not implement a custom Rust-based daemon supervisor. `systemd` and `launchd` are decades-mature, well-tested, well-understood by every operator, and integrate with the platform's logging, resource limits, and dependency management. Re-implementing any of that in `raxis-kernel-supervisor` would be wasted complexity.

### 2.1 Component diagram

```
                    ┌─────────────────────────────┐
                    │  raxis CLI                  │
                    │                             │
                    │  raxis kernel start          │ ── (foreground) ──► kernel runs in shell
                    │  raxis kernel start --daemon │ ──┐
                    │  raxis kernel stop           │   │
                    │  raxis kernel status         │   │
                    │  raxis kernel logs           │   │
                    │  raxis kernel install        │   │
                    │  raxis kernel uninstall      │   │
                    └─────────────────────────────┘   │
                                                      │
                                                      ▼ (writes service file;
                                                         invokes supervisor commands)
                                                      
                    ┌──────────────────────────────────────────────────────┐
                    │  Platform service supervisor                          │
                    │  (systemd | launchd; chosen by host OS at install)    │
                    │                                                       │
                    │  - Starts kernel process; redirects stdout/stderr     │
                    │    to log destination                                 │
                    │  - Restarts on crash with configured backoff          │
                    │  - Sends SIGTERM on stop request; SIGKILL after grace │
                    │  - Manages enable-at-login (or enable-at-boot for     │
                    │    system mode)                                       │
                    └────────────────────┬─────────────────────────────────┘
                                         │
                                         │ exec()
                                         ▼
                            ┌─────────────────────────┐
                            │  raxis-kernel process   │
                            │                         │
                            │  Reads policy.toml      │
                            │  Acquires PID lock      │
                            │  Runs as designed       │
                            │  Handles SIGTERM via    │
                            │  graceful-shutdown path │
                            │  per key-revocation     │
                            │  §7 Graceful semantics  │
                            └─────────────────────────┘
```

### 2.2 What the kernel itself does NOT do

The kernel binary implements none of the following — they are the supervisor's job:

- `fork()`-and-detach to background.
- Redirect stdout/stderr to log files.
- Manage a PID file beyond the single-instance sanity check (§9).
- Auto-restart on crash.
- Register itself for boot-at-login.
- Set process resource limits (`ulimit`, `RLIMIT_*`); these come from the service unit's resource directives.

This keeps the kernel binary single-purpose: it runs, it serves IPC, it audits, it terminates on signal. The "daemon-or-not" question is the supervisor's, not the kernel's.

---

## 3. CLI Surface

### 3.1 The complete command set

```bash
# Foreground operation (default; blocks shell)
raxis kernel start

# Daemon operation: install service + start now (user mode)
raxis kernel start --daemon

# Daemon operation: system mode (requires sudo)
sudo raxis kernel start --daemon --system

# Stop the kernel (works for both foreground and daemon modes)
raxis kernel stop

# Restart (preserves current mode; if foreground was running, restarts foreground; if daemon, restarts daemon)
raxis kernel restart

# Hot-reload policy.toml without restart (sends SIGHUP to running kernel)
raxis kernel reload

# Status: shows current mode, PID, uptime, recent log lines, capacity summary
raxis kernel status

# Tail logs (works for both modes; pulls from terminal or service log destination)
raxis kernel logs
raxis kernel logs --follow         # -f equivalent
raxis kernel logs --since "1 hour ago"

# Service management without starting/stopping the kernel
raxis kernel install               # writes service file; enables boot-at-login; does NOT start
raxis kernel install --system      # system mode; requires sudo
raxis kernel uninstall             # disables boot-at-login; removes service file; does NOT stop running instance
raxis kernel uninstall --system    # system mode; requires sudo
```

### 3.2 Flag semantics

| Flag | Effect |
|---|---|
| `--daemon` | Install service, enable for boot-at-login, start in background. Returns to shell immediately after the supervisor reports the kernel is running (or fails to start). |
| `--system` | Combined with `--daemon` or `--install`: targets system-wide service supervisor instead of user-level. Requires the invoking user to be root (sudo). |
| `--no-install` | Combined with `--daemon`: starts in background for this session only; does NOT register for boot-at-login. Useful for short-lived background sessions (e.g., during a long-running operator script). |

`--daemon` and `--no-install` are mutually exclusive when both produce conflicting behavior; `--daemon --no-install` is allowed and means "start in background now without registering for boot."

`--system` cannot be combined with `--no-install` (the system-level case is exclusively for production deployments where boot-at-startup is the point).

### 3.3 Status output format

```
$ raxis kernel status
Mode:               Daemon (user)
Service:            ~/.config/systemd/user/raxis-kernel.service
Status:             Active (running)
PID:                12847
Started at:         2026-05-04T16:22:13-07:00 (uptime: 3h 17m)
Boot-on-login:      Enabled
Auto-restart:       Enabled (last restart: never)

Capacity summary (per host-capacity.md):
  Disk:             4.2 GiB free of 100 GiB (4.2%)  ✓
  Aggregate VM mem: 12 GiB used of 48 GiB           ✓
  Active sessions:  3
  Queued intents:   0
  Disk-full state:  Healthy

Recent operator-attention events (last 24h): none

Recent log lines (last 5):
  2026-05-04T19:35:12  INFO   IntegrationMerge admitted (initiative=...)
  2026-05-04T19:35:14  INFO   IntegrationMerge applied (segment=423)
  2026-05-04T19:36:02  INFO   ApprovePlan admitted (operator=alice)
  2026-05-04T19:36:08  INFO   InferenceCompleted (model=anthropic:claude-sonnet-4.6)
  2026-05-04T19:38:31  INFO   CompleteTask completed (initiative=..., session=...)
```

When the kernel is not running:

```
$ raxis kernel status
Mode:               Not running
Service:            ~/.config/systemd/user/raxis-kernel.service (installed, disabled)
Last started at:    2026-05-04T08:14:22-07:00
Last stopped at:    2026-05-04T16:21:58-07:00 (operator request)
Last exit code:     0

To start: raxis kernel start --daemon
```

When the kernel is in foreground (started by current shell or another):

```
$ raxis kernel status
Mode:               Foreground
PID:                94532
Started at:         2026-05-04T19:00:11-07:00 (uptime: 41m)
Owning terminal:    /dev/ttys003
Service:            not installed

To convert to daemon: raxis kernel stop && raxis kernel start --daemon
```

---

## 4. Daemon Mode on Linux (systemd)

### 4.1 User-level service unit

When the operator runs `raxis kernel start --daemon` (without `--system`), the CLI generates a systemd user unit at `~/.config/systemd/user/raxis-kernel.service`:

```ini
[Unit]
Description=RAXIS Kernel (user)
Documentation=https://raxis.dev/docs/kernel-lifecycle
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/local/bin/raxis kernel start --foreground-supervised
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=on-failure
RestartSec=2s
StartLimitIntervalSec=60s
StartLimitBurst=5

# Resource limits derived from policy.toml [host_capacity] at install time;
# regenerated on `raxis kernel reload-service-config`.
LimitNOFILE=65536
MemoryMax=infinity            # OS budget; intra-VM budget is enforced inside kernel
WorkingDirectory=%h/.local/share/raxis

# Environment
Environment=RAXIS_HOME=%h/.local/share/raxis
Environment=RAXIS_POLICY_PATH=%h/.config/raxis/policy.toml
Environment=RUST_LOG=info

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=raxis-kernel

[Install]
WantedBy=default.target
```

The CLI then runs:

```
systemctl --user daemon-reload
systemctl --user enable raxis-kernel.service
systemctl --user start raxis-kernel.service
systemctl --user is-active raxis-kernel.service     # verify
loginctl enable-linger $USER                         # ensure user services run after logout
```

`loginctl enable-linger` is critical: by default, systemd user services stop when the user logs out. The kernel needs to keep running across SSH disconnects, so we enable lingering. This is one-time per user; the CLI checks `loginctl show-user $USER --property=Linger` first and skips if already enabled.

### 4.2 System-level service unit

`raxis kernel start --daemon --system` requires sudo and generates `/etc/systemd/system/raxis-kernel.service`:

```ini
[Unit]
Description=RAXIS Kernel (system)
Documentation=https://raxis.io/docs/kernel-lifecycle
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
User=raxis                                # dedicated system user; created at install if missing
Group=raxis
ExecStart=/usr/local/bin/raxis kernel start --foreground-supervised
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=on-failure
RestartSec=2s
StartLimitIntervalSec=60s
StartLimitBurst=5

LimitNOFILE=65536
MemoryMax=infinity
WorkingDirectory=/var/lib/raxis

Environment=RAXIS_HOME=/var/lib/raxis
Environment=RAXIS_POLICY_PATH=/etc/raxis/policy.toml
Environment=RUST_LOG=info

StandardOutput=journal
StandardError=journal
SyslogIdentifier=raxis-kernel

[Install]
WantedBy=multi-user.target
```

System mode integrates with system-wide initialization: the kernel starts at machine boot (`multi-user.target`), runs as `raxis:raxis` (a dedicated low-privilege system user), and uses canonical FHS paths (`/var/lib/raxis`, `/etc/raxis`).

Install steps:

```
useradd --system --home-dir /var/lib/raxis --shell /usr/sbin/nologin raxis  # if missing
install -d -o raxis -g raxis /var/lib/raxis /etc/raxis
systemctl daemon-reload
systemctl enable raxis-kernel.service
systemctl start raxis-kernel.service
systemctl is-active raxis-kernel.service
```

### 4.3 The `--foreground-supervised` flag

Note that the systemd `ExecStart` uses `raxis kernel start --foreground-supervised`, not `--daemon`. The kernel itself runs in foreground inside the systemd-supervised process; systemd handles the detach/log/restart. `--foreground-supervised` is identical to no-flag foreground except:

- The kernel uses `sd_notify` to announce readiness (`NotifyAccess=main`, `Type=notify`); systemd waits for `READY=1` before considering the service active.
- The kernel does NOT install a SIGINT handler that prints "Press ^C again to force-quit" (that's interactive UX inappropriate for supervised mode).
- The kernel writes structured log output (JSON lines or similar) suitable for journald parsing instead of pretty terminal output.

Operators do not run `--foreground-supervised` directly; the CLI generates the unit file with this flag for the supervisor.

### 4.4 Logs in systemd mode

All logs go to journald and are accessible via:

```
$ journalctl --user -u raxis-kernel             # user mode
$ sudo journalctl -u raxis-kernel               # system mode

# Or via the raxis CLI (which delegates to journalctl):
$ raxis kernel logs --follow
$ raxis kernel logs --since "10 minutes ago"
$ raxis kernel logs --grep "IntegrationMerge"
```

The kernel's audit log (per `host-capacity.md §6.3`) is separate and unaffected — it lives in `RAXIS_HOME/audit/` regardless of mode. journald-side logs are operational telemetry (info, warnings, errors, status); the audit log is the cryptographic record of state changes.

---

## 5. Daemon Mode on macOS (launchd)

### 5.1 User-level launch agent

`raxis kernel start --daemon` on macOS generates `~/Library/LaunchAgents/dev.raxis.kernel.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.raxis.kernel</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/raxis</string>
        <string>kernel</string>
        <string>start</string>
        <string>--foreground-supervised</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>          <!-- do NOT restart on clean exit (operator stop) -->
        <key>Crashed</key>
        <true/>           <!-- DO restart on crash -->
    </dict>

    <key>ThrottleInterval</key>
    <integer>10</integer>      <!-- minimum 10s between restart attempts -->

    <key>EnvironmentVariables</key>
    <dict>
        <key>RAXIS_HOME</key>
        <string>/Users/USERNAME/Library/Application Support/raxis</string>
        <key>RAXIS_POLICY_PATH</key>
        <string>/Users/USERNAME/Library/Preferences/raxis/policy.toml</string>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>

    <key>WorkingDirectory</key>
    <string>/Users/USERNAME/Library/Application Support/raxis</string>

    <key>StandardOutPath</key>
    <string>/Users/USERNAME/Library/Logs/raxis/kernel.out</string>
    <key>StandardErrorPath</key>
    <string>/Users/USERNAME/Library/Logs/raxis/kernel.err</string>

    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
</dict>
</plist>
```

(`USERNAME` is interpolated at install time; the literal file uses the current user's name.)

The CLI then runs:

```
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.raxis.kernel.plist
launchctl enable gui/$(id -u)/dev.raxis.kernel
launchctl kickstart gui/$(id -u)/dev.raxis.kernel
launchctl print gui/$(id -u)/dev.raxis.kernel | head -20    # verify state
```

`launchctl bootstrap` registers the agent with the per-user `gui` domain (active during the user's GUI session — equivalent to "boot-on-login"). The agent persists across logouts only if the user has a persistent session; for SSH-only users without a GUI session, `--system` mode is more appropriate.

### 5.2 System-level launch daemon

`sudo raxis kernel start --daemon --system` generates `/Library/LaunchDaemons/dev.raxis.kernel.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.raxis.kernel</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/raxis</string>
        <string>kernel</string>
        <string>start</string>
        <string>--foreground-supervised</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>UserName</key>
    <string>_raxis</string>          <!-- macOS convention: system users prefix with _ -->
    <key>GroupName</key>
    <string>_raxis</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>RAXIS_HOME</key>
        <string>/var/lib/raxis</string>
        <key>RAXIS_POLICY_PATH</key>
        <string>/etc/raxis/policy.toml</string>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>

    <key>WorkingDirectory</key>
    <string>/var/lib/raxis</string>

    <key>StandardOutPath</key>
    <string>/var/log/raxis/kernel.out</string>
    <key>StandardErrorPath</key>
    <string>/var/log/raxis/kernel.err</string>

    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
</dict>
</plist>
```

Install steps:

```
sudo dscl . -create /Users/_raxis UniqueID 281 PrimaryGroupID 281 \
    NFSHomeDirectory /var/lib/raxis UserShell /usr/bin/false  # if missing
sudo install -d -o _raxis -g _raxis /var/lib/raxis /etc/raxis /var/log/raxis
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.raxis.kernel.plist
sudo launchctl enable system/dev.raxis.kernel
sudo launchctl kickstart system/dev.raxis.kernel
sudo launchctl print system/dev.raxis.kernel | head -20
```

System daemons load at machine boot (before any user logs in) and persist regardless of user activity.

### 5.3 Logs in launchd mode

Logs go to plain files at `~/Library/Logs/raxis/kernel.{out,err}` (user) or `/var/log/raxis/kernel.{out,err}` (system). The `raxis kernel logs` command tails these via standard `tail` semantics; `--follow` uses `tail -F` (handles file rotation).

There is no journald equivalent on macOS. Operators wanting structured log aggregation can configure their own log shippers (vector, fluentd, custom) to ingest `kernel.out` / `kernel.err`.

### 5.4 Log rotation

The kernel does NOT rotate its own operational logs (this is supervisor territory). On Linux, journald's built-in rotation handles it. On macOS, the spec recommends operators configure `newsyslog` (Apple's bundled log rotator) via `/etc/newsyslog.d/raxis.conf`:

```
# /etc/newsyslog.d/raxis.conf
/var/log/raxis/kernel.out  _raxis:_raxis  644  10  10240  *  J
/var/log/raxis/kernel.err  _raxis:_raxis  644  10  10240  *  J
```

(10 generations, 10 MB max per file, gzip-compressed.) The `raxis kernel install --system` command can optionally write this file with `--with-newsyslog-config`; otherwise the operator is responsible.

---

## 6. Logging in Foreground Mode

When `raxis kernel start` is run without `--daemon` or `--foreground-supervised`:

- stdout and stderr go to the operator's terminal.
- Output uses pretty colored formatting (timestamps, log levels with color, structured fields rendered in human-readable form).
- ^C produces "shutting down... (press ^C again to force-quit)" with a 30-second graceful shutdown window.
- ^C twice within that window sends SIGKILL via the kernel's own escape hatch (the kernel invokes `std::process::abort()` after the second SIGINT).

Foreground mode is the developer/operator-debugging UX. It is intentionally distinct from `--foreground-supervised` (which is what the supervisor invokes — no terminal interactivity, no pretty colors, no double-^C handling).

---

## 7. Signal Handling and Shutdown

The kernel handles signals consistently across modes; the difference is who sends them:

- Foreground: SIGINT from terminal (^C) or SIGTERM from the operator's `kill` command.
- Daemon: SIGTERM from the supervisor on `raxis kernel stop` or system shutdown.

### 7.1 Signal categories (cross-reference: `key-revocation.md §7`)

The kernel itself is always terminated `Graceful`. Per `key-revocation.md §7.2`, the `Immediate` (hypervisor-stop, no SIGTERM grace) signal class applies only to microVMs being terminated for security reasons (`KeyCompromised`, `EmergencyKeyCompromised`, `CidDriftDetected`). The kernel host is never the subject of an `Immediate` termination — operators do not "compromise" their own kernel.

`Graceful` shutdown for the kernel:

```
1. SIGTERM received.
2. Reject new IPC connections (operator and gateway both); existing in-flight intents continue.
3. For each Active session, send KernelPush::SessionPausing { reason: KernelShutdown };
   wait for ACK or 5s timeout.
   The planner inside each VM, on receiving SessionPausing, performs the in-VM
   background-process cleanup sweep per planner-harness.md §5.6:
     - Iterate /sys/fs/cgroup/raxis/bash-bg-*/ cgroups in the VM
     - Send SIGTERM to cgroup.procs, wait grace_seconds (default 5; configurable via
       plan.toml [tasks.shell] bg_shutdown_grace_seconds; max 30)
     - Issue cgroup.kill for any cgroup still populated
     - Submit a final BackgroundProcessExited summary in the SessionPausing ACK so
       the audit log records the final state of each bg process
   This is best-effort: even if the planner does not ACK or does not perform the
   sweep, step 6 below will universally reap all in-VM processes at VM stop time.
4. Drain admission queue: each queued intent receives FAIL_KERNEL_SHUTTING_DOWN immediately.
5. For each in-flight `IntegrationMerge`:
     - If Phase 1 not yet committed: rollback (BEGIN IMMEDIATE was never issued).
     - If Phase 1 committed but Phase 2 not started: leave `git_apply_pending = 1`;
       startup recovery (per integration-merge.md §11.3) will resume.
     - If Phase 2 in-flight: wait up to 30s for completion; if still in flight at deadline,
       leave the partial git work in place; startup recovery (Case A) will resume on next start.
6. For each remaining active session, terminate its VM via the hypervisor's clean-stop path
   (Apple Virtualization.framework: `stop(completionHandler:)`; Firecracker: shutdown action).
   Hypervisor stop is the universal reap point: all in-VM processes (planner harness,
   any bash-bg-* cgroup, any verifier sub-cgroup) are destroyed regardless of whether
   the in-VM cleanup sweep completed. This guarantee is what makes the in-VM sweep
   in step 3 a best-effort optimization rather than a correctness requirement —
   no in-VM process can survive its hosting VM's stop. See planner-harness.md
   §5.6 for the in-VM cleanup contract; see verifier-processes.md §4.4 for verifier
   VM teardown specifics.
7. Flush any pending audit events to disk (fsync the audit log file).
8. Close SQLite connections cleanly (this commits the WAL checkpoint).
9. Exit with status 0.

If steps 2-8 are not complete within `TimeoutStopSec` (default 30s), the supervisor sends SIGKILL.
On SIGKILL: the kernel dies abruptly. Startup recovery on the next boot handles
any uncommitted state per the integration-merge.md §11.3 and audit/v3 §4.4 protocols.
The next-boot startup recovery also includes a verifier-VM orphan sweep
(per verifier-processes.md §10.2): any cgroup matching /sys/fs/cgroup/raxis/verifier-*/
on the host that is not associated with a known-running session is killed via
cgroup.kill and synthesized as a `crashed` witness for its task.
```

### 7.2 SIGHUP for policy reload

`raxis kernel reload` sends SIGHUP to the running kernel:

1. Kernel re-reads `policy.toml` (and emergency revocations file per `key-revocation.md §6`).
2. Validates new policy against current state; if invalid, emits `PolicyReloadFailed` audit event and continues with old policy.
3. If valid: advances policy epoch per `policy-epoch-diffing.md`; emits `PolicyReloaded` audit event.
4. In-flight intents continue with the policy active at their admission; new intents use the reloaded policy.

This is a non-disruptive reload — no IPC connections drop, no in-flight work is interrupted.

### 7.3 Crash semantics

If the kernel crashes (panic, SIGKILL, OOM, etc.):

- **Foreground mode:** the operator sees the crash in their terminal; the shell prompt returns; nothing auto-restarts. The operator must manually re-invoke `raxis kernel start` (or the kernel may have already done damage that requires investigation first).
- **Daemon mode:** the supervisor detects the exit; emits a platform-specific log entry; waits `RestartSec` (systemd) or `ThrottleInterval` (launchd); restarts the kernel. The new instance runs startup recovery (`integration-merge.md §11.3`, etc.) to reconcile any partial state.

### 7.4 Crash-loop detection

The supervisor's crash-loop detection is the first defense:

- **systemd:** `StartLimitBurst=5` and `StartLimitIntervalSec=60s` mean "if the service crashes 5 times within 60 seconds, stop trying to restart it." After the limit is hit, the service stays in `failed` state and operators must manually intervene with `systemctl reset-failed`.
- **launchd:** `ThrottleInterval=10` enforces a minimum 10-second gap between restarts. launchd does not natively cap total restarts; if the operator wants harder protection, they can wrap the binary in a supervisor script that exits after N rapid restarts.

The kernel itself contributes a complementary defense: on startup, it checks for "I crashed in startup recovery 3 times in a row" by inspecting `audit_segment_archive_state` for inconsistent state from prior incomplete recoveries. If detected, the kernel refuses to start with `FAIL_RECOVERY_LOOP_DETECTED` and emits `OperatorAttentionRequired { kind: RecoveryLoopDetected }` to whatever logging destination is available. Operators must investigate manually.

---

## 8. PID File and Single-Instance Enforcement

Multiple kernel instances against the same `RAXIS_HOME` would corrupt SQLite state, double-process intents, and produce undefined behavior. The kernel enforces single-instance via two complementary mechanisms.

### 8.1 SQLite-backed lock (primary)

On startup, the kernel attempts to acquire an exclusive SQLite write lock on `state.db` and writes a row to a `kernel_instance_lock` table:

```sql
CREATE TABLE kernel_instance_lock (
    instance_id     INTEGER PRIMARY KEY,        -- always 1; UNIQUE constraint enforces single row
    pid             INTEGER NOT NULL,
    hostname        TEXT NOT NULL,
    started_at_ms   INTEGER NOT NULL,
    mode            TEXT NOT NULL CHECK (mode IN ('Foreground', 'DaemonUser', 'DaemonSystem'))
);

-- Insert via:
INSERT INTO kernel_instance_lock (instance_id, pid, hostname, started_at_ms, mode)
VALUES (1, ?, ?, ?, ?)
ON CONFLICT (instance_id) DO UPDATE
   SET pid = excluded.pid, hostname = excluded.hostname,
       started_at_ms = excluded.started_at_ms, mode = excluded.mode
 WHERE kernel_instance_lock.pid IS NULL                    -- previous instance cleanly stopped
    OR NOT kernel_pid_alive(kernel_instance_lock.pid);     -- previous instance crashed
```

If the row exists with a live PID (verifiable via `kill -0 <pid>` returning 0), the new instance refuses to start with `FAIL_KERNEL_ALREADY_RUNNING { pid, started_at_ms }`. The CLI prints a helpful error pointing the operator at `raxis kernel status`.

Cleanup on graceful shutdown: the kernel UPDATEs `pid = NULL` before closing SQLite, signaling "I exited cleanly; the next instance can take over without further checks."

### 8.2 Filesystem PID file (secondary)

A complementary PID file at `RAXIS_HOME/raxis-kernel.pid` provides:

- A platform-standard discovery mechanism (`pgrep`, monitoring tools, process inspectors all expect a PID file).
- A way for the supervisor to know which process to signal even if it doesn't track the PID itself.
- A debugging aid for operators who want to inspect with standard tooling (`lsof -p $(cat raxis-kernel.pid)`, etc.).

The PID file is written after the SQLite lock is acquired and removed on graceful shutdown. The kernel does NOT trust the PID file alone for single-instance enforcement — the SQLite lock is the source of truth.

### 8.3 Why two mechanisms

The SQLite lock catches the "second kernel instance starts on the same `RAXIS_HOME`" case definitively, including across hostname mismatches (e.g., NFS-mounted home directory between two machines — though this is a configuration we explicitly do NOT support). The PID file catches the "operator wants to send SIGTERM via `kill $(cat ...)`" use case where the SQLite lock is invisible.

If they ever disagree (PID file says X, SQLite says Y, both are alive), the kernel logs a `SecurityViolation { kind: PidFileSqliteMismatch }`, halts startup, and forces operator intervention.

---

## 9. Privilege Model

### 9.1 User mode: runs as the invoking user

When `--system` is not specified, the kernel runs as the user who invoked `raxis kernel start --daemon`. Filesystem ownership: all files under `RAXIS_HOME` (default `~/.local/share/raxis` on Linux, `~/Library/Application Support/raxis` on macOS) are owned by that user.

This is the recommended mode for:

- Single-user development workstations.
- Personal-use CI environments.
- Multi-tenant hosts where each user runs their own RAXIS instance.

The user's existing credentials, SSH keys, and shell environment are accessible to the kernel — the threat model assumes the user trusts the kernel as much as they trust their own account.

### 9.2 System mode: runs as dedicated `raxis` user

`--system` creates (or expects) a dedicated low-privilege system user (`raxis` on Linux, `_raxis` on macOS by convention) with:

- A locked-out shell (`/usr/sbin/nologin` or `/usr/bin/false`).
- Home directory at `/var/lib/raxis`.
- Membership only in its own primary group.

The kernel runs as this user; SQLite, audit logs, and worktrees are owned by this user; operator IPC sockets are accessible only to members of the `raxis` group (or via `sudo -u raxis` for root-equivalent operators).

This is the recommended mode for:

- Production deployments (dedicated host serving RAXIS to a team).
- Multi-user environments where the kernel must be isolated from end-user accounts.
- Compliance environments (SOC 2, HIPAA, etc.) requiring privilege separation.

### 9.3 Adding operators to the `raxis` group

After `raxis kernel install --system`, operators who should be allowed to submit intents must be added to the `raxis` group:

```bash
sudo usermod -a -G raxis alice
# alice must log out and back in for the group change to take effect
```

The CLI's intent-submitting commands (`raxis approve-plan`, `raxis init`, etc.) check whether the invoking user has access to the operator IPC socket; if not, they emit a clear error pointing the operator at the `usermod` command.

---

## 10. Lifecycle State Machine

The service's lifecycle follows a small state machine that operators see via `raxis kernel status`:

```
┌───────────────┐
│  Not Installed│ ──install (writes service file; enables boot)──► ┌──────────────┐
│  (no service  │ ◄──────────────uninstall─────────────────────────│  Stopped     │
│   file exists)│                                                  │  (service    │
└───────────────┘                                                  │   exists,    │
                                                                   │   not active)│
                                                                   └──────┬───────┘
                                                                          │
                                                            ┌──────start──┘
                                                            │
                                                            ▼
                                                    ┌──────────────┐
                                                    │  Starting    │
                                                    │  (sd_notify  │
                                                    │   pending)    │
                                                    └──────┬───────┘
                                                           │ READY=1
                                                           ▼
                                                    ┌──────────────┐
                                                    │  Active      │
                                                    │  (running)   │
                                                    └──────┬───────┘
                                                           │
                                            ┌──────stop───┴──crash──┐
                                            │                       │
                                            ▼                       ▼
                                   ┌──────────────┐      ┌─────────────────────┐
                                   │  Stopping    │      │  CrashedRestarting  │
                                   │  (SIGTERM    │      │  (RestartSec wait;  │
                                   │   sent;      │      │   then back to      │
                                   │   draining)  │      │   Starting)          │
                                   └──────┬───────┘      └─────────────────────┘
                                          │
                              ┌──exit_0──┴──TimeoutStopSec──┐
                              │                              │
                              ▼                              ▼
                      ┌──────────────┐              ┌──────────────────┐
                      │  Stopped     │              │  KilledByTimeout │
                      │              │              │  (SIGKILL'd)     │
                      └──────────────┘              └─────────┬────────┘
                                                              │
                                                              ▼
                                                  ┌─────────────────────┐
                                                  │  CrashedRestarting  │
                                                  │  (treated as crash) │
                                                  └─────────────────────┘
                                                              │
                                          if crash count exceeds StartLimitBurst
                                          within StartLimitIntervalSec:
                                                              │
                                                              ▼
                                                  ┌──────────────────────┐
                                                  │  Failed              │
                                                  │  (no auto-restart;   │
                                                  │   manual reset       │
                                                  │   required)          │
                                                  └──────────────────────┘
```

### 10.1 Audit events for lifecycle transitions

```rust
AuditEventKind::KernelStarted {
    mode:           KernelMode,         // Foreground | DaemonUser | DaemonSystem
    pid:            u32,
    version:        String,             // crate version of raxis-kernel
    hostname:       String,
    started_at_ms:  u64,
    cli_invocation: String,             // sanitized argv
}

AuditEventKind::KernelStopping {
    reason:                 ShutdownReason,   // OperatorRequested | SignalReceived(Signal) | StartupFailure
    initiated_at_ms:        u64,
    in_flight_sessions:     u32,
    in_flight_merges:       u32,
}

AuditEventKind::KernelStopped {
    exit_code:              i32,
    duration_ms:            u64,                // time from KernelStarted to here
    graceful_shutdown_ms:   Option<u64>,        // time spent in Stopping state
    stopped_at_ms:          u64,
}

AuditEventKind::KernelCrashRecovered {
    previous_pid:           Option<u32>,
    previous_started_at_ms: Option<u64>,
    recovery_actions_taken: Vec<RecoveryAction>, // git_apply_pending resumed, audit segments rebuilt, etc.
    recovered_at_ms:        u64,
}

AuditEventKind::KernelReloaded {
    previous_policy_epoch:  u64,
    new_policy_epoch:       u64,
    reloaded_at_ms:         u64,
}

AuditEventKind::KernelReloadFailed {
    error_kind:             ReloadErrorKind,
    error_message:          String,
    failed_at_ms:           u64,
}

AuditEventKind::ServiceInstalled {
    mode:                   ServiceMode,   // User | System
    service_path:           PathBuf,
    installed_at_ms:        u64,
}

AuditEventKind::ServiceUninstalled {
    mode:                   ServiceMode,
    service_path:           PathBuf,
    uninstalled_at_ms:      u64,
}
```

`KernelCrashRecovered` is emitted on the FIRST event written by the new instance after a crash — it's the kernel's signal to the audit chain that "an instance was lost, here's what we did to recover." Forensic reviewers can detect crash-restart sequences by looking for adjacent `KernelStopped` (or its absence) followed by `KernelCrashRecovered`.

---

## 11. Operator Workflow Examples

### 11.1 First-time install on a developer workstation (Linux)

```bash
$ raxis kernel start --daemon
Installing user-level systemd service...
  ✓ Created ~/.config/systemd/user/raxis-kernel.service
  ✓ Reloaded systemd user daemon
  ✓ Enabled service for login startup
  ✓ Enabled lingering for user 'alice' (services persist after logout)
Starting raxis-kernel.service...
  ✓ Service active (PID 12847)
  ✓ Kernel ready (sd_notify READY=1 received)

raxis-kernel is now running in the background.
  Status:  raxis kernel status
  Logs:    raxis kernel logs --follow
  Stop:    raxis kernel stop
```

### 11.2 Production install on a server (Linux, system mode)

```bash
$ sudo raxis kernel install --system
Creating system user 'raxis'...
  ✓ User created (UID 281)
Creating directories...
  ✓ /var/lib/raxis (owner: raxis:raxis, mode 0700)
  ✓ /etc/raxis (owner: raxis:raxis, mode 0750)
  ✓ /var/log/raxis (owner: raxis:raxis, mode 0750)
Installing system-level systemd service...
  ✓ Created /etc/systemd/system/raxis-kernel.service
  ✓ Reloaded systemd daemon
  ✓ Enabled service for boot startup
Service installed but NOT started. Start with:
  sudo systemctl start raxis-kernel
  OR
  sudo raxis kernel start --system

Add operators to the raxis group:
  sudo usermod -a -G raxis <username>
```

### 11.3 Stopping and restarting

```bash
$ raxis kernel stop
Stopping raxis-kernel...
  ✓ SIGTERM sent
  ✓ Draining 3 active sessions (timeout: 30s)
  ✓ Service stopped cleanly
Stopped at 2026-05-04T19:54:22-07:00 (was running for 4h 32m)

$ raxis kernel restart
Stopping raxis-kernel...
  ✓ Service stopped cleanly
Starting raxis-kernel...
  ✓ Service active (PID 13201)
  ✓ Kernel ready
Restart complete.
```

### 11.4 Hot-reloading policy without restart

```bash
$ vim ~/.config/raxis/policy.toml      # operator edits policy
$ raxis kernel reload
Sending SIGHUP to running kernel (PID 13201)...
  ✓ Policy reloaded successfully
  Policy epoch: 47 → 48
```

### 11.5 Inspecting status during normal operation

```bash
$ raxis kernel status
Mode:               Daemon (system)
Service:            /etc/systemd/system/raxis-kernel.service
Status:             Active (running)
PID:                13201
Started at:         2026-05-04T19:54:25-07:00 (uptime: 1h 12m)
Boot-on-startup:    Enabled
Auto-restart:       Enabled (last restart: never since boot)

Capacity summary:
  Disk:             89 GiB free of 1 TiB                           ✓
  Aggregate VM mem: 18 GiB used of 96 GiB                          ✓
  Active sessions:  7
  Queued intents:   0
  Disk-full state:  Healthy

Recent operator-attention events (last 24h): none

Recent log lines (last 5):
  ...
```

### 11.6 Uninstalling

```bash
$ raxis kernel stop
$ raxis kernel uninstall
Uninstalling user-level systemd service...
  ✓ Disabled service
  ✓ Removed ~/.config/systemd/user/raxis-kernel.service
  ✓ Reloaded systemd user daemon

NOTE: data files (audit logs, worktrees, SQLite state) at
~/.local/share/raxis are unchanged. To purge entirely:
  rm -rf ~/.local/share/raxis ~/.config/raxis

NOTE: lingering remains enabled. To disable:
  loginctl disable-linger $USER
```

---

## 12. Invariants

### INV-LIFECYCLE-01 — Daemonization requires explicit operator opt-in

The kernel runs in foreground unless explicitly invoked with `--daemon` or `--foreground-supervised`. There is no implicit daemonization; no mode where running `raxis kernel start` silently puts the kernel in the background.

**Where:** §2 architecture; §3.2 flag semantics.

**Scenario it prevents:** An operator running `raxis kernel start` interactively expects to see logs in their terminal and to terminate with ^C. If the kernel silently daemonized, the operator would close their terminal believing the kernel had stopped — but it would keep running, possibly committing changes the operator did not realize were happening.

### INV-LIFECYCLE-02 — Single instance per `RAXIS_HOME`

At most one kernel process may run against a given `RAXIS_HOME` at a time, enforced via SQLite write lock and supplementary PID file. A second instance attempting to start while the first is alive returns `FAIL_KERNEL_ALREADY_RUNNING`.

**Where:** §8.1 SQLite lock; §8.2 PID file; §8.3 dual-mechanism rationale.

**Scenario it prevents:** An operator runs `raxis kernel start --daemon` in one shell and then `raxis kernel start --daemon` again in another (perhaps not knowing the first succeeded). Without single-instance enforcement, two kernel processes would compete for the same SQLite database — concurrent writes, potential WAL corruption, double-processing of in-flight intents, audit chain breaks. INV-LIFECYCLE-02 makes the second invocation fail loudly.

### INV-LIFECYCLE-03 — Daemonization uses native platform supervisor

V2 daemonization uses `systemd` (Linux) or `launchd` (macOS). The kernel does not implement its own daemon supervisor (no custom `fork()`, no Rust-based restart loop). Cross-platform supervisor abstraction is V3+.

**Where:** §2 architecture; §15.2 design rationale.

**Scenario it prevents:** A subtly buggy custom daemon supervisor would mishandle one of the many edge cases (zombie reaping, log redirection, signal propagation, terminal control, restart backoff). systemd and launchd have decades of operational maturity handling exactly these. Building a competing supervisor would be re-implementing OS-vendor functionality with worse battle-testing.

### INV-LIFECYCLE-04 — Graceful shutdown on SIGTERM with bounded grace period

On SIGTERM, the kernel runs the §7.1 graceful-shutdown protocol within `TimeoutStopSec` (default 30s). After the grace period, the supervisor sends SIGKILL; the kernel's startup recovery on next start handles any uncommitted state per `integration-merge.md §11.3`.

**Where:** §7.1 graceful shutdown; cross-references `key-revocation.md §7.2` for `Graceful` semantics.

**Scenario it prevents:** A SIGKILL on the kernel mid-write to SQLite or mid-finalization of an audit segment could leave inconsistent state. The bounded grace period gives the kernel a chance to flush all in-flight work cleanly. The recovery protocol handles the worst case (SIGKILL during shutdown), so operators are never stuck with unrecoverable state — but the grace period minimizes how often recovery is needed.

### INV-LIFECYCLE-05 — Service-status visibility regardless of mode

`raxis kernel status` returns accurate state (running/stopped/crashed/failed) and PID for both foreground and daemon modes. The CLI does not require knowing the mode in advance to query status.

**Where:** §3.3 status output format; §11.5 inspection example.

**Scenario it prevents:** Operators inheriting a deployment from a colleague should be able to discover what's running with one command, regardless of how the previous operator started it. Mode-aware status commands (`raxis kernel daemon-status` vs `raxis kernel foreground-status`) would force operators to know the mode in advance, defeating the purpose.

### INV-LIFECYCLE-06 — Lifecycle state changes are audit-recorded

Every service install, uninstall, start, stop, reload, and crash recovery emits a corresponding audit event per §10.1. Operators investigating an incident can reconstruct the full operational timeline from the audit log.

**Where:** §10.1 audit event schemas.

**Scenario it prevents:** A kernel that started, ran for an hour, crashed, restarted, and crashed again leaves a trail in journald or `/var/log/raxis/kernel.err`, but those logs are operational telemetry that may be rotated or lost. The audit log is forensic — it persists per `audit-retention` semantics. INV-LIFECYCLE-06 ensures that the operational lifecycle is forensically reconstructable even after journald rotates and the launchd logs are gone.

### INV-LIFECYCLE-07 — System-mode install requires root; user-mode does not

`--system` operations (install, uninstall, start, stop) require `EUID == 0`. Without it, the CLI fails with `FAIL_REQUIRES_SUDO` and a helpful message. User-mode operations never require root.

**Where:** §9 privilege model.

**Scenario it prevents:** A user attempting `raxis kernel install --system` without sudo would silently fall back to user-mode (or fail in confusing ways during `systemctl daemon-reload`). The explicit check produces a clear error pointing at the missing `sudo`.

---

## 13. Implementation Checklist

### CLI surface (`crates/cli/src/commands/kernel/`)

- [ ] `crates/cli/src/commands/kernel/start.rs`: handle `--daemon`, `--system`, `--no-install`, `--foreground-supervised` flags; dispatch to install + supervisor commands accordingly
- [ ] `crates/cli/src/commands/kernel/stop.rs`: detect mode via SQLite lock; send SIGTERM appropriate for mode (supervisor command for daemon; direct kill for foreground via PID file)
- [ ] `crates/cli/src/commands/kernel/restart.rs`: stop + start; preserve mode
- [ ] `crates/cli/src/commands/kernel/reload.rs`: send SIGHUP to running kernel via PID file
- [ ] `crates/cli/src/commands/kernel/status.rs`: query SQLite lock + supervisor + log tail for unified status output (§3.3)
- [ ] `crates/cli/src/commands/kernel/logs.rs`: dispatch to `journalctl --user` (Linux user), `journalctl` (Linux system), `tail -F` (macOS); supports `--follow`, `--since`, `--grep`
- [ ] `crates/cli/src/commands/kernel/install.rs`: write service file; reload supervisor; enable for boot
- [ ] `crates/cli/src/commands/kernel/uninstall.rs`: disable; remove service file; reload supervisor

### Service file generation (`crates/cli/src/service/`)

- [ ] `crates/cli/src/service/systemd.rs`: generate user and system unit files from template; substitutions for paths, env vars, resource limits
- [ ] `crates/cli/src/service/launchd.rs`: generate user and system plists from template; substitutions for paths, env vars
- [ ] `crates/cli/src/service/platform_detect.rs`: detect host OS (Linux + systemd, macOS + launchd, anything else → unsupported)
- [ ] `crates/cli/src/service/sudo_check.rs`: verify EUID for `--system` operations; emit `FAIL_REQUIRES_SUDO` with helpful error otherwise

### Kernel-side changes (`kernel/src/lifecycle/`)

- [ ] `kernel/src/lifecycle/foreground.rs`: ^C handling with pretty UX; SIGINT-twice → abort
- [ ] `kernel/src/lifecycle/supervised.rs`: `--foreground-supervised` mode; sd_notify integration on Linux; structured log output suitable for journald
- [ ] `kernel/src/lifecycle/instance_lock.rs`: SQLite-backed single-instance lock per §8.1; PID file per §8.2; mismatch detection
- [ ] `kernel/src/lifecycle/shutdown.rs`: graceful-shutdown protocol per §7.1; bounded by configurable timeout (default 30s, capped by supervisor's `TimeoutStopSec`)
- [ ] `kernel/src/lifecycle/recovery.rs`: startup recovery logic that detects "this is a restart after crash" and emits `KernelCrashRecovered` audit event
- [ ] `kernel/src/lifecycle/sighup.rs`: SIGHUP handler that re-reads policy.toml; coordinates with `policy-epoch-diffing.md` for atomic epoch advance

### Audit events (in `crates/audit/src/event.rs`)

- [ ] `KernelStarted { mode, pid, version, hostname, started_at_ms, cli_invocation }`
- [ ] `KernelStopping { reason, initiated_at_ms, in_flight_sessions, in_flight_merges }`
- [ ] `KernelStopped { exit_code, duration_ms, graceful_shutdown_ms, stopped_at_ms }`
- [ ] `KernelCrashRecovered { previous_pid, previous_started_at_ms, recovery_actions_taken, recovered_at_ms }`
- [ ] `KernelReloaded { previous_policy_epoch, new_policy_epoch, reloaded_at_ms }`
- [ ] `KernelReloadFailed { error_kind, error_message, failed_at_ms }`
- [ ] `ServiceInstalled { mode, service_path, installed_at_ms }`
- [ ] `ServiceUninstalled { mode, service_path, uninstalled_at_ms }`
- [ ] `OperatorAttentionRequired` extended with `kind ∈ {RecoveryLoopDetected, ServiceUnitTampered}`
- [ ] `SecurityViolation` extended with `kind ∈ {PidFileSqliteMismatch}`

### Schema additions

- [ ] `kernel_instance_lock` table per §8.1; UNIQUE constraint on `instance_id` enforces single row

### Tests

- [ ] Foreground happy path: `raxis kernel start`; verify blocks shell; verify ^C produces graceful shutdown within 30s; verify exit 0
- [ ] Foreground status: while running, `raxis kernel status` reports Mode=Foreground, correct PID
- [ ] Daemon install (Linux user): `raxis kernel start --daemon`; verify `~/.config/systemd/user/raxis-kernel.service` exists with expected content; verify `systemctl --user is-active` returns active; verify `loginctl show-user` reports linger=yes
- [ ] Daemon install (macOS user): `raxis kernel start --daemon`; verify plist exists at `~/Library/LaunchAgents/dev.raxis.kernel.plist`; verify `launchctl print` shows the service running
- [ ] Daemon install (system mode): `sudo raxis kernel start --daemon --system`; verify system user created; verify system-level service file exists; verify service active
- [ ] Daemon install without sudo: `raxis kernel start --daemon --system`; verify `FAIL_REQUIRES_SUDO`; verify error message points at sudo
- [ ] Restart preserves mode: install daemon; `raxis kernel restart`; verify still in daemon mode after
- [ ] Stop in daemon mode: `raxis kernel stop`; verify supervisor reports inactive; verify SQLite lock cleared; verify exit code 0
- [ ] Auto-restart on crash: kill -SEGV the daemon kernel; verify supervisor restarts within RestartSec; verify new instance emits `KernelCrashRecovered` audit event
- [ ] Crash-loop limit: stub kernel to crash on startup 6 times rapidly; verify supervisor stops attempting restarts after StartLimitBurst; verify `Failed` state
- [ ] Recovery loop detection: stub kernel to crash repeatedly during recovery; verify on 4th attempt the kernel itself emits `FAIL_RECOVERY_LOOP_DETECTED`
- [ ] Single-instance: start kernel; attempt second `raxis kernel start --daemon`; verify `FAIL_KERNEL_ALREADY_RUNNING` with first instance's PID
- [ ] Single-instance after crash: SIGKILL the running kernel (no graceful shutdown); start new instance; verify new instance acquires lock cleanly (detects stale row via dead PID)
- [ ] Status when not running: `raxis kernel status` reports Mode=Not Running, last started/stopped times
- [ ] Status when running foreground: `raxis kernel status` reports Mode=Foreground, owning terminal
- [ ] Status when running daemon: `raxis kernel status` reports Mode=Daemon (user|system), service path, supervisor state
- [ ] Logs in foreground: `raxis kernel logs` tails stdout/stderr from owning terminal (or `/dev/null` if none)
- [ ] Logs in daemon (Linux): `raxis kernel logs --follow` invokes `journalctl --user -u raxis-kernel -f`
- [ ] Logs in daemon (macOS): `raxis kernel logs --follow` tails `~/Library/Logs/raxis/kernel.{out,err}`
- [ ] Reload happy path: `raxis kernel reload`; verify SIGHUP delivered; verify `KernelReloaded` audit event with epoch advance
- [ ] Reload with invalid policy: stub policy.toml with invalid syntax; `raxis kernel reload`; verify `KernelReloadFailed` audit event; verify kernel continues running with old policy
- [ ] Uninstall: install service; `raxis kernel uninstall`; verify service file removed; verify supervisor reports service no longer present; verify data files at `RAXIS_HOME` are NOT removed
- [ ] Lingering: install user daemon on Linux; verify lingering enabled; uninstall; verify lingering left enabled (operator's responsibility to disable if desired)
- [ ] PID file: while running, verify `RAXIS_HOME/raxis-kernel.pid` exists with correct PID; on graceful stop, verify PID file removed; on SIGKILL, verify PID file orphaned
- [ ] PID file mismatch: stub PID file to point to a different PID than SQLite lock says; verify `SecurityViolation { PidFileSqliteMismatch }`; verify kernel halts startup
- [ ] Boot-on-login (Linux): install daemon; reboot host (or simulate via `systemctl --user stop` + `systemctl --user start`); verify kernel restarts on next login
- [ ] Boot-on-startup (Linux system): install system daemon; reboot; verify kernel running before any user logs in
- [ ] Boot-on-login (macOS): install user daemon; logout + login (or simulate via `launchctl bootout` + `launchctl bootstrap`); verify kernel restarts

---

## 14. Foundational Design Decisions

This section records the seven foundational commitments the kernel-lifecycle architecture is built on. Each entry follows the host-capacity.md §15 structure: **the decision**, **the alternative considered**, **why we rejected it**, and **the scenario the rejection prevents**.

### §14.1 — Foreground default; daemonization is opt-in via `--daemon`

**Decision.** Without flags, `raxis kernel start` runs in the foreground, blocks the operator's shell, prints logs to stdout, and stops on ^C. The `--daemon` flag opts into background operation with boot-on-login.

**Considered alternative.** Make daemon the default; `--foreground` opts into shell-bound operation.

**Rejected because.** Three problems with daemon-default:

1. **Hostile to first-time users.** A new operator running `raxis kernel start` to "see if it works" expects to see output and stop with ^C. Daemonizing silently leaves them confused about whether anything happened, and worse — the kernel is now running in a state they don't realize, possibly making changes they don't know about.
2. **Hostile to development.** Developers iterating on kernel changes want immediate log feedback. Daemon-default forces an extra `--foreground` flag for every dev-loop invocation.
3. **Hostile to CI.** Continuous-integration systems run the kernel for the duration of a test job and expect it to exit when the job ends. Daemon-default would leak background processes across CI jobs.

The opposite asymmetry (foreground-default + opt-in daemon) is the standard pattern for tools that have both modes (`postgres`, `redis-server`, `nginx -g 'daemon off;'` for foreground). The flag's name (`--daemon`) is also self-documenting in shell history; an operator who used `--daemon` once knows what they did.

**Scenario it prevents.** A new operator runs `raxis kernel start` in a tutorial, sees no output (because the kernel daemonized), assumes nothing worked, and runs it again. Now there are two kernel processes (caught by INV-LIFECYCLE-02, but the user gets confused). The opposite path — `raxis kernel start` shows logs in the terminal, confirms the operator can see output, and they then learn about `--daemon` later — is strictly more discoverable.

### §14.2 — Native platform supervisors over a custom Rust daemon supervisor

**Decision.** Daemon mode delegates to systemd (Linux) or launchd (macOS). The kernel binary itself does not fork-and-detach, manage logs, or implement restart logic.

**Considered alternative.** A `raxis-kernel-supervisor` binary that watches the kernel process, restarts it on crash, redirects logs, manages the PID file, etc.

**Rejected because.** Re-implements OS-vendor functionality with strictly worse battle-testing. systemd has been the standard Linux init system for over a decade; launchd has shipped on every Mac since 10.4. They handle:

- Zombie reaping (the supervisor must `wait()` on the child or the kernel becomes a zombie on exit).
- Signal propagation (SIGTERM from the supervisor must reach the supervised process; SIGCHLD from the supervised process must wake the supervisor).
- Log rotation, reopening on SIGUSR1, journald integration, etc.
- Restart backoff with cooldown windows.
- Boot-time integration (when does our service start? after network? after dbus? before user login?).
- Resource-limit enforcement (RLIMIT_NOFILE, MemoryMax, etc.).

Each of those is its own subtle subsystem. A custom supervisor would have to get all of them right, and any bug in any of them is a production-grade reliability problem. Using the platform supervisor inherits decades of bug fixes for free.

The downside of the platform-supervisor approach — an additional install step (writing the service file, reloading the supervisor) — is genuinely small and is the operator-facing benefit (their existing tooling for monitoring services, reading logs, etc., works seamlessly).

**Scenario it prevents.** A custom Rust supervisor has a bug where it doesn't handle SIGCHLD correctly on macOS, leaving zombie kernel processes accumulating across restarts. Operators investigating "why does my system have 47 raxis-kernel zombies?" become very unhappy. systemd/launchd handle this correctly because they've been handling exactly this case for thousands of services for years.

### §14.3 — User-level service is the default; system-level requires `--system`

**Decision.** `--daemon` without `--system` installs a user-level service. `--system` requires sudo and installs a system-wide service running as a dedicated `raxis` user.

**Considered alternative A.** System-level by default; `--user` opts into per-user mode.

**Rejected because.** Requires sudo for the most common installation path. Developers, evaluators, and personal-use operators would all hit a "needs root" prompt before they could try the kernel. The user-level path requires no special privileges, runs in the user's existing trust boundary, and works on any account.

**Considered alternative B.** Single mode (user-level only); operators wanting system-wide deployment script their own systemd unit.

**Rejected because.** Production deployments overwhelmingly want system-level installs (boot at machine startup, run as dedicated user, integrate with system-wide monitoring). Forcing operators to write their own unit files re-introduces the fragmentation problem this spec aims to solve.

The chosen approach (user-default + opt-in system) gives both: low-friction first-run experience for evaluators and developers; production-ready system install for operators who need it; clean separation of trust models.

**Scenario it prevents.** A new operator on a managed corporate Mac (where they don't have sudo) runs `raxis kernel start --daemon` and it works without administrative intervention. They can evaluate RAXIS, run a few initiatives, and decide whether to escalate to a sysadmin for a system-wide install. With sudo-required-by-default, they couldn't get past step one.

### §14.4 — Logs go to platform-native destination (journald on Linux, log files on macOS)

**Decision.** In daemon mode, stdout/stderr go to the platform's native logging system: journald on Linux, plain log files on macOS (with newsyslog for rotation).

**Considered alternative A.** Always-file-based logging (kernel manages its own log files, regardless of platform).

**Rejected because.** Defeats half the value of using the platform supervisor. journald-aware operators expect `journalctl -u raxis-kernel` to work; macOS-aware operators expect log files in `~/Library/Logs/`. Forcing a custom location means operators have to learn RAXIS-specific log paths and tools.

**Considered alternative B.** Always-journald-via-network-shipping (use a pluggable log destination configurable per deployment).

**Rejected because.** Adds significant complexity for a feature that's already well-served by platform supervisors plus the operator's existing log shipper (vector, fluentd, etc.). The `raxis kernel logs` command is a thin wrapper that delegates to the platform tool; operators who want centralized aggregation point their existing log shipper at the platform's log destination.

The kernel's audit log (the cryptographic record of state changes) is separately specified in `host-capacity.md §6.3` and `audit-retention` (V3) and is unaffected by this choice — audit logs always go to `RAXIS_HOME/audit/` regardless of operational log destination.

**Scenario it prevents.** An operator runs `journalctl -u raxis-kernel` on their Linux production host and sees "No entries." With custom log destinations, they would have to look up the RAXIS-specific path. With journald integration, the kernel "just works" with the operator's existing observability tooling.

### §14.5 — `--foreground-supervised` is a distinct flag from `--daemon` for supervisor invocation

**Decision.** When the systemd unit or launchd plist invokes the kernel, it uses `raxis kernel start --foreground-supervised`, not `--daemon`. The `--daemon` flag is only used by operators at the CLI layer; the supervisor sees the kernel running in (its own version of) foreground.

**Considered alternative.** A single `--daemon` flag that the supervisor and the operator both use.

**Rejected because.** The two contexts have different requirements:

- **Operator-invoked `--daemon`:** must install the service file, configure boot-at-login, start the supervisor's service, return to the shell.
- **Supervisor-invoked:** must run in foreground (the supervisor handles detach), use sd_notify for readiness signaling, omit pretty terminal UX, write structured logs.

A single flag with branching internal logic ("am I being invoked by a supervisor?") is fragile — what if systemd one day starts providing a different env var for supervisor-detection? The explicit `--foreground-supervised` flag makes the supervisor-context invocation unambiguous and prevents any path where operator-mode and supervisor-mode behavior could conflate.

**Scenario it prevents.** A developer testing the kernel runs `RUST_LOG=trace raxis kernel start --daemon` to see verbose daemon-mode behavior in their terminal. With a single flag, the kernel might detect "no supervisor present" and fall back to fork-and-detach, breaking their debugging workflow. With explicit `--foreground-supervised`, the only path that runs that code is the supervisor's invocation; developer-mode invocations always behave as the developer intends.

### §14.6 — Single-instance enforcement via SQLite lock + PID file

**Decision.** A SQLite-backed `kernel_instance_lock` table is the source of truth; a complementary `RAXIS_HOME/raxis-kernel.pid` file provides standard-tooling discoverability. Both are checked on startup; a mismatch halts the kernel.

**Considered alternative A.** PID file only.

**Rejected because.** PID files are fragile: stale PID files after crash require liveness checks (which can race); operators editing them by hand can confuse the kernel; cross-platform PID-liveness checks have subtle differences. The SQLite lock is atomic, transactional, and database-native (SQLite handles the "is this row from a dead process?" question with machinery the kernel already depends on).

**Considered alternative B.** SQLite lock only.

**Rejected because.** Standard tools (`pgrep`, monitoring agents, supervisor health checks) expect a PID file. Omitting it breaks integration with the operator's existing process-management tooling.

The chosen dual-mechanism approach gives both: cryptographic-grade single-instance enforcement (SQLite) plus operator-tool compatibility (PID file). The mismatch detection is a defense against tampering — if both exist but disagree, something is wrong, and the kernel halts rather than risk operating with confused identity.

**Scenario it prevents.** An operator's monitoring agent reads `raxis-kernel.pid` to check if the kernel is alive. With PID-only enforcement, the file might be stale after a crash; the monitor reports "alive" (PID exists) when the kernel is actually dead. With SQLite-lock-only enforcement, the monitor has no PID file to check and either has to invent its own discovery mechanism or use `ps`-based heuristics. The dual mechanism makes the operator's monitoring "just work" while preserving correctness.

### §14.7 — Lifecycle audit events captured to forensic log, not just operational telemetry

**Decision.** Every kernel start, stop, reload, crash recovery, install, and uninstall is recorded as an audit event in the cryptographically-chained audit log. journald or `kernel.err` files are operational telemetry only; the audit log is the forensic record.

**Considered alternative.** Lifecycle events go only to journald/log files. Skip writing them to the audit log to avoid coupling lifecycle to audit-write availability.

**Rejected because.** journald rotates on a configurable schedule (typically days); operational log files can be lost, rotated, or deleted by operators. The audit log persists per `audit-retention` semantics (months to years, with archive). When investigating a six-month-old incident, the operator wants to know "did the kernel restart at 14:32 that day?" — that question is unanswerable from rotated journald entries but trivially answered from the audit log.

The "coupling lifecycle to audit-write availability" concern is real but bounded: if the audit log is unwritable (`AuditWriteImpossible` per `host-capacity.md §7.6`), the kernel halts entirely anyway. So the lifecycle audit events follow the same fate as every other state change — they go in or the kernel stops.

The trade-off is correctly weighted: a small additional write per lifecycle transition (negligible cost) for forensic reconstructability that lasts as long as the audit retention policy.

**Scenario it prevents.** An auditor reviewing a regulatory incident asks "the kernel was running on the day of the incident, right?" Without lifecycle audit events, the only proof is journald entries that may have rotated months ago. With INV-LIFECYCLE-06, the audit log itself records `KernelStarted` and `KernelStopped` events that survive in the long-term retention archive.

---

## 15. Alternatives Considered and Rejected

### Alt A — Custom Rust daemon supervisor (`raxis-kernel-supervisor`)

Build a separate supervisor binary that watches the kernel process and handles all daemon concerns in-process. Rejected per §14.2: re-implements systemd/launchd functionality with worse battle-testing.

### Alt B — Always-daemon mode (no foreground)

Make the kernel always daemonize; remove `raxis kernel start` foreground behavior. Rejected per §14.1: hostile to first-time users, developers, and CI.

### Alt C — In-kernel `fork()`-and-detach

Implement daemonization inside the kernel binary using `fork(2)` and standard daemon-process patterns (close stdin/stdout/stderr, chdir to /, etc.). Rejected per §14.2: signal handling, log redirection, terminal control, and zombie reaping are well-known sharp edges. The platform supervisor handles all of them.

### Alt D — System-level by default

Make `raxis kernel start --daemon` install a system-wide service by default; require `--user` for per-user installs. Rejected per §14.3: requires sudo for the most common installation path, hostile to evaluators.

### Alt E — Docker container as the deployment unit

Ship `raxis-kernel` as a container image; daemonization is "run the container." Rejected: incompatible with the kernel's hypervisor requirements (Firecracker microVMs or Apple Virtualization.framework do not nest inside containers without privileged-host configurations that defeat container isolation). Also explicitly rejected by user requirements ("without having it in shell like docker").

### Alt F — Logs to stderr only (rely on supervisor to capture)

Don't try to be journald-aware or platform-aware; just write to stderr and let the supervisor figure it out. Rejected: works fine for systemd (journald captures stderr) but produces unstructured output that loses the structured-fields advantage of journald's native format. The Type=notify + structured-output approach gives operators much better journalctl filtering (`journalctl -u raxis-kernel _EVENT_KIND=IntegrationMerge`).

### Alt G — Start service WITHOUT enabling boot-on-login

Make `--daemon` start in the background without registering for boot-on-login; require a separate `--enable-boot` for that. Rejected: the common case for `--daemon` is "I want this running all the time." Requiring two flags for the common case is friction. Operators who want session-only background can use `--no-install` per §3.2.

### Alt H — Auto-detect supervisor from environment

Look at `XDG_RUNTIME_DIR`, `INVOCATION_ID`, etc. to detect "I'm being invoked by systemd" and switch behavior accordingly, without needing `--foreground-supervised`. Rejected per §14.5: env-var-based detection is fragile and can produce surprising behavior in unrelated contexts (CI runners, dev shells with similar env vars). Explicit flag is unambiguous.

### Alt I — Multiple kernel instances per RAXIS_HOME (with sharded state)

Allow multiple kernels per `RAXIS_HOME` by sharding SQLite, audit, and worktrees by instance ID. Rejected: the kernel is a singleton control plane by design; multi-instance would require fundamental rework of every spec that assumes single-kernel state. Operators wanting multi-instance can run separate `RAXIS_HOME` directories (e.g., `~/.local/share/raxis-prod`, `~/.local/share/raxis-dev`).

### Alt J — Restart-on-config-change

Auto-restart the kernel when `policy.toml` changes on disk (via inotify/FSEvents). Rejected: SIGHUP-based reload (§7.2) is non-disruptive; restart-on-change would interrupt in-flight work for changes that don't need it. Operators wanting auto-reload can configure their own filesystem-watcher to invoke `raxis kernel reload`.

### Alt K — Lifecycle commands as separate binary (`raxis-kernel-ctl`)

Split the lifecycle CLI into a separate binary like `kubectl` is separate from `kube-apiserver`. Rejected for V2: adds complexity (two binaries to install, version-pin, etc.) for marginal benefit. The existing `raxis` CLI already dispatches to many subcommands (`raxis init`, `raxis approve-plan`, etc.); adding `raxis kernel <subcommand>` follows the existing pattern. V3+ may revisit if the kernel-lifecycle subcommand surface grows large enough to warrant separation.

### Alt L — `service` integration on Linux (sysv-init compatibility shim)

Provide a `/etc/init.d/raxis-kernel` script in addition to systemd unit. Rejected: sysv-init is deprecated on every modern Linux distribution; supporting it adds maintenance burden for a vanishing user base. Operators on legacy systems can write their own init script against the documented foreground-supervised invocation.

### Alt M — `--detach` flag instead of `--daemon`

Use `--detach` (the Docker convention) as the flag name. Rejected: `--daemon` more accurately describes the resulting state (a long-lived background service registered with the OS), and is the convention used by `postgres`, `redis-server`, `mysqld`, `dhcpd`, and most other long-running services. `--detach` suggests a one-shot detachment without the registration aspect.

### Alt N — Allow `--daemon` to take a value (`--daemon=session|persistent|system`)

Use a single flag with a value rather than `--daemon` + `--system` + `--no-install`. Rejected: three discrete behaviors with three discrete use cases is well-served by three discrete flags. Combined-value flags add cognitive load when reading shell history (`--daemon=persistent` is less self-documenting than `--daemon` alone).
