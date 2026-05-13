# Run Raxis under the self-healing supervisor

> **Topic:** Operations | **Time to read:** ~6 min | **Complexity:** ⭐⭐ Intermediate

`raxis-supervisor` is an opt-in wrapper around `raxis-kernel`
that detects deadlocks, panics, and OOM kills, then auto-restarts
the kernel with a circuit breaker so a buggy kernel cannot loop
forever. The dashboard shows the operator a banner during
restarts. Operator-initiated `SIGTERM`/`SIGINT`/`SIGKILL`/`SIGHUP`
are always respected — the supervisor never overrides operator
intent.

This recipe covers the four operator-facing surfaces:
opt-in, status query, manual stop, and JWT-secret rotation.

---

## When to use the supervisor

- You want the kernel to survive transient bugs (deadlock, panic,
  OOM) without a manual restart.
- You want the dashboard to show the operator that a restart is
  in flight (rather than the dashboard appearing to hang).
- You are running Raxis as a long-lived service (not a CLI tool
  that you `Ctrl-C` after one initiative).

You do NOT need the supervisor for:

- Live-e2e harness runs — the harness MUST NOT set
  `RAXIS_SUPERVISOR_AUTO_RESTART=1`; it relies on the kernel's
  exit code as the test verdict.
- One-shot CLI ceremonies — `raxis cert mint-emergency`,
  `raxis log verify-chain`, etc. all run inside `raxis-supervisor`
  pass-through mode (no auto-restart, no sentinel writes) when
  the env var is unset.

---

## 1. Opt in

```bash
export RAXIS_SUPERVISOR_AUTO_RESTART=1
raxis-supervisor start
# ... or under systemd: set Environment= in your unit file
```

Without the env var, `raxis-supervisor` runs the kernel exactly
once with no sentinel file, no circuit-breaker state, and no
auto-restart — bit-identical to `raxis-kernel` directly. With
the env var, the supervisor:

1. Spawns `raxis-kernel` as a child process.
2. Writes `<data_dir>/kernel_lifecycle_status.json` (the
   sentinel file) at every state transition.
3. On unclean exit (deadlock = exit 70, panic = exit 101+,
   crash signal, OOM kill), classifies the cause and decides
   whether to restart.
4. Tracks attempts in a sliding window
   (`<data_dir>/supervisor_state.json`) — default 3 attempts in
   60 s. After the 3rd failure, the breaker opens and the
   supervisor halts.

Cross-reference: `INV-SUPERVISOR-OPT-IN-01`,
`INV-SUPERVISOR-CIRCUIT-BREAKER-01`.

---

## 2. Check status

```bash
raxis-supervisor status
# {
#   "status": "Healthy",
#   "supervisor_pid": 12345,
#   "kernel_pid": 12346,
#   "attempt_n": 0,
#   "max_attempts": 3,
#   "window_secs": 60,
#   "last_restart_unix_ts": 0,
#   "last_restart_reason": null,
#   "updated_at_unix_secs": 1779912345,
#   "fresh": true
# }
```

The same data is served to the dashboard at
`GET /api/health/kernel-lifecycle` and rendered in the global
`<KernelLifecycleBanner>`. When the banner reads:

- **(no banner)** — Healthy, supervisor in play, nothing to do.
- **amber `Kernel restarting (1/3) — DeadlockDetected`** —
  supervisor is mid-restart; operator action: wait ~2 s for the
  banner to clear.
- **rose `Kernel halted — restart circuit OPEN`** — supervisor
  gave up after 3 failures in 60 s; operator action: investigate
  the underlying bug, then run `raxis-supervisor reset-circuit-breaker`
  followed by `raxis-supervisor start` (see step 4).
- **rose `Supervisor process gone`** — the supervisor itself
  died but its sentinel is stale; operator action: check
  `<data_dir>/supervisor.stderr.log` and re-launch
  `raxis-supervisor start`.

---

## 3. Stop the kernel

```bash
raxis-supervisor stop
# ... or:
kill -TERM <supervisor_pid>
```

Either form respects the operator-signal contract
(`INV-SUPERVISOR-SIGTERM-RESPECT-01`):

1. Supervisor sets its `IntentionalShutdownFlag` so the next
   exit classification knows the SIGTERM came from us.
2. Forwards SIGTERM to the kernel child.
3. Waits up to `RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS` (default
   30 s) for graceful exit. If the kernel honours it ⇒ sentinel
   becomes `Halted{OperatorStop}` and the supervisor exits 0.
4. If the kernel ignores SIGTERM past the grace, the supervisor
   escalates to SIGKILL (`INV-SUPERVISOR-SHUTDOWN-GRACE-01`),
   sentinel becomes `Halted{OperatorStopForced}`, supervisor
   exits 0.

In neither case will the supervisor restart the kernel — operator
intent overrides every recovery path.

---

## 4. Reset the circuit breaker after investigating

After a `Halted{CircuitOpen}` halt, you investigate the root
cause (`<data_dir>/deadlock_dump_*.json` for deadlocks, the
audit chain for `KernelDeadlockDetected` /
`KernelRestartHaltedCircuitOpen` rows) and ship a fix. Then:

```bash
raxis-supervisor reset-circuit-breaker
# Resets <data_dir>/supervisor_state.json
raxis-supervisor start
```

The breaker file is the only state the supervisor persists
across restarts — the audit chain and the sentinel file are
not affected by the reset.

---

## 5. Rotate the dashboard JWT signing secret

The dashboard's HS256 signing secret lives at
`<data_dir>/auth/dashboard_jwt.secret` (`0600`, auth dir
`0700`). It is minted on first kernel boot and reloaded on
every subsequent boot — including supervisor-triggered
restarts — so operator JWTs survive deadlock recovery
(`INV-SUPERVISOR-OPERATOR-CONTINUITY-01`).

If you suspect the secret has been compromised (e.g. an
attacker may have read `<data_dir>`), rotate the secret to
invalidate every issued JWT in one command:

```bash
raxis dashboard rotate-jwt-secret
# ✓ rotated dashboard JWT signing secret
# generation:  2
# path:        /var/lib/raxis/auth/dashboard_jwt.secret
#
# Every previously-issued operator JWT is now invalid. Operators
# currently logged into the dashboard will be bounced to /login
# on their next request. The running kernel keeps using its
# in-memory secret until it next restarts; restart the kernel
# (or run `raxis-supervisor stop` then `raxis-supervisor start`)
# to make rotation take effect immediately.
```

The CLI is local-fs only; it does not open `operator.sock` and
does not require `--operator-key`. The next kernel boot loads
the rotated secret + new generation; pre-rotation tokens fail
verification because their `gen` claim no longer matches.

For full immediate effect (don't wait for the running kernel
to restart), follow with:

```bash
raxis-supervisor stop && raxis-supervisor start
```

Cross-reference: `INV-DASHBOARD-JWT-SECRET-PERSISTENT-01`,
`specs/v2/self-healing-supervisor.md §10`.

---

## 6. Forensic evidence after a halt

Every supervisor decision lands in three places — collect all
three before re-launching:

| Source | Path | What's there |
|---|---|---|
| Audit chain | `<data_dir>/audit.jsonl` | Hash-chained `KernelDeadlockDetected`, `KernelRestartInitiated`, `KernelRestartCompleted`, `KernelRestartHaltedCircuitOpen` rows. Cross-checks against the supervisor's view. |
| Deadlock dump | `<data_dir>/deadlock_dump_<unix_ts>.json` | Lock-graph + per-thread backtrace. Pending dumps move to `<data_dir>/deadlock_dump_consumed/` after the next kernel boot synthesises the audit row. |
| Supervisor log | `<data_dir>/supervisor.stderr.log` | One JSON-line per supervisor decision (signal received, classification, restart, breaker open). Forensic-only; not consulted by the auth path. |

`raxis log verify-chain` keeps working across restarts — the
chain remains hash-continuous because the new kernel's
`restart_lifecycle::rehydrate_restart_context` synthesises the
restart events from the dump + sentinel under the next monotonic
sequence number.

---

## 7. Disable the supervisor

If you want to drop back to the pre-V2.5 behaviour (no
supervisor, no auto-restart, no sentinel writes), simply
`unset RAXIS_SUPERVISOR_AUTO_RESTART` and re-launch:

```bash
unset RAXIS_SUPERVISOR_AUTO_RESTART
raxis-supervisor start   # passthrough — runs the kernel once
# ... or:
raxis-kernel             # equivalent
```

The dashboard banner stays hidden in this mode (the kernel
handler returns `Healthy { fresh: true, supervisor_pid: 0 }`,
which the banner explicitly suppresses).

---

## See also

- `specs/v2/self-healing-supervisor.md` — design + invariants.
- `specs/v2/dashboard-hardening.md §5.9` — banner contract.
- `guides/recipes/ops/15-incident-postmortem.md` — what to do
  with the forensic evidence.
- `guides/recipes/ops/02-respond-to-key-compromise.md` —
  operator-key compromise (separate from the JWT-secret
  compromise this recipe covers).
