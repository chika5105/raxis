# RAXIS — Environment Variable Inventory (v1)

> **Scope:** Every `RAXIS_*` environment variable consumed by any
> binary in the workspace, who sets it, who reads it, the default
> applied when unset, and the security model that constrains what
> may live in the env block.
>
> **Navigation:** [README](../../README.md) | [Part 2 Store](kernel-store.md) | [Part 3 Peripherals](peripherals.md) | [Part 4 CLI](cli-ceremony.md)
>
> **Authority:** Where this file and another v1 spec disagree on the
> wire shape of a verifier-spawn env var, [`kernel-store.md`](kernel-store.md) §2.5.6
> wins (it is the normative source for the `VerifierSpawnEnvelope`).
> Where this file and [`cli-ceremony.md`](cli-ceremony.md) disagree on operator-facing
> CLI env-var fallbacks, [`cli-ceremony.md`](cli-ceremony.md) wins. This file exists to
> give operators a single page they can grep before reaching for
> any other doc.

---

## §1 — Security model

The env block is **public to the host OS**. Anything you put in it
is visible to:

- `ps eww <pid>` from any process running under the same UID.
- `/proc/<pid>/environ` (Linux) — readable by the same UID.
- Kernel core dumps (Linux), crash reports (macOS), and any
  process-wide memory snapshot.
- Every child process the binary `exec`s without an explicit
  `env_clear()` (the kernel does call `env_clear()` before forking
  verifier subprocesses, but the operator's interactive shell does
  not — every command run from your prompt inherits your full env
  block by default).

Therefore the **non-negotiable** invariant for every `RAXIS_*`
env var documented below is:

> **No env var ever holds secret material.** Every secret-bearing
> env var holds a **path** to a file on disk that itself carries
> the secret. The file is `chmod 600`-able (and SHOULD be); the
> env var is not.

Today's variables that point at secret files (rather than carrying
the secret directly):

| Env var | Points at | Why a path, not bytes |
|---|---|---|
| `RAXIS_OPERATOR_KEY` | Operator's Ed25519 PEM | The PEM file is `chmod 600`. The path can leak via `ps`; the bytes cannot. |
| `RAXIS_OPERATOR_CERT` | `*.cert.toml` | The cert is signed by the operator's offline key — leaking the path discloses the cert's location, not the cert-mint key (which lives air-gapped). |

Variables that carry **secret bytes directly** are restricted to
the kernel→subprocess boundary (verifier, gateway), where the
parent calls `Command::env_clear()` before exec'ing the child so
the secret never lives in any process the operator can see:

| Env var | Lifetime | Audience | Mitigations |
|---|---|---|---|
| `RAXIS_VERIFIER_TOKEN` | One verifier subprocess invocation; consumed on first valid `WitnessSubmission` | Verifier subprocess only | Single-use; `Command::env_clear()` before exec; never written to disk by the kernel. |
| `RAXIS_GATEWAY_TOKEN` | Lifetime of the gateway subprocess | Gateway subprocess only | 32-byte random; `Command::env_clear()` before exec; the kernel verifies it on the first frame and rejects connections without it (`gateway_roundtrip.rs::missing_token_rejected`). |
| `RAXIS_SESSION_TOKEN` | Lifetime of one planner session | Planner subprocess only | Output by `raxis session create --reveal-token` to **stderr** so it can be captured to a `chmod 600` file via `2>session.env`; the CLI prints only a redacted fingerprint to stdout by default. |

Operator workflow rule: **never `export RAXIS_VERIFIER_TOKEN=...`,
`RAXIS_GATEWAY_TOKEN=...`, or `RAXIS_SESSION_TOKEN=...` in your
own shell.** They are populated by the kernel into a child
process's env block via `Command::env(...)` — your interactive
shell has no business holding any of them, and a stray export
would taint every subsequent command's env block.

---

## §2 — Operator-set env vars

These are the env vars an operator may set in their own shell to
control the behavior of `raxis` (the CLI), `raxis-kernel`, or the
genesis ceremony. All have CLI-flag equivalents that take
precedence when both are present.

### `RAXIS_DATA_DIR`

| | |
|---|---|
| **Read by** | `raxis` (CLI) — every subcommand. `raxis-kernel` — process boot. `raxis-gateway` — process boot. |
| **Set by** | Operator (typically once per shell or in a systemd unit). |
| **Default when unset** | `$HOME/.raxis` — see `cli/src/main.rs::run` and `kernel/src/main.rs::data_dir`. If `$HOME` is also unset, falls back to `/root/.raxis` (a safe default for daemonized installs running as root). |
| **CLI flag override** | `--data-dir <path>` (CLI only — the kernel has no flag override; it reads `$RAXIS_DATA_DIR` directly). |
| **Contents** | Absolute path to the kernel's data directory (`policy/`, `keys/`, `kernel.db`, `audit/`, `witness/`, `sockets/`, `runtime/`). See [`kernel-store.md`](kernel-store.md) §2.5.1 for the full subdirectory layout. |
| **Security note** | Path only — never key material. The directory itself is created `0700` by `bootstrap.rs`. |

### `RAXIS_OPERATOR_KEY`

| | |
|---|---|
| **Read by** | `raxis` (CLI) — global flag resolver in `cli/src/main.rs::resolve_operator_key_path`. |
| **Set by** | Operator (typically once per shell, or in a wrapper script). |
| **Default when unset** | `None`. Per-subcommand validation surfaces `usage: --operator-key <path> is required` for any operator-socket command (`plan submit`, `plan approve`, `session create`, etc.). |
| **CLI flag override** | `--operator-key <path>` — the explicit flag **always wins** over the env var, even if the env var is set. The env-lookup is short-circuited (not even read) when the flag is present. See `cli/src/main.rs::operator_key_resolution_tests`. |
| **Contents** | Absolute path to the operator's Ed25519 private-key PEM (the same file consumed by `raxis policy sign --key <path>`). |
| **Security note** | Path only — the PEM file at the path **must** be `chmod 600`. The env var is widely visible (`ps eww`, `/proc/$pid/environ`); the file at the path is not, provided the operator preserves the mode bits. |

### `RAXIS_OPERATOR_CERT`

| | |
|---|---|
| **Read by** | `raxis-kernel` — bootstrap path only (`kernel/src/main.rs::main` when `RAXIS_BOOTSTRAP=1`). |
| **Set by** | Operator (one-shot, usually inline with the bootstrap command itself: `RAXIS_BOOTSTRAP=1 RAXIS_OPERATOR_CERT=/path raxis-kernel`). |
| **Default when unset** | `None`. The bootstrap path treats this as optional — if absent, the kernel-side ceremony is skipped and the operator is expected to have already run `raxis genesis` (the CLI ceremony) which mints the cert in-process. See [`cli-ceremony.md`](cli-ceremony.md) §4.2. |
| **CLI flag override** | None (this is a kernel-side env var — the CLI uses `--operator-cert <path>` on `raxis genesis` instead). |
| **Contents** | Absolute path to a pre-minted `*.cert.toml` (typically produced by `raxis cert mint` on an air-gapped workstation). |
| **Security note** | Path only — the cert file is signed by an offline key the kernel never holds. Cert-mandatory enforcement is `INV-CERT-01` (`specs/invariants.md`). |

### `RAXIS_BOOTSTRAP`

| | |
|---|---|
| **Read by** | `raxis-kernel` — process boot (`kernel/src/main.rs::main`). |
| **Set by** | Operator, exactly once per data-dir lifetime: `RAXIS_BOOTSTRAP=1 raxis-kernel`. |
| **Default when unset** | `None` (kernel runs in normal mode). |
| **CLI flag override** | None. The bootstrap path is intentionally **only** reachable via env var to discourage accidental re-bootstrap of an existing data dir. |
| **Contents** | Any non-empty string (the value is checked with `is_ok()`, not parsed). The convention is `1`. |
| **Behaviour** | Triggers the one-shot first-run ceremony: open `kernel.db`, install the genesis `policy_epoch_history` row, write `audit/segment-000.jsonl` with a `GenesisRecord`, write the four authority/quality/verifier-token/operator keys under `keys/`, then `exit(0)`. The kernel never returns from bootstrap mode — the operator must restart `raxis-kernel` without `RAXIS_BOOTSTRAP` to enter the normal serving loop. |
| **Security note** | When combined with `RAXIS_FORCE=1` (below) on an existing data dir, bootstrap will overwrite. **There is no automatic backup** — the operator is responsible for snapshotting `kernel.db`, `audit/`, `witness/`, and `policy/` before re-bootstrap. |

### `RAXIS_FORCE`

| | |
|---|---|
| **Read by** | `raxis-kernel` — bootstrap path only (`kernel/src/main.rs::main` when `RAXIS_BOOTSTRAP=1`). |
| **Set by** | Operator, only when intentionally re-bootstrapping a data dir that already contains state. |
| **Default when unset** | `None` (bootstrap refuses to overwrite an existing `kernel.db` / `audit/segment-000.jsonl`). |
| **CLI flag override** | None. The CLI exposes `--force` on `raxis genesis` for the same purpose; there is no CLI flag on `raxis-kernel` itself. |
| **Contents** | Any non-empty string. |
| **Behaviour** | Allows bootstrap to overwrite an existing data dir. Used by integration tests (`kernel_signal_shutdown.rs`) and operators who deliberately want to reset a demo install. **Never** set this in a production startup script — a transient `RAXIS_BOOTSTRAP=1` left in the environment combined with `RAXIS_FORCE=1` would silently destroy the audit chain. |

### `RAXIS_VCS_TIMEOUT_SECS`

| | |
|---|---|
| **Read by** | `raxis-kernel` — `kernel/src/vcs/diff.rs::vcs_timeout`. |
| **Set by** | Operator, optionally, when the kernel's git operations need a longer (or shorter) deadline than the 30s default. |
| **Default when unset** | `30` seconds. |
| **Hard cap** | `120` seconds — values higher than this are clamped down silently. |
| **Contents** | Decimal integer string (parsed with `u64::parse`). Non-numeric or zero values fall back to the default. |
| **Use case** | Repos with very large `git diff` outputs, slow shared filesystems, or CI environments with constrained CPU. The hard cap exists so a misconfigured value can never wedge the kernel indefinitely. |

---

## §3 — Kernel→subprocess env vars (you should never set these yourself)

These env vars are populated by `raxis-kernel` into the env block
of a child process it `exec`s. The kernel uses `Command::env_clear()`
before adding them, so the child inherits **only** what the kernel
puts in. Operators setting any of these in their own shell would
have **no effect** on the kernel's spawn behavior — they are
documented here only so you can recognize them in `ps`, audit
logs, and the integration test suite.

### Verifier subprocess (`VerifierSpawnEnvelope`)

Normative source: [`kernel-store.md`](kernel-store.md) §2.5.6 (this is a one-line
pointer back; the full table lives there).

| Env var | Audience | Notes |
|---|---|---|
| `RAXIS_VERIFIER_TOKEN` | Verifier | 32 bytes hex; single-use; consumed on first valid `WitnessSubmission`. |
| `RAXIS_TASK_ID` | Verifier | `task_id` of the task being evaluated. |
| `RAXIS_EVALUATION_SHA` | Verifier | Commit SHA the witness must be bound to. |
| `RAXIS_WORKTREE_ROOT` | Verifier | Working directory for the evaluation (the planner session's worktree). |
| `RAXIS_KERNEL_SOCKET` | Verifier | UDS path to submit `WitnessSubmission` to. |
| `RAXIS_GATE_TYPE` | Verifier | `GateType` variant string (e.g. `TestCoverage`). |
| `RAXIS_INITIATIVE_ID` | Verifier | Logging context only — must NOT be used for auth decisions. |

### Gateway subprocess

Normative source: [`peripherals.md`](peripherals.md) §gateway and `gateway/src/lib.rs`.

| Env var | Audience | Notes |
|---|---|---|
| `RAXIS_GATEWAY_TOKEN` | Gateway | 32 bytes hex. Echoed back on the first frame; mismatch → connection rejected. |
| `RAXIS_GATEWAY_SOCKET` | Gateway | UDS path the gateway opens for inbound kernel→gateway calls. |
| `RAXIS_GATEWAY_BACKEND` | Gateway | `mock` or `http`. v1 ships `mock` only; `http` falls back to `mock` with a warning. |
| `RAXIS_DATA_DIR` | Gateway | Inherited from the kernel for log-path / config resolution. |
| `PATH` | Gateway | Inherited from the kernel so the gateway can `exec` helper binaries. |
| `HOME` | Gateway | Inherited so any embedded HTTP client can find user-config files (e.g. `~/.netrc`). |

### Session token (operator→planner subprocess)

| Env var | Audience | Notes |
|---|---|---|
| `RAXIS_SESSION_TOKEN` | Planner subprocess | 32 bytes hex. Output by `raxis session create --reveal-token` to **stderr** for capture via `2>session.env`. The kernel never logs the raw token — only its SHA-256 hash appears in the audit chain. |

---

## §4 — Test-only env vars (NOT part of any production contract)

These are knobs the integration test suite uses to drive the
verifier-stub and exercise specific kernel error paths. They are
documented here only so a developer reading the kernel's stderr
output during a `cargo test` run can map an unexpected log line
back to its source.

| Env var | Set by | Read by | Purpose |
|---|---|---|---|
| `RAXIS_STUB_RESULT_CLASS` | `cargo test` harnesses (`gates::verifier_runner::integration`) | `raxis-verifier-stub` | Dial the stub into `Pass` / `Fail` / `Inconclusive`. Default `Pass`. |
| `RAXIS_STUB_BODY_JSON` | Test harnesses | `raxis-verifier-stub` | Inject a custom JSON body into the submitted `WitnessRecord`. Default `{}`. |
| `RAXIS_STUB_SLEEP_MS` | Test harnesses (wall-clock-kill suite) | `raxis-verifier-stub` | Sleep N ms before connecting; lets tests verify the kernel's `max_wall_seconds` SIGKILL. Default `0`. |
| `RAXIS_STUB_SKIP_SEND` | Test harnesses (kernel-side-EOF suite) | `raxis-verifier-stub` | When `1`, the stub connects then immediately closes; tests how the kernel handles a verifier that exits without submitting. |
| `RAXIS_TEST_BLEEDOVER_<rand>` | `verifier_runner::tests::env_scrub_bleedover_test` | (none — set in parent, asserted absent in child) | Pinned check that `Command::env_clear()` actually removes the parent's env vars before exec'ing the verifier. Random suffix prevents inter-test races under `cargo test --jobs N`. |
| `RAXIS_TEST_POLICY_DIR` | Internal test mode | `raxis-policy` test mode | Reserved for test fixtures; absent in release builds (see [`philosophy.md`](philosophy.md) line 219). |

These vars **must not** appear in any production startup script,
systemd unit, or operator workflow. Their behavior is allowed to
change in any release without notice — they are not part of the
v1 stability contract.

---

## §5 — System env vars referenced by RAXIS

RAXIS reads three non-`RAXIS_*` env vars from the OS env block:

| Env var | Read by | Use |
|---|---|---|
| `HOME` | `raxis` (CLI), `raxis-kernel`, `raxis-gateway` (inherited) | Fallback for `~/.raxis` when `RAXIS_DATA_DIR` is unset; passed through to gateway subprocess. |
| `PATH` | `raxis-kernel` → gateway subprocess (`kernel/src/gateway/supervisor.rs`) | Inherited so the gateway can `exec` helper binaries. |
| `USER` / `LOGNAME` | `raxis` (CLI) — `cli/src/reveal.rs` | Used in the redacted-token output to label which user the token was minted for; `LOGNAME` is consulted only when `USER` is unset. |

RAXIS does **not** read `LD_PRELOAD`, `LD_LIBRARY_PATH`,
`DYLD_INSERT_LIBRARIES`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`,
`CARGO_HOME`, `RUSTUP_HOME`, or any other sysadmin-typical env
var as part of any normative behavior. The kernel's `env_clear()`
before `exec`'ing verifier subprocesses is precisely so an
operator's `LD_PRELOAD` cannot leak into a verifier and bypass
the witness contract.

---

## §6 — Quick-reference: precedence rules

| Setting | CLI flag | Env var | Default |
|---|---|---|---|
| Data directory | `--data-dir <path>` | `RAXIS_DATA_DIR` | `~/.raxis` (or `/root/.raxis` if `$HOME` unset) |
| Operator key (CLI) | `--operator-key <path>` | `RAXIS_OPERATOR_KEY` | None — required for operator-socket commands |
| Operator socket (CLI) | `--socket <path>` | (none) | `<data-dir>/sockets/operator.sock` |
| Operator cert (kernel boot) | (none) | `RAXIS_OPERATOR_CERT` | None — optional in bootstrap mode |
| Bootstrap mode (kernel) | (none) | `RAXIS_BOOTSTRAP=1` | Disabled (normal serving loop) |
| Force overwrite (kernel bootstrap) | (none) | `RAXIS_FORCE=1` | Disabled (refuses to overwrite) |
| VCS timeout (kernel) | (none) | `RAXIS_VCS_TIMEOUT_SECS` | `30` (capped at `120`) |

For every row where both a CLI flag and an env var exist, the
**explicit flag always wins**. The env var is a convenience to
avoid retyping; an explicit flag is the operator's authoritative
intent for that one invocation, and a stale shell export must
never silently override it.
