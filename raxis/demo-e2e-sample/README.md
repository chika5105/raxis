# RAXIS demo: end-to-end runnable walkthrough

This directory is the **single-file runnable recipe** for a fresh local RAXIS install.
Following the steps below, in order, on a clean machine, takes you from "no
binaries on `$PATH`" to "kernel running, plan approved, planner session minted,
audit chain verified" with no detours.

The recipe is intentionally complete — you should not have to bounce to other
documents to get a working demo. For the canonical reference docs (every CLI
flag, every error code, every invariant), the cross-references at the bottom
of this file are the source of truth; this guide is the operationally-shortest
path through them.

> What `setup.sh` materializes is small on purpose: a tiny 2-commit Git repo
> under `src/` and `tests/`, plus `plan.toml` ready to sign. The minimal plan
> declares one task (`task-alpha`), no gates, and `path_allowlist =
> ["src/", "tests/"]`. Everything below operates on that.

---

## Prerequisites

- **Rust toolchain** (stable; the workspace's `rust-toolchain.toml` picks the
  right channel automatically).
- **OpenSSL 3.x on `$PATH`.** The macOS default `/usr/bin/openssl` is
  LibreSSL, which cannot generate Ed25519 keys. On macOS install Homebrew
  `openssl@3` and prepend its `bin/` to `$PATH` (or invoke by full path);
  on Linux your distro's `openssl` package is typically already OpenSSL 3.
- **Git.**
- **`uuidgen`** (preinstalled on macOS and most Linux distros).

Verify:

```bash
openssl version          # MUST show OpenSSL 3.x, NOT LibreSSL
git --version
uuidgen
cargo --version
```

---

## Step 1 — Build and install the three binaries

The workspace produces three binaries: `raxis` (operator CLI, crate name
`raxis-cli`), `raxis-kernel` (the long-lived daemon), and `raxis-gateway`
(auto-spawned by the kernel — never run manually). Install all three so the
kernel can find the gateway on `$PATH`.

From the workspace root (`raxis/`):

```bash
cargo install --path cli      --locked --force
cargo install --path kernel   --locked --force
cargo install --path gateway  --locked --force
```

Confirm `~/.cargo/bin` is on `$PATH`, then:

```bash
which raxis raxis-kernel raxis-gateway
raxis --help | head -20
```

> Faster development alternative: skip `cargo install` for `raxis` /
> `raxis-kernel` and run from a debug build (`cargo run -p raxis-cli -- <args>`,
> `cargo run -p raxis-kernel`). You **still** need `raxis-gateway` on `$PATH`
> because the kernel spawns it as a subprocess.

---

## Step 2 — Pick a clean data directory

The kernel keeps all live state under `$RAXIS_DATA_DIR` (defaults to
`~/.raxis`). For the demo, use a throwaway location so you can blow it away
cleanly:

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
rm -rf "$RAXIS_DATA_DIR"   # ONLY for a fresh demo run
```

Use the **same** `RAXIS_DATA_DIR` value in every terminal that runs `raxis*`
binaries below.

---

## Step 3 — Generate an operator Ed25519 keypair

These are PEM files compatible with OpenSSL 3's `genpkey` / `pkey`:

```bash
mkdir -p "$HOME/raxis-keys"
cd "$HOME/raxis-keys"

openssl genpkey -algorithm ED25519 -out operator_private.pem
openssl pkey    -in operator_private.pem -pubout -out operator_public.pem

chmod 600 operator_private.pem
```

> The repo contains an example `operator_private.pem` at the workspace root,
> but treat that as illustration only — generate your own.

---

## Step 4 — Run the genesis ceremony (convenience path)

Genesis generates the kernel's authority, quality, and verifier-token keys;
mints a self-signed `OperatorCert` from your private key in-process; and
writes `policy.toml` with the cert embedded under `[operators.entries.cert]`:

```bash
raxis genesis \
  --operator-key  "$HOME/raxis-keys/operator_private.pem" \
  --operator-name "Chika"
```

Your private bytes are read into memory only and **never persisted** under
`$RAXIS_DATA_DIR` — the CLI tests pin this with a recursive seed-leakage scan.

For tighter security (production / multi-machine), use the air-gapped path
instead — pre-mint the cert with `raxis cert mint` on a machine that holds
the private key, then `raxis genesis --operator-cert <file>`. Full details
in [`specs/v1/cli-ceremony.md`](../specs/v1/cli-ceremony.md) §`genesis`.

Inspect what genesis produced:

```bash
ls "$RAXIS_DATA_DIR"
ls "$RAXIS_DATA_DIR/policy"
ls "$RAXIS_DATA_DIR/keys"
head -60 "$RAXIS_DATA_DIR/policy/policy.toml"
```

---

## Step 5 — Materialize the demo repo and plan

```bash
./setup.sh /tmp/raxis-e2e-demo
```

(Adjust the destination if `/tmp/raxis-e2e-demo` already exists; `setup.sh`
refuses to overwrite an existing repo.) Capture the paths it prints — every
later step assumes these exports are set:

```bash
export DEMO_ROOT=/tmp/raxis-e2e-demo
export REPO_ROOT="$DEMO_ROOT/repo"
export PLAN_DIR="$DEMO_ROOT/plan"
export HEAD_OID="$(git -C "$REPO_ROOT" rev-parse HEAD)"
export PARENT_OID="$(git -C "$REPO_ROOT" rev-parse HEAD^)"
echo "REPO_ROOT=$REPO_ROOT  PLAN_DIR=$PLAN_DIR"
echo "HEAD=$HEAD_OID  PARENT=$PARENT_OID"
```

`setup.sh` also prints these on its last lines if you lose track.

---

## Step 6 — Allowlist your worktree root in `policy.toml`

The kernel rejects any `session create` whose `worktree_root` is not under
`[sessions].allowed_worktree_roots`. The demo lives under `/tmp/raxis-e2e-demo`
and you'll add a worktree under `/tmp/raxis-e2e-worktrees`, so allowlist `/tmp`
(or the specific parent paths if you want to be tighter).

Edit `$RAXIS_DATA_DIR/policy/policy.toml` and add a `[sessions]` block (or
extend the existing one):

```toml
[sessions]
allowed_worktree_roots = ["/tmp"]
```

Re-sign the policy after every edit (idempotent — re-running just rewrites
`policy.sig`):

```bash
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$HOME/raxis-keys/operator_private.pem"
```

> If the kernel is already running when you edit the policy, run
> `raxis epoch advance --policy <path> --sig <path>` to flip the in-memory
> epoch without restarting. For a fresh demo it's simpler to just edit before
> Step 7.

---

## Step 7 — Start the kernel

In a **dedicated terminal** so its stderr stream stays visible. With
`$RAXIS_DATA_DIR` exported the same way:

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
raxis-kernel
```

You should see JSON-formatted log lines like `policy loaded`, `key registry
loaded`, `store opened`, `audit chain genesis`, `KernelStarted`. The kernel
auto-spawns and supervises the gateway subprocess. Leave this terminal
running for the rest of the demo; switch back to your operator terminal for
the steps below.

Sanity check from a second terminal (with `$RAXIS_DATA_DIR` exported):

```bash
raxis status     # one-screen overview
raxis doctor     # full preflight: cert zones, audit chain, schema version
```

`doctor` should print all-green; `status` should show kernel uptime and an
empty initiative list.

> **About `--operator-key`** — every command from here on that talks to
> the kernel's operator socket (`plan submit`, `plan approve`,
> `plan reject`, `session create`, `session revoke`, `initiative abort`,
> `initiative quarantine`, `task abort/resume/retry`, `delegation grant`,
> `escalation approve/deny`, `epoch advance`, `operator
> quarantine-plans-by`, `cert install`) requires `--operator-key
> <path>` as a **global flag** (it goes BEFORE the subcommand, not
> after). The kernel uses it to perform an Ed25519 challenge-response
> handshake on every connection. Read-only commands (`status`,
> `inspect`, `doctor`, `verify-chain`, `log`, `inbox`, `sessions`,
> `escalations`, `verifiers`, `witnesses`, `budget`) do NOT need it.
>
> To avoid retyping the path on every command, you have two choices:
>
> 1. **Env var (preferred — survives `$(...)` subshells):**
>
>    ```bash
>    export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"
>    ```
>
>    The CLI honors `RAXIS_OPERATOR_KEY` as a fallback whenever
>    `--operator-key` is not passed explicitly. The env var holds a
>    **path** only — never key bytes — which preserves the security
>    model: no secret material ever transits the process
>    environment, where it would be visible to `ps eww`,
>    `/proc/$pid/environ`, kernel core dumps, or any child process
>    that inherits the env block. See
>    [`specs/v1/env-vars.md`](../specs/v1/env-vars.md) for the full
>    inventory and security model.
>
> 2. **Shell alias (works only in interactive shells):**
>
>    ```bash
>    alias raxisop='raxis --operator-key "$HOME/raxis-keys/operator_private.pem"'
>    ```
>
>    Useful if you want a visible reminder on every line that
>    you're about to write. Aliases are not preserved across
>    `$(...)` subshells, so command substitution has to inline the
>    full flag.
>
> Every later command shown below assumes option 1 — the
> `RAXIS_OPERATOR_KEY` export — and drops the `--operator-key` flag
> from the snippets. If you skipped the export, prepend
> `--operator-key "$HOME/raxis-keys/operator_private.pem"` to every
> write command. Explicit `--operator-key` always wins over the env
> var (defence-in-depth: a stale shell export must not silently
> override a freshly-typed flag).

---

## Step 8 — Sign the demo plan

Back in your operator terminal:

```bash
raxis policy sign \
  "$PLAN_DIR/plan.toml" \
  --key "$HOME/raxis-keys/operator_private.pem"

ls "$PLAN_DIR"   # plan.toml + plan.sig
```

---

## Step 9 — Submit and approve the plan

The kernel always mints a fresh UUID v4 as the canonical `initiative_id`. The
first argument to `plan submit` is a **free-form label** for log lines only
— capture the UUID it echoes back, **not** the label:

Both commands are operator-socket calls and pick up the operator key
from the `RAXIS_OPERATOR_KEY` export you set after Step 7 (or the
explicit `--operator-key` flag if you skipped the export):

```bash
SUBMIT_OUT="$(raxis plan submit demo "$PLAN_DIR")"
printf '%s\n' "$SUBMIT_OUT"

INIT_ID="$(printf '%s\n' "$SUBMIT_OUT" | awk '/^Initiative/ {print $2; exit}')"
echo "INIT_ID=$INIT_ID"

raxis plan approve "$INIT_ID"
```

After `plan approve` the initiative transitions `Draft → ApprovedPlan`, and
the single demo task (`task-alpha`) is scheduled (`Admitted`). Confirm:

```bash
raxis status                              # kernel-wide rollup (counts by initiative state)
raxis initiative show "$INIT_ID"          # initiative-level deep-dive: state,
                                          # plan-bundle envelope, quarantine
                                          # status, and task count
raxis initiative show "$INIT_ID" \
      --with-tasks                        # ↑ same, but expand the per-task table
raxis inspect task-alpha                  # task-level deep-dive: predecessors,
                                          # gates, witnesses, plan_fields
```

> `raxis initiative show <init_id>` is the V2 read surface for "tell
> me everything about this initiative": it joins the `initiatives`
> row, the `plan_bundles` header (signed_by + sealed_at + per-artifact
> manifest — raw artifact bytes are NEVER printed; pass
> `--bundle --to <dir>` to extract them, see `plan-bundle-sealing.md`
> §8.5), the quarantine row (if any), and the per-task table in one
> snapshot. Operator fingerprints (signed_by, quarantined_by) render
> with display names per `kernel-store.md` §2.5.2 — e.g. `signed_by:
> Chika (abcd1234)` — so you don't have to cross-reference
> `raxis cert list`. Pass `--json` for a single structured object;
> use `raxis inspect <task_id>` for task-level forensics; use
> `raxis log <init_id>` and `raxis verify-chain` for chronological
> history. The `raxis initiative` *write* surface still only exposes
> `abort` and `quarantine` — read goes through `initiative show`,
> write through `initiative <verb>`.

The same `INIT_ID` is what every WRITE command keys off — `plan reject`,
`initiative abort`, `initiative quarantine`, `task retry`, etc. all expect
the kernel-assigned UUID, never the label you passed to `plan submit`.

---

## Step 10 — Create a planner worktree and session

In v1 the kernel never creates worktrees; you do. Pick a `lineage_id` (one
per logical agent — reuse it across session-revoke + recreate cycles for the
same agent; use a fresh one for genuinely independent agents):

```bash
LINEAGE_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
WT="/tmp/raxis-e2e-worktrees/$LINEAGE_ID"
mkdir -p "$(dirname "$WT")"

git -C "$REPO_ROOT" worktree add "$WT" -b "agents/$LINEAGE_ID"

raxis session create \
        --role planner \
        --worktree-root "$WT" \
        --base-tracking-ref refs/heads/main \
        --lineage-id "$LINEAGE_ID" \
        --task task-alpha \
        2> "$DEMO_ROOT/session-1.env"
```

The CLI prints the human-readable session info (session id, expires-at,
lineage id, etc.) to **stdout** and the `RAXIS_SESSION_TOKEN=<hex>` line to
**stderr** so you can capture it with `2>` without it appearing in shell
history. The kernel never logs the token (only its SHA-256 hash is written
to the audit chain).

Read it back when you need to inject it into a planner subprocess:

```bash
cat "$DEMO_ROOT/session-1.env"
# → RAXIS_SESSION_TOKEN=<64 hex chars>
```

---

## Step 11 — Verify the audit chain

Every kernel decision (genesis emits, plan submit, plan approve, session
created) was hash-chained into `$RAXIS_DATA_DIR/audit/segment-000.jsonl`.
Verify it end-to-end:

```bash
raxis verify-chain            # walks every segment-NNN.jsonl in numeric
                              # order; exits 0 (intact) or 3 (broken)
tail -n 5 "$RAXIS_DATA_DIR/audit/segment-000.jsonl"
```

> `raxis verify-chain` is the only audit-chain verification surface.
> The V1-draft `audit verify` / `audit gaps` shims were removed in V2
> (no two CLI commands may perform the same action).  Use
> `--quick` for the first-+-last fast path or `--from <seq>` to
> narrow the reported stats to a window.

You should see (roughly in order): `KernelStarted`, `OperatorAuthenticated`,
`InitiativeCreated`, `PlanApproved`, `SessionCreated`. INV-04 (audit
tamper-detection) and INV-05 (decisions reproducible from records) hold by
construction; `verify-chain` is the operator-side check.

---

## What this demo does NOT do

The demo intentionally stops at "scheduled tasks + minted session" because
**v1 does not bundle a planner agent**. From here, an operator-supplied agent
process would consume the session token and start submitting `IntentRequest`s
(`SingleCommit`, then `CompleteTask`) over the planner socket. The shape of
those messages is in [`specs/v1/peripherals.md`](../specs/v1/peripherals.md)
§3.1 and [`specs/v1/planner-api.md`](../specs/v1/planner-api.md). The native
`raxis-planner` binary is a v2 deliverable (see the V2 table row "Planner
architecture" in [`README.md`](../README.md)).

If you want to exercise the kernel-side path-allowlist enforcement against
the demo without writing an agent: `SingleCommit` accepts a vacuous diff
when `base_sha == head_sha`, so an empty-diff intent over `$HEAD_OID`
against `path_allowlist = ["src/", "tests/"]` (from `plan/plan.toml`)
round-trips cleanly. The closest thing to an automated end-to-end is the
integration tests under `raxis/kernel/tests/` (especially `intent_*.rs` and
the e2e fixtures referenced by [`specs/v1/cli-ceremony.md`](../specs/v1/cli-ceremony.md)
§4.3).

---

## Tear-down

In the kernel terminal: **`Ctrl-C`** (clean SIGINT — the kernel emits
`KernelStopped` and exits 0).

Then in the operator terminal:

```bash
git -C "$REPO_ROOT" worktree remove --force "$WT"            2>/dev/null || true
git -C "$REPO_ROOT" branch        -D       "agents/$LINEAGE_ID" 2>/dev/null || true
rm -rf "$RAXIS_DATA_DIR" "$DEMO_ROOT" /tmp/raxis-e2e-worktrees
```

---

## File layout you just created

| Path | Owner | What it holds |
|---|---|---|
| `$RAXIS_DATA_DIR/policy/policy.{toml,sig}` | operator | the signed authority bundle |
| `$RAXIS_DATA_DIR/keys/` | kernel | authority/quality/verifier-token keys + per-operator pubkey + cert |
| `$RAXIS_DATA_DIR/kernel.db` | kernel | SQLite WAL — the v1 tables (`SCHEMA_VERSION = 4`) |
| `$RAXIS_DATA_DIR/audit/segment-000.jsonl` | kernel | append-only hash-chained decision log |
| `$RAXIS_DATA_DIR/witness/` | kernel | content-addressed verifier evidence blobs |
| `$RAXIS_DATA_DIR/sockets/` | kernel | UDS sockets: `operator.sock`, `planner.sock`, `gateway.sock` |
| `$RAXIS_DATA_DIR/runtime/heartbeat.json` | kernel | 5s rolling status snapshot (read by `raxis status`) |
| `$DEMO_ROOT/repo/` | `setup.sh` | tiny git repo, two commits, `src/lib.rs` + `tests/smoke.rs` |
| `$DEMO_ROOT/plan/plan.{toml,sig}` | operator | demo plan + Ed25519 signature |
| `/tmp/raxis-e2e-worktrees/$LINEAGE_ID/` | operator | the planner's isolated git worktree |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Algorithm ed25519 not found` on `openssl genpkey` | macOS default LibreSSL | Install Homebrew `openssl@3` and put it on `$PATH` (Step 0) |
| `unknown flag --operator-pubkey` from `raxis genesis` | Cert-mandatory release removed it | Use `--operator-key` (convenience) or `--operator-cert` (air-gapped) |
| `--operator-key <path> is required for this command` on `plan submit` / `plan approve` / `session create` / etc. | Operator-socket commands need the key to perform the kernel's challenge-response handshake; neither `--operator-key` nor `RAXIS_OPERATOR_KEY` was found | Either `export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"` once per shell, or pass `--operator-key <path>` as a **global flag BEFORE the subcommand** (not after). See the box at the end of Step 7 for the full list of operator-socket commands |
| `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS` on `session create` | Worktree path not under any `[sessions].allowed_worktree_roots` entry | Edit policy → re-sign → restart kernel (or `raxis epoch advance` if it's running) |
| `FAIL_UNKNOWN_SIGNER` on `plan submit` | Plan signed with a key not in `policy.toml`'s operator entry | Re-sign the plan with the same `--key` you used for genesis |
| `ERR_SCHEMA_MISMATCH` (exit 7) from any read-only command | CLI compiled against a different `SCHEMA_VERSION` than the kernel that wrote the DB | Rebuild + reinstall the CLI from the same workspace as the kernel |
| `cannot connect to operator socket` | Kernel not running, or `$RAXIS_DATA_DIR` differs between terminals | Confirm `raxis-kernel` is up; `echo $RAXIS_DATA_DIR` in each terminal must match |
| CLI typos | — | The dispatcher gives "did you mean X?" suggestions at every level (`raxis stauts` → `status`) |
| General preflight | — | `raxis doctor` runs cert-zone checks, audit chain probe, schema version probe, and worktree-root sanity in one command |

---

## Cross-references (the canonical sources)

- [`raxis/README.md`](../README.md) — Quick Start §1–§7 (genesis, certs, quarantine, CLI ergonomics)
- [`specs/v1/cli-ceremony.md`](../specs/v1/cli-ceremony.md) §4.1 (every subcommand) and §4.2 (genesis ceremony walkthrough)
- [`specs/v1/peripherals.md`](../specs/v1/peripherals.md) §3.1 (planner IPC contract — what an agent would send next)
- [`specs/v1/planner-api.md`](../specs/v1/planner-api.md) (machine-readable error code + remediation table for planner authors)
- [`specs/v1/kernel-store.md`](../specs/v1/kernel-store.md) §2.5.1 (store DDL), §2.5.8 (VCS path enforcement), §2.5.10 (initiative quarantine)
