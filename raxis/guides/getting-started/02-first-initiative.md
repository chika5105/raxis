# 02 · Your First Initiative

> **Goal.** Genesis → kernel running → one task plan admitted → file
> committed to `main` → audit chain verifies. ~10 minutes.

This page is the runnable end-to-end "hello world" for RAXIS. The
plan creates one file (`HELLO.md`) inside a freshly initialised git
repo, commits it, and lets the kernel fast-forward `main`.

---

## 0 · Pick a data directory

The kernel keeps every byte of live state — SQLite store, sockets,
audit segments, witness blobs — under `$RAXIS_DATA_DIR` (defaults to
`~/.raxis`). For your first run, use a throwaway path:

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
```

Use the **same** value in every terminal that runs `raxis*` binaries
below.

---

## 1 · Mint an operator keypair

```bash
mkdir -p "$HOME/raxis-keys"
cd "$HOME/raxis-keys"

openssl genpkey -algorithm ED25519 -out operator_private.pem
openssl pkey    -in operator_private.pem -pubout -out operator_public.pem
chmod 600 operator_private.pem

export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"
```

If `openssl genpkey` fails with `Algorithm ed25519 not found`, the
default `openssl` is LibreSSL. See
[`01-prereqs.md`](01-prereqs.md#what-you-need-regardless-of-os).

---

## 2 · Genesis

Genesis is the one-time ceremony that:

1. Generates the kernel's authority, quality, and verifier-token keys.
2. Mints a self-signed `OperatorCert` from your private key in-process
   (the private bytes are read into memory only and **never** persisted
   under `$RAXIS_DATA_DIR`).
3. Writes `<data_dir>/policy/policy.toml` with the cert embedded under
   `[operators.entries.cert]`.
4. Lays down the chain-anchor audit segment.

```bash
raxis genesis \
  --operator-key  "$RAXIS_OPERATOR_KEY" \
  --operator-name "$USER"
```

Air-gapped variant (mint the cert offline with `raxis cert mint` on
the machine that holds the private key, then pass `--operator-cert
<path>`): see [`recipes/cli/01-genesis.md`](../recipes/cli/01-genesis.md).

Genesis runs **exactly once** per `RAXIS_DATA_DIR`. Re-running it on
an existing install fails with `genesis: refusing to overwrite
existing data dir`. To force a fresh genesis (irreversible — destroys
your audit chain), `rm -rf "$RAXIS_DATA_DIR"` first.

Inspect what genesis produced:

```bash
ls "$RAXIS_DATA_DIR"          # audit/  keys/  kernel.db  policy/  runtime/
head -60 "$RAXIS_DATA_DIR/policy/policy.toml"
```

---

## 3 · Configure a provider (Anthropic example)

Genesis does **not** wire in an LLM provider. Add one now so the
agents can call a model. Anthropic is the most-tested provider in V2.

```bash
mkdir -p "$RAXIS_DATA_DIR/providers"
cat > "$RAXIS_DATA_DIR/providers/anthropic-prod.toml" <<'EOF'
api_key = "sk-ant-REPLACE_ME"
EOF
chmod 600 "$RAXIS_DATA_DIR/providers/anthropic-prod.toml"
```

The kernel's `FileCredentialBackend` enforces mode `0600` on every
provider credential file; any other mode is a boot-time refusal.

Edit `$RAXIS_DATA_DIR/policy/policy.toml` and append the provider
block plus the worktree allowlist (the parent directory the demo
will create its scratch repos under):

```toml
[[providers.entries]]
id            = "anthropic-prod"
kind          = "Anthropic"
credentials   = "anthropic-prod.toml"
default_model = "claude-haiku-4-5"

[sessions]
allowed_worktree_roots = ["/tmp"]
```

> Use whichever model alias your account has access to. Other
> providers (OpenAI, Gemini, …) follow the same pattern; see
> [`recipes/policy/10-providers-section.md`](../recipes/policy/10-providers-section.md).

Re-sign the policy:

```bash
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
```

---

## 4 · Start the kernel

In a dedicated terminal:

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
raxis-kernel
```

Healthy startup prints (among other lines):

```text
{"level":"info","event":"PolicyLoaded","epoch_id":1}
{"level":"info","event":"KeyRegistryLoaded"}
{"level":"info","event":"AuditChainGenesis"}
{"level":"info","event":"KernelStarted"}
{"level":"info","event":"DashboardListening","url":"http://127.0.0.1:9820"}
```

The kernel auto-spawns the gateway subprocess; do not run
`raxis-gateway` by hand. The dashboard URL on the last line is
clickable — bookmark it for page 03.

Leave this terminal running. Switch to a second terminal for
everything below; export `RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` there
too.

---

## 5 · Materialise a scratch repo

```bash
export DEMO_ROOT="/tmp/raxis-hello"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

git init -q
echo "# hello world demo" > README.md
git -c user.email=demo@raxis.local -c user.name=Demo add . >/dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## 6 · Write the plan

Save this as `$DEMO_ROOT/plan.toml`:

```toml
[plan.initiative]
description = "Create a HELLO.md file with a one-line greeting and commit it."

[workspace]
name     = "Hello world"
base_ref = "refs/heads/main"
lane_id  = "default"

[[tasks]]
task_id            = "greeter"
session_agent_type = "Executor"
clone_strategy    = "blobless"
path_allowlist     = ["HELLO.md"]
predecessors       = []
context            = """
Write a single Markdown file `HELLO.md` whose only contents are the
line `Hello, RAXIS.` (followed by a trailing newline). Stage and
commit the file as a single commit with the message `add HELLO.md`.
"""
```

Field-by-field references:
[`plan.initiative`](../recipes/plan/01-plan-initiative-block.md),
[`workspace`](../recipes/plan/02-workspace-block.md),
[`tasks`](../recipes/plan/03-tasks-block.md),
[`session_agent_type`](../recipes/plan/06-session-agent-type.md),
[`path_allowlist`](../recipes/plan/04-path-allowlist.md),
[`clone_strategy`](../recipes/plan/05-clone-strategy.md).

The kernel auto-spawns one `Orchestrator` per initiative; you only
declare `Executor` and `Reviewer` tasks. Trying to declare an
Orchestrator task is rejected at admission as
`orchestrator_task_not_permitted`.

---

## 7 · Validate, submit, approve

```bash
# Local pre-flight — catches obvious mistakes before any IPC.
raxis plan validate "$DEMO_ROOT/plan.toml"
# expected: a list of [OK] lines and exit 0.

# Sign + submit atomically. The CLI builds the canonical byte array,
# signs it with your operator key, and ships (bundle, signature) to
# the kernel over IPC. No `plan.sig` file is produced (V2 sealed-bundle
# admission per specs/v2/plan-bundle-sealing.md §4).
raxis submit plan "$DEMO_ROOT/plan.toml" --no-dry-run

INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
echo "INIT_ID=$INIT_ID"

raxis plan approve "$INIT_ID"
# expected: "tasks_admitted: 1"
```

---

## 8 · Watch it run

```bash
raxis initiative show "$INIT_ID" --with-tasks
```

The Orchestrator boots first, picks up the `greeter` task, and spawns
the Executor VM. The Executor edits `HELLO.md`, commits, and submits
`CompleteTask`. The kernel verifies the touched-paths union, evaluates
gates, and (since there are no review tasks and no merge verifiers in
this plan) fast-forwards `main` to the Executor's commit SHA.

Follow the audit chain live in a third terminal:

```bash
raxis log "$INIT_ID" -f
```

---

## 9 · Verify success

Five checks confirm the run landed correctly. Each one is a single
command:

```bash
# 1. Initiative is Completed; the task is Completed.
raxis initiative show "$INIT_ID" --with-tasks
# State: Completed
# greeter: Completed

# 2. The audit chain has the lifecycle events.
raxis log "$INIT_ID" --kind InitiativeCreated --limit 1
raxis log "$INIT_ID" --kind PlanApproved      --limit 1
raxis log "$INIT_ID" --kind TaskCompleted     --limit 1
raxis log "$INIT_ID" --kind IntegrationMergeCompleted --limit 1

# 3. The chain still verifies end-to-end.
raxis verify-chain
# expected: non-zero record count, zero gaps, ok

# 4. `main` advanced to the Executor's commit and the file is there.
git -C "$DEMO_ROOT" log --oneline -5
git -C "$DEMO_ROOT" show main:HELLO.md

# 5. Full preflight comes back green.
raxis doctor
```

If any of these are red, jump to
[`04-troubleshooting.md`](04-troubleshooting.md) — the top ten failure
modes are catalogued there with exact fixes.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
# Optional — wipe the whole install and start over:
# rm -rf "$RAXIS_DATA_DIR"
```

---

## What just happened

| Stage                    | Component                                        | Audit event(s)                          |
| ------------------------ | ------------------------------------------------ | --------------------------------------- |
| Plan submission          | `raxis-cli` → `raxis-kernel` IPC                 | `InitiativeCreated`, `PlanBundleSealed` |
| Plan approval            | `kernel/handlers/intent::handle_approve_plan`    | `PlanApproved`, `TaskAdmitted`          |
| Orchestrator spawn       | `session_spawn_orchestrator` → AVF / Firecracker | `SessionStarted` (Orchestrator)         |
| Executor spawn           | same path, after `ActivateSubTask`               | `SessionStarted` (Executor)             |
| Tool calls inside the VM | `raxis-planner-executor` → kernel via vsock      | `IntentAccepted` per tool use           |
| Task completion          | `handle_complete_task`                           | `TaskCompleted`                         |
| Main fast-forward        | `handle_integration_merge` Check 5               | `IntegrationMergeCompleted`             |
| Audit append             | every event above                                | `AuditChainAppended` (paired write)     |

Now flip to [`03-dashboard-tour.md`](03-dashboard-tour.md) and walk
the same run from the operator UI.

---

## How the LLM learns what's installed

The Executor LLM runs inside an airgapped VM with **no outbound
network** — `pip install`, `npm install`, `cargo install`, and
`go get` will all fail (the credential proxies only proxy DB /
SMTP traffic, not package mirrors). So how does the LLM know
what's already baked into the image so it can write a script
that just imports what it needs?

Two coherent surfaces, both backed by the same in-VM probe
(`crates/planner-core/src/vm_capabilities.rs`):

1. **System-prompt hint.** At session start the planner
   driver injects a `## VM Environment` block into the LLM's
   system prompt: image role + digest, language toolchain
   versions (Python 3.11 / Node 20 / Rust / Go), the curated
   set of pre-installed Python DB clients
   (`psycopg2-binary`, `pymongo`, `redis`, `PyMySQL`,
   `pymssql`), the binary CLI surface (`bash`, `git`, `gh`,
   `jq`, `ripgrep`, `fd`, `make`, `gcc`, …), the
   credential-proxy env-var **names**
   (`DATABASE_URL`, `MONGO_URL`, `REDIS_URL`, `SMTP_URL`),
   the workdir path + git HEAD, and a one-line warning that
   egress is gated.
2. **`vm_capabilities` LLM tool.** Registered in every role
   registry. The LLM can call it on any subsequent turn for a
   finer query — e.g. "is `numpy` available?" returns a JSON
   manifest with the exact installed version (or `null`),
   importability, and site-packages path.

Both surfaces read from the same per-process cache, so the
hint and the tool's output are byte-coherent for a given
`(image digest, session env)` pair (which is what makes the
LLM provider's prompt cache hit across turns). Kernel-private
env vars (safe session id, vsock loopback plan, sidecar HMAC
secrets, anything matching `*SECRET*` / `*API_KEY*` /
`*_TOKEN`) are redacted automatically — the LLM only sees the
variables it can safely use.

The mechanism is **image-agnostic** by construction: it
introspects the actual VM (PATH walk + `--version` probes +
`dist-info` reads + filtered `std::env::vars()` +
`git rev-parse HEAD`), so it works identically for the
canonical `raxis-executor-starter` image (this guide) and for
operator-pinned BYO images
([`recipes/ops/17-bring-your-own-image.md`](../recipes/ops/17-bring-your-own-image.md)).
The full schema and redaction rules live in
[`specs/v2/canonical-images.md §6`](../../specs/v2/canonical-images.md);
the invariant that pins the contract is `INV-EXEC-DISCOVERY-01`
([`specs/invariants.md §10.4a`](../../specs/invariants.md)).

---

## Cross-references

- [`scenarios/01-hello-world/`](../scenarios/01-hello-world/) — the
  same flow as a runnable scenario folder (with a checked-in
  `plan.toml`). This page expands the inline instructions; the
  scenario folder is the canonical copy-pasteable variant.
- [`specs/v2/plan-bundle-sealing.md`](../../specs/v2/plan-bundle-sealing.md)
  — the canonical bytes / signing contract behind `submit plan`.
- [`specs/v2/integration-merge.md`](../../specs/v2/integration-merge.md)
  — the admission checks that gate the final `main` fast-forward.
- what is
  shipped on the V2 surface today.
