# 02 · Your First Initiative

> **Goal.** Genesis → kernel running → one task plan admitted → file
> committed to `main` → audit chain verifies. ~10 minutes.

This page is the runnable end-to-end "hello world" for RAXIS. The
plan creates one file (`HELLO.md`) inside the default managed repo,
commits it, and lets the kernel fast-forward `main`.

If you already ran the Homebrew helper from the website:

```bash
"$(brew --prefix raxis)/share/raxis/install.sh"
```

you can skip straight to
[5 · Seed the default managed repo](#5--seed-the-default-managed-repo).
The helper already created the operator key, ran genesis with bootstrap
admin permissions, configured the provider, signed policy, and started
the daemon.

---

## 0 · Export the two runtime paths

The kernel keeps every byte of live state — SQLite store, sockets,
audit segments, witness blobs — under `$RAXIS_DATA_DIR`. The Homebrew
bottle keeps the immutable runtime bundle under
`$(brew --prefix raxis)/share/raxis`.

For your first run, use the Homebrew service data dir. This keeps the
CLI, daemon, dashboard, and later `brew services` restarts on one
state root:

```bash
export RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
export RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"
```

Use the **same** values in every terminal that runs `raxis*` binaries
below. Source-build operators should set `RAXIS_INSTALL_DIR` to the
install dir produced by `cargo xtask source-setup`.

---

## 1 · Mint an operator keypair

```bash
install -d -m 700 "$HOME/raxis-keys"

openssl genpkey -algorithm ED25519 -out "$HOME/raxis-keys/operator_private.pem"
openssl pkey \
  -in "$HOME/raxis-keys/operator_private.pem" \
  -pubout \
  -out "$HOME/raxis-keys/operator_public.pem"
chmod 600 "$HOME/raxis-keys/operator_private.pem"

export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"
```

`RAXIS_OPERATOR_KEY` is a convenience variable. Without it, every
signed request below needs `--key "$HOME/raxis-keys/operator_private.pem"`
or `--operator-key "$HOME/raxis-keys/operator_private.pem"` spelled
out.

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

This creates a non-admin operator by default. The Homebrew helper uses
`--admin` for the initial bootstrap operator so first-run users can
install replacement operator certs and advance policy epochs without a
separate recovery ceremony. Admin authority is still explicit policy:
the bootstrap cert includes privileged operations such as
`OperatorCertInstall` and `RotateEpoch`.

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
install -d -m 700 "$RAXIS_DATA_DIR/providers"

printf 'Anthropic API key: '
stty -echo
IFS= read -r RAXIS_ANTHROPIC_API_KEY
stty echo
printf '\n'
{
  printf 'api_key = "%s"\n' "$RAXIS_ANTHROPIC_API_KEY"
  printf 'auth_header = "x-api-key"\n'
  printf 'auth_prefix = ""\n'
} > "$RAXIS_DATA_DIR/providers/anthropic-prod.toml"
unset RAXIS_ANTHROPIC_API_KEY
chmod 600 "$RAXIS_DATA_DIR/providers/anthropic-prod.toml"
```

The kernel's `FileCredentialBackend` enforces mode `0600` on every
provider credential file; any other mode is a boot-time refusal.
Anthropic also requires `x-api-key` rather than the gateway's default
`Authorization: Bearer` header, so keep the `auth_header` and
empty `auth_prefix` lines.

Now make three policy edits:

1. Ensure kernel-managed worktrees live under the data dir.
2. Point the dashboard at the Homebrew-shipped static bundle.
3. Add the gateway/provider block.

```bash
perl -0pi -e 's|allowed_worktree_roots = \[[^\]]*\]|allowed_worktree_roots = ["'"$RAXIS_DATA_DIR"'/worktrees"]|' \
  "$RAXIS_DATA_DIR/policy/policy.toml"

if ! rg -q '^static_dir[[:space:]]*=' "$RAXIS_DATA_DIR/policy/policy.toml"; then
  perl -0pi -e 's|(jwt_ttl_secs = [0-9]+\n)|${1}static_dir   = "$ENV{RAXIS_INSTALL_DIR}/dashboard"\n|' \
    "$RAXIS_DATA_DIR/policy/policy.toml"
fi

cat >> "$RAXIS_DATA_DIR/policy/policy.toml" <<EOF

[gateway]
binary_path              = "$(brew --prefix raxis)/bin/raxis-gateway"
spawn_timeout_secs       = 5
respawn_backoff_ms       = 1000
max_consecutive_respawns = 5

[[providers]]
provider_id              = "anthropic-prod"
kind                     = "Anthropic"
credentials_file         = "anthropic-prod.toml"
inference_timeout_ms     = 120000
data_fetch_timeout_ms    = 30000
max_response_bytes       = 16777216
pricing.input_tokens_per_dollar  = 200000
pricing.output_tokens_per_dollar = 50000
EOF
```

The pricing values are conservative tokens-per-dollar estimates used
for budget admission. Tune them to your provider contract later; they
do not expose your API key and do not change which model the planner
requests. The `120000` ms inference timeout matches the live agent
runtime budget used by the starter images; smaller provider caps can
reject normal tasks before the model call is attempted. Other
providers follow the same pattern; see
[`recipes/policy/10-providers-section.md`](../recipes/policy/10-providers-section.md).

Re-sign the policy:

```bash
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_DATA_DIR/keys/authority_keypair.pem"
```

Policy artifacts are signed by the local authority key. Keep using
`RAXIS_OPERATOR_KEY` for operator requests such as `submit plan`,
`plan approve`, `session create`, and future `epoch advance`
commands.

---

## 4 · Start the kernel daemon

For the Homebrew path, run RAXIS as a user launchd daemon:

```bash
export RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
export RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"

brew services start raxis
brew services list | awk 'NR==1 || $1=="raxis"'
raxis-supervisor status
raxis doctor
```

Expected: `brew services list` shows `raxis started`,
`raxis-supervisor status` reports `Healthy`, and `raxis doctor` reports
`worst: OK`.

The kernel auto-spawns the gateway subprocess; do not run
`raxis-gateway` by hand. The dashboard listens on:

```text
http://127.0.0.1:9820
```

Logs:

```bash
tail -f "$(brew --prefix)/var/log/raxis/kernel.log"
tail -f "$(brew --prefix)/var/log/raxis/kernel.err.log"
tail -f "$RAXIS_DATA_DIR/supervisor.stderr.log"
cat "$RAXIS_DATA_DIR/kernel_lifecycle_status.json"
```

Homebrew captures launchd stdout/stderr under `$(brew --prefix)/var/log`.
Supervisor health decisions, circuit-breaker state, and many startup
errors are also written under `$RAXIS_DATA_DIR`; check those files when
the Homebrew logs are empty.

To stop the daemon:

```bash
brew services stop raxis
```

If you are debugging startup, stop the Homebrew service and run the
kernel in a foreground terminal instead:

```bash
brew services stop raxis
export RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
export RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"
raxis-kernel
```

Healthy foreground startup prints (among other lines):

```text
{"level":"info","event":"PolicyLoaded","epoch_id":1}
{"level":"info","event":"KeyRegistryLoaded"}
{"level":"info","event":"AuditChainGenesis"}
{"level":"info","event":"KernelStarted"}
{"level":"info","event":"DashboardListening","url":"http://127.0.0.1:9820"}
```

Use one start mode at a time. If you use foreground mode, leave that
terminal running and switch to a second terminal for everything below;
export `RAXIS_INSTALL_DIR`, `RAXIS_DATA_DIR`, and `RAXIS_OPERATOR_KEY`
there too.

---

## 5 · Seed the default managed repo

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"

rm -rf "$RAXIS_MAIN_REPO"
install -d "$(dirname "$RAXIS_MAIN_REPO")"
git init -q "$RAXIS_MAIN_REPO"
git -C "$RAXIS_MAIN_REPO" symbolic-ref HEAD refs/heads/main

printf '# hello world demo\n' > "$RAXIS_MAIN_REPO/README.md"
git -C "$RAXIS_MAIN_REPO" \
  -c user.email=demo@raxis.local \
  -c user.name=Demo \
  add README.md
git -C "$RAXIS_MAIN_REPO" \
  -c user.email=demo@raxis.local \
  -c user.name=Demo \
  commit -qm "init"
```

RAXIS does not run against the directory you happen to be standing in.
The production kernel clones from the managed repository selected by
`[workspace] repository`. The first guide uses the default repository
id `main`, stored at `$RAXIS_DATA_DIR/repositories/main`, then clones
into kernel-managed worktrees under `$RAXIS_DATA_DIR/worktrees`.

For your own project after this demo, use a managed clone:

```bash
raxis repo adopt main /path/to/your/repo
raxis repo status main
```

0.2.0 supports multiple managed repositories. Adopt additional repos
with names such as `api` or `web`, then set
`repository = "api"` in the plan's `[workspace]` block. Avoid symlinks
for normal use; they make it too easy to let a governed run mutate an
unexpected checkout.

---

## 6 · Write the plan

```bash
export PLAN_PATH="/tmp/raxis-hello-plan.toml"
export RAXIS_TASK_ID="greeter-$(date +%Y%m%d%H%M%S)"

cat > "$PLAN_PATH" <<EOF
[plan.initiative]
description = "Create a HELLO.md greeting file and commit it."

[workspace]
name       = "Hello world"
lane_id    = "default"
target_ref = "refs/heads/main"
repository = "main"

[[tasks]]
task_id            = "$RAXIS_TASK_ID"
description        = "Create HELLO.md and commit it."
session_agent_type = "Executor"
clone_strategy    = "blobless"
path_allowlist     = ["HELLO.md"]
predecessors       = []
prompt             = """
Write a small Markdown greeting file named HELLO.md at the repository
root. Put the exact text: hello from alex.
Stage and commit it as a single commit with the message: add HELLO.md.
Do not modify any other file.
"""
EOF
```

`description` is the short human summary shown in plan views.
`prompt` is the main instruction sent to the Executor. Older examples
used `context`; 0.2.0 rejects that field because it looked meaningful
but was not used by the agent.

Task IDs are globally indexed in the kernel store. The timestamp keeps
this quickstart easy to rerun without colliding with an older
`greeter` task in the same data dir.

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
raxis plan validate "$PLAN_PATH"
# expected: a list of [OK] lines and exit 0.

# Sign + submit atomically. The CLI builds the canonical byte array,
# signs it with your operator key, and ships (bundle, signature) to
# the kernel over IPC. No `plan.sig` file is produced (V2 sealed-bundle
# admission per specs/v2/plan-bundle-sealing.md §4).
INIT_ID="$(raxis submit plan "$PLAN_PATH" --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
echo "INIT_ID=$INIT_ID"

raxis plan approve "$INIT_ID"
# expected: "tasks_admitted: 1"
```

---

## 8 · Watch it run

```bash
raxis initiative show "$INIT_ID" --with-tasks
```

The Orchestrator boots first, picks up the `$RAXIS_TASK_ID` task, and
spawns the Executor VM. The Executor edits `HELLO.md`, commits, and submits
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
# $RAXIS_TASK_ID: Completed

# 2. The audit chain has the lifecycle events.
raxis log "$INIT_ID" --kind InitiativeCreated --limit 1
raxis log "$INIT_ID" --kind PlanApproved      --limit 1
raxis log "$INIT_ID" --kind TaskCompleted     --limit 1
raxis log "$INIT_ID" --kind IntegrationMergeCompleted --limit 1

# 3. The chain still verifies end-to-end.
raxis verify-chain
# expected: non-zero record count, zero gaps, ok

# 4. `main` advanced to the Executor's commit and the file is there.
git -C "$RAXIS_MAIN_REPO" log --oneline -5
git -C "$RAXIS_MAIN_REPO" show main:HELLO.md

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
rm -f "$PLAN_PATH"
# Optional — reset the demo repo for another scenario:
# rm -rf "$RAXIS_MAIN_REPO"
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
- [`specs/v2/release-and-distribution.md`](../../specs/v2/release-and-distribution.md)
  — what the Homebrew release ships on the V2 surface today.
