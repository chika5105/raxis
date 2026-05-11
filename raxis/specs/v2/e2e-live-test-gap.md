# RAXIS V2 Full E2E Live Test Specification

> **Status:** Gap document — prerequisites listed in §9 must land first.
> **Deliverable:** `kernel/tests/full_e2e_session_lifecycle.rs`
> **Gate:** `RAXIS_LIVE_E2E=1` — **never runs in CI/CD**.
> **Last updated:** 2026-05-08

---

## §1 — Objective

One integration test — `full_session_lifecycle` — exercising the
complete operator → kernel → agent → verifier → merge chain with
**zero mocks**. Every component uses its production code path.

---

## §2 — Infrastructure Setup

### §2.1 — Docker Compose File

Create `live-e2e/docker-compose.e2e.yml`:

```yaml
# live-e2e/docker-compose.e2e.yml
# Dedicated infrastructure for the full E2E lifecycle test.
# Ports are offset from defaults to avoid collisions.
version: "3.9"

services:
  postgres:
    image: postgres:16-alpine
    container_name: raxis-e2e-pg
    ports:
      - "54399:5432"
    environment:
      POSTGRES_USER: raxis_test
      POSTGRES_PASSWORD: raxis_test_pass
      POSTGRES_DB: raxis_e2e
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U raxis_test -d raxis_e2e"]
      interval: 2s
      timeout: 5s
      retries: 10
    tmpfs:
      - /var/lib/postgresql/data  # ephemeral — no persistence needed

  mongodb:
    image: mongo:7
    container_name: raxis-e2e-mongo
    command: ["--auth"]
    ports:
      - "27399:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: raxis_test
      MONGO_INITDB_ROOT_PASSWORD: raxis_test_pass
    healthcheck:
      test: >
        mongosh --quiet --eval
        "db.adminCommand('ping').ok"
        -u raxis_test -p raxis_test_pass
        --authenticationDatabase admin
      interval: 2s
      timeout: 5s
      retries: 10
    tmpfs:
      - /data/db
```

### §2.2 — Host Networking

Both containers bind to **`127.0.0.1`** on the host via the `ports`
mapping. The RAXIS kernel and its credential proxies also bind to
`127.0.0.1:0`. All connections stay on loopback — no bridge
networking, no DNS resolution. This mirrors the production
`credential-proxy.md §6` locality invariant.

```
Host loopback (127.0.0.1)
├── :54399 → Docker Postgres (container port 5432)
├── :27399 → Docker MongoDB  (container port 27017)
├── :<dyn>  → PG Proxy       (kernel-bound, ephemeral port)
├── :<dyn>  → Mongo Proxy    (kernel-bound, ephemeral port)
├── :<dyn>  → GCP Proxy      (kernel-bound, ephemeral port)
└── :<dyn>  → Gateway        (kernel-bound, UDS or ephemeral TCP)
```

### §2.3 — Startup / Teardown Commands

```bash
# Start infrastructure (wait for healthy)
docker compose -f live-e2e/docker-compose.e2e.yml up -d --wait

# Verify
docker compose -f live-e2e/docker-compose.e2e.yml ps
# Both services must show "healthy"

# Run the test
RAXIS_LIVE_E2E=1 cargo test -p raxis-kernel \
  --test full_e2e_session_lifecycle -- --nocapture

# Teardown
docker compose -f live-e2e/docker-compose.e2e.yml down -v
```

---

## §3 — Credential Files

All credential files live under `<kernel_data_dir>/credentials/`.
The test creates them programmatically before plan submission.

### §3.1 — `test-pg-dev.env`

```env
# Postgres connection details for the Docker instance.
# The proxy reads these to connect upstream.
PGHOST=127.0.0.1
PGPORT=54399
PGUSER=raxis_test
PGPASSWORD=raxis_test_pass
PGDATABASE=raxis_e2e
PGSSLMODE=disable
```

**Proxy behaviour:** `PostgresProxy` reads `PGHOST`/`PGPORT`/
`PGUSER`/`PGPASSWORD` from the credential value. The agent-side
connection uses dummy credentials (the proxy intercepts
`AuthenticationOk`); the proxy uses real credentials upstream.

### §3.2 — `test-mongo-dev.env`

```env
# MongoDB connection URI with SCRAM-SHA-256 credentials.
# The proxy parses this as a mongodb:// URI to extract
# host, port, username, password, and authSource.
MONGO_HOST=127.0.0.1
MONGO_PORT=27399
MONGO_USER=raxis_test
MONGO_PASSWORD=raxis_test_pass
MONGO_AUTH_DB=admin
MONGO_DATABASE=raxis_e2e
```

**Proxy behaviour:** `MongodbProxy` must complete the SCRAM-SHA-256
4-message handshake (`SASLStart → ServerFirst → SASLContinue →
ServerFinal`) with the upstream Docker MongoDB. This is the
**acceptance criterion for V2_GAPS B3 (MongoDB auth gap)**.

### §3.3 — `test-gcp-dev.json`

Copied verbatim from `~/.config/gcloud/application_default_credentials.json`
(created by `gcloud auth application-default login`). The proxy
reads the `client_id`, `client_secret`, and `refresh_token` fields
to mint short-lived access tokens via Google's OAuth2 token endpoint.

```rust
// In-test credential injection
let adc_path = dirs::home_dir().unwrap()
    .join(".config/gcloud/application_default_credentials.json");
assert!(adc_path.exists(),
    "Run `gcloud auth application-default login` first");
std::fs::copy(&adc_path, cred_dir.join("test-gcp-dev.json")).unwrap();
```

### §3.4 — Anthropic API Key

Read from `raxis/.env` (already exists on the operator's machine):

```env
# raxis/.env (operator-managed, git-ignored)
ANTHROPIC-API-DEV-KEY=sk-ant-api03-...
```

The test reads this at startup and injects it into the gateway's
provider config:

```rust
let dotenv = std::fs::read_to_string(
    project_root.join(".env")
).expect(".env not found in project root");
let api_key = dotenv.lines()
    .find(|l| l.starts_with("ANTHROPIC-API-DEV-KEY="))
    .and_then(|l| l.strip_prefix("ANTHROPIC-API-DEV-KEY="))
    .expect("ANTHROPIC-API-DEV-KEY not found in .env");
```

---

## §4 — Plan File (`plan.toml`)

The test submits this plan via the operator IPC socket. The shape
below matches the kernel's actual plan parser
(`kernel/src/initiatives/lifecycle.rs::parse_plan_*`) verbatim.

> **Spec drift note (2026-05-10).** Earlier drafts of this spec
> showed top-level `[plan]` (`name`, `version`) and `[plan.gateway]`
> (`provider`, `model`) blocks. Those keys are NOT recognised by
> the kernel's plan parser — they are inert when included. The
> provider/model selection is operator-side state pinned in the
> policy's `[gateway]` + `[[providers]]` blocks
> (`peripherals.md §3.2`); the test injects them into the
> bootstrapped policy.toml in `enable_gateway_in_policy`. The
> `[workspace] lane_id` field is REQUIRED by
> `validate_single_lane_propagation`; every `[[tasks]]` block must
> declare a non-empty `description` per `v2_extended_gaps.md §1.1`.

```toml
[plan.initiative]
description = """
Create hello.txt containing the text "Hello from RAXIS E2E test!".
Use the executor's edit_file tool. Confirm completion via task_complete.
"""

[workspace]
name    = "E2E live test"
lane_id = "e2e-live-lane"

# ── Executor task ──────────────────────────────────────
[[tasks]]
task_id            = "write-hello"
name               = "Create hello.txt with a greeting"
session_agent_type = "Executor"
path_allowlist     = ["hello.txt"]
description = """
Create a file called hello.txt containing the text:
Hello from RAXIS E2E test!
"""

  [[tasks.credentials]]
  name       = "test-pg-dev"
  proxy_type = "postgres"
  mount_as   = "DATABASE_URL"

  [[tasks.credentials]]
  name       = "test-mongo-dev"
  proxy_type = "mongodb"
  mount_as   = "MONGO_URL"

  [[tasks.credentials]]
  name       = "test-gcp-dev"
  proxy_type = "gcp"
  mount_as   = "GCP_METADATA_URL"

# ── Reviewer task ──────────────────────────────────────
[[tasks]]
task_id            = "review-hello"
name               = "Review hello.txt changes"
session_agent_type = "Reviewer"
predecessors       = ["write-hello"]
description = """
Confirm that hello.txt was created with the expected content. Approve.
"""

# ── Verifier (deferred) ────────────────────────────────
# V2 verifier dispatch is exercised by the per-proxy live-e2e
# slices; folding it in here would gate the test on yet another
# canonical image (`raxis-verifier-default-…`). When the canonical
# verifier image lands, add:
#
# [[verifiers]]
# id         = "check-hello"
# command    = "test -f hello.txt && grep -q 'Hello' hello.txt"
# task_ids   = ["write-hello"]
# on_failure = "block_review"
# timeout    = "30s"
```

### §4.1 — Plan Admission Checks Exercised

| Check | What it validates |
|---|---|
| `DuplicateMountAs` | `DATABASE_URL`, `MONGO_URL`, `GCP_METADATA_URL` are all unique |
| Path-allowlist | Only `hello.txt` is writable by the executor |
| DAG construction | `review-hello` depends on `write-hello` |
| Credential resolution | All three credential names exist in `<data_dir>/credentials/` |
| Verifier parsing | `check-hello` binds to `write-hello` with `block_review` semantics |

---

## §5 — Provider Configuration

Provider configuration is split between the policy (which providers
are permitted, with what budget / timeouts) and the credentials
file (the API key bytes, isolated under mode 0600).

### §5.1 — Policy-side `[gateway]` + `[[providers]]`

The bootstrapped genesis `policy.toml` ships these blocks COMMENTED
OUT (`crates/genesis-tools::render_genesis_policy_toml`). The test's
`enable_gateway_in_policy` helper rewrites the file post-bootstrap
to enable them. The kernel's `load_policy` does NOT verify a
signature on the policy file at boot — signature verification only
fires inside `policy_manager::advance_epoch` (the runtime
epoch-rotation path) — so the post-bootstrap mutation persists
across the second `Command::new(kernel_bin).spawn()`.

```toml
[gateway]
binary_path              = "/abs/path/to/raxis-gateway"  # = $RAXIS_GATEWAY_BINARY
spawn_timeout_secs       = 30
respawn_backoff_ms       = 1000
max_consecutive_respawns = 5

[[providers]]
provider_id           = "anthropic-e2e"
kind                  = "Anthropic"
credentials_file      = "anthropic-e2e.toml"
inference_timeout_ms  = 120000
data_fetch_timeout_ms = 30000
pricing.input_tokens_per_dollar      = 200_000
pricing.output_tokens_per_dollar     = 50_000
pricing.cache_read_tokens_per_dollar = 2_000_000
```

### §5.2 — Credentials file

The gateway resolves `[[providers]].credentials_file` against
`<data_dir>/providers/<file>` via `FileCredentialBackend`
(`raxis/gateway/src/policy_view.rs::load_provider_credentials`).
The wire shape is the canonical `ProviderCredentials` flat TOML;
Anthropic uses a custom `auth_header` and empty `auth_prefix`.
Mode 0600 is mandated by `peripherals.md §3.2`.

```toml
# <data_dir>/providers/anthropic-e2e.toml
api_key     = "sk-ant-..."   # injected from raxis/.env at test time
auth_header = "x-api-key"
auth_prefix = ""
```

---

## §6 — System Prompts

### §6.1 — Executor NNSP (injected by kernel)

The executor receives this Non-Negotiable System Prompt via the
kernel's KSB (Kernel State Block) injection:

```
You are a RAXIS executor agent. Your task is described below.
You have access to the following tools: read_file, edit_file, bash.
You MUST only modify files within your path allowlist: ["hello.txt"].
Any attempt to modify files outside this list will be rejected.

Your credential proxies are available at:
  DATABASE_URL=postgresql://raxis@127.0.0.1:<pg_proxy_port>/raxis_e2e
  MONGO_URL=mongodb://raxis@127.0.0.1:<mongo_proxy_port>/raxis_e2e
  GCP_METADATA_URL=http://127.0.0.1:<gcp_proxy_port>

Task: Create hello.txt with a greeting
Description: Create a file called hello.txt containing the text:
Hello from RAXIS E2E test!
```

### §6.2 — Reviewer NNSP

```
You are a RAXIS reviewer agent. You are reviewing changes made by
task "write-hello". You must evaluate the diff and verifier results,
then submit your verdict: Approve, RequestChanges, or Reject.

Diff:
<kernel injects the actual git diff here>

Verifier results:
  check-hello: PASSED (exit code 0)

Submit your verdict using the review_verdict tool.
```

---

## §7 — Test Steps (with file paths and assertions)

### §7.1 — Scaffolding

**File:** `kernel/tests/full_e2e_session_lifecycle.rs`

```rust
mod common;
use common::kernel_harness::{KernelInstance, acquire_test_lock};
use std::time::Duration;

#[test]
fn full_session_lifecycle() {
    if std::env::var("RAXIS_LIVE_E2E").as_deref() != Ok("1") {
        eprintln!(
            "Skipped: set RAXIS_LIVE_E2E=1 and start infrastructure:\n\
             docker compose -f live-e2e/docker-compose.e2e.yml up -d --wait"
        );
        return;
    }
    let _lock = acquire_test_lock();
    // ... steps 7.2–7.13
}
```

### §7.2 — Bootstrap Kernel

```rust
let kernel = KernelInstance::bootstrap_and_spawn();
kernel.wait_until_ready_or_panic(Duration::from_secs(15));
```

**Creates:**
- `<data_dir>/kernel.db` (SQLite store)
- `<data_dir>/audit/segment-000.jsonl`
- `<data_dir>/sockets/operator.sock`
- `<data_dir>/sockets/planner.sock`
- `<data_dir>/runtime/heartbeat.json`
- `<data_dir>/keys/` (Ed25519 key registry)

**Assert:** stderr contains `"event":"sockets_bound"`.

### §7.3 — Inject Credentials + Pre-flight

```rust
let cred_dir = kernel.data_dir().join("credentials");
std::fs::create_dir_all(&cred_dir).unwrap();

// §3.1 — Postgres
std::fs::write(cred_dir.join("test-pg-dev.env"), "\
PGHOST=127.0.0.1\n\
PGPORT=54399\n\
PGUSER=raxis_test\n\
PGPASSWORD=raxis_test_pass\n\
PGDATABASE=raxis_e2e\n\
PGSSLMODE=disable\n").unwrap();

// §3.2 — MongoDB
std::fs::write(cred_dir.join("test-mongo-dev.env"), "\
MONGO_HOST=127.0.0.1\n\
MONGO_PORT=27399\n\
MONGO_USER=raxis_test\n\
MONGO_PASSWORD=raxis_test_pass\n\
MONGO_AUTH_DB=admin\n\
MONGO_DATABASE=raxis_e2e\n").unwrap();

// §3.3 — GCP (copy ADC)
let adc = dirs::home_dir().unwrap()
    .join(".config/gcloud/application_default_credentials.json");
assert!(adc.exists(), "Run: gcloud auth application-default login");
std::fs::copy(&adc, cred_dir.join("test-gcp-dev.json")).unwrap();

// §3.4 — Anthropic (read from .env, write provider config)
// ... (see §5 for provider file content)

// Pre-flight checks
assert!(std::net::TcpStream::connect("127.0.0.1:54399").is_ok(),
    "Postgres not reachable. Run: docker compose -f \
     live-e2e/docker-compose.e2e.yml up -d --wait");
assert!(std::net::TcpStream::connect("127.0.0.1:27399").is_ok(),
    "MongoDB not reachable. Run: docker compose -f \
     live-e2e/docker-compose.e2e.yml up -d --wait");
```

### §7.4 — Submit Plan + Operator Validation

Send `ApprovePlan` IPC frame containing the plan from §4.

**Assert:**
- IPC response `Ok { initiative_id }`
- Audit: `InitiativeCreated { plan_name: "e2e-live-test" }`
- DB: initiative row with `state = "Approved"`

**Operator CLI validation (run from a second terminal):**

```bash
# Verify kernel is running and plan was accepted
raxis status --json --data-dir <data_dir>
# Expected: { "liveness": "running", "initiatives": 1,
#             "active_sessions": 0, "pending_escalations": 0 }

raxis initiative list --data-dir <data_dir>
# Expected: e2e-live-test | Approved | 0/2 tasks complete
```

### §7.5 — Orchestrator Spawn + LLM Interaction

Kernel auto-spawns orchestrator. The orchestrator's planner loop:

1. Receives KSB from kernel (task DAG, credentials, constraints)
2. Calls Anthropic with this system prompt:

```
[NNSP — Non-Negotiable System Prompt]
You are a RAXIS orchestrator. You manage task execution for
initiative "e2e-live-test". Your available tasks:

  - write-hello (Executor) — Create hello.txt. Status: Pending.
  - review-hello (Reviewer) — Review hello.txt. Depends on: write-hello.

Activate tasks using the activate_task tool. You MUST activate
write-hello first because review-hello depends on it.
```

3. Anthropic responds with a `tool_use` block:

```json
{
  "role": "assistant",
  "content": [{
    "type": "tool_use",
    "id": "toolu_01...",
    "name": "activate_task",
    "input": { "task_id": "write-hello" }
  }]
}
```

4. Planner loop translates `activate_task` → `IpcMessage::IntentSubmission { kind: "SpawnExecutor", task_id: "write-hello" }`
5. Kernel admits the intent → spawns executor session

**Assert:**
- Audit: `SessionStarted { role: "orchestrator" }`
- Audit: `CredentialProxyStarted { proxy_type: "postgres" }`
- Audit: `CredentialProxyStarted { proxy_type: "mongodb" }`
- Audit: `CredentialProxyStarted { proxy_type: "gcp" }`
- Audit: `SessionStarted { role: "executor", task_id: "write-hello" }`
- DB: task `write-hello` state = `Running`

**Operator CLI validation:**

```bash
raxis sessions --data-dir <data_dir>
# Expected:
# SESSION_ID | ROLE         | TASK         | STATUS
# <uuid>     | orchestrator | —            | Running
# <uuid>     | executor     | write-hello  | Running

raxis status --json --data-dir <data_dir>
# Expected: "active_sessions": 2
```

### §7.6 — Executor Tool Calls (Real LLM)

The executor's planner loop calls Anthropic with the NNSP from §6.1.
Expected LLM interaction sequence:

**Turn 1 — LLM decides to create the file:**

```json
// Request to Anthropic (POST /v1/messages)
{
  "model": "claude-sonnet-4-20250514",
  "max_tokens": 4096,
  "system": "<NNSP from §6.1>",
  "messages": [{
    "role": "user",
    "content": "Execute your assigned task."
  }],
  "tools": [
    {
      "name": "edit_file",
      "description": "Create or edit a file. Path must be in allowlist.",
      "input_schema": {
        "type": "object",
        "properties": {
          "path": { "type": "string" },
          "content": { "type": "string" }
        },
        "required": ["path", "content"]
      }
    },
    {
      "name": "read_file",
      "description": "Read file contents.",
      "input_schema": {
        "type": "object",
        "properties": { "path": { "type": "string" } },
        "required": ["path"]
      }
    },
    {
      "name": "bash",
      "description": "Run a shell command.",
      "input_schema": {
        "type": "object",
        "properties": { "command": { "type": "string" } },
        "required": ["command"]
      }
    },
    {
      "name": "task_complete",
      "description": "Signal task completion.",
      "input_schema": {
        "type": "object",
        "properties": { "summary": { "type": "string" } },
        "required": ["summary"]
      }
    }
  ]
}
```

**Turn 1 — LLM response (tool_use):**

```json
{
  "content": [{
    "type": "tool_use",
    "name": "edit_file",
    "input": {
      "path": "hello.txt",
      "content": "Hello from RAXIS E2E test!\n"
    }
  }]
}
```

Planner loop translates `edit_file` → `IpcMessage::IntentSubmission { kind: "TodoWrite", path: "hello.txt", content: "Hello from RAXIS E2E test!\n" }`.

Kernel admits (path `hello.txt` is in allowlist) → stages file → creates git commit.

**Turn 2 — Tool result returned to LLM:**

```json
{
  "role": "user",
  "content": [{
    "type": "tool_result",
    "tool_use_id": "toolu_01...",
    "content": "File hello.txt created successfully."
  }]
}
```

**Turn 2 — LLM response (task_complete):**

```json
{
  "content": [{
    "type": "tool_use",
    "name": "task_complete",
    "input": {
      "summary": "Created hello.txt with greeting text."
    }
  }]
}
```

Planner loop translates `task_complete` → `IpcMessage::IntentSubmission { kind: "TaskComplete", task_id: "write-hello" }`.

**Assert:**
- Audit: `IntentAdmitted { kind: "TodoWrite", path: "hello.txt" }`
- Audit: `IntentAdmitted { kind: "TaskComplete" }`
- Worktree: `hello.txt` exists, contains "Hello"
- Git: commit with `hello.txt` staged
- DB: task state = `PendingVerification`

### §7.7 — Verifier Dispatch + Witness

Kernel automatically dispatches `check-hello` verifier (command:
`test -f hello.txt && grep -q 'Hello' hello.txt`).

The verifier runs as a subprocess in the executor's worktree.
Exit code 0 → `WitnessSubmission { passed: true }` → gate
re-evaluation → task transitions to `PendingReview`.

**Assert:**
- Audit: `VerifierDispatched { verifier_id: "check-hello" }`
- Audit: `WitnessArrived { verifier_id: "check-hello", passed: true }`
- DB: task state = `PendingReview`

**Operator CLI validation:**

```bash
raxis verifiers --data-dir <data_dir>
# Expected:
# VERIFIER     | TASK        | STATUS | EXIT_CODE
# check-hello  | write-hello | Passed | 0

raxis witnesses --data-dir <data_dir>
# Expected:
# WITNESS_ID | VERIFIER    | PASSED | TIMESTAMP
# <uuid>     | check-hello | true   | 2026-05-08T...
```

### §7.8 — Reviewer Session (Real LLM Review)

Kernel spawns reviewer for `review-hello`. The reviewer's planner
loop receives the KSB containing the diff and verifier results.

**Anthropic request:**

```json
{
  "model": "claude-sonnet-4-20250514",
  "max_tokens": 4096,
  "system": "<NNSP from §6.2 with real diff + witness results>",
  "messages": [{
    "role": "user",
    "content": "Review the changes and submit your verdict."
  }],
  "tools": [{
    "name": "review_verdict",
    "description": "Submit review verdict: approve, request_changes, or reject.",
    "input_schema": {
      "type": "object",
      "properties": {
        "verdict": {
          "type": "string",
          "enum": ["approve", "request_changes", "reject"]
        },
        "rationale": { "type": "string" }
      },
      "required": ["verdict", "rationale"]
    }
  }]
}
```

**Expected LLM response:**

```json
{
  "content": [{
    "type": "tool_use",
    "name": "review_verdict",
    "input": {
      "verdict": "approve",
      "rationale": "File hello.txt created with correct content. Verifier passed."
    }
  }]
}
```

Planner loop translates → `IpcMessage::ReviewVerdict { task_id: "write-hello", verdict: Approve, rationale: "..." }`.

**Assert:**
- Audit: `SessionStarted { role: "reviewer" }`
- Audit: `ReviewVerdictSubmitted { verdict: "approve" }`
- DB: task state = `Approved`

**Operator CLI validation:**

```bash
raxis status --json --data-dir <data_dir>
# Expected: all tasks approved, pending merge

raxis inbox --data-dir <data_dir>
# Expected: notification that review-hello completed with verdict=approve
# (only if Shell/File notification channels are configured — the E2E
#  plan omits [[notifications]] so inbox may be empty, which is valid)
```

### §7.9 — Pre-Merge Operator Validation

Before the orchestrator submits `IntegrationMerge`, the operator
can inspect the full state:

```bash
# Check all tasks are approved
raxis initiative list --data-dir <data_dir>
# Expected: e2e-live-test | MergeReady | 1/1 tasks approved

# Check no pending escalations
raxis escalations --data-dir <data_dir>
# Expected: No pending escalations.

# Check inbox for any warnings
raxis inbox --data-dir <data_dir>
# Expected: empty or informational notifications only

# Inspect the diff that will be merged
raxis inspect --kind worktree --initiative <id> --data-dir <data_dir>
# Expected: shows hello.txt diff

# Verify audit chain integrity before merge
raxis verify-chain --data-dir <data_dir>
# Expected: "Chain integrity: OK (N events, no gaps)"
```

### §7.10 — Integration Merge

Orchestrator submits `IntegrationMerge` intent. Kernel runs
checks 1–5c from `integration-merge.md`:

1. All tasks in `Approved` state
2. All verifier witnesses present and passed
3. No pending escalations
4. Path-allowlist union covers all changed files
5. Merge commit attribution links to audit chain

**Assert:**
- Audit: `IntegrationMergeCompleted { initiative_id }`
- Git: merge commit in log with RAXIS attribution trailer
- DB: initiative state = `Merged`

**Operator CLI validation (post-merge):**

```bash
raxis initiative list --data-dir <data_dir>
# Expected: e2e-live-test | Merged | 1/1 tasks merged

raxis status --json --data-dir <data_dir>
# Expected: "active_sessions": 0 (all sessions terminated)
```

### §7.12 — Credential Proxy Verification

**Postgres (real upstream query through proxy):**

```rust
// Connect through proxy — NOT directly to Docker
let pg_url = format!(
    "postgresql://raxis@127.0.0.1:{}/raxis_e2e",
    pg_proxy_port
);
let (client, conn) = tokio_postgres::connect(
    &pg_url, tokio_postgres::NoTls
).await.unwrap();
tokio::spawn(conn);

client.execute(
    "CREATE TABLE IF NOT EXISTS e2e_test (id SERIAL, val TEXT)", &[]
).await.unwrap();
client.execute(
    "INSERT INTO e2e_test (val) VALUES ($1)", &["raxis-e2e"]
).await.unwrap();
let rows = client.query(
    "SELECT val FROM e2e_test WHERE val = $1", &["raxis-e2e"]
).await.unwrap();
assert_eq!(rows[0].get::<_, String>(0), "raxis-e2e");
client.execute("DROP TABLE e2e_test", &[]).await.unwrap();
```

**MongoDB (real upstream with SCRAM-SHA-256 through proxy):**

```rust
// Connect through proxy — exercises SCRAM-SHA-256 handshake
let mongo_url = format!(
    "mongodb://raxis@127.0.0.1:{}/raxis_e2e",
    mongo_proxy_port
);
let client = mongodb::Client::with_uri_str(&mongo_url)
    .await.unwrap();
let db = client.database("raxis_e2e");
let coll = db.collection::<bson::Document>("e2e_test");

coll.insert_one(
    bson::doc! { "key": "raxis-e2e", "ts": bson::DateTime::now() },
    None,
).await.unwrap();
let found = coll.find_one(
    bson::doc! { "key": "raxis-e2e" }, None
).await.unwrap();
assert_eq!(
    found.unwrap().get_str("key").unwrap(),
    "raxis-e2e"
);
coll.drop(None).await.unwrap();
```

**GCP (real token from gcloud ADC):**

```rust
let resp = reqwest::blocking::Client::new()
    .get(format!(
        "http://127.0.0.1:{}/computeMetadata/v1/\
         instance/service-accounts/default/token",
        gcp_proxy_port,
    ))
    .header("Metadata-Flavor", "Google")
    .send().unwrap();
assert_eq!(resp.status(), 200);
let body: serde_json::Value = resp.json().unwrap();
assert_eq!(body["token_type"], "Bearer");
assert!(!body["access_token"].as_str().unwrap().is_empty());
```

### §7.13 — Graceful Shutdown

```rust
let status = kernel.shutdown_with(
    libc::SIGTERM, Duration::from_secs(30)
);
assert!(status.success());
```

### §7.14 — Post-Mortem Audit Chain

**File:** `<data_dir>/audit/segment-000.jsonl`

| # | Event | Key fields |
|---|---|---|
| 1 | `KernelBootCompleted` | `policy_epoch` |
| 2 | `InitiativeCreated` | `plan_name: "e2e-live-test"` |
| 3 | `SessionStarted` | `role: "orchestrator"` |
| 4 | `CredentialProxyStarted` | `proxy_type: "gcp"` |
| 5 | `CredentialProxyStarted` | `proxy_type: "postgres"` |
| 6 | `CredentialProxyStarted` | `proxy_type: "mongodb"` |
| 7 | `SessionStarted` | `role: "executor"` |
| 8 | `IntentAdmitted` | `kind: "TodoWrite"` |
| 9 | `IntentAdmitted` | `kind: "TaskComplete"` |
| 10 | `VerifierDispatched` | `verifier_id: "check-hello"` |
| 11 | `WitnessArrived` | `passed: true` |
| 12 | `SessionStarted` | `role: "reviewer"` |
| 13 | `ReviewVerdictSubmitted` | `verdict: "approve"` |
| 14 | `IntegrationMergeCompleted` | `initiative_id` |
| 15 | `GcpCredentialServed` | `blocked: false` |
| 16 | `QueryAudited` | `proxy_type: "postgres"` |
| 17 | `QueryAudited` | `proxy_type: "mongodb"` |
| 18 | `CredentialProxyStopped` | `credentials_served: ≥1` (×3) |
| 19 | `KernelShutdown` | `exit: "graceful"` |

**Chain integrity assertions:**
- `seq` strictly monotonically increasing (no gaps)
- Every `prev_sha256` = SHA-256 of prior event's bytes
- No `SecurityViolationDetected` events
- No `blocked: true` events

---

## §8 — Components Exercised

| Component | Crate | Step |
|---|---|---|
| Kernel bootstrap | `raxis-kernel` | 7.2 |
| Operator IPC | `raxis-kernel` | 7.4 |
| Plan parser + `DuplicateMountAs` | `raxis-plan-credentials` | 7.4 |
| Policy admission | `raxis-policy` | 7.4, 7.6 |
| Task DAG | `raxis-kernel` | 7.4 |
| Session spawn | `raxis-session-spawn` | 7.5, 7.6, 7.10 |
| Apple VZ isolation | `raxis-isolation-apple-vz` | 7.5, 7.6, 7.10 |
| Credential proxy manager | `raxis-credential-proxy-manager` | 7.5, 7.12 |
| Postgres proxy (upstream) | `raxis-credential-proxy-postgres` | 7.12 |
| MongoDB proxy (SCRAM + upstream) | `raxis-credential-proxy-mongodb` | 7.12 |
| GCP metadata proxy | `raxis-credential-proxy-gcp` | 7.12 |
| File credential backend | `raxis-credentials-file` | 7.3 |
| Gateway → Anthropic | `raxis-gateway-substrate` | 7.6, 7.7, 7.10 |
| Planner agent loop | `raxis-planner-*` | 7.6, 7.7, 7.10 |
| Intent admission (13-step) | `raxis-kernel` | 7.6–7.11 |
| Worktree provision | `raxis-worktree-provision` | 7.6 |
| Worktree staging + commit | `raxis-worktree-staging` | 7.7 |
| Verifier dispatch | `raxis-kernel` | 7.9 |
| Witness handler | `raxis-kernel` | 7.9 |
| Reviewer verdict | `raxis-kernel` | 7.10 |
| Integration merge | `raxis-kernel` | 7.11 |
| Audit writer + verifier | `raxis-audit-tools` | 7.14 |
| Store (SQLite) | `raxis-store` | All |
| Crypto (Ed25519) | `raxis-crypto` | 7.2 |
| IPC framing | `raxis-ipc` | 7.4–7.11 |
| Signal handling | `raxis-kernel` | 7.13 |

**Coverage:** 31 of 35 workspace crates.

---

## §9 — Blockers (Implementation Order)

### §9.1 — Critical Path

| # | Gap | V2_GAPS | Est. lines | What's missing |
|---|---|---|---|---|
| 1 | **B1: Planner agent loop** | §3 B1 | ~2,600 | Model API client, tool registry (`read_file`, `bash`, `edit_file`), tool dispatch loop, intent submission, KSB renderer |
| 2 | **T0-1: Session spawn handler** | §6 | ~400 | Kernel can't spawn sessions yet |
| 3 | **Gateway → Anthropic HTTP client** | §3 B1 | ~400 | `gateway-substrate` has config types, no HTTP client |
| 4 | **Apple VZ image builder** | — | ~300 | `isolation-apple-vz` exists, no image build tooling |

### §9.2 — Required for Full Chain

| # | Gap | V2_GAPS | Est. lines |
|---|---|---|---|
| 5 | B3: Postgres upstream forwarding | §3 B3 | ~200 |
| 6 | **B3: MongoDB SCRAM-SHA-256 + upstream** | §3 B3 | ~300 |
| 7 | B2: Base tool registry | §3 B2 | ~800 |
| 8 | GCP ADC → access token exchange | §3 B3 | ~100 |

### §9.3 — Implementation Order

```
1. B1  — Planner agent loop (model client + tool dispatch)
2. T0-1 — Session spawn handler
3. Gateway → Anthropic HTTP client
4. Apple VZ image builder
5. B3  — Postgres upstream forwarding
6. B3  — MongoDB SCRAM-SHA-256 + upstream relay
7. Write this test
8. Use test failures to find integration bugs
9. Green test = V2 core is functional
```

---

## §10 — What This Test Does NOT Cover

| Gap | Why | Coverage |
|---|---|---|
| Firecracker isolation | macOS dev → Apple VZ | Linux CI |
| MySQL/MSSQL upstream | Not in plan | Per-proxy live-e2e slices |
| Multi-task DAG parallelism | Single task sufficient | DAG-focused test |
| Retry after verifier failure | Happy path only | Retry-focused test |
| Cloud restriction enforcement | V2 Phase 2 | Restriction unit tests |
| Token limit enforcement | C1 gap | Separate test |
| Provider failover | C2 gap | Separate test |

---

## §11 — File Inventory

| File | Purpose | Created by |
|---|---|---|
| `live-e2e/docker-compose.e2e.yml` | Docker infrastructure | Operator (§2.1) |
| `raxis/.env` | `ANTHROPIC-API-DEV-KEY` | Operator (exists) |
| `~/.config/gcloud/application_default_credentials.json` | GCP ADC | `gcloud auth` |
| `<data_dir>/credentials/test-pg-dev.env` | PG creds | Test (§7.3) |
| `<data_dir>/credentials/test-mongo-dev.env` | Mongo creds | Test (§7.3) |
| `<data_dir>/credentials/test-gcp-dev.json` | GCP creds | Test (§7.3) |
| `<data_dir>/providers/anthropic.toml` | Gateway config | Test (§5) |
| `kernel/tests/full_e2e_session_lifecycle.rs` | Test file | Implementer |
