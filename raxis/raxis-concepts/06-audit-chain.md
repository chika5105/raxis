# RAXIS Audit Chain — End-to-End Explained

> **Audience.** Operators verifying the chain (`raxis audit verify`),
> incident responders investigating a tamper claim, and contributors
> adding a new `AuditEventKind`.
>
> **Authority.** Wire format and chain rules are normative in
> `specs/v1/kernel-store.md` §2.5.2 ("Audit log transaction
> boundary"). The runtime is the `crates/audit/` crate.
>
> **Paradigm anchor.** The audit chain is the implementation of
> **R-9 — Tamper-evident provenance**: every privileged kernel
> decision is recorded with a hash that links it to the previous
> record, so the operator (or recovery code, or a forensics tool)
> can detect any post-hoc edit, gap, or reorder.

---

## What is the audit chain?

The audit chain is a **tamper-evident, append-only log** of every
privileged kernel decision: every intent admission/rejection, every
delegation grant, every credential proxy query, every escalation,
every verifier run, every policy epoch advance — all serialised as
JSON Lines (`.jsonl`) with a SHA-256 link to the **raw bytes** of
the previous line.

If any record is mutated after the fact (or the file is truncated,
or a record reordered), the SHA-256 link breaks at exactly that
record and `raxis audit verify` reports the offending line number.

---

## Step 1: How events are emitted

Every audit-worthy state transition in the kernel calls a single
trait method:

```rust
audit_sink.emit(
    AuditEventKind::IntentAccepted { /* … */ },
    session_id,        // Option<&str>
    task_id,           // Option<&str>
    initiative_id,     // Option<&str>
)?;
```

The trait (verified against `crates/audit/src/sink.rs`):

```rust
pub trait AuditSink: Send + Sync {
    fn emit(
        &self,
        kind:          AuditEventKind,
        session_id:    Option<&str>,
        task_id:       Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<AuditEvent, AuditWriterError>;
}
```

> **⚠️ Earlier drafts of this doc described a `details: Option<&str>`
> 4th argument and a `Result<(), …>` return. Both are wrong.** The
> 4th arg is `initiative_id` and the method returns the materialised
> `AuditEvent` (carrying the freshly-assigned `seq` and `event_id`)
> so callers can correlate downstream notifications with the chain
> record they emitted.

**Ordering invariant (INV-AUDIT-PAIRED-01).** Every `emit` call
**MUST** come *after* the corresponding SQLite transaction has
returned `Ok(())`. There is no compile-time enforcement of this
rule — the kernel review process treats any `audit.emit(..)` inside
an open transaction as a P0 spec violation.

---

## Step 2: Event kinds (selection)

The `AuditEventKind` enum is large. The major families:

| Family | Representative variants | Triggered when |
|---|---|---|
| Intent lifecycle | `IntentAccepted`, `IntentRejected`, `TaskStateChanged` | After admission Phase C commits |
| Session lifecycle | `SessionCreated`, `SessionRevoked`, `SessionExpired` | Session spawn/revocation/timeout sweep |
| Delegation lifecycle | `DelegationGranted`, `DelegationStaleSet`, `DelegationSignatureUnverifiable` | Operator grants, epoch advances, recovery |
| Gate evaluation | `GateEvaluated`, `VerifierSpawned`, `WitnessRecorded` | Phase B of admission |
| Credential proxies | `CredentialProxyStarted`, `CredentialProxyStopped`, `DatabaseQueryExecuted`, `HttpProxyRequestExecuted`, `SmtpMessageRelayed` | Lifecycle and per-request paths in each proxy |
| Escalation | `EscalationCreated`, `EscalationApproved`, `EscalationDenied`, `EscalationConsumed` | Operator escalation flow |
| Break-glass | `BreakglassActivated`, `BreakglassExpired` | Emergency overrides |
| Budget | `BudgetReserved`, `BudgetReleased`, `TokenBudgetExceeded` | Lane admission and release |
| Policy | `PolicyEpochAdvanced`, `PolicyAdvanceRejected`, `PolicyAdvanceFailed` | `policy_manager::advance_epoch` |
| Push | `KernelPushEnqueued` | Per-session V2.3 dispatcher (see V2_GAPS §12.1) |
| Recovery | `ReconciliationGap` | Boot-time reconciler: gap between SQLite tail and JSONL tail |
| Security | `SecurityViolation { violation_class }` | Static dispatch matrix or pre-auth blocklist (see `SecurityViolationClass`) |

The full list lives in `crates/audit/src/event.rs::AuditEventKind`.
Adding a variant also requires updating
`crates/policy/src/bundle.rs::KNOWN_AUDIT_EVENT_KINDS` (a registry
fixture pinned by drift-guard tests).

---

## Step 3: At-rest format and chain hash

Each audit segment is a JSONL file under
`<RAXIS_DATA_DIR>/audit/audit-NNNN.jsonl`. Every line is a
serialised `AuditEvent`:

```json
{
  "seq":           42,
  "event_id":      "8b1d3f9e-…",
  "event_kind":    "IntentAccepted",
  "session_id":    "9c7e…",
  "task_id":       "task-build-auth",
  "initiative_id": "init-Q4-2026",
  "payload":       { /* event-kind-specific fields */ },
  "emitted_at":    1714500000,
  "prev_sha256":   "<64-hex-chars>"
}
```

**Chain hash rule (verified against `crates/audit/src/writer.rs`):**

> `prev_sha256` is `SHA-256` of the **raw bytes** of the previous
> JSONL line, **including the trailing `\n`**. The first record of
> any segment uses `"0" × 64` (`AuditWriter::GENESIS_PREV_SHA256`)
> as `prev_sha256`.

The hash is taken over the *entire prior line as written*, not over
a structured field tuple. This means re-serialising the previous
record with a different field order, whitespace, or numeric
representation breaks the chain — the bytes on disk are the
authoritative pre-image.

**Genesis segment.** The first segment opens with a special
`Genesis` record (see `crates/audit/src/genesis.rs`) that captures
the operator certificate fingerprint, kernel version, policy
SHA-256, and other root-of-trust facts. `recovery::reconcile`
refuses to run if no genesis record exists.

---

## Step 4: Chain verification

```bash
raxis audit verify --data-dir /var/lib/raxis
```

The verifier (`crates/audit/src/reader.rs`) runs:

1. Walk every segment file in lexicographic order.
2. For each line, parse JSON, capture `seq` and `prev_sha256`.
3. Compute `SHA-256(previous_line_bytes_with_newline)` and compare
   against the current line's `prev_sha256`.
4. Confirm `seq` increments by exactly 1 per line.
5. On mismatch, emit `ChainPrevSha256Break { line_number, expected, got }` or
   `ChainSequenceGap { line_number, expected, got }`.

A successful pass prints stats; a failure exits non-zero with the
offending line number so an incident responder can diff that line
against the kernel's local hot-cache or an external archive.

---

## Step 5: Crash recovery (`ReconciliationGap`)

Per INV-AUDIT-PAIRED-06, if the kernel crashes between an SQLite
commit and the corresponding JSONL append, the JSONL tail lags the
SQLite tail at boot. `recovery::reconcile`:

1. Reads the SQLite-side audit pointer (the highest `seq` recorded
   in the `audit_pointer` row).
2. Reads the JSONL tail by walking the latest segment.
3. If `jsonl_tail.seq < pointer.seq` it appends a single
   `ReconciliationGap { lost_seq_lo, lost_seq_hi }` record at
   `pointer.seq + 1`, with `prev_sha256` chained to the JSONL tail.
4. The chain is now consistent — `raxis audit verify` will pass.
5. The lost records are NOT recovered (the fact that they were
   committed is durable, but the structured payload is gone). The
   gap record is a forensic flag for the operator.

---

## Production vs test sinks

| Sink | Crate | Usage |
|---|---|---|
| `FileAuditSink` | `crates/audit/src/sink.rs` | Production. Wraps an `AuditWriter` behind a `std::sync::Mutex` (separate from the Store mutex per §2.5.2) |
| `FakeAuditSink` | `crates/test-support/src/audit_sink.rs` | Tests only (dev-dep). In-memory `Vec<AuditEvent>`; assertions inspect the buffer |

```rust
let sink = FakeAuditSink::new();
// run kernel operation under test …
let events = sink.events();
assert!(
    events.iter().any(|e| e.event_kind == "IntentAccepted"),
);
```

The `FakeAuditSink` lives in `raxis-test-support` (a dev-dep-only
crate by construction) — it cannot be linked into a release binary
even by accident.

---

## Edge cases

### 1. Audit write fails mid-intent

Per `kernel-store.md` §2.5.2, **lifecycle audit failure is fatal**:
the kernel aborts the ongoing operation rather than proceed with
an unaudited side-effect. This is the policy for session creation,
delegation grants, credential-proxy lifecycle, escalations,
policy epoch advances, and witness recording.

Per-request emissions (e.g. one `DatabaseQueryExecuted` per Postgres
query) deliberately use `tracing::warn!` on failure rather than
tearing down the session — see concept 03 §"Gap Found: Audit
Failure Handling". This is an explicit asymmetry; the lifecycle
events are the hard boundary.

### 2. Audit segment file is corrupted

`raxis audit verify` reports the exact line number and which
SHA-256 (or sequence number) failed. Operators can diff the
reported line against an off-host archive or the kernel's
`tracing` log buffer to attribute the corruption.

### 3. Disk full — kernel cannot append

`AuditWriter::append` returns `AuditWriterError::Io`. The kernel
surfaces this as a fatal error and refuses to admit further
intents until the operator frees space. Audit events are never
silently dropped.

### 4. Clock skew between records

`emitted_at` is advisory (operator-readable). Chain integrity
depends only on `seq` (kernel-monotonic) and `prev_sha256` (raw
prior line bytes). Time travel does not break the chain.

### 5. Two writers race for the same segment (forbidden)

INV-AUDIT-PAIRED-03 — only one `AuditWriter` per active segment.
The kernel constructs exactly one and never clones the handle.
Test harnesses must use a fresh data directory per test
(`crates/test-support/src/audit_dir.rs::TempAuditDir`) to avoid
sharing a writer across kernels.

---

## Key source files

| File | Role |
|---|---|
| `crates/audit/src/event.rs`              | `AuditEvent` (record), `AuditEventKind` (1 variant per family) |
| `crates/audit/src/sink.rs`               | `AuditSink` trait + production `FileAuditSink` |
| `crates/audit/src/writer.rs`             | `AuditWriter` (append-only segment writer), `AuditWriterError`, `last_chain_state` |
| `crates/audit/src/reader.rs`             | `verify_chain_full`, `verify_chain_from`, `quick_chain_check`, `ChainReader` |
| `crates/audit/src/genesis.rs`            | `write_genesis_segment` (one-shot bootstrap; refuses on existing genesis) |
| `crates/test-support/src/audit_sink.rs`  | `FakeAuditSink` for tests |
| `crates/test-support/src/audit_dir.rs`   | `TempAuditDir` test fixture |
| `cli/src/commands/audit.rs`              | `raxis audit verify` operator subcommand |
| `kernel/src/recovery.rs`                 | `ReconciliationGap` insertion (INV-AUDIT-PAIRED-06) |
| `crates/policy/src/bundle.rs`            | `KNOWN_AUDIT_EVENT_KINDS` registry pinned by drift-guard tests |
| `specs/v1/kernel-store.md` §2.5.2         | Normative wire format and write-ordering invariant |
