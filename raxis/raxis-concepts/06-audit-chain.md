# RAXIS Audit Chain — End-to-End Explained

## What is the audit chain?

The audit chain is a **tamper-evident log** of everything that happens in the kernel. Every intent, every delegation grant, every credential proxy query, every escalation, every verifier run — all recorded with hashes linking each entry to the previous one.

If any entry is modified after the fact, the chain breaks and verification fails.

---

## Step 1: How Events are Written

Every audit-worthy action in the kernel calls:

```rust
audit_sink.emit(
    AuditEventKind::IntentAdmitted { session_id, task_id, intent_kind, ... },
    Some(&session_id),
    Some(&task_id),
    None,
)
```

The `AuditSink` trait has one method:
```rust
pub trait AuditSink: Send + Sync {
    fn emit(
        &self,
        kind:       AuditEventKind,
        session_id: Option<&str>,
        task_id:    Option<&str>,
        details:    Option<&str>,
    ) -> Result<(), AuditWriterError>;
}
```

---

## Step 2: Event Kinds

The kernel emits dozens of event kinds. Here are the categories:

| Category | Event Kinds | When |
|---|---|---|
| **Intent lifecycle** | `IntentAdmitted`, `IntentRejected`, `IntentCompleted`, `IntentFailed` | Each admission decision |
| **Session lifecycle** | `SessionCreated`, `SessionRevoked`, `SessionExpired` | Session spawn/teardown |
| **Delegation lifecycle** | `DelegationGranted`, `DelegationExpired`, `DelegationStaleMarked` | Operator grants/epoch advance |
| **Gate evaluation** | `GateEvaluationResult`, `VerifierSpawned`, `WitnessReceived` | Claims/gates pipeline |
| **Credential proxy** | `CredentialProxyStarted`, `CredentialProxyStopped`, `DatabaseQueryExecuted`, `HttpProxyRequestExecuted`, `SmtpMessageRelayed` | Every proxied query/request |
| **Escalation** | `EscalationCreated`, `EscalationApproved`, `EscalationRejected` | Human-in-the-loop |
| **Break-glass** | `BreakglassActivated`, `BreakglassExpired` | Emergency overrides |
| **Budget** | `BudgetReserved`, `BudgetReleased`, `TokenBudgetExceeded` | Lane budget lifecycle |

---

## Step 3: Chain Structure

Each audit entry is serialized as JSON and appended to a segment file:

```
$RAXIS_DATA_DIR/audit/segment-000.jsonl
$RAXIS_DATA_DIR/audit/segment-001.jsonl
...
```

Each line is:
```json
{
  "seq": 42,
  "ts": 1700000042,
  "kind": "IntentAdmitted",
  "session_id": "sess-abc",
  "task_id": "task-1",
  "prev_hash": "a1b2c3...",
  "entry_hash": "d4e5f6...",
  "payload": { ... }
}
```

The `entry_hash` is `SHA-256(seq || ts || kind || prev_hash || payload)`. The `prev_hash` of entry N+1 equals `entry_hash` of entry N. This forms the chain.

---

## Step 4: Chain Verification

```bash
raxis-cli audit verify --data-dir /path/to/raxis-data
```

The verifier:
1. Reads every segment file in order
2. For each entry, computes `SHA-256(seq || ts || kind || prev_hash || payload)`
3. Compares against `entry_hash`
4. Verifies `prev_hash` matches the previous entry's `entry_hash`
5. Reports any breaks

If the chain is intact → `✅ Audit chain verified: 42 entries, 0 breaks`.
If tampered → `❌ Chain break at seq 17: expected prev_hash a1b2c3, got f00bad`.

---

## Step 5: Genesis Entry

The very first entry in the chain is the **genesis entry**:

```json
{
  "seq": 0,
  "kind": "Genesis",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "payload": {
    "authority_pubkey": "...",
    "quality_pubkey": "...",
    "operator_fingerprint": "...",
    "policy_sha256": "..."
  }
}
```

This establishes the chain's root of trust. All subsequent entries are chained to this.

---

## Production vs Test Audit Sinks

| Sink | Usage | Behavior |
|---|---|---|
| `FileAuditSink` | Production | Writes to segment files, crash-safe |
| `FakeAuditSink` | Tests | In-memory, captures events for assertions |

The `FakeAuditSink` is re-exported through `raxis-test-support` so every kernel test can inspect what audit events were emitted:

```rust
let sink = FakeAuditSink::new();
// ... run kernel operation ...
let events = sink.events();
assert!(events.iter().any(|e| matches!(e.kind, AuditEventKind::IntentAdmitted { .. })));
```

---

## Edge Cases

### 1. Audit write fails mid-intent

Per kernel-store.md §2.5.2: **audit failure is fatal**. The kernel aborts the intent rather than proceeding with an unaudited action. This is enforced for lifecycle events (`CredentialProxyStarted`, session creation, etc.).

Per-request events (individual database queries through the credential proxy) use a softer policy — `tracing::warn!` instead of abort — to avoid tearing down an active session due to transient audit pipe issues.

### 2. Audit segment file is corrupted

`raxis-cli audit verify` detects the break. The operator can see exactly which entry was corrupted and the sequence number where the chain diverged.

### 3. Disk full — can't write audit

The kernel detects the write failure and enters a degraded state. New intents are rejected until the operator frees space. The kernel does not silently drop audit entries.

### 4. Clock skew between entries

The `ts` field is advisory (for human readability). The chain integrity depends on `seq` (monotonic counter) and `entry_hash`/`prev_hash`, not timestamps. Clock skew doesn't break the chain.

---

## Key Source Files

| File | Role |
|------|------|
| `crates/audit/src/event.rs` | `AuditEventKind` enum — all event types |
| `crates/audit/src/sink.rs` | `AuditSink` trait |
| `crates/audit/src/file_sink.rs` | `FileAuditSink` — production writer |
| `crates/audit-tools/src/lib.rs` | `FakeAuditSink` — test capture sink |
| `crates/audit/src/verify.rs` | Chain verification logic |
