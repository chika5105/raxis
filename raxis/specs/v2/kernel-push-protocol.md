# RAXIS V2 — Kernel Push Protocol

> **Status:** V2 Specified
> **Cross-references:**
> - `specs/v1/peripherals.md §1` — Wire format (length prefix + bincode); **canonical**
> - `specs/v1/peripherals.md §3.1` — Planner IPC contract (request/response baseline)
> - `guides/security/raxis-security-model.md Part 3` — VM/host VSock channel; **discrepancy: that doc says big-endian length; this spec corrects to little-endian to match peripherals.md**
> - `specs/v2/integration-merge.md §12` — Operator approval flow (relies on EscalationResolved push)
> - `specs/v2/environment-access-control.md §6` — EgressApprovalRequired push
> - `specs/v2/kernel-mechanics-prompt.md §2` — KSB `state = Paused` reflects push-pending sessions
> - `specs/v2/v2-deep-spec.md §INV-VM-CAP-05` — VSock CID drift detection

---

## 1. The Problem

V1 modelled the planner-kernel channel as strict request/response: planner sends `IntentRequest`, kernel sends `IntentResponse`, repeat. There were no kernel-initiated messages.

V2 introduces extensive kernel-initiated communication:

- The Orchestrator must be notified when sub-tasks complete (`SubTaskCompleted`), when reviewers all pass (`AllReviewersPassed`), when a reviewer rejects (`ReviewRejected`).
- Any session must be notified when a kernel-initiated escalation it triggered is resolved (`EscalationResolved`), rejected (`EscalationRejected`), or times out (`EscalationTimedOut`).
- Any session must be notified of approaching token limits (`TokenLimitApproaching`).
- Any session must be notified of revocation, host-capacity changes, and other state events.

Without a written protocol, every implementer will choose different framing, different delivery guarantees, and different reconnect semantics. The Orchestrator pause/resume contract — which is the entire v2 escalation flow — depends on this protocol being correct. This spec is the single source of truth.

---

## 2. Connection Topology

At most one VSock connection exists between the Kernel and each agent's planner at any given moment. The Kernel listens on the VSock port assigned to the session (derived from the session's CID); the planner connects.

### 2.1 Connection clobbering, not rejection

When a second connection arrives with a `session_token` that passes ALL Handshake validations (HMAC, session exists, not revoked, CID match — see §5.1), the Kernel forcibly closes the existing connection and the new connection takes over the stream. The Kernel emits `AuditEventKind::ConnectionClobbered { session_id, old_connection_started_at, old_connection_last_activity_at, new_connection_cid, new_handshake_nonce }`.

We chose clobbering over rejection because rejection has an unrecoverable failure mode: VSock zombie connections — where the host's view of the connection lingers as alive after the guest side has restarted (hypervisor pause/resume hiccups, vhost-vsock state lag, abrupt VM-process restarts that don't propagate FIN cleanly) — would lock the planner out for the duration of host socket cleanup, which can be hours. With clobbering, the legitimate planner restart succeeds immediately.

Clobbering does NOT weaken security against in-VM threats. The single-connection rule was originally intended as a defense against a second process inside the VM racing the planner for the channel. On reflection, that's not a real defense: a compromised planner already controls the legitimate VSock connection, and the threat model already treats the planner as untrusted (the entire VM isolation design rests on this). A second in-VM process stealing the `session_token` from `/raxis/session.env` and clobbering the legit planner gains nothing the compromised legit planner couldn't already do. The single-connection invariant was operational hygiene (no two-stream confusion in the dispatcher), not a security boundary.

Clobbering IS conditional on Handshake passing **CID match**: the connecting CID must equal `sessions.vsock_cid` recorded at first-connection time. CID drift is a `SecurityViolation` per INV-VM-CAP-05 — no clobber, immediate session termination. Clobbering only happens when both sides are demonstrably the same VM.

---

## 3. Frame Format

Every frame on the VSock connection follows this layout:

```
+-----------+------+----------------+
| 4 bytes   | 1B   | N bytes        |
| length LE | tag  | bincode body   |
+-----------+------+----------------+
```

| Field | Type | Description |
|---|---|---|
| `length` | `u32` little-endian | Total frame size: `tag (1) + body (N)`. Does **not** include the length field itself. Maximum value: `4 * 1024 * 1024` (4 MiB). |
| `tag` | `u8` | Frame type discriminator. See §4. |
| `body` | `[u8; N]` | bincode-serialized payload, schema determined by `tag`. |

**Length-cap enforcement.** If `length > 4 MiB`, the receiver closes the connection without reading the body and emits `SecurityViolation { kind: OversizedFrame }`. This prevents memory-exhaustion attacks via malformed frames.

**bincode version pin.** All frame bodies use `bincode = "=2.0.1"` exactly, with the default little-endian, fixed-int encoding. Version drift between Kernel and planner is a binary-compat break and must be caught at handshake (see §5.2).

**Endianness.** All multi-byte integers in both the framing layer and the bincode body are little-endian. This matches `bincode`'s default and `specs/v1/peripherals.md §1`. (The mention of big-endian in `raxis-security-model.md Part 3` is a documentation error and will be corrected in that document; this spec is the authority.)

---

## 4. Frame Type Discriminator

| Tag | Direction | Frame | Defined in |
|---|---|---|---|
| `0x01` | planner → kernel | `IntentRequest` | `peripherals.md §3.1` |
| `0x02` | kernel → planner | `IntentResponse` | `peripherals.md §3.1` |
| `0x03` | kernel → planner | `KernelPush` | §9 of this spec |
| `0x04` | planner → kernel | `Ack { push_id }` | §7 of this spec |
| `0x05` | planner → kernel | `Handshake` | §5.1 of this spec |
| `0x06` | kernel → planner | `HandshakeAck` | §5.1 of this spec |
| `0x07` | kernel → planner | `HandshakeReject` | §5.1 of this spec |

**Reserved tag values.** `0x00` is reserved (uninitialized memory detection — receiving `0x00` closes the connection with `FAIL_MALFORMED_FRAME`). `0x08`–`0xFF` are reserved for future expansion. An unknown tag closes the connection with `FAIL_UNSUPPORTED_FRAME` and emits `SecurityViolation { kind: UnknownFrameTag }`.

---

## 5. Connection Lifecycle

### 5.1 Handshake

The first frame on every new connection MUST be `Handshake` (tag `0x05`). Any other frame closes the connection with `FAIL_PROTOCOL_VIOLATION` and emits `SecurityViolation { kind: NoHandshake }`.

```rust
pub struct Handshake {
    /// Session token: <session_id>:<hmac>. HMAC-validated by the Kernel
    /// using the kernel_secret loaded at startup.
    pub session_token:        String,

    /// Highest push_id the planner has durably ACKed and processed.
    /// None if this is the planner's first connection for this session.
    /// Used by the Kernel to determine which pending_pushes to drain.
    pub last_acked_push_id:   Option<u64>,

    /// Bincode encoding of the planner's protocol version.
    /// Currently the only valid value is ProtocolVersion::V2_0.
    pub planner_protocol:     ProtocolVersion,

    /// Random 16-byte nonce. Recorded by the Kernel as
    /// sessions.last_handshake_nonce; rejected if it matches the value
    /// already stored (defends against handshake replay).
    pub handshake_nonce:      [u8; 16],

    /// Maximum number of unacked pushes the planner is willing to have
    /// in-flight at once. Kernel uses min(this, kernel_max_window) as
    /// the effective window for both reconnect drain (§6.3) and steady-
    /// state delivery. Range 1..=256. Default 64. Memory-constrained
    /// planners may request smaller windows (e.g., 8) to bound their
    /// in-process buffering.
    pub requested_push_window: u8,
}

pub struct HandshakeAck {
    /// Kernel's monotonic Unix timestamp at handshake completion.
    /// Planner uses this only for clock-skew detection (logged as warning
    /// if local time differs by > 60s; does NOT cause connection failure —
    /// the Kernel's timestamps are authoritative throughout the system).
    pub server_time_unix:     i64,

    /// Number of unacked pushes the Kernel is about to send.
    /// Planner uses this to size its receive buffer and to detect when
    /// catch-up is complete (see §6.3).
    pub pending_push_count:   u32,

    /// Kernel's protocol version for compat verification.
    pub kernel_protocol:      ProtocolVersion,

    /// The actual window size the Kernel will use for this session:
    /// min(requested_push_window, kernel_max_window). Planner MUST
    /// respect this; sending Acks for pushes the Kernel hasn't sent yet
    /// is a protocol violation.
    pub effective_push_window: u8,
}

pub struct HandshakeReject {
    pub reason:               HandshakeRejectReason,
}

pub enum HandshakeRejectReason {
    InvalidToken,
    UnknownSession,
    SessionRevoked,
    CidMismatch,                // INV-VM-CAP-05 — drift detected
    HandshakeNonceReused,
    ProtocolVersionMismatch { kernel_supports: ProtocolVersion },
    InvalidPushWindow { allowed: RangeInclusive<u8> },
}
```

Note: `DuplicateConnection` is NOT a rejection reason. Per §2.1, a duplicate connection that passes all other validations clobbers the existing one rather than being rejected.

**Handshake validation order in the Kernel** (fail-closed; first failure short-circuits):

1. Frame format valid (length cap, tag, bincode deserialize) → else `FAIL_MALFORMED_FRAME`.
2. `session_token` HMAC verifies → else `FAIL_AUTH`.
3. `sessions.id = session_id` exists → else `UnknownSession`.
4. `sessions.revoked = 0` → else `SessionRevoked`.
5. `sessions.vsock_cid IS NULL OR sessions.vsock_cid = incoming_cid` → else **`CidMismatch`** (INV-VM-CAP-05). On `IS NULL` (first connection), record `incoming_cid` in `sessions.vsock_cid` in the same transaction as `HandshakeAck` emission.
6. `handshake_nonce ≠ sessions.last_handshake_nonce` → else `HandshakeNonceReused`.
7. `planner_protocol == kernel_protocol` (exact match for v2.0; stricter than semver) → else `ProtocolVersionMismatch`.
8. `requested_push_window ∈ 1..=256` → else `InvalidPushWindow`.
9. **Clobber step (not a failure).** If an existing connection currently holds this session, force-close it: write `ConnectionClobbered { reason: SupersededByNewerHandshake }` as a final frame on the old connection (best-effort, may not be received), shutdown both halves of the old socket, and emit `AuditEventKind::ConnectionClobbered { ... }`. Then proceed to step 10.
10. Compute `effective_push_window = min(requested_push_window, kernel_max_window)` (kernel_max_window default 256, configurable in `policy.toml`).

On any failure (steps 1–8), the Kernel sends `HandshakeReject { reason }` and closes the connection. On success, the Kernel sends `HandshakeAck { effective_push_window, ... }` and proceeds to §6.

### 5.2 Steady-state operation

Once handshake is complete, both sides may send frames at any time, subject to:

- The planner sends only `IntentRequest` (`0x01`) or `Ack` (`0x04`).
- The Kernel sends only `IntentResponse` (`0x02`) or `KernelPush` (`0x03`).
- Each side reads frames in a loop, dispatching by tag.

There is **no synchronous request-blocks-pushes ordering**. A planner mid-`IntentRequest` may receive a `KernelPush` between sending the request and receiving the response. The planner's main loop must handle interleaving:

```rust
// Planner main loop (illustrative)
loop {
    let frame = vsock.read_frame()?;
    match frame.tag {
        0x02 => route_to_pending_intent_request(frame),  // IntentResponse
        0x03 => enqueue_kernel_push(frame),              // KernelPush
        _    => return Err(ProtocolViolation),
    }
}
```

### 5.3 Disconnection

Either side may close the connection at any time. Reasons:

| Closer | Reason | Behavior |
|---|---|---|
| Planner | Normal shutdown (VM teardown) | Send FIN; Kernel records `connection_closed_at` in sessions; no impact on session state. |
| Planner | Crash | Kernel detects via `read()` returning 0 bytes (EOF) or `ECONNRESET`. Transitions to "awaiting reconnect" mode (does NOT immediately fail the session). |
| Kernel | Session revoked | Kernel sends final `IntentResponse` with `FAIL_REVOKED` if a request is in flight, then closes. Pending pushes are discarded. |
| Kernel | Restart | Kernel closes all VSock connections gracefully on shutdown. On restart, planners reconnect (see §6). |

**No half-close.** The protocol does not support `shutdown(SHUT_WR)` — closing one direction. Either both directions are open or both are closed.

---

## 6. Reconnection

Reconnection is the central durability mechanism. Both planner crashes and Kernel restarts are recovered by the same protocol.

### 6.1 When the planner reconnects

The planner reconnects when it notices its VSock `read_frame()` returned EOF or errored. It re-establishes the VSock connection and sends `Handshake` per §5.1.

The planner's `last_acked_push_id` is the highest `push_id` whose handler has run to completion AND been persisted to the planner's local state file (`/raxis/planner_state.json` in the read-only mount? — actually that's a problem; see §6.5). Pushes that were received but not yet processed must NOT be ACKed.

### 6.2 When the Kernel reconnects

If the Kernel restarts while the planner is running, the planner's existing VSock connection drops (the Kernel's listening socket is gone). The planner detects this on its next `read()` and reconnects.

The Kernel, on restart, runs `kernel/src/startup.rs` reconciliation (see `v2-deep-spec.md` Group 2) which:
1. Reads `sessions WHERE state IN ('Active', 'Paused', 'AwaitingEscalation')` and `vsock_cid IS NOT NULL`.
2. For each, verifies the VM is still running (PID liveness check).
3. Re-binds the VSock listener on the session's port.
4. Awaits the planner's reconnect Handshake.

Per INV-VM-CAP-05, the incoming `vsock_cid` on the Handshake MUST match `sessions.vsock_cid`. Mismatch → `HandshakeReject { reason: CidMismatch }` and session terminated with `SecurityViolation { kind: CidDriftDetected }`.

### 6.3 Windowed drain protocol

After successful Handshake, the Kernel:

1. Reads `pending_pushes WHERE session_id = ? AND push_id > last_acked_push_id ORDER BY push_id ASC` (full count, not paged).
2. Sends `HandshakeAck { pending_push_count: <full_count>, effective_push_window: W }`.
3. Sends an initial batch of up to `W` pushes.
4. Each subsequent ACK frees one window slot; on slot-free, the Kernel sends the next pending push (if any). Maintains exactly `≤ W` in-flight pushes (sent but not yet ACKed) at any moment.
5. Returns to steady-state operation (§5.2) once `pending_push_count` has been delivered AND ACKed.

The planner:

1. Receives `HandshakeAck`, notes `pending_push_count` and `effective_push_window`.
2. Receives up to `W` pushes initially.
3. Processes each, persists local state, sends `Ack { push_id }` for each. Sending the ACK is what tells the Kernel to send the next push.
4. Continues receiving pushes paced by ACKs; never expects more than `W` in-flight at once. Receiving a `KernelPush` while already at the window limit is a Kernel protocol violation — close connection, audit `SecurityViolation { kind: WindowExceeded }`.
5. After processing all `pending_push_count` pushes, transitions to steady-state.

**Why windowed and not firehose.** Sending all pending pushes in a tight loop has two failure modes that windowing eliminates:

- **Reader-races-handler.** In a planner that uses an async frame reader and a separate handler task, the reader can pull all 800 frames into an in-process channel before the handler processes the first. The channel is then unbounded buffered state. With a window of 64, the reader is naturally paced by ACK emission from the handler.
- **ACK-gap reasoning.** When the Kernel has sent push #100 and the planner has only ACKed up to #20, the Kernel cannot tell from the wire whether pushes #21–99 have been processed-but-pending-ACK or are still queued in the reader's channel. With a window, the Kernel knows: at most `W` are in-flight, the rest are still in the Kernel-side queue.

Windowing is NOT motivated by absolute byte sizes — even 1000 pending frames at ~500 bytes each is well under 1 MB, far from any practical memory limit. The motivation is processing-pace matching and dispatcher-state determinism.

**Catch-up barrier.** The planner does NOT send any new `IntentRequest` until it has received and processed all `pending_push_count` pushes. This guarantees the LLM sees the most recent kernel state before its next inference call.

If `pending_push_count = 0`, catch-up is immediate; the planner may begin sending `IntentRequest` immediately after `HandshakeAck`.

### 6.4 Push ID monotonicity across reconnects

`push_id` is assigned by the Kernel's `pending_pushes.push_id` `AUTOINCREMENT` column. It is monotonically increasing per session, never reset, never reused, even across Kernel restarts (SQLite preserves `AUTOINCREMENT` state).

A planner that receives `push_id = 7` and then `push_id = 10` (skipping 8, 9) without an intervening reconnect MUST close the connection with `FAIL_PROTOCOL_VIOLATION` and emit a local audit-relevant error. This shouldn't happen with correct Kernel implementation but is a defense against framing bugs.

### 6.5 The planner's `last_acked_push_id` durability

This is the subtle part. The planner must remember `last_acked_push_id` across crashes. Where does it persist?

**Decision:** the planner keeps `last_acked_push_id` in memory only and re-derives it from the Kernel's view on reconnect.

Mechanism:
- Planner crashes → loses `last_acked_push_id`.
- On reconnect, planner sends `Handshake { last_acked_push_id: None }`.
- Kernel re-sends ALL pushes from `pending_pushes` for this session (`acked_at IS NULL`).
- Planner re-processes (idempotent — see §8).
- Planner ACKs each as it processes; Kernel deletes the `pending_pushes` rows.

This is at-least-once delivery with idempotency on the planner side. The planner does not need durable storage; the Kernel's `pending_pushes` table IS the durable queue.

**Why not have the planner persist `last_acked_push_id`?** The planner runs in a microVM whose only writable surface is `/workspace` (the agent's worktree). Persisting protocol state there would either pollute the worktree (bad: agents would see RAXIS protocol state in their working files) or require a separate VirtioFS mount for protocol state (extra attack surface). Re-deriving from the Kernel's state is simpler and the at-least-once + idempotent design absorbs the duplication.

---

## 7. The `pending_pushes` Table

### 7.1 Schema

```sql
-- Migration N: pending pushes for at-least-once delivery
CREATE TABLE pending_pushes (
    push_id            INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    session_id         TEXT    NOT NULL REFERENCES sessions(id),
    push_kind          TEXT    NOT NULL,
    payload            BLOB    NOT NULL,         -- bincode-serialized KernelPush
    enqueued_at        INTEGER NOT NULL,         -- Unix timestamp (seconds)
    first_delivered_at INTEGER,                  -- NULL until first delivery attempt
    delivery_count     INTEGER NOT NULL DEFAULT 0,
    ack_deadline_at    INTEGER,                  -- NULL until first delivery; then = first_delivered_at + push_ack_timeout_seconds
    acked_at           INTEGER                   -- NULL until ACKed (then row is deleted by sweeper after retention)
);

CREATE INDEX idx_pending_pushes_session_unsent
    ON pending_pushes(session_id, push_id)
    WHERE acked_at IS NULL AND first_delivered_at IS NULL;

CREATE INDEX idx_pending_pushes_inflight_deadline
    ON pending_pushes(ack_deadline_at)
    WHERE acked_at IS NULL AND first_delivered_at IS NOT NULL;
```

The two partial indexes split the working set by lifecycle stage: "queued, not yet sent" (drained by the delivery loop) vs "sent, awaiting ACK" (scanned by the timeout sweeper). Rows are deleted by a separate sweeper 60 seconds after ACK, leaving forensic retention.

Per-session columns added to `sessions`:

```sql
ALTER TABLE sessions ADD COLUMN push_queue_cap INTEGER NOT NULL DEFAULT 100;
ALTER TABLE sessions ADD COLUMN push_window_size INTEGER NOT NULL DEFAULT 64;
ALTER TABLE sessions ADD COLUMN push_ack_timeout_seconds INTEGER NOT NULL DEFAULT 300;
```

`push_queue_cap` is computed at session creation time per §10.1. `push_window_size` is set on each Handshake from `effective_push_window`. `push_ack_timeout_seconds` is read from `policy.toml` (default 300; can be raised per session role).

### 7.2 Enqueue contract

Push enqueueing happens in the same `BEGIN IMMEDIATE` transaction as the kernel state change that triggers the push (INV-STORE-02 atomicity).

Example: when `EscalationConsumed` fires for a `ProtectedPathMerge` escalation:

```sql
BEGIN IMMEDIATE;
UPDATE escalations
   SET state = 'Consumed', resolved_by = :operator
 WHERE id = :escalation_id;

INSERT INTO audit_events (kind, ...)
VALUES ('EscalationConsumed', ...);

UPDATE sessions
   SET state = 'Active'
 WHERE id = :orchestrator_session_id;

INSERT INTO audit_events (kind, ...)
VALUES ('SessionResumed', ...);

INSERT INTO pending_pushes (session_id, push_kind, payload, enqueued_at)
VALUES (:orchestrator_session_id, 'EscalationResolved', :bincode, :now);

COMMIT;
```

If the transaction commits, the push is durably enqueued. If it rolls back, no state change, no push. There is no scenario where the FSM transitions but the push is missing.

### 7.3 Delivery loop and window-paced send

The Kernel runs one delivery task per active VSock connection. The task tracks an in-memory `in_flight_count` (sent but not yet ACKed) and the session's `push_window_size`. Per cycle:

1. Compute `slots_free = push_window_size - in_flight_count`. If `slots_free <= 0`, block on the ACK channel until a slot frees.
2. Poll `pending_pushes WHERE session_id = ? AND acked_at IS NULL AND first_delivered_at IS NULL ORDER BY push_id ASC LIMIT slots_free`.
3. For each row, write the corresponding `KernelPush` frame to the VSock.
4. UPDATE `first_delivered_at = NOW()`, `ack_deadline_at = NOW() + push_ack_timeout_seconds`, `delivery_count = delivery_count + 1`.
5. Increment `in_flight_count` per send.
6. On VSock write error (connection closed), abort and wait for reconnect.
7. On ACK received: decrement `in_flight_count`, signal the ACK channel.
8. On new push enqueue (signaled by tokio channel from the enqueueing transaction): unblock and resume.

ACKs from the planner update `acked_at`; a separate sweeper deletes rows where `acked_at IS NOT NULL AND acked_at < NOW() - 60s` (60-second grace to handle in-flight reads).

### 7.4 ACK timeout and timeout-then-fail

A separate timer (running every 5 seconds) scans `pending_pushes WHERE acked_at IS NULL AND first_delivered_at IS NOT NULL AND ack_deadline_at < NOW()` (uses `idx_pending_pushes_inflight_deadline`). For each timed-out row:

1. Mark the corresponding session `state = 'Failed', failure_reason = 'PushAckTimeout'`.
2. Emit `AuditEventKind::SessionTerminated { reason: PushAckTimeout, session_id, push_id, push_kind, deadline_at, deadline_exceeded_by_seconds }`.
3. Trigger VM teardown (SIGTERM, then SIGKILL after 5s).
4. The timed-out row is left in `pending_pushes` for forensic retention; cleanup happens via a long-tail retention policy (default 30 days).

Default `push_ack_timeout_seconds = 300` (5 minutes). The default is generous because legitimate push handlers may need to wait through an in-flight LLM call before processing — the planner reads pushes between intents, not during them. Real-world LLM inference can take 60–120 seconds; 5 minutes accommodates this with comfortable margin. Configurable per session role in `policy.toml`.

**Timeout extends on planner activity.** When the timeout sweeper is about to fail a session, it first checks `sessions.last_planner_frame_at` (updated by the IPC layer on every received frame). If `last_planner_frame_at > first_delivered_at`, the planner has communicated since the push was sent — extend `ack_deadline_at` by `push_ack_timeout_seconds / 2` (default 2.5 min) and re-check next cycle. This prevents killing a planner that is actively communicating but slow on a specific push (e.g., the planner is processing other pushes in the same window). The extension applies at most twice per push before terminal failure.

**No proactive re-delivery on the same connection.** The Kernel does NOT re-send a delivered-but-not-ACKed push on the same connection. The combination of (a) no proactive re-send and (b) ACK timeout per above means: pushes are delivered once on the steady-state connection; if the planner doesn't ACK within deadline (with extensions), the session fails rather than the Kernel piling up duplicate sends. Re-delivery happens only via reconnect (§6.3), where idempotency on the planner side absorbs the duplicates.

---

## 8. Idempotency Requirements on the Planner

Every push handler in the planner MUST be idempotent: receiving the same `push_id` twice produces the same observable effect as receiving it once.

For RAXIS's push types this is structurally guaranteed by the form of the push handlers:

| Push kind | Handler semantics | Idempotency mechanism |
|---|---|---|
| `SubTaskActivated` | Append "task <id> activated" to LLM context | Re-appending is harmless; LLM treats as restated fact |
| `SubTaskCompleted` | Append "task <id> completed at sha <s>" to LLM context | Same |
| `AllReviewersPassed` | Append "all reviewers approved task <id>" | Same |
| `ReviewRejected` | Append critique to LLM context, set `tasks.last_critique` | Set is idempotent (overwrites identical value) |
| `EscalationResolved` | Append "escalation <id> approved" to context; resume from Paused | Re-appending harmless; resume already-Active session is a no-op |
| `EscalationRejected` | Append "escalation <id> rejected" to context; transition to Failed | Already-Failed session ignores |
| `EscalationTimedOut` | Same as Rejected | Same |
| `MergeApprovalRequired` | Append "operator must approve merge for <commit>" | Re-appending harmless |
| `PushApprovalRequired` | Same shape | Same |
| `EgressApprovalRequired` | Same shape | Same |
| `EgressApprovalRejected` | Append rejection to context | Re-appending harmless |
| `SubEscalationResolutionRequired` | Append "sub-escalation `<id>` from task `<t>` requires your resolution by `<deadline>`" to Orchestrator context; record `(escalation_id, source_task_id)` in Orchestrator's pending-resolutions list | Re-appending harmless; pending-resolutions list keyed on `escalation_id` so duplicates collapse |
| `TokenLimitApproaching` | Update KSB local cache; LLM sees on next inference | Idempotent overwrite |
| `SessionFailed` | Trigger graceful shutdown | Already-shutting-down is a no-op |
| `SessionRevoked` | Same | Same |
| `HostCapacityFreed` | Append to context for Orchestrator | Re-appending harmless |

**Rule:** every `KernelPush` variant added in the future MUST document its idempotency mechanism in this table. The table is documentation; **enforcement is in `tests/push_idempotency.rs`**, a property-based test that enumerates every variant of the `KernelPush` enum and, for each, verifies:

1. **Duplicate delivery**: deliver the push twice; assert observable planner FSM state matches the single-delivery baseline.
2. **Reordered delivery**: pair the push with another and deliver in both orders; assert final state matches the canonical order.
3. **Drop-and-replay**: simulate planner crashing mid-handler, restart, replay all unacked pushes; assert final state matches single-delivery baseline.

A new variant added without a test case fails compilation via `compile_assert_all_variants_tested!(KernelPush)`, a macro that exhaustively matches the enum and statically rejects unmatched variants. The doc table is for human reviewers; the macro + property tests are the actual enforcement.

**The `last_processed_push_id` in-memory tracker.** The planner keeps `last_processed_push_id: u64` in memory. On each push received, if `push.push_id <= last_processed_push_id`, the planner ACKs immediately without re-processing (defense-in-depth — saves redundant context appends within a single connection). On reconnect, this resets to 0 and the planner re-processes whatever the Kernel re-sends.

---

## 9. KernelPush Variants

Authoritative enumeration for V2.0:

```rust
pub enum KernelPush {
    // ── DAG progression ──
    SubTaskActivated   { task_id: TaskId, base_sha: String },
    SubTaskCompleted   { task_id: TaskId, completed_sha: String, newly_activatable: Vec<TaskId> },
    AllReviewersPassed { task_id: TaskId },
    ReviewRejected     { task_id: TaskId, critique: String, reviewer_session_id: Uuid },

    // ── Escalation FSM ──
    EscalationResolved   { escalation_id: EscalationId, class: EscalationClass, resolved_by: String },
    EscalationRejected   { escalation_id: EscalationId, class: EscalationClass, resolved_by: String },
    EscalationTimedOut   { escalation_id: EscalationId, class: EscalationClass },

    // ── Kernel-initiated escalation notifications (the auto-created ones) ──
    MergeApprovalRequired   { escalation_id: EscalationId, protected_paths: Vec<String>, commit_sha: String },
    MergeApprovalRejected   { escalation_id: EscalationId, commit_sha: String },
    PushApprovalRequired    { escalation_id: EscalationId, commit_sha: String, remote: String, ref_spec: String },
    EgressApprovalRequired  { escalation_id: EscalationId, url: String, method: String, environment: String },
    EgressApprovalRejected  { escalation_id: EscalationId, url: String, method: String },

    // ── Two-tier escalation routing (delivered to Orchestrator) ──
    // See `agent-disagreement.md §6` for routing semantics.
    // Resolution outcomes are delivered to the source Executor via the existing
    // `EscalationResolved` / `EscalationRejected` / `EscalationTimedOut` variants
    // above, regardless of whether the resolver was the Orchestrator or the operator.
    SubEscalationResolutionRequired {
        escalation_id:           EscalationId,
        escalation_kind:         EscalationClass,
        source_task_id:          TaskId,
        source_session_id:       Uuid,
        resolution_deadline_at:  i64,         // Unix timestamp = orchestrator_routed_at + orchestrator_timeout
    },

    // ── Resource pressure ──
    TokenLimitApproaching { limit_type: String, current: u64, limit: u64, pct_used: u8 },
    HostCapacityFreed     { newly_activatable: Vec<TaskId> },
    QueuePressure         { current: u32, cap: u32, severity: QueuePressureSeverity },

    // ── Session terminal events ──
    SessionFailed   { reason: SessionFailReason },
    SessionRevoked  { reason: RevocationReason },
}
```

**Wire envelope:**

```rust
pub struct KernelPushFrame {
    pub push_id:     u64,
    pub session_id:  Uuid,         // redundant with VSock session, but explicit for forensics
    pub enqueued_at: i64,          // Unix timestamp at enqueue (NOT delivery)
    pub push:        KernelPush,
}
```

The `enqueued_at` field allows the planner to detect significantly delayed pushes (e.g., enqueued 30 minutes ago, just delivered after a reconnect) and contextualize them appropriately ("escalation was resolved 30 minutes ago, while we were disconnected").

---

## 10. Backpressure

### 10.1 Per-session push queue cap (plan-derived)

The cap on `pending_pushes` for a session is computed at session creation and stored in `sessions.push_queue_cap`:

| Session role | Cap formula | Notes |
|---|---|---|
| Orchestrator (`can_delegate = true`) | `max(100, plan.max_subtasks × 20)` | Each sub-task generates ~20 lifetime events (Activated, Completed, AllReviewersPassed, optional ReviewRejected, optional EscalationResolved chain) |
| Executor (`can_delegate = false`, role = Executor) | `100` | No expected bursts; small finite event set |
| Reviewer (`can_delegate = false`, role = Reviewer) | `50` | Receives only its own activation + cancellation pushes |

Plans expecting larger bursts may declare `[orchestrator] expected_push_burst = N` in `plan.toml`; the Kernel uses `max(formula, expected_push_burst)` up to a hard ceiling of `10000` (defense against pathological plans). The hard ceiling is configurable in `policy.toml` only by the operator.

### 10.2 Soft pressure: early-warning push

When `pending_pushes` for a session reaches **50% of cap**, the Kernel enqueues `KernelPush::QueuePressure { current, cap, severity: Warning }` to that same session (counted against the session's own cap, but it always fits because the threshold check happens before enqueue). At **75% of cap**, severity escalates to `Critical`.

The push is itself idempotent — re-delivering Warning or Critical just re-appends a notice to the planner's context. The KSB (`kernel-mechanics-prompt.md §2`) also surfaces `queue_depth_pct` so the LLM sees the pressure on its next inference even without processing the push.

The intent is to give the recipient session — typically an Orchestrator behind a long inference call — visibility that it must drain or face termination. The planner's prompt logic SHOULD interpret QueuePressure as a signal to abort the current inference loop, drain pending pushes, and only then resume planning.

### 10.3 Hard cap: terminate the recipient (NEVER the producer)

When a kernel handler attempts to enqueue a push that would exceed the recipient's `push_queue_cap`, the transaction takes the **overflow path** instead of the normal enqueue path. Both paths commit atomically with the producer's state change:

**Normal path** (recipient queue has space):
- producer state change → INSERT into `pending_pushes` → COMMIT.

**Overflow path** (recipient queue at cap):
- producer state change → UPDATE `sessions SET state='Failed', failure_reason='PushQueueOverflow' WHERE id = recipient_id` → INSERT `audit_events (kind='SessionTerminated', reason='PushQueueOverflow', session_id=recipient_id, attempted_push_kind, ...)` → COMMIT.

In both paths, the producer's state advances. The push is either delivered or causes the recipient's failure — it is never silently dropped, and it never blocks or rolls back the producer.

Post-commit (outside transaction):
- SIGTERM the recipient's VM, then SIGKILL after 5s.
- If the failed session was an Orchestrator, cascade-terminate all descendant sub-tasks with `reason: ParentSessionRevoked` (per `key-revocation.md §7.3` cascade rules, reused here; signal-handling category inherits from the parent's reason — `PushQueueOverflow` is Graceful, so children get SIGTERM grace).
- The initiative as a whole transitions to `state = 'Blocked'` and an `OperatorAttentionRequired` audit event is emitted. The operator must manually intervene (e.g., spawn a replacement Orchestrator under a new plan extension that picks up where the failed one left off).

### 10.4 Why terminate the recipient and not the producer

The producer's work — typically a successful Executor commit, a Reviewer verdict, or an Operator approval — is cryptographically valid and globally visible the moment git writes the object. Rolling back the producer's state transition because the recipient's queue is full destroys valid, approved work.

The recipient is terminated because it is, by definition, unable to keep up. Either it is genuinely deadlocked (a bug we can't fix at runtime), runaway (consuming inference budget without making progress), or designed for a smaller burst than its plan allows. In all three cases, fail-closed termination plus operator escalation is the correct response. Producer-rollback is never the right response, because it confuses "this consumer is unhealthy" with "this work didn't happen."

### 10.5 Why not block (pause) upstream producers

Considered: the `CompleteTask` handler blocks waiting for the Orchestrator's queue space to free. Rejected because it breaks **session independence**:

- The Executor is held hostage to the Orchestrator's processing pace.
- Cross-session blocking compounds: if the Executor has Reviewers waiting on its commit, they stall too; if the Orchestrator has multiple Executors all blocked, the entire DAG freezes.
- A single slow Orchestrator can stall every other initiative running on the host (SQLite's write lock is database-wide; a blocked transaction starves writes everywhere).
- The Kernel's job is to keep state advancing in the producer; it cannot stall producers waiting for consumers without violating its own atomicity guarantees.

The user-experience effect of upstream-pause would be: "my Executor session is hanging because the Orchestrator is slow." That's worse than "my Orchestrator session was killed and the operator must restart it" — at least the latter is observable and actionable.

### 10.6 Why not a "SlowDrain" recipient state

Considered: when a recipient hits 75% cap, the Kernel transitions it to a `SlowDrain` FSM state with different scheduling. Rejected because the Kernel cannot make the recipient drain faster — `SlowDrain` doesn't do anything actionable that `KernelPush::QueuePressure { Critical }` (§10.2) doesn't already do. The push at least surfaces in the recipient's KSB and prompt; an FSM state shift would be invisible to the LLM. Adding bookkeeping without enforcement isn't worth the surface area.

### 10.7 Why not drop oldest

Considered: at cap, drop the oldest unacked push to make room. Rejected because dropping breaks at-least-once delivery (INV-PUSH-02). A dropped `EscalationResolved` means the Orchestrator never resumes from Paused — the operator approved, but the agent doesn't know. Silent loss of state-change notifications is worse than failing the session.

### 10.8 Why not block the kernel

Considered: hold `BEGIN IMMEDIATE` until queue space frees. Rejected because SQLite's write lock is database-wide; one slow draining session stalls every other session's intent processing. Fail-closed termination is consistent with INV-01 (fail-closed default).

---

## 11. Cross-cutting: ordering between IntentResponse and KernelPush

These two frame types are independent. The Kernel does NOT promise:
- That `IntentResponse` for `IntentRequest` #N arrives before `KernelPush` enqueued at time T (where T > submission of #N).
- That a `KernelPush` enqueued in the same transaction as the response to #N arrives before that response.

What the Kernel DOES promise:
- `IntentResponse`s for the same session arrive in submission order (FIFO per session for request/response).
- `KernelPush`es for the same session arrive in `push_id` order (FIFO per session for pushes).
- Within each stream, the Kernel does not reorder.

The planner must handle interleaving in its main loop. Specifically: if an `IntentRequest` is in flight and a `KernelPush::SessionRevoked` arrives, the planner must process the revocation immediately (initiate shutdown) rather than waiting for the response. Subsequent `IntentResponse` (if any) for the in-flight request is discarded.

**Subtle case: response to a request that triggered a push.**

Example: planner submits `IntegrationMerge`. Kernel admits, transitions state, enqueues `KernelPush::SubTaskCompleted` to the Executor (a *different* session) as part of its transaction, and sends `IntentResponse::Accepted` to the Orchestrator's planner. The Orchestrator does NOT receive the Executor's push — it's for a different session. So no interleaving question for the Orchestrator.

The general rule: pushes are session-scoped. Cross-session signalling is just "Kernel enqueues a push on session B as a side effect of an intent from session A." Each session's stream is independent.

---

## 12. Invariants

### INV-PUSH-01 — Producer state advances atomically with either push enqueue OR recipient failure

Every kernel state change that should produce a push commits atomically with EXACTLY ONE of:

- (a) the push being durably enqueued in `pending_pushes` (normal path), OR
- (b) the recipient being marked `state = 'Failed', failure_reason = 'PushQueueOverflow'` and a `SessionTerminated` audit event being emitted (overflow path).

There is no scenario where the producer's state advances without one of these two outcomes. There is no scenario where the producer's state is rolled back because of recipient health.

**Where:** §10.3. The transaction commits one of two state-machine paths; both paths are atomic with the producer's state change.

**Scenario it prevents:** A valid Executor commit is rolled back because the Orchestrator's queue is full. INV-PUSH-01 (revised from V2-draft) preserves the commit and instead fails the slow recipient. The producer always wins; the recipient survives or fails based on its own queue health.

**Crash recovery:** If the kernel crashes between transaction commit and post-commit teardown (SIGTERM of the failed recipient), restart reconciliation per `key-revocation.md §5.3` re-runs SIGTERM on any session in `state = Failed` whose VM PID is still alive. The atomicity guarantee is preserved across crashes.

### INV-PUSH-02 — At-least-once delivery, idempotent processing, ACK-deadline-bounded

Every enqueued push is delivered to the planner at least once before its ACK deadline. The planner's push handler is idempotent: receiving the same `push_id` twice produces the same observable effect. If the planner does not ACK within `push_ack_timeout_seconds` (with extensions on planner activity per §7.4), the session is failed with `PushAckTimeout`.

**Where:** §7.3 (delivery loop), §7.4 (timeout-then-fail), §6.3 (drain on reconnect), §8 (handler idempotency table + property test).

**Scenario it prevents:** Planner deadlocks while reading a frame; never ACKs; Kernel waits forever. The deadline turns silent deadlock into observable session failure with full forensic detail (which push, when delivered, by how much it exceeded). The planner-activity extension prevents false positives where the planner is communicating but slow on a specific push.

### INV-PUSH-03 — FIFO per session

Pushes for one session are delivered in `push_id` order. Pushes for different sessions are independent.

**Where:** Drain query is `ORDER BY push_id ASC`; delivery loop processes in order; planner detects gaps as protocol violations (§6.4).

**Scenario it prevents:** `EscalationResolved { id: esc-99 }` (push #5) and `EscalationRejected { id: esc-100 }` (push #6) arrive out of order. Without FIFO, the planner might believe esc-100 resolved first. With FIFO, the temporal causality is preserved.

### INV-PUSH-04 — At most one connection per session, via clobbering

A session has at most one active VSock connection at any moment. New connections that pass full Handshake validation (including CID match per INV-VM-CAP-05) clobber any existing connection (which is forcibly closed) rather than being rejected.

**Where:** §2.1 (rationale and threat model); §5.1 step 9 (clobber step in Handshake validation).

**Scenario it prevents (formerly):** Confused-deputy attacks via duplicate connections were the original concern. Re-evaluated in §2.1: a single-connection rejection rule does not actually defend against an in-VM attacker (who can use the existing connection), and rejection has an unrecoverable failure mode (VSock zombie connections lock the planner out). Clobbering preserves the "one stream per session" property at the dispatcher layer while avoiding the lockout. CID-mismatch still triggers `SecurityViolation` per INV-VM-CAP-05 — clobbering only happens when CIDs match.

### INV-PUSH-05 — Backpressure terminates the recipient, never drops, never blocks the producer

When the recipient's `pending_pushes` reaches its configured `push_queue_cap`, the recipient session is failed with `PushQueueOverflow`. The push is never silently dropped (would break INV-PUSH-02). The producer's state change is never aborted (would violate INV-PUSH-01). The Kernel never blocks waiting for queue space (would violate session independence; would stall every session's writes).

**Where:** §10.3 (fail recipient), §10.5 (no upstream pause), §10.6 (no SlowDrain), §10.7 (no drop-oldest), §10.8 (no kernel-block).

**Scenario it prevents:** A slow recipient causes either (a) silent message loss, (b) unbounded Kernel memory growth, (c) cross-session stalls, or (d) producer-state-rollback destroying valid work. INV-PUSH-05 chooses the only fail-closed-and-isolated option: terminate the slow recipient, preserve all producer state, leave other sessions untouched.

---

## 13. Implementation Checklist

### Schema (migration N)

- [ ] Create `pending_pushes` table per §7.1 with `push_id`, `session_id`, `push_kind`, `payload`, `enqueued_at`, `first_delivered_at`, `delivery_count`, `ack_deadline_at`, `acked_at`
- [ ] Create partial index `idx_pending_pushes_session_unsent` on `(session_id, push_id) WHERE acked_at IS NULL AND first_delivered_at IS NULL`
- [ ] Create partial index `idx_pending_pushes_inflight_deadline` on `(ack_deadline_at) WHERE acked_at IS NULL AND first_delivered_at IS NOT NULL`
- [ ] Add columns to `sessions`: `last_handshake_nonce BLOB`, `connection_closed_at INTEGER`, `last_planner_frame_at INTEGER`, `push_queue_cap INTEGER NOT NULL DEFAULT 100`, `push_window_size INTEGER NOT NULL DEFAULT 64`, `push_ack_timeout_seconds INTEGER NOT NULL DEFAULT 300`
- [ ] Add `failure_reason TEXT` to `sessions` (shared with `key-revocation.md`; declare once)

### Wire types

- [ ] Add `Frame` enum with explicit `tag` byte to `crates/types/src/wire.rs`
- [ ] Add `Handshake { ..., requested_push_window: u8 }`, `HandshakeAck { ..., effective_push_window: u8 }`, `HandshakeReject { reason }`
- [ ] Add `HandshakeRejectReason` (NO `DuplicateConnection`; ADD `InvalidPushWindow { allowed: RangeInclusive<u8> }`)
- [ ] Add `KernelPush` enum with all V2 variants including `QueuePressure { current, cap, severity }`
- [ ] Add `QueuePressureSeverity { Warning, Critical }`
- [ ] Add `KernelPushFrame` envelope
- [ ] Add `Ack { push_id: u64 }`
- [ ] Pin `bincode = "=2.0.1"` in `Cargo.toml`
- [ ] Add `compile_assert_all_variants_tested!(KernelPush)` macro and use it in `tests/push_idempotency.rs`

### Kernel side

- [ ] Implement `kernel/src/ipc/framing.rs`: read/write 4-byte LE length + tag + body, with 4 MiB cap
- [ ] Implement `kernel/src/ipc/handshake.rs`: 10-step validation order including clobber step
- [ ] Implement `kernel/src/ipc/clobber.rs`: force-close existing connection on duplicate-with-valid-handshake
- [ ] Implement `kernel/src/ipc/push_dispatcher.rs`: per-session delivery task with windowed send (track in_flight_count, respect push_window_size)
- [ ] Implement `kernel/src/ipc/push_enqueue.rs`: transactional helper that takes either the normal-path (INSERT push) or overflow-path (UPDATE recipient state to Failed + audit) inside the same transaction as the producer's state change
- [ ] Implement soft-pressure: when post-INSERT count crosses 50% cap, ALSO enqueue `QueuePressure { Warning }`; at 75%, enqueue `Critical`
- [ ] Implement Ack handler: `UPDATE pending_pushes SET acked_at = ? WHERE push_id = ?`; signal in-process channel to free a window slot
- [ ] Implement ACK timeout sweeper (5s scan interval) per §7.4, with planner-activity extension logic
- [ ] Background sweeper deletes ACKed rows older than 60s (live cleanup); long-tail sweeper deletes timed-out rows older than 30 days
- [ ] Connection lifecycle: detect EOF, mark `connection_closed_at`, await reconnect
- [ ] CID-binding check on every Handshake (INV-VM-CAP-05); record CID on first connection
- [ ] Update `last_planner_frame_at` on every received frame (used by timeout extension logic)

### Planner side (in `raxis-planner`)

- [ ] Implement frame reader loop dispatching by tag
- [ ] Implement Handshake on connection establishment with `requested_push_window` (default 64; configurable via planner CLI flag)
- [ ] Respect `effective_push_window` in `HandshakeAck`; track in-flight count locally; never expect more than W in-flight
- [ ] Implement reconnect loop on VSock EOF (exponential backoff: 100ms, 200ms, 400ms, capped at 5s)
- [ ] Implement push handlers for each `KernelPush` variant (idempotent per §8 table)
- [ ] Implement `last_processed_push_id` in-memory tracker; defensive double-process avoidance
- [ ] Implement `QueuePressure` handler: surface in KSB/prompt; logic to interrupt long inferences and drain
- [ ] Send `Ack { push_id }` after each push handler completes
- [ ] Catch-up barrier: don't send IntentRequest until `pending_push_count` pushes received

### Audit events

- [ ] `SecurityViolation` sub-kinds: `OversizedFrame`, `UnknownFrameTag`, `NoHandshake`, `CidDriftDetected`, `HandshakeNonceReused`, `WindowExceeded` (planner ACKed beyond window)
- [ ] `ConnectionClobbered { session_id, old_connection_started_at, old_connection_last_activity_at, new_connection_cid, new_handshake_nonce }`
- [ ] `SessionResumed` (when Paused → Active via push)
- [ ] `SessionTerminated { reason }` includes `PushQueueOverflow`, `PushAckTimeout`
- [ ] `QueuePressureWarning { session_id, current, cap }`
- [ ] `QueuePressureCritical { session_id, current, cap }`
- [ ] `PushDelivered { session_id, push_id, push_kind, delivery_count }` (at first delivery only; not on re-delivery)
- [ ] `PushAcked { session_id, push_id }` (on Ack receipt)
- [ ] `PushAckTimeout { session_id, push_id, push_kind, deadline_at, deadline_exceeded_by_seconds }`

### Tests (integration)

- [ ] Round-trip: enqueue 100 pushes, planner receives all 100 in order, ACKs all
- [ ] Reconnect with `last_acked_push_id = None`: all unacked pushes re-sent, paced by window
- [ ] Reconnect with `last_acked_push_id = 50`: only push_id > 50 re-sent
- [ ] Window respect: planner declares `requested_push_window = 8`; verify never more than 8 in-flight even with 1000 pending
- [ ] Window respect: planner ACKs a push the kernel hasn't sent → connection closed, `WindowExceeded` audited
- [ ] Property test (`tests/push_idempotency.rs`): for every `KernelPush` variant, duplicate/reorder/drop-replay produces canonical FSM state
- [ ] Backpressure: enqueue cap+1 pushes; (cap+1)th triggers OVERFLOW path → recipient `state = Failed`, producer's state STILL committed, `SessionTerminated` audit emitted
- [ ] Backpressure independence: session A overflows, session B unaffected; no SQLite stall
- [ ] Backpressure: producer is Executor with valid commit, recipient is Orchestrator at cap → Executor's `tasks.state = Completed` commits, Orchestrator killed, commit preserved in worktree
- [ ] Soft pressure: enqueue to 50% cap → `QueuePressure { Warning }` arrives; to 75% → `Critical` arrives; idempotent on re-deliver
- [ ] CID drift: planner reconnects with different CID → `HandshakeReject { CidMismatch }`, `SecurityViolation` emitted, NO clobber
- [ ] Clobber on legitimate restart: planner crashes (no FIN), restarts, reconnects with same CID → existing zombie connection clobbered, `ConnectionClobbered` audited, new connection accepted
- [ ] Clobber doesn't lock out: simulate VSock zombie (kill planner with SIGKILL on host, leaving host-side socket alive); planner restarts within 100ms; verify Handshake succeeds via clobber
- [ ] ACK timeout: planner reads but never ACKs; after `push_ack_timeout_seconds`, session failed with `PushAckTimeout`
- [ ] ACK timeout extension: planner sends other frames during the timeout window → deadline extends; only fails if completely silent for full deadline
- [ ] Handshake nonce replay: identical Handshake replayed → `HandshakeNonceReused`
- [ ] Kernel restart mid-session: planner reconnects, drains pending pushes via window, resumes
- [ ] Catch-up barrier: planner with 5 pending pushes does not send IntentRequest until all 5 received
- [ ] Frame size cap: 5 MiB frame rejected with connection close

---

## 14. Alternatives Considered and Rejected

### Alt A — At-most-once delivery with planner-durable Ack state

Rejected because the planner has no durable storage that satisfies RAXIS's other invariants. The worktree is the only writable mount, but using it for protocol state pollutes the agent's view of "files I work on" and creates an attack surface (agent reads its own ack state, hallucinates about it). At-least-once with idempotency is simpler and equivalently correct.

### Alt B — Separate vsock connection for pushes

Rejected because it doubles the VSock connection management complexity, doubles the handshake/auth surface, and creates ordering puzzles between the two streams (does `EscalationResolved` on the push channel arrive before or after `IntentResponse::Rejected` on the request channel for the same root cause?). One channel with frame multiplexing is cleaner.

### Alt C — Synchronous "request push delivery" intent

Planner periodically sends `IntentRequest::Poll` to fetch pending pushes. Rejected because it's polling, which the entire v2 escalation design explicitly avoids. Polling burns inference units (every poll costs something) and adds latency between operator approval and agent resumption.

### Alt D — Push framing piggy-backed on `IntentResponse`

Bundle pending pushes inside the `IntentResponse` for the planner's next intent. Rejected because the planner has no scheduled "next intent" while Paused — the entire point of pause is to stop sending intents. With this design, pushes would never reach a paused planner.

### Alt E — Big-endian length prefix (matching the security model doc)

Rejected because:
- `peripherals.md §1` is the canonical wire-format spec and says little-endian.
- bincode's default is little-endian; matching the framing layer to the body avoids byte-order context switches.
- The "network byte order = big-endian" convention is for IP-layer protocols, not application-layer over local IPC.

The discrepancy in `raxis-security-model.md Part 3` will be fixed in that document; this spec is the authority for wire format.

### Alt F — `last_acked_push_id` durable in `/raxis/session.env`

The planner's read-only mount could include a writable scratch directory just for protocol state. Rejected because any writable mount is an attack surface. The existing at-least-once + idempotent design absorbs the cost of forgetting `last_acked_push_id` across crashes (the cost is one extra round-trip drain on reconnect, which is free in human terms).

### Alt G — Reject duplicate connections instead of clobbering

The original draft of this spec proposed rejecting any second connection while the first was alive (`FAIL_DUPLICATE_CONNECTION`). Rejected on review because:

- VSock zombie connections (host-side socket lingering after guest restart) lock the planner out for hours until host TCP-style cleanup fires. A legitimate planner restart after hypervisor pause/resume becomes unrecoverable.
- The single-connection rule does not actually defend against in-VM threats. A compromised planner already controls the legitimate connection; an attacker process inside the VM stealing the session_token to open a second connection gains nothing.

Clobbering preserves the operational property of one stream per session at the dispatcher layer while eliminating the lockout failure mode. CID-mismatch protection (INV-VM-CAP-05) handles the actual threat (different VM trying to take over a session).

### Alt H — Block (pause) upstream producers when recipient queue is full

The producing handler (e.g., `CompleteTask`) blocks waiting for the recipient's queue space. Rejected because it breaks session independence (Executor held hostage to Orchestrator's pace), and SQLite write-lock is database-wide so cross-session blocking compounds into kernel-wide stalls. See §10.5.

### Alt I — Drop oldest unacked push to make room

At cap, drop the oldest unacked push. Rejected because dropping breaks at-least-once delivery (INV-PUSH-02). A dropped `EscalationResolved` means the Orchestrator never resumes from Paused. Silent loss of state-change notifications is worse than failing the session. See §10.7.

### Alt J — Block kernel writes (hold transaction) until queue space frees

`BEGIN IMMEDIATE` is held until the recipient drains. Rejected because SQLite's write lock is database-wide; one slow recipient stalls every session's intent processing. Fail-closed termination is consistent with INV-01. See §10.8.

### Alt K — `SlowDrain` recipient FSM state

Transition slow recipients to a distinct FSM state. Rejected because the Kernel cannot make recipients drain faster — `SlowDrain` doesn't do anything actionable that `KernelPush::QueuePressure { Critical }` doesn't already do, and unlike a push, an FSM state shift is invisible to the LLM. See §10.6.

### Alt L — Fixed 1000 cap regardless of session role

The original draft proposed a flat 1000 cap for every session. Rejected because Orchestrators with large sub-task DAGs can legitimately generate burst traffic well past 1000 events; a flat cap punishes plan-allowed parallelism. Replaced with the plan-derived formula in §10.1.

### Alt M — Markdown table as the idempotency enforcement

The original draft enforced the idempotency requirement via a "lint" rule on the documentation table. Rejected because Markdown tables don't enforce code semantics. Replaced with property-based testing in `tests/push_idempotency.rs` plus `compile_assert_all_variants_tested!` for compile-time exhaustiveness. See §8.

### Alt N — 30-second push ACK timeout

Considered as a tight bound to detect deadlocks fast. Rejected because legitimate push handlers may run between intents while an LLM call is in flight; 30 seconds would falsely fail planners during normal slow inferences. Default is 5 minutes with planner-activity extension (§7.4).
