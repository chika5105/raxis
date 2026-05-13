# Concurrency and Locking — V2 Canonical Contract

**Status:** normative. Every lock-bearing struct under `raxis/`
MUST follow this contract; deviations require a doc-comment that
explains the exception and a sister entry in
`raxis/specs/v2/lock-audit-<date>.md`.

**See also:** `raxis/specs/v2/lock-audit-20260513.md` — the V2
sweep that hand-traced every existing lock-bearing site and
verified compliance.

## 1. Why this document exists

V2 inherited a `Mutex<rusqlite::Connection>` re-entrant deadlock
from commit `8524f50` (`feat(store): SqliteCircuitStore`) that
hung five tests indefinitely; the bug was masked for ~3 days
because the only callers in the tree were the (hanging) unit
tests. The fix (`bb89145`,
`fix(store/circuit-breaker): eliminate re-entrant
Mutex<Connection> deadlock in record/promote/reset paths`)
extracted a `load_with_conn(&Connection, …)` helper and made the
public `load` wrap it with a single lock acquisition; the
mutating methods now reuse the outer guard for the post-commit
read-back.

This file pins the lessons learned so the next contributor adding
shared state cannot re-introduce the same shape.

## 2. Single-lock-per-public-call rule (`INV-LOCK-01`)

Every public method on a `&self` API that holds a lock MUST
acquire that lock **exactly once** for the full duration of the
call. Concretely:

- A method that locks `self.x` may NOT call another `&self`
  method that ALSO locks `self.x` while the guard is alive.
- If a private helper needs the same locked resource, take the
  borrowed resource as a parameter
  (`helper_with_x(&self, x: &X, …)`); the public surface wraps
  with `let g = self.x.lock(); helper_with_x(&g, …)`.
- The doc-comment on every public method MUST state the lock
  contract.

This rule applies to:

- `std::sync::Mutex` / `std::sync::RwLock`
- `parking_lot::Mutex` / `parking_lot::RwLock`
- `tokio::sync::Mutex` / `tokio::sync::RwLock`

None of these are re-entrant on the same thread (the parking_lot
ones panic on re-entry; the std ones deadlock; the tokio ones
suspend forever on the runtime). The single-lock-per-call rule
makes re-entry mechanically impossible.

## 3. Lock-order discipline (`INV-LOCK-02`)

When a critical section MUST hold two locks (rare; document the
necessity), pin a global ordering and document it:

1. The order MUST be the same at every call site that takes both
   locks (otherwise an A→B at one site + B→A at another site is
   a classic two-thread deadlock).
2. The order MUST be documented in the module-level doc-comment
   AND in `lock-audit-<date>.md`.
3. The borrow checker MUST help where possible — e.g. lock B
   should only be reachable through a guard of A (so the
   compiler refuses to reverse the order).

V2's only pinned multi-lock site:

- `SessionStreamCapture` (`crates/dashboard-kernel/src/stream_capture.rs`)
  takes per-session `file_size` THEN per-session `file`.
  `compact_locked` is private and only called from `append`
  while holding `file_size`; it then takes `file`. Order:
  `file_size → file`.

## 4. `await`-while-holding-mutex (`INV-LOCK-03`)

Holding a `tokio::sync::Mutex` guard across an `.await` is
allowed when:

1. The awaited future does NOT take the same mutex
   (mechanical: the borrow checker sees the guard is alive).
2. The awaited future does NOT take ANOTHER lock that any other
   task could take while waiting on this guard
   (`INV-LOCK-02` cross-check).

Holding a `std::sync::Mutex` or `parking_lot::Mutex` guard across
an `.await` is **forbidden** in async contexts (these block the
worker thread, not the task; a deadlock here freezes the
runtime).

## 5. SQLite-specific rule (`INV-LOCK-04`)

`Mutex<rusqlite::Connection>` follows a stricter form of
`INV-LOCK-01`:

- The mutex MUST be `tokio::sync::Mutex` for any code path that
  may run inside the kernel runtime (`crates/store/src/db.rs`
  documents this as INV-STORE-01).
- A `BEGIN IMMEDIATE` transaction MUST be opened inside the
  guard scope and committed/rolled-back before the guard drops.
  The borrow checker enforces this — `Transaction<'_>` borrows
  from `Connection`.
- The post-commit read-back (a common pattern: write, then
  re-read the canonical row to return) MUST reuse the outer
  guard via a private `_with_conn` helper. **Calling
  `self.load(...)` (or any other `&self` method that locks
  `self.conn`) from inside a write-path's outer guard is the
  bug `bb89145` fixed.**

## 6. Channel discipline (`INV-LOCK-05`)

`tokio::sync::mpsc::channel(N)` producers MUST NOT hold a lock
that the consumer needs to release. Concretely:

- A producer task that holds lock A and sends to a bounded
  channel risks blocking forever if the consumer task needs A
  to read the next message.
- The fix: producer copies what it needs out from under the
  lock (cloning the `Sender` is `O(1)` — clone the sender, drop
  the guard, send).

## 7. `Condvar` (`INV-LOCK-06`)

V2 does not use `Condvar`. If a future PR introduces one,
`Condvar::wait(guard)` releases ONLY the passed guard — any
other locks held at the call site stay held. Document the
order in `lock-audit-<date>.md`.

## 8. Verification protocol

A new lock-bearing struct lands as a PR with:

- The struct's doc-comment includes a "Lock contract" section
  pointing back to this file.
- Every public method that takes a lock has a `Lock contract:`
  paragraph in its rustdoc.
- A regression test that exercises the previously-broken shape
  (use `tokio::time::timeout(Duration::from_secs(5), …)` so a
  regression hangs the test instead of the suite).
- The audit row in `lock-audit-<date>.md` is updated with the
  new site's verdict (typically SAFE for a fresh well-formed
  site).

## 9. Bug archaeology

Past lock-related deadlocks captured in this contract so the
shape is searchable in the future:

- **Re-entrant `Mutex<Connection>` (May 2026).** Commit
  `8524f50` introduced four mutating methods on
  `SqliteCircuitStore` that took `self.conn.lock()`, ran a
  `BEGIN IMMEDIATE`, then called `self.load(provider, model)`
  for the post-commit read-back. `Mutex<Connection>` is not
  re-entrant; the second acquisition parked the calling thread
  in `__psynch_mutexwait` while still holding the outer guard.
  Five tests hung indefinitely. Fixed in `bb89145`.

(Future entries append-only.)
