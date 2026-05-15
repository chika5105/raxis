// raxis-kernel::auth::cid_blocklist — pre-auth VSock CID blocklist (Step 15).
//
// Normative reference: `v2-deep-spec.md §Step 15 — Pre-Auth Blocklist`.
//
// Purpose
// -------
// Defends the VSock `accept()` layer from a hostile process that
// reaches the Kernel before any authentication has occurred. There is
// no session to revoke at that point — the connection is pre-auth —
// so we maintain an in-memory set of "known-bad" VSock CIDs and
// short-circuit `accept()` for CIDs already in the set. The check is
// a single hash-set lookup against an integer key, performed BEFORE
// any bytes are read from the socket.
//
// Why `FxHashSet<u32>` (not `HashSet<u32>`)
// -----------------------------------------
// Per `v2-deep-spec.md §Step 15` line 625 and `kernel-store.md §2.5.1
// "Hash table strategy"`: VSock CIDs are Kernel-generated integers
// derived at VM creation time. They are NOT attacker-controlled
// values, so HashDoS resistance (the only thing the SipHash-13 default
// gets us over FxHash) buys nothing here, and the FxHash function is
// ~2× faster on small integer keys. The blocklist is consulted on
// every `accept()` call, so the speed win is load-bearing.
//
// Why an `RwLock` and not `Mutex`
// -------------------------------
// The accept loop is the hot reader: every connection consults the
// blocklist exactly once. Writers (the pre-auth violation handler)
// are rare. `RwLock` lets the accept loop fan out across multiple
// connection attempts without contending with itself, and only
// serialises against the (much rarer) insertion path.
//
// Special CID values
// ------------------
// Two CID values are reserved by the Linux VSock protocol and MUST
// NOT be inserted into the blocklist:
//   * `VMADDR_CID_HOST  = 2`   — the host-side CID. Blocking it would
//     blacklist the kernel's own loopback (used by host-resident
//     planners during V1).
//   * `VMADDR_CID_LOCAL = 1`   — local-only loopback. Same reasoning.
//
// The `insert_safe` constructor rejects these values with
// `BlocklistInsertError::ReservedCid` so a careless caller cannot
// accidentally lock out the host. The `insert_unchecked` API is
// intentionally `pub(crate)` and only used by tests that want to
// pin the underlying set behaviour.

use std::sync::RwLock;

use rustc_hash::FxHashSet;

/// Reserved Linux VSock CID for the host-side endpoint
/// (`<linux/vm_sockets.h>`'s `VMADDR_CID_HOST`).
pub const VMADDR_CID_HOST: u32 = 2;

/// Reserved Linux VSock CID for local-only loopback
/// (`VMADDR_CID_LOCAL`).
pub const VMADDR_CID_LOCAL: u32 = 1;

/// Reserved Linux VSock CID meaning "any CID" / wildcard
/// (`VMADDR_CID_ANY = 0xFFFFFFFF`). Inserting this would block every
/// future connection — clearly nonsense.
pub const VMADDR_CID_ANY: u32 = u32::MAX;

/// Errors raised by `CidBlocklist::insert`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlocklistInsertError {
    /// The caller tried to block one of the reserved Linux VSock CIDs
    /// (`VMADDR_CID_HOST`, `VMADDR_CID_LOCAL`, or `VMADDR_CID_ANY`).
    /// Doing so would lock the host out of its own kernel; reject
    /// fail-closed.
    #[error("CID {0} is a reserved VSock identifier and cannot be blocklisted")]
    ReservedCid(u32),
}

/// In-memory set of CIDs whose connection attempts are dropped at
/// `accept()` time. Step 15 of `v2-deep-spec.md`.
///
/// Threading: this type holds an `RwLock<FxHashSet<u32>>` internally
/// and exposes only `&self` methods, so it is `Send + Sync` and can
/// be wrapped in an `Arc` shared between the accept loop and the
/// pre-auth violation handler.
#[derive(Debug)]
pub struct CidBlocklist {
    inner: RwLock<FxHashSet<u32>>,
}

impl CidBlocklist {
    /// Create an empty blocklist.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(FxHashSet::default()),
        }
    }

    /// Add `cid` to the blocklist. Returns `Ok(true)` if the CID was
    /// newly inserted, `Ok(false)` if it was already present, or an
    /// error if the caller tried to block a reserved VSock CID.
    ///
    /// **Idempotent:** repeated calls with the same CID are harmless;
    /// the second call returns `Ok(false)`. The pre-auth violation
    /// handler can therefore call `insert` unconditionally on every
    /// malformed-frame event without bookkeeping.
    pub fn insert(&self, cid: u32) -> Result<bool, BlocklistInsertError> {
        if matches!(cid, VMADDR_CID_HOST | VMADDR_CID_LOCAL | VMADDR_CID_ANY) {
            return Err(BlocklistInsertError::ReservedCid(cid));
        }
        Ok(self
            .inner
            .write()
            .expect("CidBlocklist lock poisoned")
            .insert(cid))
    }

    /// Remove `cid` from the blocklist. Returns `true` if the CID was
    /// present, `false` otherwise.
    ///
    /// The kernel's accept loop never calls `remove` on its own — a
    /// blocklisted CID stays blocklisted for the lifetime of the
    /// kernel process. The operator may invoke this through an
    /// administrative path (e.g. `raxis-cli reset cid-blocklist`) to
    /// clear an entry once the underlying compromise is confirmed
    /// remediated. We expose it primarily so tests can rebuild a
    /// fresh blocklist between scenarios without rebuilding the
    /// surrounding kernel state.
    pub fn remove(&self, cid: u32) -> bool {
        self.inner
            .write()
            .expect("CidBlocklist lock poisoned")
            .remove(&cid)
    }

    /// Pre-auth gate: `true` if this CID should be dropped at
    /// `accept()` before any byte is read off the socket. This is
    /// the hot path; it takes a read lock and runs in O(1).
    pub fn contains(&self, cid: u32) -> bool {
        self.inner
            .read()
            .expect("CidBlocklist lock poisoned")
            .contains(&cid)
    }

    /// Number of entries currently on the blocklist. Used by the
    /// operator-side metrics surface and by tests pinning insert /
    /// remove arithmetic.
    pub fn len(&self) -> usize {
        self.inner.read().expect("CidBlocklist lock poisoned").len()
    }

    /// Empty-set predicate.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drain the blocklist, returning the previously-blocked CIDs in
    /// undefined order. Used by `raxis-cli reset cid-blocklist`.
    /// We deliberately do NOT expose iteration over the live set —
    /// callers that need a snapshot get one via `clear`.
    pub fn clear(&self) -> Vec<u32> {
        let mut guard = self.inner.write().expect("CidBlocklist lock poisoned");
        guard.drain().collect()
    }

    /// `pub(crate)` escape hatch for tests that need to seed the
    /// blocklist with values that `insert` would otherwise reject.
    /// Production code MUST go through `insert`.
    #[cfg(test)]
    pub(crate) fn insert_unchecked(&self, cid: u32) {
        self.inner
            .write()
            .expect("CidBlocklist lock poisoned")
            .insert(cid);
    }
}

impl Default for CidBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_blocklist_is_empty() {
        let bl = CidBlocklist::new();
        assert_eq!(bl.len(), 0);
        assert!(bl.is_empty());
        assert!(!bl.contains(42));
    }

    #[test]
    fn insert_returns_true_on_first_insertion_and_false_on_repeat() {
        // Idempotency contract — the pre-auth violation handler calls
        // `insert` unconditionally on every malformed-frame event, so
        // repeats must be harmless and observable.
        let bl = CidBlocklist::new();
        assert_eq!(bl.insert(101), Ok(true), "first insert is novel");
        assert_eq!(bl.insert(101), Ok(false), "second insert is a no-op");
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn contains_returns_true_after_insertion() {
        let bl = CidBlocklist::new();
        bl.insert(7).unwrap();
        assert!(bl.contains(7));
        assert!(!bl.contains(8), "neighbouring CID must not collide");
    }

    #[test]
    fn remove_returns_true_when_cid_was_present() {
        let bl = CidBlocklist::new();
        bl.insert(99).unwrap();
        assert!(bl.remove(99), "remove must report presence");
        assert!(!bl.contains(99));
        assert!(!bl.remove(99), "remove of an absent CID returns false");
    }

    #[test]
    fn insert_rejects_reserved_host_cid() {
        let bl = CidBlocklist::new();
        let err = bl
            .insert(VMADDR_CID_HOST)
            .expect_err("VMADDR_CID_HOST must be rejected");
        assert!(matches!(err, BlocklistInsertError::ReservedCid(2)));
        assert!(
            bl.is_empty(),
            "rejection must NOT mutate the underlying set"
        );
    }

    #[test]
    fn insert_rejects_reserved_local_loopback_cid() {
        let bl = CidBlocklist::new();
        let err = bl
            .insert(VMADDR_CID_LOCAL)
            .expect_err("VMADDR_CID_LOCAL must be rejected");
        assert!(matches!(err, BlocklistInsertError::ReservedCid(1)));
    }

    #[test]
    fn insert_rejects_wildcard_any_cid() {
        let bl = CidBlocklist::new();
        let err = bl
            .insert(VMADDR_CID_ANY)
            .expect_err("VMADDR_CID_ANY must be rejected");
        assert!(matches!(err, BlocklistInsertError::ReservedCid(u32::MAX)));
    }

    #[test]
    fn cid_three_is_the_first_legal_blocklist_entry() {
        // VMADDR_CID_HYPERVISOR = 0 is legal but unusual; VMADDR_CID_LOCAL
        // = 1 and VMADDR_CID_HOST = 2 are reserved. The first "ordinary"
        // VM CID assigned by the host's VSock subsystem is therefore 3.
        // Pin that 3 admits cleanly — defense in depth against an
        // accidental "block CIDs <= N" guard.
        let bl = CidBlocklist::new();
        bl.insert(3).unwrap();
        assert!(bl.contains(3));
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn cid_zero_admits_for_completeness() {
        // CID 0 is `VMADDR_CID_HYPERVISOR` (rare in modern Linux).
        // Step 15 does not list it as reserved, so the blocklist
        // admits it. We pin this so a future tightening of the reserved
        // set is a deliberate spec change, not an accidental drift.
        let bl = CidBlocklist::new();
        assert_eq!(bl.insert(0), Ok(true));
        assert!(bl.contains(0));
    }

    #[test]
    fn clear_returns_previous_entries_and_empties_set() {
        let bl = CidBlocklist::new();
        for cid in [10, 20, 30] {
            bl.insert(cid).unwrap();
        }
        let mut drained = bl.clear();
        drained.sort();
        assert_eq!(drained, vec![10, 20, 30]);
        assert!(bl.is_empty());
    }

    #[test]
    fn clear_on_empty_blocklist_returns_empty_vec() {
        let bl = CidBlocklist::new();
        assert!(bl.clear().is_empty());
        assert!(bl.is_empty());
    }

    #[test]
    fn many_unique_cids_round_trip() {
        // Exercise the underlying FxHashSet under a moderate fan-out
        // to flush any "wrong-collision" sensitivity. CIDs are u32;
        // this would catch a bug like "we accidentally truncated to
        // u16" or "the hasher confuses 100 and 101".
        let bl = CidBlocklist::new();
        for cid in 100..=999u32 {
            bl.insert(cid).unwrap();
        }
        assert_eq!(bl.len(), 900);
        for cid in 100..=999u32 {
            assert!(bl.contains(cid), "missing CID {cid}");
        }
        // Boundary values should NOT be accidentally present.
        assert!(!bl.contains(99));
        assert!(!bl.contains(1000));
    }

    #[test]
    fn blocklist_is_send_and_sync() {
        // Compile-time pin: the kernel wraps the blocklist in an
        // `Arc<CidBlocklist>` shared between the accept loop and the
        // pre-auth violation handler. Both Send and Sync are required.
        // A future regression that swaps `RwLock` for an unsynchronised
        // primitive surfaces here.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CidBlocklist>();
    }

    #[test]
    fn concurrent_readers_do_not_block_each_other() {
        // The accept loop fans out across many connection attempts;
        // the blocklist read MUST permit concurrent readers. We assert
        // the contract by holding two read guards at the same time —
        // an `RwLock` permits this; a `Mutex` would deadlock.
        use std::sync::Arc;

        let bl = Arc::new(CidBlocklist::new());
        bl.insert(42).unwrap();

        let g1 = bl.inner.read().unwrap();
        let g2 = bl.inner.read().unwrap();
        assert!(g1.contains(&42));
        assert!(g2.contains(&42));
    }

    #[test]
    fn insert_unchecked_bypasses_reserved_check_for_test_setup() {
        // Pin the test escape hatch: production code MUST go through
        // `insert`, but test fixtures occasionally need to seed an
        // arbitrary value. This test documents that contract.
        let bl = CidBlocklist::new();
        bl.insert_unchecked(VMADDR_CID_HOST);
        assert!(bl.contains(VMADDR_CID_HOST));
    }
}
