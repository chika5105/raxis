# `[meta]` — policy artifact metadata

> **Topic:** Policy reference | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

The `[meta]` block stamps the policy bundle with its epoch, the
operator who signed it, and the wall-clock at signing time. The
kernel uses these fields to track the active epoch in
`policy_epoch_history`, attribute every kernel decision back to a
specific operator, and reject artifacts older than the
`[plan_signing] max_plan_bundle_age_secs` window (when applicable).

---

## Field reference

| Field | Type | Required | Effect |
|---|---|---|---|
| `epoch` | `u64` | yes | Monotonic counter. Each `raxis policy sign` increments this. The kernel rejects an admit whose epoch is < the current. |
| `signed_by` | `String` (hex fingerprint) | yes | The operator's `pubkey_fingerprint`. Must match an entry under `[[operators.entries]]`. |
| `signed_at` | `i64` (Unix seconds) | yes | Wall-clock at signing time. Used for `policy_epoch_history.signed_at`; appears in audit events. |
| `policy_sha256` | `String` | optional | SHA-256 of the policy bytes embedded by the signing tool. The loader **ignores** this field and computes the SHA-256 fresh from raw bytes; it's accepted only for forward-compat. |

---

## Example

```toml
[meta]
epoch     = 7
signed_by = "8a4f2c1e9b6d0f3a7e5c4b2d1f8e7a6c5b4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f"
signed_at = 1730000000
```

`signed_by` is the **fingerprint**, not the display name. Find it via:

```bash
raxis cert list \
  | awk '$1 != "display_name" {print $0}'
```

---

## Signing semantics

`raxis policy sign` overwrites all three fields atomically:

1. Reads the current `epoch` from `kernel.db.policy_epoch_history`.
2. Increments by one.
3. Stamps `signed_by` from the key passed via `--key`.
4. Stamps `signed_at` from the host's `time(NULL)`.
5. Re-emits the canonicalised TOML and writes a sidecar
   `<policy>.sig` with the Ed25519 signature.

You almost never edit `[meta]` by hand — `raxis policy sign` is the
canonical mutator. The exception is hand-bootstrapping a test
fixture, where you stamp epoch=1 and pre-compute the signature for
deterministic testing.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `signed_by` doesn't match any operator entry | The signing key isn't installed under `[[operators.entries]]`. Add the operator first (see *Add a second operator to an existing install* recipe). |
| `epoch` decreases between two `policy sign` invocations | A second `policy sign` from a different host with stale state. Always sign from the kernel host or fetch the latest policy first. |
| `signed_at` more than `max_plan_bundle_age_secs` in the past | Policy is too stale; re-sign now. The kernel doesn't auto-rotate. |
| `Validation: epoch must be > 0` | The genesis row uses `epoch=1`; you can't manually set `epoch=0`. |

---

## Reference: related commands + state

| Surface | Purpose |
|---|---|
| `raxis policy sign <path> --key <pem>` | Atomic re-sign — increments epoch, stamps signed_by/signed_at, writes sidecar signature. |
| `raxis policy show --history` | Prints `policy_epoch_history` table: every (epoch, signed_by, signed_at, sha256) row the kernel has seen. |
| `raxis epoch advance --policy <new.toml> --sig <new.sig>` | Atomically applies a pre-signed new policy bundle. |
| `policy_epoch_history` (kernel.db) | Operator-readable, kernel-internal table that records every epoch transition. |
