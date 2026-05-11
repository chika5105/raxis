# `[authority]` — kernel-internal signing keys

> **Topic:** Policy reference | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

`[authority]` records the public halves of the kernel's two internal
signing keypairs. It is **not** an operator-edited block — these
keys are minted at genesis and persisted to the data dir. The
policy file stores only the public hex so any reader (including the
operator dashboard) can verify kernel-emitted signatures without
loading the private keys.

---

## Field reference

| Field | Type | Required | Effect |
|---|---|---|---|
| `authority_pubkey` | `String` (64 hex chars) | yes | Raw 32-byte Ed25519 verifying key for `ApprovalProof` signatures and policy artifact signatures. The kernel uses the matching private half to sign every artifact it emits to disk. |
| `quality_pubkey` | `String` (64 hex chars) | yes | Raw 32-byte Ed25519 verifying key reserved for V2 witness-record signing (`kernel-store.md §2.5.4`). Loaded but unused at boot in V1. |

Both fields are mandatory; missing either at boot triggers
`BOOT_ERR_KEY_LOAD`.

---

## Example

```toml
[authority]
authority_pubkey = "8b1f2a4c6d8e0f9b3a7c5e4d2f1b0a9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3"
quality_pubkey   = "a1b2c3d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f6071829304a5b6c7d8e"
```

The corresponding **private** keys live at:

- `$RAXIS_DATA_DIR/keys/authority.key` (mode `0600`).
- `$RAXIS_DATA_DIR/keys/quality.key` (mode `0600`).

Both files are owned by the kernel process. The policy never holds
the private bytes; the policy is the *publishable* half.

---

## When this block changes

The genesis ceremony writes `[authority]` once and never again
under normal operation. The block changes only if you:

- **Re-genesis a fresh data dir.** The new genesis mints new keys
  and writes new fingerprints — old artifacts signed with the
  previous keys cannot be verified by the new install.
- **Run a kernel-key rotation ceremony.** This is intentionally
  not yet a single CLI command; it requires staging a new policy
  with new `[authority]` values, re-signing every in-flight signed
  artifact (escalation tokens, delegations) under the new keys, and
  performing an `epoch advance` with both old and new versions
  side-by-side until every consumer has migrated. Out of scope for
  the V2 MVP — file an issue if you need it.

You should **never** hand-edit `[authority]`. The kernel's loader
boots the matching private keys from `keys/`; pasting the public
hex of a different keypair makes those private files mismatched and
the kernel fails to boot.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `BOOT_ERR_KEY_LOAD: keys/authority.key missing` | Genesis was never run on this data dir, OR the file was deleted. There is no rebuild path; re-genesis. |
| `BOOT_ERR_KEY_LOAD: authority pubkey mismatch` | `[authority] authority_pubkey` in policy doesn't match the public half of `keys/authority.key`. Either the policy was edited by hand, or the data dir's keys were swapped between two installs. |
| `BOOT_ERR_CREDENTIAL_MODE: keys/authority.key not 0600` | `chmod 600 "$RAXIS_DATA_DIR/keys/"*.key`. The file mode is enforced at boot. |

---

## Reference: relevant kernel-internal files

| Path | Purpose |
|---|---|
| `<data-dir>/keys/authority.key` | Private half of the authority keypair. Mode `0600`, owned by the kernel user. |
| `<data-dir>/keys/quality.key` | Private half of the quality keypair. Same mode. |
| `<data-dir>/keys/verifier_token.key` | HMAC seed for verifier process tokens. Not surfaced in policy because it's a symmetric secret. |

---

## Variations / extension points

There are no operator-tunable knobs in this block. If you need
distinct signing identities for different artifact families, that's
out of scope for V2 — the kernel uses **one** authority keypair for
every internally-signed artifact and **one** quality keypair
reserved for the witness layer.
