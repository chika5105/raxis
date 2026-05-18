# `[[operators.entries]]` — operator identities

> **Topic:** Policy reference | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

Every signed artifact the kernel admits is attributed to one of the
`[[operators.entries]]` blocks. Each block binds an operator's
public key fingerprint to an embedded cert, a display name, and the
permitted operator IPC operations. **No cert ⇒ no entry** — the
parser refuses entries without an embedded `[operators.entries.cert]`
sub-table.

---

## Field reference

| Field | Type | Required | Effect |
|---|---|---|---|
| `pubkey_fingerprint` | `String` (32 hex chars) | yes | SHA-256[:16] of the operator's Ed25519 public key. Stamped into every signed artifact's `signed_by` field; appears on every audit row attributing a kernel decision to this operator. |
| `display_name` | `String` | yes | Human-readable label used by `raxis cert list`, audit events, the dashboard, and CLI prompts. |
| `pubkey_hex` | `String` (64 hex chars) | yes | Raw 32-byte Ed25519 verifying key, lower hex. The kernel verifies signatures with this. |
| `permitted_ops` | `Vec<String>` | yes | List of `OperatorOp` strings (`CreateInitiative`, `ApprovePlan`, `RejectPlan`, `AbortInitiative`, `QuarantinePlan`, `RaiseEscalation`, `ApproveEscalation`, `DenyEscalation`, `GrantDelegation`, `RevokeSession`, `AdvanceEpoch`, `CredentialAdd`, `CredentialRotate`, ...). The kernel rejects an op outside this scope with `OPERATOR_NOT_AUTHORIZED`. **At validate time the kernel mirrors `cert.permitted_ops` over this field — the cert is the source of truth.** |
| `force_misconfig_bypass` | `bool` | optional, default `false` | When `true`, structural cert validation errors do NOT block policy load. Bypasses are recorded in `bypassed_cert_misconfigs` and audited via `OperatorCertMisconfigBypassed`. **Self-signature failures and pubkey-mismatch errors are NEVER bypassable.** |

### Embedded cert sub-table

`[operators.entries.cert]` carries the entire `OperatorCert` struct
inline. Its fields:

| Field | Type | Effect |
|---|---|---|
| `version` | `u32` | Cert format version. |
| `kind` | `String` | `"Standard"` or `"Emergency"`. |
| `display_name` | `String` | MUST equal the outer `display_name`. |
| `pubkey` | `String` (hex) | MUST equal the outer `pubkey_hex`. |
| `permitted_ops` | `Vec<String>` | Source of truth for the operator's scope. |
| `not_before` / `not_after` | `i64` (Unix secs) | Validity window. The kernel rejects signatures outside this window with `CERT_EXPIRED`. |
| `signature` | `String` (hex) | Ed25519 self-signature over the canonical-encoded cert body. |

---

## Example

```toml
[[operators.entries]]
pubkey_fingerprint = "8a4f2c1e9b6d0f3a"
display_name       = "alice"
pubkey_hex         = "8a4f2c1e9b6d0f3a8a4f2c1e9b6d0f3a8a4f2c1e9b6d0f3a8a4f2c1e9b6d0f3a"
permitted_ops      = ["CreateInitiative", "ApprovePlan", "GrantDelegation"]

[operators.entries.cert]
version       = 1
kind          = "Standard"
display_name  = "alice"
pubkey        = "8a4f2c1e9b6d0f3a8a4f2c1e9b6d0f3a8a4f2c1e9b6d0f3a8a4f2c1e9b6d0f3a"
permitted_ops = ["CreateInitiative", "ApprovePlan", "GrantDelegation"]
not_before    = 1730000000
not_after     = 1761536000
signature     = "<128 hex chars>"
```

The cert + outer fields together form the operator entry. The
loader **mirrors** `cert.permitted_ops` over the outer
`permitted_ops`; whatever you typed at the outer level is replaced.
Always keep them in sync to avoid post-load surprises.

---

## Adding an operator

```bash
# On the new operator's machine:
raxis cert mint \
  --key bob_private.pem \
  --display-name bob \
  --ops "CreateInitiative,ApprovePlan" \
  --validity-days 365 \
  --out bob.cert.toml

# On the kernel host:
raxis cert install bob.cert.toml \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml"
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
```

See *Add a second operator to an existing install* recipe for the
end-to-end ceremony, including the offline-cert exchange.

---

## Revoking an operator

```bash
raxis --operator-key "$RAXIS_OPERATOR_KEY" cert revoke ./bob.cert.toml \
  --reason rotation \
  --reference change-2026-05
```

Revocation writes a signed record under `<data-dir>/revocations/`.
Restart the kernel for the revocation record to take effect; from
then on, the kernel rejects subsequent signatures from the revoked
fingerprint with `CERT_REVOKED`.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `cert: missing field "signature"` at policy load | Hand-edited cert; re-mint and re-paste. |
| `cert pubkey != outer pubkey_hex` | Mismatched fields. The cert is authoritative; either fix the outer to match or re-mint with the right key. |
| `OperatorCertMisconfigBypassed` audit event on every kernel boot | An entry has `force_misconfig_bypass = true` AND its cert tripped a structural invariant. Address the underlying cert problem and clear the bypass. |
| `OPERATOR_NOT_AUTHORIZED` on `policy sign` | The signer's `permitted_ops` doesn't include `PolicySign` (or whatever the op is). Re-mint a cert with the right ops. |
| `CERT_EXPIRED` on every signature | The cert's `not_after` has elapsed. Re-mint and re-install. |

---

## Reference: relevant CLI

| Command | Purpose |
|---|---|
| `raxis cert list` | Enumerate operator entries + their expiry windows. |
| `raxis cert mint --key <pem> --display-name <name> --ops <csv> [--validity-days N] --out <path>` | Mint a self-signed cert. |
| `raxis cert install <cert.toml> --policy <policy.toml>` | Insert a cert-backed operator entry. |
| `raxis [--operator-key <pem>] cert revoke <cert.toml> --reason <rotation\|compromise> --reference <id>` | Revoke an operator cert. |
| `raxis cert verify <cert.toml>` | Cryptographic self-signature check, offline. |

---

## Variations

- **Read-only auditor.** No cert is needed for read-only local
  inspection commands; access is controlled by filesystem and socket
  permissions.
- **Time-boxed co-signer.** Short `--validity-days 7`. Pair with a
  rotation reminder.
- **Multiple roles for one human.** A single human can have multiple
  certs with different `display_name`s and scopes — useful when
  audit attribution wants to tell apart "alice as on-call" vs
  "alice as policy-maintainer" decisions.
