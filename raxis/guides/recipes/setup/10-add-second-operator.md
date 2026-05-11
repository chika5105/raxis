# Add a second operator to an existing install

> **Topic:** Setup | **Time to read:** ~4 min | **Complexity:** ⭐⭐ Intermediate

The genesis operator is just one entry under `[[operators]]`.
Subsequent operators are added by minting their cert (offline,
on the second person's machine), pasting the cert into policy, and
re-signing with the **existing** operator's key. The new operator's
keypair never reaches the host.

---

## Prerequisites

- Existing install. `RAXIS_DATA_DIR` exported on the host.
- The existing operator's signing key at `$RAXIS_OPERATOR_KEY`.
- A second person's `operator.cert.toml` minted via
  `raxis cert mint` on their machine (they keep their private PEM).

---

## Step 1 — Receive the new operator's cert

The second operator runs on their own machine:

```bash
raxis cert mint \
  --key "$HOME/raxis-keys/bob_private.pem" \
  --display-name "bob" \
  --permitted-ops CreateInitiative,ApprovePlan \
  --validity-days 365 \
  --out "$HOME/raxis-keys/bob.cert.toml"

# Bob ships ONLY this file to the kernel host:
cat "$HOME/raxis-keys/bob.cert.toml"
```

On the host, save the cert somewhere safe — it's not secret, but
it's load-bearing:

```bash
mkdir -p "$RAXIS_DATA_DIR/operator-certs"
mv ~/transfers/bob.cert.toml "$RAXIS_DATA_DIR/operator-certs/"
```

---

## Step 2 — Inspect the cert before trusting it

```bash
raxis cert show "$RAXIS_DATA_DIR/operator-certs/bob.cert.toml"
raxis cert verify "$RAXIS_DATA_DIR/operator-certs/bob.cert.toml"
```

Sanity-check:

- `display_name` is what you expected.
- `permitted_ops` matches the agreed-upon scope.
- `not_after` is a sensible date.
- `verify` reports a green self-signature.

If any field is wrong, **reject the cert**. Bob re-mints; you do
not edit the cert by hand.

---

## Step 3 — Append the operator entry to policy

The cleanest approach is `raxis cert install`, which atomically:

1. Adds the `[[operators.entries]]` block to `policy.toml`.
2. Embeds the cert under `[operators.entries.cert]`.
3. Re-signs the bundle with `--operator-key` (the existing operator).

```bash
raxis cert install \
  "$RAXIS_DATA_DIR/operator-certs/bob.cert.toml" \
  --operator-key "$RAXIS_OPERATOR_KEY"
```

Or do it manually:

```bash
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"
```

Append:

```toml
[[operators.entries]]
pubkey_fingerprint = "<bob's fingerprint>"
display_name       = "bob"
pubkey_hex         = "<bob's pubkey hex>"
permitted_ops      = ["CreateInitiative", "ApprovePlan"]

[operators.entries.cert]
# Paste the entire body of bob.cert.toml here (under this header).
# All fields are required; do not modify.
```

Then re-sign:

```bash
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
```

---

## Step 4 — Confirm the kernel admitted the new operator

```bash
raxis log --kind PolicyReloaded --limit 1
# {"event":"PolicyReloaded","new_epoch_id":N,"changed_sections":["operators"]}

raxis cert list
# alice (existing): expires 2027-05-10  permitted_ops=...
# bob   (new):      expires 2027-05-10  permitted_ops=CreateInitiative,ApprovePlan
```

The audit chain has a `PolicyReloaded` event with
`changed_sections: ["operators"]`; `cert list` enumerates both
operators with their expiry windows and scopes.

---

## Step 5 — Bob runs his first signed operation

On Bob's machine:

```bash
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/bob_private.pem"
# (Either point at the kernel host's IP, or run on a host with the
# same RAXIS_DATA_DIR mounted via NFS — out of scope for this recipe.)

raxis submit plan ./plan.toml --no-dry-run
```

The audit chain attributes the resulting events to Bob's
fingerprint:

```text
{"event":"InitiativeCreated","initiative_id":"...","signed_by_fingerprint":"<bob's fp>","signed_by_display":"bob"}
```

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `cert install: not authorized — your cert lacks AddOperator` | Existing operator's cert doesn't include `AddOperator` in `permitted_ops`. Either re-mint the existing cert with that op, or hand-edit policy as in step 3 (the file edit only requires `policy sign` privilege, which all operators implicitly have via their key). |
| `policy validate: duplicate operator fingerprint` | Bob's cert was already added (perhaps under a different display name). Use `raxis cert list` to confirm. |
| `cert verify: signature did not match key inside cert` | The cert was tampered with in transit. Reject. Bob re-mints. |
| Bob's `submit plan` fails with `OPERATOR_NOT_AUTHORIZED` | The op he's trying isn't in his `permitted_ops`. Either he asks his cert to be re-issued, or the existing operator runs the op for him. |

---

## Reference: relevant CLI

| Command | Purpose |
|---|---|
| `raxis cert show <path>` | Inspect a cert before trusting it. |
| `raxis cert verify <path>` | Cryptographic self-signature check. |
| `raxis cert install <path> --operator-key <key>` | Atomic add-operator-then-sign ceremony. |
| `raxis cert revoke --fingerprint <fp> [--reason …]` | Revoke an operator immediately; subsequent signatures from that fingerprint are rejected. |
| `raxis cert list` | Enumerate every operator entry currently in policy. |
| `raxis cert list-revocations` | Enumerate every revoked operator + the epoch the revocation took effect. |

---

## Reference: `[[operators.entries]]` policy fields

| Field | Required | Effect |
|---|---|---|
| `pubkey_fingerprint` | yes | The 32-byte SHA-256 of the cert's pubkey, lower hex. Pasted into every signed artifact's `signed_by` field. |
| `display_name` | yes | Human-readable label; appears in `raxis cert list`, audit events, and CLI prompts. |
| `pubkey_hex` | yes | Raw 32-byte Ed25519 verifying key, lower hex. The kernel uses this for signature verification. |
| `permitted_ops` | yes | List of `OperatorOp` strings; the kernel rejects requests outside this scope with `OPERATOR_NOT_AUTHORIZED`. |
| `[operators.entries.cert]` | yes | Embedded cert block — fingerprint here MUST equal the outer `pubkey_fingerprint`; the parser rejects mismatches. |

---

## Variations

- **Read-only auditor.** Mint a cert with `--permitted-ops ""`
  (empty); no signing operation is permitted. The fingerprint still
  appears in `raxis cert list` so other operators see who has
  observation authority. Read-only operations (`raxis log`,
  `raxis status`, etc.) don't require a signed envelope at all and
  work for any user with shell access to `RAXIS_DATA_DIR`.
- **Time-bounded co-signer.** Mint Bob's cert with
  `--validity-days 30` for a 30-day on-call rotation. After expiry
  the kernel auto-rejects his signatures with `CERT_EXPIRED`; just
  re-issue when the rotation rolls.
- **Different signing scopes.** Bob can have `CreateInitiative` only,
  Carol `ApproveEscalation` only, Dave the full set. Each cert is
  evaluated per-call against its own `permitted_ops`.
