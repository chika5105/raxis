# Mint an operator cert offline (`raxis cert mint`)

> **Topic:** Setup | **Time to read:** ~3 min | **Complexity:** ⭐ Beginner

`raxis cert mint` produces an `operator.cert.toml` from a private
Ed25519 PEM. The cert binds a public key to a display name, a set
of permitted operations, and a validity window. The kernel admits
**only** signed artifacts whose signature matches an operator entry
*and* whose cert is unexpired and unrevoked.

This recipe is the air-gapped flow: mint on a machine that holds
the private key, then ship only the resulting cert to the kernel
host.

---

## Prerequisites

- An Ed25519 private PEM (see *Generate an operator keypair offline*
  recipe).
- The `raxis` CLI on `$PATH`. The CLI needs no kernel state to
  mint — `raxis cert mint` is a pure local crypto operation.

---

## Quick mint (defaults)

```bash
raxis cert mint \
  --key "$HOME/raxis-keys/operator_private.pem" \
  --display-name "$USER" \
  --out "$HOME/raxis-keys/operator.cert.toml"
```

Defaults applied:

- `--permitted-ops` defaults to **all** operator operations
  (`CreateInitiative,ApprovePlan,RejectPlan,AbortInitiative,...`).
  Restrict it explicitly for CI / break-glass keys (see *Variations*).
- `--validity-days` defaults to `365`. The cert's `not_after` is
  the host's clock at mint time + this many days.
- The signing algorithm is fixed at Ed25519. There is no toggle.

---

## Inspect what you minted

```bash
raxis cert show "$HOME/raxis-keys/operator.cert.toml"
```

Sample output:

```text
display_name:    alice
fingerprint:     6ad9c1f8...d0ee
permitted_ops:   CreateInitiative, ApprovePlan, RejectPlan, ...
not_before:      2026-05-10T17:30:00Z
not_after:       2027-05-10T17:30:00Z
key_id:          ed25519:6ad9c1f8...
self_signed:     true
```

`fingerprint` is what you paste into `[[operators.entries]]
pubkey_fingerprint` in `policy.toml`. The cert itself goes inline
under `[operators.entries.cert]` once you re-sign.

---

## Verify the signature offline

```bash
raxis cert verify "$HOME/raxis-keys/operator.cert.toml"
```

This cryptographically verifies that the cert's `signature` field
was produced by the public key inside the cert. Self-signed certs
verify against themselves; certs signed by a separate root authority
require `--root <path>`.

---

## Re-issue (rotate) a cert

When the existing cert nears expiry, re-mint with the **same**
private key:

```bash
raxis cert mint \
  --key "$HOME/raxis-keys/operator_private.pem" \
  --display-name "$USER" \
  --validity-days 365 \
  --out "$HOME/raxis-keys/operator-new.cert.toml"
```

The new cert has the **same fingerprint** (the fingerprint hashes
the *public key*, which hasn't changed) but a fresh validity window.
Replace the inline cert in `policy.toml` and re-sign — no
`policy_epoch_history` migration is needed because the operator
identity hasn't changed.

To rotate the *key* itself (not just the cert), see the
*Operator-mediated key rotation* pattern recipe.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `cert mint: --key <path> is required` | The CLI does NOT consult `RAXIS_OPERATOR_KEY` for `cert mint` — pass `--key` explicitly so the operation is fully argument-traceable. |
| `cert mint: unknown permitted op "FooBar"` | A typo or an op that doesn't exist. Run `raxis cert mint --help` for the canonical list. |
| `cert show: failed to parse: missing field "signature"` | The cert file is corrupt or hand-edited. Re-mint. |
| `cert verify: signature did not match key inside cert` | The cert was hand-edited or its signature is from a different key. Re-mint. |

---

## Reference: command surface

| Command | Purpose |
|---|---|
| `raxis cert mint --key <pem> --display-name <name> [--permitted-ops <csv>] [--validity-days N] --out <path>` | Mint a self-signed cert from a private PEM. |
| `raxis cert mint-emergency` | Same as `mint` but stamps a `kind = "Emergency"` claim on the cert; used for break-glass operators with auto-revoke after first use. |
| `raxis cert show <path>` | Decode and pretty-print a cert. |
| `raxis cert verify <path>` | Cryptographically verify the cert's self-signature. |
| `raxis cert install <path>` | Inject a cert into the running kernel's policy under a fresh epoch (requires `--operator-key` for the policy re-signing step). |
| `raxis cert revoke --fingerprint <fp> [--reason <text>]` | Add a revocation row; the kernel rejects all subsequent signatures from that fingerprint. |
| `raxis cert list` | Show all operator certs currently in policy + their expiry dates. |
| `raxis cert list-revocations` | Show every revoked cert + the epoch they were revoked at. |

---

## Variations

- **Restrict to CI signing only.**

  ```bash
  raxis cert mint \
    --key ci-private.pem \
    --display-name ci-bot \
    --permitted-ops CreateInitiative \
    --validity-days 90 \
    --out ci.cert.toml
  ```

  The CI bot can submit plans but cannot approve escalations or grant
  delegations. Same key, narrower powers.

- **Break-glass cert.**

  ```bash
  raxis cert mint-emergency \
    --key breakglass.pem \
    --display-name breakglass-2026-05 \
    --validity-days 7 \
    --out breakglass.cert.toml
  ```

  Short validity + emergency claim. The kernel emits an extra audit
  event (`EmergencyCertUsed`) on every signature from this fingerprint.

- **Short-lived dev cert.** `--validity-days 1` for an ephemeral
  developer key that auto-expires overnight. Combined with
  `cert revoke` it's a full-trust-model story for local hot-seat
  development.
