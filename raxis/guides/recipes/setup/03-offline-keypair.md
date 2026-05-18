# Generate an operator keypair offline

> **Topic:** Setup | **Time to read:** ~3 min | **Complexity:** ⭐ Beginner

The operator keypair is the root of trust for every signed artifact
the kernel admits — `policy.toml`, plan bundles, escalation
approvals, delegations. The recommended posture is to mint it on a
**second machine** that the kernel host cannot reach, then move only
the public key (or a pre-minted cert) to the kernel host. The
private bytes never touch the data dir.

---

## Prerequisites

- OpenSSL **3.x** on `$PATH` (`openssl version` MUST start with
  "OpenSSL 3", not "LibreSSL"). On macOS install with
  `brew install openssl@3` and prepend its `bin/` directory.
- A directory you control with mode `0700` to hold the private key.

---

## Step 1 — Generate the keypair

```bash
mkdir -p "$HOME/raxis-keys"
chmod 700 "$HOME/raxis-keys"
cd "$HOME/raxis-keys"

openssl genpkey -algorithm ED25519 -out operator_private.pem
openssl pkey -in operator_private.pem -pubout -out operator_public.pem

chmod 600 operator_private.pem
```

The result is two PEM files. `operator_private.pem` holds the
32-byte Ed25519 seed (PKCS#8-encoded); `operator_public.pem` holds
the 32-byte verifying key. **Only the public file ever leaves this
machine.**

---

## Step 2 — Print the public-key fingerprint

```bash
openssl pkey \
  -in operator_public.pem \
  -pubin \
  -outform DER 2>/dev/null \
  | sha256sum \
  | awk '{print $1}'
```

This is the **fingerprint** the kernel uses to identify your operator
identity in `[[operators.entries]]`. Save it — you'll paste it into
the genesis policy block, and you'll see it on every audit row that
attributes a decision back to you.

---

## Step 3 — Hand-off options

Pick **one** of these three:

### Option A: hand-carry the private key to the kernel host (simplest)

Copy `operator_private.pem` to the kernel host (USB stick, scp over
internal-only network, etc.). On the kernel host:

```bash
chmod 600 operator_private.pem
mv operator_private.pem "$HOME/raxis-keys/"
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"
```

Use this for sandbox / single-developer installs.

### Option B: pre-mint the operator cert on the offline machine (recommended)

```bash
# On the offline machine, with the private key locally:
raxis cert mint \
  --key "$HOME/raxis-keys/operator_private.pem" \
  --display-name "$USER" \
  --ops CreateInitiative,GrantDelegation,ApproveEscalation \
  --validity-days 365 \
  --out "$HOME/raxis-keys/operator.cert.toml"
```

Then transfer **only** `operator.cert.toml` to the kernel host. The
private key never crosses the network. On the kernel host:

```bash
raxis genesis --operator-cert "$HOME/transfers/operator.cert.toml"
```

This is the recommended posture for any non-toy install — the kernel
host never sees the private bytes, even at genesis.

### Option C: HSM / Cloud KMS

For production, the private key should live in an HSM or cloud KMS
that exposes Ed25519 signing. That integration is out of scope for
this recipe — the contract is identical: produce a signed cert, then
use Option B to pass the cert to genesis.

---

## What success looks like

```bash
# Confirm the private key is mode 0600.
stat -f '%Mp%Lp' "$HOME/raxis-keys/operator_private.pem"   # macOS
stat -c '%a'      "$HOME/raxis-keys/operator_private.pem"   # Linux
# Both should print: 600

# Confirm the cert (Option B) decodes:
raxis cert show "$HOME/raxis-keys/operator.cert.toml"
```

`raxis cert show` prints the operator display name, fingerprint,
permitted operations, validity window, and the signing-key ID. If
any field is empty or malformed the cert is unusable — re-mint.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `Algorithm ed25519 not found` | LibreSSL detected. Install `brew install openssl@3` and prepend its `bin/` to `$PATH`. |
| `error reading private key: bad password read` | Your shell has `OPENSSL_CONF` pointing at an FIPS profile that disables Ed25519. `unset OPENSSL_CONF` and retry. |
| `cert mint: --ops contains unknown op` | The op string drifted between releases. Run `raxis cert mint --help` to see the current valid set. |
| Kernel rejects the cert at genesis with `CERT_EXPIRED` | The cert's validity window started before the host's clock. Either re-mint with `--validity-days 365` (default), or fix the host clock. |

---

## Reference: env vars + commands

| Variable / command | Purpose |
|---|---|
| `RAXIS_OPERATOR_KEY` | Path to the private PEM, read by every signing CLI when `--operator-key` is omitted. |
| `raxis cert mint` | Produces a signed `operator.cert.toml` from a private key, offline. |
| `raxis cert show <path>` | Decodes a cert and prints its fields without needing the kernel. |
| `raxis cert verify <path>` | Cryptographically verifies a cert's signature against its embedded public key. |

---

## Variations

- **Permitted-ops scoping.** `--ops` accepts a comma-list.
  Restrict it: a "CI signing operator" might get only
  `CreateInitiative`; a "key-rotation operator" gets only
  `GrantDelegation,ApproveEscalation`. The kernel enforces these
  per-call.
- **Shorter validity.** Use `--validity-days 30` for ephemeral
  break-glass keys; the kernel rejects expired certs at signing
  time, not just at genesis.
- **Multiple operators.** Mint one cert per operator; add each as a
  separate `[[operators.entries]]` block in `policy.toml` and
  re-sign. The kernel admits any signature whose fingerprint matches
  ANY operator entry.
