# `raxis policy sign`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

Signs a `policy.toml` (or other non-plan artifact) with the
operator's private key. Atomic: increments `[meta] epoch`, stamps
`signed_by` and `signed_at`, writes a sidecar `<file>.sig`. Plans
are signed and submitted atomically through `submit plan` — this
command intentionally rejects `plan.toml` artifacts.

---

## Syntax

```text
raxis policy sign <artifact.toml> --key <pem>
```

---

## Flags

| Flag | Effect |
|---|---|
| `--key <pem>` | Path to the operator's Ed25519 private PEM. Falls back to `RAXIS_OPERATOR_KEY` if unset. |

---

## Example

```bash
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"
# … make edits …

raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"

# Confirm the kernel hot-reloaded:
raxis log --kind PolicyReloaded --limit 1
```

---

## What it does

1. Reads the file.
2. Reads the current epoch from `kernel.db.policy_epoch_history`
   (read-only handle).
3. Increments by one.
4. Stamps `[meta] epoch`, `signed_by` (from key fingerprint), and
   `signed_at` (host's `time(NULL)`) atomically.
5. Re-emits canonicalised TOML to the same path.
6. Computes Ed25519 over the canonical bytes.
7. Writes `<artifact>.sig` (sidecar) with the signature in hex.

The kernel watches `policy/policy.toml` for mtime changes and
hot-reloads on every change — no kernel restart needed for most
sections.

### Sections that DO require a kernel restart

- `[gateway]` — the gateway supervisor is wired at boot.
- `[host_capacity] required_min_fd_limit` — RLIMIT is set at boot.

For everything else, hot-reload is sufficient.

---

## Plans are NOT signed via this command

```bash
raxis policy sign /path/to/plan.toml ...
# → policy sign: refusing to sign a plan.toml artifact
#   hint: use `raxis submit plan <plan.toml>` to sign + submit atomically.
```

Plans use a different signing surface (`submit plan`) because the
plan-bundle envelope includes a `signed_at` and nonce specifically
to defeat replay; signing them via `policy sign` would skip that
envelope.

---

## Common errors

| Symptom | Fix |
|---|---|
| `policy sign: --key <path> is required` | Either pass `--key` or set `RAXIS_OPERATOR_KEY`. |
| `policy sign: cannot read key file: Permission denied` | `chmod 600 "$RAXIS_OPERATOR_KEY"`. |
| `policy sign: refusing to sign plan.toml` | Use `raxis submit plan` for plans. |
| `policy sign: epoch <N> already exists` | Two `policy sign` invocations in flight. The kernel is the source of truth on epoch numbering; re-read with `raxis policy show --history` and retry. |
| Kernel doesn't hot-reload | Sometimes editors write via temp+rename and break the inotify watch. `touch "$RAXIS_DATA_DIR/policy/policy.toml"` after the edit + sign. |

---

## Reference

| Surface | Purpose |
|---|---|
| `raxis policy show [--history]` | Inspect the active bundle and the epoch history. |
| `raxis policy diff <left.toml> <right.toml>` | Semantic diff between two bundles. |
| `raxis epoch advance --policy <path> --sig <sig>` | Force-advance the epoch (used for atomic policy hand-off ceremonies). |
| `raxis policy generate-sidecar-secret` | Mint a sidecar HMAC for sub-process IPC integrity (less common). |

---

## Variations

- **CI signing.** Pin a CI cert with narrow `permitted_ops`; sign
  policy bumps from CI when an operator review approves them.
- **Detached signature.** The `.sig` sidecar is plain hex; you can
  archive it independently of the policy file for forensic
  reconstruction.
- **Multi-operator co-signing.** V2 admits one signature per
  bundle; multi-sig is V3. For now, designate a single signer per
  policy bundle.
