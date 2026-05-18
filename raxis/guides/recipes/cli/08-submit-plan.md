# `raxis submit plan`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

Atomic plan-bundle submission — **the only way** to admit a plan
to the kernel. Reads `plan.toml`, builds the canonical bundle,
stamps a fresh nonce + `signed_at`, signs in memory, and submits
via the V2 IPC envelope. There is no intermediate `plan.sig` file.

`--dry-run` is the **default**. To actually commit the bundle, pass
`--no-dry-run` explicitly.

---

## Syntax

```text
raxis submit plan <plan.toml> [--initiative-id <id>]
                              [--dry-run | --no-dry-run]
                              [--operator-key <pem>]
```

---

## Flags

| Flag | Effect |
|---|---|
| `--dry-run` (default) | Build and validate the bundle locally. Does NOT submit. Prints the would-be `initiative_id` and bundle stats. |
| `--no-dry-run` | Submit for real. Returns the live `initiative_id` and the bundle's resolved (epoch, signed_at, nonce). |
| `--initiative-id <id>` | Reuse a pre-allocated `initiative_id`. Most operators don't need this; the kernel mints one automatically. |
| `--operator-key <pem>` | Global CLI flag before `submit`; overrides `RAXIS_OPERATOR_KEY` for this invocation. |

---

## Examples

### Standard submission

```bash
raxis submit plan ./plan.toml --no-dry-run
# Output:
# initiative_id: 1f3c8a4b...
# bundle_sha:    ab12cd34...
# epoch:         7
# Status:        Draft  (waiting for `raxis plan approve`)

INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"
```

### Dry-run preflight

```bash
raxis submit plan ./plan.toml
# Equivalent to --dry-run.
# Output:
# would-submit:   1f3c8a4b...    (mock initiative_id; the real one allocates at submit time)
# bundle_sha:     ab12cd34...
# bundle_bytes:   4321
# artifact_count: 1
# (no IPC, no kernel state mutation)
```

### Explicit key

```bash
raxis --operator-key /etc/raxis/keys/ci-bot.pem \
  submit plan ./plan.toml --no-dry-run
```

---

## What it does atomically

```text
1. Read plan.toml from disk.
2. Run raxis plan validate (structural pre-flight).
3. Canonical-encode plan.toml (whitespace, key ordering, etc.).
4. Build the V2.1 plan bundle envelope:
     {
       schema:           "raxis-plan-bundle/v2.1",
       initiative_id:    <generated UUID> | <--initiative-id>,
       epoch:            <kernel's current policy epoch>,
       signed_at:        time(NULL),
       nonce:            <256-bit CSPRNG>,
       artifacts:        [{name: "plan.toml", bytes: <canonical>}, ...],
     }
5. Compute SHA-256 over the canonicalised bundle.
6. Sign the SHA with the operator's private key.
7. Send the bundle + signature over operator.sock as a single IPC frame.
8. Wait for kernel response; print the resolved initiative_id.
```

The bundle is single-shot: each `submit plan` mints a new nonce, so
there's no plan.sig file lingering on disk. Replays are caught by
the kernel's nonce-table.

---

## What the kernel does on receipt

```text
1. Verify the operator signature against [[operators.entries]].
2. Verify the bundle envelope:
   - signed_at within [plan_signing] freshness window.
   - nonce not in plan_bundle_nonces_seen.
3. Validate the canonical plan.toml against the active policy:
   - lane exists, target_ref allowed, vm_image known, ...
4. Persist:
   - kernel.db: initiatives, plan_bundle_artifacts.
   - audit/segment-NNN.jsonl: PlanBundleAdmitted, InitiativeCreated.
5. Return initiative_id.
```

The result is a `Draft` initiative — admitted but not yet running.
A separate `raxis plan approve <initiative_id>` advances it to
admit-tasks-and-spawn.

---

## Common errors

| Symptom | Fix |
|---|---|
| `submit plan: --operator-key required` | Pass it OR set `RAXIS_OPERATOR_KEY`. |
| `submit plan: signature_check_failed` | Operator's fingerprint doesn't match any `[[operators.entries]]`. The CLI signed correctly; the kernel rejected. Check `raxis cert list`. |
| `FAIL_PLAN_BUNDLE_EXPIRED` | Host clock skew vs the kernel host. `date -u` to compare; fix NTP. |
| `FAIL_UNKNOWN_LANE` | The plan's `lane_id` isn't in policy. Add it or fix the plan. |
| `FAIL_VM_IMAGE_NOT_DECLARED` | Plan references a `vm_image` not in `[[vm_images]]`. |
| `FAIL_PLAN_BUNDLE_REPLAY` | Same bundle submitted twice; the nonce is already in `plan_bundle_nonces_seen`. Re-run `submit plan` to mint a fresh nonce. |
| `bundle exceeds [plan_bundle_limits].max_bundle_bytes` | The plan + auxiliaries is too large. Slim or raise the limit. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis plan validate <plan.toml>` | Local pre-flight; cheaper than a `--dry-run` round-trip. |
| `raxis initiative list --state Draft` | List initiatives waiting for approval. |
| `raxis plan approve <initiative_id>` | Approve and admit the tasks. |
| `raxis plan reject <initiative_id>` | Reject without spawning. |
| `raxis initiative show <id> --bundle` | Inspect what was admitted. |

---

## Variations

- **CI submission.** Run from a CI runner with a narrow-scope CI
  cert (only `CreateInitiative` permitted). The submission emits
  audit; an operator on call approves later.
- **Pre-allocated initiative_id.** Pass `--initiative-id <uuid>` to
  use a UUID minted by an upstream service. Useful for systems
  that need stable IDs *before* the bundle is submitted.
- **Multi-artifact bundles.** `plan.toml` is artifact[0]; add
  auxiliary artifacts via `[plan.artifacts]` references in the
  plan (V2.1+ extension). Most plans don't need this.
