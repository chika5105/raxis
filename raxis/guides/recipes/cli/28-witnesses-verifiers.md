# `raxis witnesses` and `raxis verifiers`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

`verifiers` lists every verifier image the kernel knows about and
their current status. `witnesses` is the content-addressed
inventory of mechanical-evidence blobs verifiers have produced.

---

## verifiers — registered verifier images

```bash
raxis verifiers
# Output:
# VERIFIER_ID      IMAGE_REF              STATUS    LAST_USE                COST
# cargo-test       sha256:7f88...:v1.2    ok        2026-05-10T17:31:14Z    runtime~30s
# rg-pre-commit    sha256:3a2c...:v0.4    ok        2026-05-10T17:30:55Z    runtime~2s
# review-checks    sha256:9c41...:v0.7    quarantined  —                    —
```

Quarantined verifiers were last seen producing inconsistent
witnesses (cache hit hash mismatch), and the kernel refuses to use
them until an operator clears the quarantine:

```bash
raxis verifiers clear-quarantine review-checks --reason "fixed in v0.8"
```

Show one verifier's detail:

```bash
raxis verifiers show cargo-test
# Output:
# verifier_id:    cargo-test
# image_ref:      sha256:7f88...:v1.2
# image_signed_by: 8a4f... (operator alice)
# image_signed_at: 2026-05-01T00:00:00Z
# command:        ["cargo", "test", "--workspace"]
# env:            { RAXIS_TASK_ID, RAXIS_GATE_TYPE, RAXIS_VERIFIER_TOKEN, RAXIS_KERNEL_SOCKET, RAXIS_WORKTREE_ROOT }
# witness_count:  421
# cache_size:     11 MB
# last_use:       2026-05-10T17:31:14Z
```

The `env` line shows exactly which `RAXIS_*` vars the kernel
stamps into a verifier subprocess (see
[verifier env vars](../env/10-verifier-env-vars.md)).

---

## witnesses — content-addressed evidence

```bash
raxis witnesses
# Output:
# WITNESS_SHA      VERIFIER       FIRST_SEEN              SIZE    REFS
# 7f880c2e...      cargo-test     2026-05-10T17:31:14Z    11.4KB  3 (tasks: implementer-x, code_reviewer-x, …)
# 3a2c01ff...      rg-pre-commit  2026-05-10T17:30:55Z    812B    1
# ...
```

Filters:

```bash
raxis witnesses --task implementer-2025-05-10
raxis witnesses --verifier cargo-test
raxis witnesses --since 2026-05-10T00:00:00Z
raxis witnesses --json | jq '.[] | {witness_sha, verifier, refs}'
```

`REFS` counts how many tasks reference this witness — high counts
indicate a cache hit across multiple runs (the kernel
content-addresses, so a clean test run with the same input
produces the same witness sha).

### Show one witness blob

```bash
raxis witnesses show 7f880c2e
# Output: structured metadata (verifier id, witness sha, args, task,
# session, exit code, stdout/stderr summary, raw_size).
#
# To dump raw bytes: --raw

raxis witnesses show 7f880c2e --raw > /tmp/cargo-test.witness
```

Witness blobs are typically small JSON-or-text artifacts (e.g.,
the JSON output of `cargo test --message-format json`). `--raw`
gives you the original bytes.

---

## Common errors

| Symptom | Fix |
|---|---|
| `verifiers: image not signed by trusted operator` | Embed the image-signing key in policy under `[[vm_images]]` — see [policy/11-vm-images-section](../policy/11-vm-images-section.md). |
| `verifiers: image quarantined (witness mismatch)` | Investigate via `raxis log --kind VerifierMismatchDetected`; clear after fix. |
| `witnesses show: not found` | Wrong sha; use the prefix from `raxis log --kind WitnessRecorded`. |
| `witnesses --raw: blob too large for stdout` | Redirect to a file: `... --raw > out.bin`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis log --kind WitnessRecorded` | Audit events that point at witness blobs. |
| `raxis task outputs <task_id>` | Witnesses + patches per task. |
| `raxis explain <task_id>` | Decision tree referencing the relevant witnesses. |
| `raxis verifiers show <id>` | Per-verifier image / env detail. |

---

## Variations

- **Cache-hit measurement.** `raxis witnesses --json | jq '[.[] | .refs] | add / length'`
  approximates witness reuse rate.
- **Forensic export.** `raxis witnesses --task <id> --json` plus
  `witnesses show --raw` for each entry produces a self-contained
  evidence bundle for a task.
- **Verifier upgrade rollout.** Update `[[vm_images]]` in policy,
  re-sign, push to operators; old verifier images stay registered
  but new ones get used. Track via `verifiers show <id>` and
  compare `image_signed_at`.
- **Mismatch alert.** `raxis log --kind VerifierMismatchDetected --since 24h --json | wc -l`
  for a daily incident-detection cron.
