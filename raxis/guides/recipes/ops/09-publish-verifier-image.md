# Publish a new verifier image

> **Topic:** Operations | **Time to read:** ~4 min | **Complexity:** ⭐⭐⭐ Advanced

End-to-end: build a verifier image, sign it, embed it in policy,
and reference it from a plan. Verifiers are container images
the kernel runs to produce mechanical evidence (witnesses) that
gate task acceptance.

---

## Prerequisites

- A working containerization toolchain (`docker` or `buildah`).
- An image-signing keypair. Either reuse the operator key or use a
  separate signing key referenced via `RAXIS_IMAGE_SIGNING_KEY` /
  `RAXIS_IMAGE_VERIFY_KEY`.
- Operator authority for `PublishVerifierImage` and
  `SignPolicy`.

---

## Concepts

A verifier image is a container that:

- Reads its environment for `RAXIS_TASK_ID`, `RAXIS_GATE_TYPE`,
  `RAXIS_VERIFIER_TOKEN`, `RAXIS_KERNEL_SOCKET`, `RAXIS_WORKTREE_ROOT`,
  `RAXIS_EVALUATION_SHA` (see [env/10-verifier-env-vars](../env/10-verifier-env-vars.md)).
- Connects to the kernel over `RAXIS_KERNEL_SOCKET` and authenticates
  with the verifier token.
- Reads the worktree at `RAXIS_WORKTREE_ROOT`.
- Writes a witness blob via the kernel's `RecordWitness` intent.
- Exits 0 on success; non-zero indicates verifier failure (the
  kernel records this and rejects the task).

Witnesses are content-addressed; identical input → identical sha,
which the kernel uses for caching.

---

## Steps

### 1. Build the verifier

Minimal example — an `rg` (ripgrep) verifier that flags
`TODO` markers and produces a witness.

```dockerfile
# Dockerfile.rg-verifier
FROM cgr.dev/chainguard/static:latest
COPY rg /usr/local/bin/rg
COPY verifier-entry /usr/local/bin/verifier-entry
ENTRYPOINT ["/usr/local/bin/verifier-entry"]
```

`verifier-entry`:

```bash
#!/usr/bin/env sh
set -eu
cd "$RAXIS_WORKTREE_ROOT"

# Run the check.
if rg --json TODO > /tmp/todo.json; then
  CLASS=fail
else
  CLASS=pass
fi

# Submit the witness.
raxis-verifier submit-witness \
  --class "$CLASS" \
  --body /tmp/todo.json
```

Build:

```bash
docker build -t my-org/rg-verifier:v1 -f Dockerfile.rg-verifier .
docker save my-org/rg-verifier:v1 | gzip > /tmp/rg-verifier-v1.tar.gz
```

### 2. Sign the image

```bash
raxis verifiers sign \
  --image    /tmp/rg-verifier-v1.tar.gz \
  --signing-key "$RAXIS_IMAGE_SIGNING_KEY" \
  --out      /tmp/rg-verifier-v1.signed
# Output:
# image_sha:    sha256:9c41...
# signed_by:    8a4f...  (operator alice)
# signature:    <hex>
```

The output bundle includes the image bytes + the operator
signature. The kernel verifies this against the signing key
embedded in `[[vm_images]]` before pulling.

### 3. Install the image in the registry

```bash
raxis verifiers install /tmp/rg-verifier-v1.signed
# Output:
# verifier_id:    rg-verifier-v1   (auto-derived from the image's annotated label)
# image_sha:      sha256:9c41...
# state:          ready
```

Or manually edit `[[vm_images]]` in `policy.toml`:

```toml
[[vm_images]]
id           = "rg-verifier-v1"
image_ref    = "sha256:9c41..."
signed_by    = "8a4f..."     # signer kid
signed_at    = "2026-05-10T17:00:00Z"
command      = ["/usr/local/bin/verifier-entry"]
purpose      = "verifier"     # or "executor"
description  = "Ripgrep TODO check"
```

Re-sign and apply:

```bash
raxis policy sign /tmp/policy.toml --operator-key /tmp/op.key
```

### 4. Reference from a plan

```toml
[[tasks.verifiers]]
id          = "rg-verifier-v1"
gate        = "pre_review"     # or "pre_merge", "pre_admit"
required    = true
```

`gate` controls when the kernel runs the verifier:

- `pre_admit` — before the task starts; failure prevents admission.
- `pre_review` — between executor finish and reviewer start.
- `pre_merge` — after reviewer approves but before the merge.

`required = true` makes failure abort the task. `required = false`
records the witness but doesn't gate.

### 5. Test

Submit a plan that references the new verifier:

```bash
raxis submit plan ./test-plan.toml
raxis plan approve <init_id>
# Wait for the task to run.
raxis task outputs <task_id>
# Expect to see the rg-verifier-v1 witness.
raxis log <init_id> --kind WitnessRecorded
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `verifiers install: signature invalid` | The signing key isn't trusted. Confirm `[[vm_images]].signed_by` matches your `RAXIS_IMAGE_SIGNING_KEY`'s kid. |
| Verifier exits with `RAXIS_KERNEL_SOCKET unset` | The kernel isn't passing the env; check the verifier image is registered with `purpose = "verifier"` (executors get a different env). |
| Verifier produces a witness but the task still fails | Check `class` field; only `pass` is treated as success unless `required = false`. |
| Image too large | Verifier images should be tiny. Use `cgr.dev/chainguard/static`, distroless, or scratch. The kernel pulls on first use. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis verifiers` | List registered verifiers. |
| `raxis verifiers sign` | Sign an image bundle. |
| `raxis verifiers install` | Embed a signed image into policy. |
| `raxis log --kind WitnessRecorded` | Past witnesses. |
| `raxis log --kind VerifierMismatchDetected` | Cache-hit hash mismatches. |
| [policy/11-vm-images-section](../policy/11-vm-images-section.md) | Schema. |
| [env/10-verifier-env-vars](../env/10-verifier-env-vars.md) | Env vars the verifier sees. |

---

## Variations

- **Built-in verifiers.** `cargo-test`, `rg-pre-commit`,
  `eslint-check`, `pytest-quick`. Build a small library and reuse
  across plans.
- **Per-language verifier sets.** Group verifiers by ecosystem
  (`rust-default`, `python-default`); plans pick one set in
  `[[tasks.verifiers]]`.
- **Heavyweight verifiers.** A verifier that runs full integration
  tests; pair with longer `cumulative_max_seconds` in the plan.
- **Caching strategy.** Witness sha is computed over the verifier's
  inputs (worktree sha, args, env relevant subset). For
  determinism, always make the verifier read only from the
  worktree, not external state.
