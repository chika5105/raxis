# `raxis-verifier-symbol-index` — kernel-canonical symbol-index verifier

**Image alias:** `raxis-verifier-symbol-index` (reserved, kernel-canonical)
**Role:** `VerifierSymbolIndex`
**Status:** verifier-runtime — **shipped**

## What it does

This image is the kernel-canonical verifier that produces a
**symbol index** (function / type / macro definitions and their
file:line locations) over the worktree the kernel mounts at
`/raxis/worktree`. The witness submitted back to the kernel includes
the streaming-ctags JSON output as an artefact (
`WitnessSubmission.body["artifact"]`, see
`crates/verifier/src/lib.rs`) so the Reviewer can re-resolve
symbols on a per-symbol basis without rebuilding the index from
scratch.

## D7 fast-incremental design

The naive `ctags -R src/` over a 10k-file repo takes 30+ seconds —
unacceptable as a per-spawn gate. The D7 verifier layers four
speed paths that compound:

1. **Diff-scoped indexing.** The kernel passes `RAXIS_BASE_SHA` and
   `RAXIS_EVALUATION_SHA` in the spawn envelope. The verifier runs
   `git diff --name-only $RAXIS_BASE_SHA $RAXIS_EVALUATION_SHA`
   first and tags ONLY the changed files. The Reviewer reads the
   symbol index on a per-symbol basis (not per-file), so missing
   the unchanged files is correctness-preserving as long as the
   verifier publishes a *delta* on top of a stable
   `BASE_SYMBOL_INDEX` blob.

2. **Persistent BASE_SYMBOL_INDEX.** The kernel-side blob store
   keeps one `symbol_index.json` per `RAXIS_BASE_SHA` (LRU-capped
   at 256 base indexes per repo via the kernel-side cache; D7's
   "cache eviction" requirement). The verifier reads the cached
   base from `/raxis/base_index/symbol_index.json` (mounted
   read-only by the kernel pre-spawn) and merges the per-file
   diff results into it before emitting the witness.

3. **Parallel ctags.** Each changed file is processed via
   `find ... -print0 | xargs -0 -P $(nproc) -n 32 ctags -f - --output-format=json`
   so the symbol-index pipeline scales linearly with the number of
   cores in the verifier VM. `ctags` itself is embarrassingly
   parallel — single-file invocations have no shared state.

4. **Content-addressed file cache.** Each per-file index is keyed
   by `sha256(file_bytes)`. If the kernel-side cache has a hit, the
   verifier skips re-tagging that file even when its path appears
   in `git diff` (the file was changed somewhere upstream but
   rewound to a known-good content in a later commit). The verifier
   emits cache-warming hints alongside the witness; the kernel
   writes them to the artefact store via the existing
   `crates/artifact-store` interface.

### Skiplist (hard-coded, not `.gitignore`-derived)

`.gitignore` resolution adds I/O the verifier cannot afford on the
hot path. The skiplist below matches the executor-starter image's
discipline:

* `target/`         — Rust build output
* `node_modules/`   — JavaScript / TypeScript build output
* `vendor/`         — Go / Ruby vendored deps
* `.git/`           — git internals
* `dist/`           — generic distribution output
* `build/`          — generic build output

## Perf budget (normative — `INV-VERIFIER-SYMBOL-INDEX-PERF-CEILING-01`)

Measured on a 10k-file repo (Rust source-tree-shape, average file
size ~ 4 KiB), with the BASE_SYMBOL_INDEX served from the kernel-
side cache:

| Scenario                                | Wall-clock ceiling | Source of truth                                       |
|-----------------------------------------|--------------------|--------------------------------------------------------|
| No-change diff (base == evaluation)     | **< 200 ms**       | `manifest.toml [perf_budget] warm_index_no_change_ms`  |
| 50-file diff, warm base                 | **< 1 s**          | `manifest.toml [perf_budget] warm_index_50_file_diff_ms` |
| Full repo rebuild, cold base, no cache  | **< 5 s**          | `manifest.toml [perf_budget] cold_index_full_repo_ms`  |

Regressions surface as `INV-VERIFIER-SYMBOL-INDEX-PERF-CEILING-01`
violations in the kernel-side audit chain (the verifier emits the
wall-clock duration into `WitnessSubmission.body["timed_out"]`
adjacent metadata; a `VerifierTimeout` audit event closes the
pair on overrun per `INV-VERIFIER-AUDIT-PAIRED-WRITE-01`).

## Trust model

The kernel-binary-embedded digest
(`crates/canonical-images::EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST`,
populated by `build.rs` from
`RAXIS_EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST_HEX` or a
matching signed manifest under the V2 trust path) is the SOLE
truth at spawn time. Operator policy CANNOT override this
(`INV-VERIFIER-CANONICAL-SYMBOL-INDEX-DIGEST-PINNED-01`). Any
`[[vm_images]] name = "raxis-verifier-symbol-index"` is rejected
at policy load with `FAIL_POLICY_RESERVED_VM_IMAGE_NAME`
(`INV-VERIFIER-12`).
