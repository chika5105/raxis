# Canonical Image Trust Anchor (V3)

Status: V3 (iter60). Supersedes V2's "warn-only on unpopulated anchor"
boot posture (`specs/v2/planner-harness.md §14.4`,
`specs/v2/release-and-distribution.md §8`). Cross-refs:

- `kernel/src/canonical_images_preflight.rs` — boot-time fail-loud
  assertion + canonical-image manifest preflight.
- `crates/canonical-images/build.rs` — compile-time anchor
  embedding.
- `xtask/src/images.rs` — `cargo xtask images bake-all` operator
  recipe.
- `specs/invariants.md::INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01` —
  pinned contract.

## §1 — Purpose

The kernel verifies every canonical VM image
(`raxis-reviewer-core-<kver>.img`,
`raxis-orchestrator-core-<kver>.img`, future
`raxis-executor-starter-<kver>.img`) against an Ed25519-signed
`<role>-<kver>.manifest.toml` at boot AND at every activation. The
verifier needs the public half of the kernel signing key — the
"trust anchor" — embedded at compile time. There is no runtime
discovery path: a kernel binary's trust anchor is whatever the
build emitted, and the operator's only control over it is the env
var the build script reads.

A kernel that boots with no trust anchor cannot cryptographically
distinguish a signed manifest from a junk one. Pre-V3 the kernel
logged the unpopulated anchor as a `warn` and continued; the
matching `verify_canonical_image_via_manifest` call short-circuited
with `SigningKeyFpNotPopulated` and the kernel silently degraded
onto `read_unverified_image_format_hint`. V3 inverts this posture:
a no-anchor kernel refuses to boot.

## §2 — Build-time anchor mechanism

The trust anchor is embedded as a `[u8; 32]` compile-time constant
in `crates/canonical-images/build.rs`. The build script resolves
the bytes in priority order:

1. `RAXIS_KERNEL_SIGNING_KEY_HEX` — 64 lowercase hex chars (output
   of `xxd -p -c 64 signing.pub`). The preferred form for CI / HSM
   pipelines that shuttle short strings.
2. `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` — absolute path to a
   32-byte raw file. Reserved for HSM-backed pipelines that never
   materialise the key as a hex string.
3. **No fallback.** If neither variable is set, the build script
   emits the all-zero placeholder `[0u8; 32]`, AND the kernel boot
   path asserts at runtime that this placeholder is never the
   live anchor on a kernel the operator intends to run.

The build script declares `cargo:rerun-if-env-changed` for both
variables so a `cargo build` after the operator exports
`RAXIS_KERNEL_SIGNING_KEY_HEX` re-runs the build script and emits a
freshly-anchored kernel without a `cargo clean`. **The build script
does NOT probe the filesystem for keys** — no `~/.config/...`, no
`.git/info/...`, no auto-discovery. The two env vars are the entire
input surface. This keeps the resolution chain auditable: every
build's anchor is fully determined by the env at `cargo build`
invocation time.

## §3 — Fail-loud boot contract

At every kernel boot, immediately after the banner prints and
before any subsystem that can either

* admit a session (operator IPC dispatcher, dashboard HTTP bind),
* spawn a planner VM (`session_spawn_orchestrator`,
  `IsolationBackend::launch`), or
* service a planner fetch (`gateway`, `credential_proxy_manager`),

the kernel calls
`canonical_images_preflight::assert_trust_anchor_present_or_panic`.
This function compares
`raxis_canonical_images::EXPECTED_KERNEL_SIGNING_KEY_BYTES`
against the all-zero placeholder; if they match, it `panic!`s with
the stable string
`"FATAL: kernel built without a manifest-trust anchor."` followed
by the operator-actionable remediation listed below.

The panic message **MUST** name:

1. The env var (`RAXIS_KERNEL_SIGNING_KEY_HEX`) so an operator can
   recover by export-and-rebuild.
2. The xtask recipe (`cargo xtask images bake-all`) so an operator
   with no env-var habit can recover by running the umbrella
   one-command pipeline.
3. This spec path (`specs/v3/canonical-image-trust-anchor.md`) so
   the operator has somewhere to read the full contract.

`#[should_panic(expected = "kernel built without a manifest-trust anchor")]`
in `canonical_images_preflight::tests::assert_trust_anchor_panics_on_all_zero_bytes`
witnesses the contract. The exact stable-string surface is
`canonical_images_preflight::TRUST_ANCHOR_FAIL_LOUD_MESSAGE`.

### §3.1 — Why panic instead of `std::process::exit(1)`

`panic!` produces a fatal stack-unwound exit under
`panic = "abort"` (pinned in `raxis/Cargo.toml [profile.release]`)
that the supervisor sentinel records as a kernel crash. The
self-healing supervisor's restart-ceiling logic
(`specs/v2/self-healing-supervisor.md §3.2`) sees the abort as a
hard-fault category and refuses to respawn the kernel after the
configured ceiling, surfacing the misconfiguration as
`SupervisorRefusedRestart` rather than burning a restart-budget
slot per boot attempt. A bare `exit(1)` from the trust-anchor
assertion would look like a clean shutdown and tempt the
supervisor into an unbounded restart loop on a permanently
misconfigured host.

### §3.2 — Why before bootstrap mode?

Bootstrap mode (`RAXIS_BOOTSTRAP=1`) does not currently spawn VMs
or admit sessions — it runs the genesis-policy / cert-mint
ceremony and exits. Even so, the assertion runs BEFORE the
bootstrap branch because the trust-anchor presence is a property
of THE KERNEL BINARY, not of the run mode. Producing a bootstrap
artefact from a kernel that cannot subsequently verify its own
canonical images would let an operator complete the cert-mint
ceremony and then have every kernel boot from that ceremony
panic — the worst-of-both-worlds case.

### §3.3 — Defense-in-depth: preflight still runs

The boot assertion does NOT remove the per-image manifest
preflight at step 8b (`verify_canonical_images_at_boot`). A kernel
that passes the trust-anchor check still verifies every canonical
image's signed manifest end-to-end; both gates are required. The
preflight's `TrustAnchorUnpopulated` outcome remains in the
`PreflightOutcome` enum because the verifier in
`raxis-canonical-images` is also called from
`IsolationBackend::launch` and `resolve_image_kind_for_role`, both
of which can encounter the placeholder anchor through paths that
do not go through `main()` (e.g. activation-time defense-in-depth
or the unverified-hint fallback). The variant is structurally
unreachable from `main()` after iter60.

## §4 — Dev workflow

The dev round-trip is:

```text
cargo xtask images bake-all
  → kernel boots with valid trust anchor
  → no panic
```

`bake-all` does the following on FIRST invocation:

1. Resolves a dev-host signing keypair.
   * If `RAXIS_KERNEL_SIGNING_KEY_HEX` is already set in the env
     (CI, release pipeline), **use it verbatim** and DO NOT
     regenerate. The CI-supplied value is authoritative.
   * Otherwise, looks for
     `<repo>/.git/info/raxis-signing-key/raxis-dev-signing.key.hex`
     (private half) +
     `<repo>/.git/info/raxis-signing-key/raxis-dev-signing.pub.hex`
     (public half, 64 lowercase hex chars).
   * If neither file exists, generates a fresh Ed25519 keypair
     with `ed25519_dalek::SigningKey::generate(...)`, writes both
     halves to the `.git/info/...` directory (mode 0600 on the
     private half), and proceeds.
2. Bakes every canonical role image with the private half (the
   existing `images::build_one_role` codepath).
3. Re-invokes `cargo build -p raxis-kernel` with
   `RAXIS_KERNEL_SIGNING_KEY_HEX` set in the spawned child's env
   to the public-half hex. The kernel build picks up the env var
   via `cargo:rerun-if-env-changed`, re-runs `build.rs`, and emits
   a kernel binary with the matching trust anchor. From this
   moment forward `cargo run -p raxis-kernel` boots without the
   trust-anchor panic.

The dev-key directory lives at
`<repo_root>/.git/info/raxis-signing-key/` — INSIDE the `.git`
directory tree, which git never tracks. No `.gitignore` line is
needed; `.git/info/` is already opaque to git's tracking machinery.
The dev key never leaves the operator's workstation, never enters a
commit, and never crosses the trust boundary between the dev host
and any other host.

Subsequent `bake-all` invocations are idempotent: the keypair on
disk is reused, the kernel rebuild is a fast no-op when nothing
has changed, and the operator's iteration loop is
`make change → cargo xtask images bake-all → cargo run -p raxis-kernel`.

### §4.1 — Why `.git/info/` and not `~/.config/raxis/keys/`?

Three reasons:

1. **Repo-scoped lifetime.** A `git clone` produces a fresh
   `.git/info/` per checkout. Two checkouts of the same repo on
   the same host get distinct dev keypairs by construction — no
   risk of one worktree's key signing manifests that another
   worktree's kernel verifies. (The pre-iter60 design used a
   per-user `~/.config/...` path that shared one key across every
   checkout; a stale key from a long-dead branch could re-sign
   manifests for a fresh kernel and create confusing trust
   states.)
2. **No probe surface.** `~/.config/raxis/keys/` requires the
   build script to know where `$HOME` is, what user is running the
   build, what scope (root / user / sudo-user / hermetic CI) the
   build runs in. `.git/info/` is a fixed offset from the
   workspace root the xtask is already operating against.
3. **Cleanup is `rm -rf <repo>`.** A developer who deletes a
   repo's worktree deletes the dev key. No `~/.config/...`
   leftovers to forget about.

### §4.2 — Threat model for a leaked dev key

A leaked dev key signs canonical-image manifests that the
operator's dev kernel verifies. The blast radius is bounded by
two structural facts:

1. **Dev keys are NOT valid release keys.** The release pipeline's
   trust anchor is a separate, HSM-backed key whose public half
   is committed to the release branch under
   `RAXIS_KERNEL_SIGNING_KEY_HEX` via the build-pipeline env (or
   `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` for HSM-attested
   workflows). A kernel built from a release branch with the
   release env vars set never trusts a dev key, even if the dev
   key is leaked to the public.
2. **Dev kernels never run untrusted images.** The dev workflow's
   only canonical-image source is `cargo xtask images bake-all`,
   which signs with the same dev key it generated. An attacker
   with the leaked dev key could forge a manifest for an
   adversarial `.img`, but to get a dev kernel to load that image
   the attacker would also need to place the `.img` +
   `manifest.toml` at the kernel's resolved `RAXIS_INSTALL_DIR`
   — a write to a per-user / per-worktree directory whose contents
   the operator is already trusting. Reaching that directory is
   pre-conditional on a compromise the trust anchor is not
   designed to defend against.

Operators rotating a dev key after a suspected leak run
`rm -rf <repo>/.git/info/raxis-signing-key/ && cargo xtask images bake-all`
to generate fresh halves and rebuild the kernel against them.

## §5 — Production workflow

Release-pipeline builds resolve `RAXIS_KERNEL_SIGNING_KEY_HEX` from
the pipeline's HSM-backed key custody. The trust anchor is the
**public** half of the release signing keypair; the matching
**private** half stays inside the HSM and only the signed
manifest crosses the trust boundary onto operator disks.

This section is a placeholder linked from
`specs/v2/release-and-distribution.md §8` (which V3 will rework).
The mechanical resolution path is unchanged from V2:

* `RAXIS_KERNEL_SIGNING_KEY_HEX` — the build pipeline exports the
  release key's hex form (64 lowercase chars) into the env
  immediately before `cargo build -p raxis-kernel`.
* `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` — for HSM-backed
  pipelines that never materialise the bytes as a hex string. The
  build script reads the 32-byte raw file from the supplied path.

A production kernel built from the release pipeline boots, passes
the trust-anchor assertion, AND passes the per-image manifest
preflight against manifests the release HSM produced. Dev keys
have no role in this codepath; the
`<repo>/.git/info/raxis-signing-key/` directory does not exist on a
release-pipeline worker.

## §6 — Operator runbook

### §6.1 — "Kernel won't boot with `FATAL: kernel built without a manifest-trust anchor.`"

The kernel binary was compiled without
`RAXIS_KERNEL_SIGNING_KEY_HEX`. The operator's three recovery
recipes:

1. **Dev / local-build host.** Run
   `cargo xtask images bake-all`. It auto-generates a dev
   keypair on first run, bakes the canonical images, re-invokes
   `cargo build -p raxis-kernel` with the env var set, and the
   next `cargo run` succeeds.
2. **CI worker.** Export the project's CI-supplied
   `RAXIS_KERNEL_SIGNING_KEY_HEX` before the build step:
   ```bash
   export RAXIS_KERNEL_SIGNING_KEY_HEX="$(cat /run/secrets/raxis-kernel-pub.hex)"
   cargo build -p raxis-kernel --release
   ```
3. **Release pipeline.** The pipeline's signing step should
   already export the var. Audit the `cargo build` step's
   environment; the most common cause is a credential-mounting
   misconfiguration that didn't surface the secret.

### §6.2 — "I rotated the dev key and now `bake-all` keeps regenerating it"

`bake-all` regenerates only when both
`<repo>/.git/info/raxis-signing-key/raxis-dev-signing.key.hex` AND
the `.pub.hex` are missing. If you want to force regeneration
without `rm`, delete both files. To keep a specific keypair across
rotations, copy the two files into `.git/info/raxis-signing-key/`
before running `bake-all` and they will be reused.

### §6.3 — "I want the panic message to mention my company's runbook URL"

The fail-loud message is intentionally minimal —
`RAXIS_KERNEL_SIGNING_KEY_HEX` + `cargo xtask images bake-all` +
this spec path. Operators with internal runbooks chain the spec
path into their own documentation; the kernel does not embed
deployment-specific URLs. The exact message is exposed as
`canonical_images_preflight::TRUST_ANCHOR_FAIL_LOUD_MESSAGE` for
operators who want to forward it verbatim into a notification
pipeline.

## §7 — Key-rotation drift and the wrong-key contract (INV-IMAGE-VERIFY-REJECT-MISMATCH-01)

The fail-loud invariant in §3 covers "no key at all" — a kernel
built without `RAXIS_KERNEL_SIGNING_KEY_HEX` refuses to boot. The
orthogonal failure mode is "valid key, but **wrong** key": a
kernel that boots fine but whose embedded anchor disagrees with
the manifests on disk. The realistic operator workflow that
triggers this case is **key-rotation drift**.

### §7.1 — The scenario

```text
Day 1:
  $ cargo xtask images bake-all
    → generates dev keypair K_a (priv + pub) under
      <repo>/.git/info/raxis-signing-key/
    → signs every canonical image with K_a's private half
    → exports RAXIS_KERNEL_SIGNING_KEY_HEX=<K_a pub hex>
    → re-invokes `cargo build -p raxis-kernel`
  $ cargo run -p raxis-kernel
    → kernel boots with K_a anchor
    → preflight verifies K_a-signed manifests against K_a anchor
    → every session admission succeeds

Day 2 (operator rotates the dev key without re-baking):
  $ rm -rf <repo>/.git/info/raxis-signing-key/
  $ cargo xtask images bake-all
    → generates fresh keypair K_b
    → would re-sign images, BUT (e.g. on a partial bake-all run
      that fails between key-gen and per-role bake) the on-disk
      manifests are still K_a-signed
    → exports RAXIS_KERNEL_SIGNING_KEY_HEX=<K_b pub hex>
    → re-invokes `cargo build -p raxis-kernel`
  $ cargo run -p raxis-kernel
    → kernel boots with K_b anchor
    → preflight tries to verify K_a-signed manifests against
      K_b anchor
    → `ManifestError::SigningKeyFpMismatch`
```

A more common variant of the same scenario:

* An operator clones the repo to a second worktree, runs
  `bake-all` there (generating keypair K_c), then comes back to
  the first worktree and `cargo run`s the K_a kernel against
  manifests that worktree 2 re-baked under K_c.
* CI runs `cargo build -p raxis-kernel` with the
  CI-supplied `RAXIS_KERNEL_SIGNING_KEY_HEX` but the test fixture
  shipped K_a-signed manifests from a different build.

### §7.2 — Contract

When the embedded anchor and the manifest's signer disagree, the
kernel MUST:

1. Surface a structured error
   (`CanonicalImageError::Manifest { source: ManifestError::SigningKeyFpMismatch | SignatureFailed | SignatureMalformed | SigningKeyFpMalformed }`)
   — NOT a log warning, NOT a silent degrade onto the
   unverified-hint path.
2. Emit exactly one `AuditEventKind::SecurityViolationDetected`
   with `violation_kind = "CanonicalImageSignatureMismatch"`
   (the stable string exposed at
   `kernel/src/canonical_images_preflight.rs::CANONICAL_IMAGE_SIGNATURE_MISMATCH_VIOLATION_KIND`).
   The kind MUST NOT collapse onto the per-role
   `{Reviewer,Orchestrator,ExecutorStarter}ImageDigestMismatch`
   slot used for byte-tamper events — the operator remediation
   differs (re-bake vs. re-install).
3. Refuse to admit any session whose `IsolationBackend::launch`
   would consult the affected image. The activation seam re-runs
   the manifest verifier as defense-in-depth and returns a
   structured `IsolationError` that the session-admission path
   maps into a kernel-side admission refusal.

### §7.3 — Why a distinct audit `violation_kind`

The tamper-event dashboards (`60-egress.json` and the security
incidents panel of the operator console) pivot on
`violation_kind`. Collapsing the wrong-key case onto the
per-role `*ImageDigestMismatch` slot would mix two operationally
distinct failure modes:

* `ReviewerImageDigestMismatch` (et al.) — the image's bytes
  changed after signing. Realistic causes: filesystem corruption,
  an attacker swapping the `.img` after the manifest was placed.
  Remediation: reinstall from a verified source.
* `CanonicalImageSignatureMismatch` — the image's bytes match
  the manifest's signed digest, but the manifest was signed by a
  different keypair than the one the kernel embeds. Realistic
  causes: key-rotation drift. Remediation: re-bake images with
  the matching key, or rebuild the kernel against the manifests'
  key.

The dashboards graph the two series separately so the operator
sees a tamper spike on the security incidents panel but a
key-rotation drift event surfaces on a "dev-host hygiene"
counter that does NOT page on-call.

### §7.4 — Operator recovery

Run `cargo xtask images bake-all` once. It regenerates the
keypair if `.git/info/raxis-signing-key/` is missing, OR reuses
the existing keypair if it's present; either way it re-signs the
canonical images with the current key's private half and
rebuilds the kernel against the matching public half. After one
bake-all the preflight succeeds and session admission resumes.

If the operator wants to keep the existing kernel anchor and
re-sign the images against it (the inverse direction), they
export the kernel's embedded public-hex half as the
`RAXIS_IMAGE_SIGNING_KEY` for the image-builder pipeline before
re-running `bake-all`. The kernel exposes its embedded anchor in
hex form via `raxis doctor canonical-images --print-anchor` (V3
addition).

### §7.5 — Witness

`kernel/src/canonical_images_preflight.rs::tests::wrong_key_manifest_emits_signature_mismatch_audit`
mirrors the canonical-images crate's
`verify_via_manifest_with_key_rejects_wrong_signing_key` witness
AND pins the audit surface (the canonical-images crate has no
audit dependency). The witness constructs a real K_a-signed
manifest, verifies it against K_b's verifying key, asserts the
classifier maps the error to `"CanonicalImageSignatureMismatch"`,
and confirms the `FakeAuditSink` records the
`SecurityViolationDetected` event.

Pairs with two focused unit witnesses in the same module:

* `classify_signature_errors_as_signature_mismatch` — every
  signature-related `ManifestError` variant maps to the stable
  audit kind.
* `classify_non_signature_errors_keep_per_kind_audit_slot` —
  structural errors keep the per-role audit slot.
