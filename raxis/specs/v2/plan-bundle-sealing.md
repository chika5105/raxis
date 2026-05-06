# Plan Bundle Sealing — V2

> **Status.** Normative for V2.
> **Cross-references:**
> - `invariants.md` `INV-INIT-06` (Plan immutable post-admission — strengthened by this spec)
> - `policy-plan-authority.md` (`[plan_bundle_limits]` policy section, FAIL_PLAN_BUNDLE_* codes)
> - `v1/kernel-store.md` §2.5.3 (V1 `signed_plan_artifacts` table — superseded for V2 storage layout)
> - `v1/cli-ceremony.md` `plan submit` (V1 two-step `plan sign` + `plan submit` — replaced by atomic `raxis submit plan` in V2)
> - `key-revocation.md` (operator key lookup at admission)
> - `v2-deep-spec.md` Step 17 (`approve_plan` shift-left validation)

---

## §1 — Why "Plan Bundle Sealing"

### 1.1 The shape of the problem

`plan.toml` is the **operator's signed promise**: the document the kernel
treats as the operator's authority to create work, allocate budgets, and
admit agent sessions. The signature on this document is what makes
RAXIS's authority model auditable — every audit row in the log can be
traced back to the bytes the operator authenticated.

V1 implemented this as a two-step ceremony:

1. `raxis-cli plan sign <plan_dir>` — reads `plan.toml` from disk,
   computes a SHA-256 over the bytes, signs the digest with the
   operator's Ed25519 key, writes a sibling `plan.sig` file.
2. `raxis-cli plan submit <initiative_id> <plan_dir>` — sends the
   directory path to the kernel; the kernel re-reads `plan.toml` from
   disk, re-hashes, re-verifies, and seals the bytes into
   `signed_plan_artifacts` (`v1/kernel-store.md` §2.5.3).

This worked when "the plan" was a single self-contained file. V2 introduces
the operational pressure to compose plans from multiple host-side artifacts
(arbitrary text snippets, custom criteria documents, NNSP-overlay text in
future revisions, and similar). Without a disciplined model, this creates
three concrete failures:

1. **TOCTOU on the host disk.** Anything between `plan sign` and
   `plan submit` — including a parallel CI job, a directory move, a
   filesystem corruption event — breaks the signature. Operators learn to
   distrust the signing step and start re-signing speculatively, eroding
   the audit trail.
2. **Non-atomic admission.** The kernel, mid-admission, re-reads files
   from disk. A symlink swap, race condition, or `..` traversal can cause
   the kernel to seal **different bytes** than the operator signed.
3. **Unbounded blob growth.** Any field that takes a host-side path can
   reference a 1 GiB binary. The kernel's SQLite store inherits that
   blob and carries it forever as part of the immutable plan record.

### 1.2 The fix: one operation, one byte array, one signature

V2 collapses the entire signed-plan lifecycle into a single primitive:
the **plan bundle**. A plan bundle is a deterministically-encoded byte
array containing `plan.toml` plus every artifact it transitively
references, with names, sizes, and per-artifact hashes. The operator
signs the bundle hash. The CLI sends `(bundle_bytes, signature)` to the
kernel in **one IPC call**. The kernel verifies, seals, and from that
point forward reads plan-derived data exclusively from its content-
addressed store (`INV-INIT-06`).

There is no on-disk `plan.sig`. There is no `plan_dir`. There is no
window where the kernel re-reads from the host filesystem. The bytes
the operator signed and the bytes the kernel executes are the same
bytes.

This mechanism is **Plan Bundle Sealing**. It is the technical
enforcement of `INV-INIT-06` in V2.

### 1.3 What this spec covers (and does not)

**In scope:**
- Bundle wire format and canonical encoding (§3).
- CLI workflow — atomic sign+submit (§4).
- Path-resolution and path-escape policy for transitive artifacts (§5).
- Templating policy (§6 — there is no templating).
- Bundle size discipline (§7).
- Kernel-side admission, sealing, and post-admission read discipline (§8).
- Failure codes and operator messaging (§9).
- Garbage collection — the absence thereof (§10).

**Out of scope:**
- The semantic content of `plan.toml` itself (covered in
  `policy-plan-authority.md`, `planner-harness.md`, `verifier-processes.md`,
  `custom-tools.md`, etc.). Plan Bundle Sealing is the **transport and
  storage** layer; what fields the plan declares is orthogonal.
- Operator key custody and revocation (`key-revocation.md`).
- Audit retention of bundle bytes (`v3/audit-retention.md` once V3 lands;
  V2 retains indefinitely per §10).

---

## §2 — Foundational Decisions

The decisions below are normative. Section numbers (D1–D8) preserve the
labels used during design discussion for cross-reference.

| # | Decision | Rationale |
|---|----------|-----------|
| **D1** | **Custom-tool scripts live in the operator's VM image; the kernel does NOT bundle them and does NOT verify their bytes.** | Per-script hash verification is a strict subset of OCI image-digest pinning (`INV-VM-CAP-03`). It covers neither the interpreter, libc, shared libraries, nor the script's transitive dependencies. Operators who want supply-chain integrity for tooling pin the entire VM image by digest. The kernel does not babysit the Executor's sandbox. |
| **D2** | **Atomic sign+submit.** No standalone `plan sign` step in V2. `raxis submit plan plan.toml` parses, resolves, bundles, hashes, signs, and submits in a single CLI invocation. | Eliminates the TOCTOU window between sign and submit. The bytes signed and the bytes submitted are identical because they are constructed once, in memory, in a single process. |
| **D3** | **Strictly bounded path resolution.** Host-side paths referenced from `plan.toml` resolve relative to the directory containing `plan.toml`. Symlinks are followed, but the resolved real path MUST lie inside the plan-root tree; otherwise `FAIL_PLAN_BUNDLE_PATH_ESCAPE`. Use of `..` to escape the root is rejected. | The plan-root tree IS the operator's authority surface. Allowing a path to escape (whether literally with `..` or transitively through a symlink) lets a plan-bundle-time link change the bytes the kernel seals after the operator's eyeballs have left the room. |
| **D4** | **No transitive includes, no templating.** Files are bundled as opaque byte arrays. The kernel parser does NOT evaluate `{{include: foo.md}}`, `m4` macros, env-var substitution, or any other indirection. | Templating creates a second admission surface (the template engine's bug surface) and a second authority surface (operator signs source, kernel evaluates expanded form). External preprocessors (Make, m4, esbuild, etc.) are the operator's correct tool for plan composition; they run before `raxis submit plan`. |
| **D5** | **Strict bundle size discipline (configurable in `policy.toml`).** Default caps: 1 MiB per artifact, 10 MiB total bundle size, 200 artifacts maximum. Fail-closed at the CLI; defensive re-check at the kernel. | The bundle becomes part of the immutable kernel store and carries forward into every audit, recovery, and forensic operation for the lifetime of the system. Without caps, a careless `acceptance_criteria_path = "/var/log/syslog"` produces a 5 GiB SQLite row that operators discover months later. |
| **D6** | **Plan Bundle Sealing IS the technical enforcement of `INV-INIT-06`.** No new invariant ID. The invariant is strengthened to read: *"Once admitted, the kernel reads plan-derived data exclusively from its internal content-addressed store. The host filesystem is NEVER consulted for plan files after admission."* | The architectural intent of `INV-INIT-06` was always "the host filesystem stops mattering after admission"; V1 left wiggle room because the kernel re-opened `plan.toml` during recovery in early prototypes. V2 closes that wiggle room and names the closure mechanism. |
| **D7** | **Canonical terminology: "Plan Bundle Sealing".** | One name across docs, audit events, error codes, and operator UX. Variants (`plan_bundle`, `plan_bundle_sha256`, `PlanBundleSealed`) follow standard naming derivations. |
| **D8** | **No automatic garbage collection of bundle bytes.** Bundles are retained indefinitely in `kernel.db`. V3 audit retention may eventually move them to cold storage, but V2 keeps them hot. | The bundle is the foundational cryptographic input to the initiative state machine. Deleting it destroys forensic reproducibility — without it, audit-chain replay cannot re-derive the plan that the kernel actually executed. The size caps in D5 make indefinite retention tractable. |

---

## §3 — Bundle Wire Format

### 3.1 Logical structure

A plan bundle is an ordered list of **artifacts**. Each artifact is a
named opaque byte array with a per-artifact SHA-256. The first artifact
is always `plan.toml` (the artifact name is fixed; the original on-disk
filename is irrelevant once bundled).

```
PlanBundle {
    schema_version: u16,                  // = 1 for V2
    created_at_unix_secs: u64,            // CLI clock at bundling time
    plan_root_relpath: String,            // relative path the operator passed; informational
    artifacts: Vec<BundleArtifact>,       // ordered; artifacts[0] is "plan.toml"
}

BundleArtifact {
    name: String,         // bundle-internal name; see §3.3 for naming rules
    bytes: Vec<u8>,       // raw bytes, no normalization
    sha256: [u8; 32],     // SHA-256(bytes); included for self-verification + audit
}
```

### 3.2 Canonical encoding for hashing

The hash that the operator signs is taken over a **canonical
serialization** of the bundle. RAXIS uses a length-prefixed binary
encoding (the same approach the kernel uses for audit-chain hashing):

```
canonical_input =
    "RAXIS-V2-PLAN-BUNDLE\0"                          // 21-byte ASCII domain prefix + 0x00
 || u16_be(schema_version)
 || u64_be(created_at_unix_secs)
 || u32_be(plan_root_relpath.len()) || plan_root_relpath_utf8
 || u32_be(artifacts.len())
 || for each artifact in order:
        u32_be(name.len()) || name_utf8
     || u64_be(bytes.len()) || bytes
     || artifact.sha256                                  // 32 bytes

bundle_sha256 = SHA-256(canonical_input)
signing_input = "RAXIS-V2-PLAN-BUNDLE-SIG\0" || bundle_sha256
signature     = Ed25519::sign(operator_private_key, signing_input)
```

The `"RAXIS-V2-PLAN-BUNDLE\0"` and `"RAXIS-V2-PLAN-BUNDLE-SIG\0"`
domain-separation prefixes follow the established RAXIS pattern
(`v1/kernel-store.md` §2.5.5, `key-revocation.md` §3). This prevents
cross-protocol replay of a signature minted for one purpose against a
different verifier.

The signature covers `bundle_sha256`, not `canonical_input`, for
auditability: the kernel records `bundle_sha256` in the initiatives row
as a 32-byte digest field rather than recomputing it on every join.

### 3.3 Artifact naming rules

- `artifacts[0].name` is exactly the literal string `"plan.toml"`.
- All other artifact names are the **bundle-relative path** of the
  artifact, computed as `relative(plan_root, resolved_real_path)` after
  the path-resolution rules in §5.
  - Example: if `plan.toml` references `./prompts/ext.md`, the bundle
    name is `prompts/ext.md`.
- Bundle names use forward slashes, are NFC-normalized UTF-8, and are
  **bundle-unique** (the same artifact deduplicates by `sha256`; the
  same bundle name appearing twice with different bytes is a CLI-side
  rejection — `FAIL_PLAN_BUNDLE_NAME_COLLISION`).
- Bundle names MUST NOT begin with `/`, MUST NOT contain `..` segments,
  and MUST NOT contain NUL bytes. A name violating this is a CLI bug
  (the path-resolution layer cannot produce such a name in correct
  operation); the kernel rejects defensively with
  `FAIL_PLAN_BUNDLE_INVALID_NAME`.

### 3.4 IPC wire envelope

The CLI sends one operator-socket message:

```rust
OperatorRequest::CreateInitiative {
    initiative_id:   InitiativeId,
    plan_bundle:     Vec<u8>,           // canonical_input bytes per §3.2
    bundle_sha256:   [u8; 32],          // SHA-256(plan_bundle); echoed for cheap kernel-side cross-check
    signature:       [u8; 64],          // Ed25519 signature over signing_input per §3.2
    signed_by:       OperatorFingerprint, // SHA-256[:16] of operator's Ed25519 public key
}
```

`bundle_sha256` is redundant with `SHA-256(plan_bundle)`; the kernel
recomputes it and rejects mismatches with `FAIL_PLAN_BUNDLE_SHA256_MISMATCH`.
Including the field on the wire lets the kernel reject cheap before
allocating Ed25519 verification cycles for an obviously-corrupt bundle.

The **only** way to deliver a plan bundle to the kernel is via
`OperatorRequest::CreateInitiative`. The V1 message
`OperatorRequest::CreateInitiative { plan_toml_path, plan_sig_path }`
(with on-disk path arguments) is removed in V2; the kernel rejects the
old shape at IPC-decode time as an unknown variant.

---

## §4 — CLI Workflow: `raxis submit plan`

### 4.1 Invocation

```
raxis-cli submit plan <plan.toml> [--initiative-id <id>] [--dry-run]
```

The single positional argument is the path to `plan.toml`. The CLI
derives the **plan root** as the parent directory of this path
(canonicalized via `realpath`).

`--initiative-id` is optional; if omitted, the CLI generates a UUIDv7.

`--dry-run` runs the full admission chain without sealing the bundle
or creating an initiative; see `operator-ergonomics.md §12` for the
canonical specification of the dry-run flow.

> **Bundle bytes are post-prepare bytes.** The operator typically runs
> `raxis-cli plan prepare <plan.toml>` first
> (`operator-ergonomics.md §5`) so that policy-resolved defaults are
> filled into `plan.toml` and the operator can review them before
> signing. The operator then signs the **prepared** plan via this
> command. From the kernel's perspective there is no concept of "raw
> operator bytes" vs "defaulted bytes": the bundle contains exactly
> what the operator signed. The `# @raxis-default v0.4.0` annotation
> comments that `plan prepare` writes are part of the signed plan.toml
> bytes (they're TOML comments) but carry no kernel-side semantics —
> the kernel parser ignores them. If a plan is submitted without first
> running `plan prepare`, and the policy declares defaults the
> operator omitted, admission step 0e fails with
> `FAIL_PLAN_REQUIRES_PREPARE { missing_fields }`
> (`policy-plan-authority.md §5 step 0e`).

### 4.2 Phases (all in-process, no external state)

```
1. parse:        Read plan.toml bytes from disk; parse as TOML.
2. resolve:      Walk the parsed plan; collect every host-side path
                 reference (a future-extension hook; see §5.4).
3. canonicalize: For each path, compute resolved_real_path per §5;
                 reject path escapes immediately.
4. bundle:       Read each artifact's bytes (capped per §7.2 per-read);
                 build BundleArtifact list in declaration order;
                 plan.toml is artifacts[0].
5. validate:     Enforce size caps per §7.
6. canonical_encode: Produce canonical_input bytes per §3.2.
7. hash:         bundle_sha256 = SHA-256(canonical_input).
8. sign:         Load operator key (per --operator-key arg / env);
                 sign signing_input per §3.2.
9. submit:       Open operator socket; perform challenge-response
                 handshake; send OperatorRequest::CreateInitiative
                 per §3.4; await response.
10. report:      Print initiative_id and `Status: Draft` on success;
                 print FAIL code + remediation hint on failure.
```

There is **no intermediate file written to disk**. The bundle is
constructed in memory, hashed in memory, signed in memory, and sent
to the kernel over the operator socket. The operator's view is a
single command that either succeeds (initiative created) or fails
(with a specific FAIL code). There is no signed artifact left over
for an attacker to mutate or replay.

### 4.3 Operator key loading

`raxis submit plan` accepts `--operator-key <path>` (or
`RAXIS_OPERATOR_KEY` env var; precedence per `v1/env-vars.md`). The
key is read once, used to compute the Ed25519 signature in §4.2 step 8,
and dropped before the IPC submission. The kernel never sees the
private key — only the resulting signature and the operator
fingerprint that lets the kernel resolve the public key from
`policy.operators`.

### 4.4 Failure handling and exit codes

The CLI exits non-zero on any failure. The exit code maps to the
RAXIS FAIL code per `v1/cli-ceremony.md`'s convention; the failing
phase (parse / resolve / bundle / validate / submit) is included in
the error text so the operator knows where to look.

CLI-side failures (parse, resolve, validate) emit no kernel-side
audit event — the kernel never saw the request. Submit-time failures
(kernel rejects after IPC) DO produce an `InitiativeAdmissionFailed`
audit row keyed by `bundle_sha256` (so post-mortem can correlate the
operator's local bundle to the kernel's reject reason).

### 4.5 What V1 commands V2 removes

- **`raxis-cli plan sign`** — removed. The CLI does not write
  `plan.sig` files. Build pipelines that previously called
  `plan sign` separately must collapse to `plan submit`.
- **`raxis-cli plan submit <initiative_id> <plan_dir>`** —
  signature changed. V2 takes `<plan.toml>` directly (a file, not a
  directory) and an optional `--initiative-id`. The two-arg form
  with a directory is rejected at argument parse time with a hint
  pointing to the new invocation.

---

## §5 — Path Resolution and Path-Escape Policy (D3)

### 5.1 Plan root

The **plan root** is `realpath(parent_dir(plan.toml))` — the
canonicalized absolute directory containing `plan.toml`. All
host-side paths referenced from `plan.toml` are resolved relative
to this root.

The plan root is the operator's authority surface. Any artifact
whose resolved real path is **inside** the plan root is treated as
authorized; any artifact resolving **outside** is rejected.

### 5.2 Path resolution algorithm

For each host-side path reference `p` in the parsed plan:

1. **Empty / null check.** Empty strings, `null`, or non-string types
   for path-typed fields → `FAIL_PLAN_BUNDLE_INVALID_PATH`.
2. **Absolute paths rejected.** A leading `/` is a structural
   misuse — operators should always reference paths relative to the
   plan root. → `FAIL_PLAN_BUNDLE_ABSOLUTE_PATH`.
3. **`..` segments rejected pre-resolution.** Any path containing a
   literal `..` segment (`./../`, `foo/../bar`, etc.) → immediate
   `FAIL_PLAN_BUNDLE_PATH_ESCAPE`. This is rejected even if the
   final resolved path would happen to land inside the plan root,
   because the operator's intent is structurally suspicious.
4. **Resolve via `realpath`.** Compute
   `resolved = realpath(plan_root + "/" + p)`. This follows symlinks
   transitively. Symlink loops are rejected with
   `FAIL_PLAN_BUNDLE_SYMLINK_LOOP` (the underlying `realpath` will
   return `ELOOP`).
5. **Containment check.** Verify
   `resolved.starts_with(plan_root + "/")`. If not, →
   `FAIL_PLAN_BUNDLE_PATH_ESCAPE`. The trailing `/` matters: a
   sibling directory `<plan_root>_evil/` is rejected because it does
   not start with `<plan_root>/`.
6. **Existence + readability check.** `resolved` must be a regular
   file (not a directory, device, or special file) and must be
   readable by the CLI process. Failures →
   `FAIL_PLAN_BUNDLE_ARTIFACT_UNREADABLE` with the underlying errno
   in the error detail.

### 5.3 Worked examples

```
plan_root = /home/op/work/myplan
plan.toml references                    →  resolved                                 →  outcome
"./prompts/ext.md"                      →  /home/op/work/myplan/prompts/ext.md     →  OK; bundle name "prompts/ext.md"
"prompts/ext.md"                        →  /home/op/work/myplan/prompts/ext.md     →  OK; identical
"./outside.md" → symlinked to ../sibling/outside.md  →  /home/op/work/sibling/outside.md  →  FAIL_PLAN_BUNDLE_PATH_ESCAPE
"../shared/common.md"                   →  (rejected pre-resolution)               →  FAIL_PLAN_BUNDLE_PATH_ESCAPE
"/etc/raxis/template.md"                →  (rejected: absolute path)               →  FAIL_PLAN_BUNDLE_ABSOLUTE_PATH
"./prompts/ext.md" → symlink to /tmp/x  →  /tmp/x                                  →  FAIL_PLAN_BUNDLE_PATH_ESCAPE
"./prompts/ext.md" → symlink to ./inner/x.md (still inside root)  →  /home/op/work/myplan/prompts/inner/x.md  →  OK; bundle name "prompts/ext.md" (per §3.3 — the bundle name is computed from the *declared* path, not the resolved real path)
```

The last case captures an important distinction: the **bundle name**
is determined by the path-as-written in `plan.toml` (relative to the
plan root, after lexical normalization), not by the resolved real
path. This means the operator's plan-as-read references symbolic
names; the kernel never sees that two declared paths happened to
resolve to the same physical inode.

### 5.4 Forward-compatibility hook

V2 ships with **zero plan.toml fields** that take host-side paths.
The current `plan.toml` schema is fully self-contained: every field
that conveys text content (initiative description, acceptance
criteria, custom-tool description, verifier args, etc.) is an inline
TOML string.

Plan Bundle Sealing's path-resolution rules in §5.1–§5.3 are normative
infrastructure for **any future field that takes a host-side path**.
When such a field is added (e.g., a hypothetical
`acceptance_criteria_path = "./criteria/task42.md"`), it inherits this
spec's resolution and bundling discipline by reference; the field's
own spec only declares its semantic role (which task it applies to,
how the kernel renders it into the KSB, etc.).

The CLI's path-collection step (§4.2 step 2) is implemented as a
visitor over the parsed plan that recognizes a registered set of
"host-path-typed" fields. Adding a new field of this type is a
single-line edit to the visitor. In V2, the visitor's set is empty
and `bundle.artifacts.len() == 1` for every well-formed plan.

---

## §6 — Templating and Transitive Includes (D4)

The kernel's plan parser is **strictly literal**. It does not evaluate:

- `{{include: <path>}}` directives or any other variant of plan-side
  inlining.
- `${VAR}` or `$(cmd)` env / shell substitution.
- `m4`, `mustache`, `jinja2`, or any other template engine syntax.
- Conditional sections, file-glob expansions, or content-derived
  loops.

If an operator wants to compose a plan from multiple files (e.g., a
shared `common-acceptance-criteria.md` injected into multiple task
descriptions), the operator runs an **external preprocessor** before
calling `raxis submit plan`:

```bash
# Operator's Makefile
plan.toml: plan.toml.in common-acceptance-criteria.md
	m4 plan.toml.in > plan.toml

submit: plan.toml
	raxis submit plan plan.toml
```

The bytes the operator authenticates are the bytes of the **expanded**
`plan.toml`. The preprocessor and its inputs are part of the
operator's build environment and outside RAXIS's authority surface.

### 6.1 Why no kernel-side templating

Two reasons, in order of importance:

1. **Authority drift.** If the operator signs `plan.toml.in` and the
   kernel evaluates `{{include: foo.md}}` at admission, the kernel is
   reading bytes the operator did not directly authenticate. The
   include's bytes are de facto authorized by the include directive's
   presence in the signed source — but the kernel has to trust its
   own template engine to substitute the right bytes, in the right
   order, from the right path. That trust establishes a parallel
   authority surface (the template engine) the operator never reviewed.
2. **Parser bug surface.** Every templating engine ships with parser
   bugs. RAXIS deliberately keeps its own admission-time parser as
   small and as easily-auditable as possible. Adding macro evaluation
   triples the parser's complexity and creates a class of admission-
   time vulnerabilities (e.g., the well-known recursion bombs in
   poorly-written template engines) that the kernel currently does
   not have to defend against.

External preprocessors avoid both: the preprocessor is the operator's
chosen tool, runs in the operator's environment, and produces a
single byte stream the operator signs literally.

---

## §7 — Bundle Size Discipline (D5)

### 7.1 Caps

Three independent caps apply at bundling time. All three are enforced
**at the CLI** (so the kernel never sees an oversize bundle in normal
operation) and **at the kernel** (defensively, in case a non-canonical
or malicious CLI tries to bypass).

| Cap | Default | Configurable in `policy.toml` | FAIL code |
|---|---|---|---|
| Per-artifact size | 1 MiB (`1_048_576` bytes) | `[plan_bundle_limits].max_artifact_bytes` | `FAIL_PLAN_BUNDLE_ARTIFACT_TOO_LARGE` |
| Total bundle size (sum of artifact bytes; canonical-encoding overhead negligible) | 10 MiB (`10_485_760` bytes) | `[plan_bundle_limits].max_bundle_bytes` | `FAIL_PLAN_BUNDLE_TOO_LARGE` |
| Artifact count | 200 | `[plan_bundle_limits].max_artifact_count` | `FAIL_PLAN_BUNDLE_TOO_MANY_ARTIFACTS` |

`plan.toml` itself counts as one artifact and contributes to all three
caps. In V2 (where the visitor's host-path field set is empty), every
bundle has exactly one artifact and the per-artifact cap is the binding
constraint.

### 7.2 CLI enforcement

The CLI enforces caps **streamingly during the bundle phase** (§4.2
step 4) — it does NOT read a 5 GiB file into memory just to discover
it exceeds the cap. The artifact-read loop reads
`max_artifact_bytes + 1` bytes; if the file has more, the CLI aborts
the read, frees the buffer, and emits `FAIL_PLAN_BUNDLE_ARTIFACT_TOO_LARGE`.

The total-bundle and count caps are checked after each successful
artifact read; exceeding either short-circuits the rest of the
bundling phase.

### 7.3 Kernel-side defensive enforcement

On `CreateInitiative` admission, the kernel re-checks all three caps
against the wire bundle. A bundle exceeding any cap is rejected with
the corresponding FAIL code and an `InitiativeAdmissionFailed` audit
event (`bundle_sha256`, `cap_violated`, `observed_value`,
`limit_value`). In normal operation this path is dead code; it
exists to defend against custom non-canonical CLIs.

### 7.4 Configuration: `[plan_bundle_limits]`

In `policy.toml`:

```toml
[plan_bundle_limits]
max_artifact_bytes  = 1_048_576       # 1 MiB
max_bundle_bytes    = 10_485_760      # 10 MiB
max_artifact_count  = 200
```

All three fields are positive integers. Operators may **lower** the
caps below the defaults but MUST NOT raise them above the
implementation hard ceilings: `max_artifact_bytes ≤ 64 MiB`,
`max_bundle_bytes ≤ 128 MiB`, `max_artifact_count ≤ 1024`. Attempts
to set values above the hard ceilings are rejected at policy load
with `FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING`. The hard
ceilings exist to prevent a misconfigured policy from greenlighting
bundles that would individually overwhelm the SQLite write path.

---

## §8 — Kernel-Side Admission and Sealing

### 8.1 Admission sequence (extends `policy-plan-authority.md` §5)

When `OperatorRequest::CreateInitiative` arrives, the kernel performs
the following checks in order. Earlier checks short-circuit later
ones. All checks happen **before** any database write.

```
1. Decode the IPC envelope; reject malformed wire bytes with
   FAIL_PLAN_BUNDLE_DECODE_FAILED.
2. Recompute SHA-256(plan_bundle); reject mismatch with
   FAIL_PLAN_BUNDLE_SHA256_MISMATCH.
3. Re-check size caps per §7.3.
4. Parse the canonical encoding per §3.2; reject malformed canonical
   structure with FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED.
5. Verify per-artifact SHA-256s match the recorded values; reject
   mismatch with FAIL_PLAN_BUNDLE_ARTIFACT_HASH_MISMATCH.
6. Verify artifacts[0].name == "plan.toml"; reject with
   FAIL_PLAN_BUNDLE_FIRST_ARTIFACT_NOT_PLAN_TOML.
7. Verify all artifact names per §3.3 (no leading /, no .., NFC,
   etc.); reject with FAIL_PLAN_BUNDLE_INVALID_NAME.
8. Look up operator entry by signed_by fingerprint in
   policy.operators; reject with FAIL_UNKNOWN_SIGNER if absent.
9. Verify Ed25519 signature against operator pubkey per §3.2; reject
   with FAIL_PLAN_SIGNATURE_INVALID.
10. Check key revocation state per key-revocation.md; reject as
    appropriate (FAIL_KEY_COMPROMISED / FAIL_KEY_RETIRED).
11. Parse plan.toml from artifacts[0].bytes; admit through the
    full policy-plan-authority.md §5 shift-left validation chain.
12. On success, seal the bundle into the store per §8.2.
```

### 8.2 Storage layout

The V1 `signed_plan_artifacts` table (`v1/kernel-store.md` §2.5.3) is
**superseded** for V2 admissions. V2 introduces a parallel table
that holds the full bundle:

```sql
CREATE TABLE plan_bundles (
    bundle_sha256          BLOB PRIMARY KEY,        -- 32 bytes; the canonical bundle hash
    bundle_bytes           BLOB NOT NULL,           -- canonical_input per §3.2
    signature              BLOB NOT NULL,           -- 64 bytes; Ed25519 signature
    signed_by              BLOB NOT NULL,           -- 8 bytes; operator fingerprint
    schema_version         INTEGER NOT NULL,
    artifact_count         INTEGER NOT NULL,
    bundle_bytes_len       INTEGER NOT NULL,
    sealed_at_unix_secs    INTEGER NOT NULL
);

CREATE TABLE plan_bundle_artifacts (
    bundle_sha256          BLOB NOT NULL REFERENCES plan_bundles(bundle_sha256),
    artifact_seq           INTEGER NOT NULL,        -- 0 = plan.toml; 1.. = others
    artifact_name          TEXT NOT NULL,
    artifact_sha256        BLOB NOT NULL,           -- 32 bytes
    artifact_bytes         BLOB NOT NULL,           -- raw bytes
    artifact_bytes_len     INTEGER NOT NULL,
    PRIMARY KEY (bundle_sha256, artifact_seq)
);

ALTER TABLE initiatives
    ADD COLUMN plan_bundle_sha256 BLOB
    REFERENCES plan_bundles(bundle_sha256);
```

`initiatives.plan_artifact_sha256` (V1 column referencing
`plan.toml` bytes alone) is retained for V1 initiatives but not
populated for V2 ones; V2 rows carry `plan_bundle_sha256` instead.
Migration is forward-only: existing V1 initiatives keep their V1
storage; the V1 admission path is removed for new initiatives but
the read path remains for audit and recovery of pre-V2 data.

The bundle bytes are stored **once** keyed by `bundle_sha256`. Two
initiatives that happen to use byte-identical bundles share a single
`plan_bundles` row; this dedup is incidental (SHA-256 collisions
aside) and not exploited for correctness.

### 8.3 Post-admission read discipline (D6 enforcement)

Once an initiative has a non-NULL `plan_bundle_sha256`, the kernel
**MUST NOT** open any file under the plan root for that initiative
again. Every subsequent operation reads from `plan_bundles` /
`plan_bundle_artifacts`:

- `approve_plan` — re-verifies signature against `plan_bundles.bundle_bytes`
  and `plan_bundles.signature`, NOT against any on-disk file.
- Crash recovery — replays from the SQLite store; the host filesystem
  is irrelevant.
- Audit chain reconstruction — joins `audit_events` to `plan_bundles`
  by `bundle_sha256`; bundle bytes recoverable for any historical
  initiative without consulting the operator's working tree.
- KSB rendering — pulls `plan.toml` bytes from `artifacts[0]`; pulls
  any future host-path-derived artifacts from `artifacts[1..]`. The
  rendering pipeline takes a `&BundleArtifact` lookup function, not a
  filesystem path.

Reference implementation: `raxis-kernel::store::plan_bundle::read_artifact`
is the **only** API by which initiative-execution code accesses
plan-derived bytes. Callers that try to construct host paths from
`bundle.plan_root_relpath` are a spec violation.

### 8.4 Operator-visible filesystem state after submission

`raxis submit plan` does **not** create files in `<data_dir>/plans/`
or anywhere else. The V1 on-disk layout
(`<data_dir>/plans/<initiative_id>/plan.toml`) is removed in V2.

For human inspection, `raxis-cli initiative show <id> --bundle` reads
the bundle from the SQLite store and writes it to stdout (or a
caller-specified directory tree). This is purely a forensic helper;
the kernel does not consume the output.

---

## §9 — Failure Codes

All Plan Bundle Sealing FAIL codes are namespaced `FAIL_PLAN_BUNDLE_*`
and live in the canonical failure-code reference in
`policy-plan-authority.md` §3 (with this spec as the authoritative
home for their semantics).

| Code | Phase | Trigger |
|---|---|---|
| `FAIL_PLAN_BUNDLE_INVALID_PATH` | CLI resolve | Path field is empty / null / wrong type. |
| `FAIL_PLAN_BUNDLE_ABSOLUTE_PATH` | CLI resolve | Path begins with `/`. |
| `FAIL_PLAN_BUNDLE_PATH_ESCAPE` | CLI resolve | Path contains `..` segments OR resolves outside plan root (after symlink follow). |
| `FAIL_PLAN_BUNDLE_SYMLINK_LOOP` | CLI resolve | `realpath` returned `ELOOP` for a referenced path. |
| `FAIL_PLAN_BUNDLE_ARTIFACT_UNREADABLE` | CLI bundle | Resolved path is not a regular file or is unreadable. |
| `FAIL_PLAN_BUNDLE_NAME_COLLISION` | CLI bundle | Two declared paths produce the same bundle name with different bytes. |
| `FAIL_PLAN_BUNDLE_ARTIFACT_TOO_LARGE` | CLI / Kernel | Artifact byte length exceeds `max_artifact_bytes`. |
| `FAIL_PLAN_BUNDLE_TOO_LARGE` | CLI / Kernel | Total bundle byte length exceeds `max_bundle_bytes`. |
| `FAIL_PLAN_BUNDLE_TOO_MANY_ARTIFACTS` | CLI / Kernel | Artifact count exceeds `max_artifact_count`. |
| `FAIL_PLAN_BUNDLE_DECODE_FAILED` | Kernel | IPC envelope failed to decode. |
| `FAIL_PLAN_BUNDLE_SHA256_MISMATCH` | Kernel | Wire `bundle_sha256` does not match `SHA-256(plan_bundle)`. |
| `FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED` | Kernel | Bundle bytes failed to parse against the canonical encoding (§3.2). |
| `FAIL_PLAN_BUNDLE_ARTIFACT_HASH_MISMATCH` | Kernel | A per-artifact `sha256` field does not match `SHA-256(artifact.bytes)`. |
| `FAIL_PLAN_BUNDLE_FIRST_ARTIFACT_NOT_PLAN_TOML` | Kernel | `artifacts[0].name != "plan.toml"`. |
| `FAIL_PLAN_BUNDLE_INVALID_NAME` | Kernel | An artifact name violates the §3.3 naming rules. |
| `FAIL_PLAN_SIGNATURE_INVALID` | Kernel | Ed25519 verification of `signing_input` failed. (Identical to V1 code; reused.) |
| `FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING` | Policy load | A `[plan_bundle_limits]` value exceeds the implementation hard ceiling per §7.4. |
| `FAIL_PLAN_REQUIRES_PREPARE { missing_fields }` | Kernel admission step 0e | The plan omits at least one defaultable field whose policy default is set; the operator did not run `raxis-cli plan prepare` first. Canonical home: `operator-ergonomics.md §20`. Listed here for cross-reference because it fires on `submit plan` admission alongside the other Plan Bundle Sealing checks. |

The CLI's failure messages MUST include the **declared path** (as
written in `plan.toml`) for path-related failures, not just the
resolved real path. This is the only string the operator can match
against their own source — telling them
`FAIL_PLAN_BUNDLE_PATH_ESCAPE: ./prompts/ext.md` is actionable;
telling them `FAIL_PLAN_BUNDLE_PATH_ESCAPE: /tmp/x` is not.

For `FAIL_PLAN_REQUIRES_PREPARE`, the CLI's failure message MUST
include the `missing_fields` list and a one-line remediation hint:
`run \`raxis-cli plan prepare ./plan.toml\` to fill defaults, then
re-submit`.

---

## §10 — No Garbage Collection (D8)

Plan bundles are retained in `plan_bundles` and `plan_bundle_artifacts`
**indefinitely**. There is no V2 mechanism that deletes a bundle row,
not even on initiative termination, abort, or purge. The bundle bytes
are foundational cryptographic inputs to the initiative state machine:

- Audit-chain replay needs the bundle bytes to re-derive the plan
  the kernel actually executed.
- Forensic post-mortems on a compromised key (`key-revocation.md`)
  need to know which exact plans the compromised key authenticated;
  this requires the bundle bytes to remain joinable from the audit
  log.
- Operator dispute resolution ("did I really sign that plan?") is
  resolved by recomputing the bundle hash from stored bytes and
  re-verifying against the recorded signature; both sides need the
  bytes still on disk.

The size caps in §7.1 keep indefinite retention tractable: at
worst-case 10 MiB per initiative, 100,000 initiatives consume
~1 TiB. Real-world workloads will be orders of magnitude below this.

V3's `audit-retention.md` lifecycle MAY add a cold-storage tier for
plan bundles (e.g., chunked archival to operator-controlled S3
buckets with on-demand rehydration). The V3 design will follow
`audit-retention.md`'s archival pattern (sidecar archiver,
content-addressed payload store, retain forever in operator-controlled
storage). V2 does not implement this; the bundle bytes stay in
`kernel.db` for the lifetime of the system.

---

## §11 — Cross-Spec Impacts

| Spec | Change |
|---|---|
| `invariants.md` | `INV-INIT-06` strengthened: adds the post-admission read-discipline clause (§8.3). No new invariant ID (Plan Bundle Sealing is the technical enforcement of the existing invariant). Cross-reference points here. |
| `policy-plan-authority.md` | New `[plan_bundle_limits]` policy schema (§7.4). New FAIL codes added to the canonical failure-code reference (§9). `approve_plan` shift-left check chain extended with the §8.1 admission sequence at the front. |
| `v1/kernel-store.md` | Note V2 supersedes the §2.5.3 `signed_plan_artifacts` storage layout for V2-admitted initiatives; the V1 table is retained read-only for V1 initiatives and for audit-chain replay of pre-V2 history. The V1 on-disk `<data_dir>/plans/<initiative_id>/` layout is not used for V2. |
| `v1/cli-ceremony.md` | `plan sign` removed in V2. `plan submit` signature changed (file argument, not directory). Old invocation rejected at parse time with a hint. |
| `v1/env-vars.md` | `RAXIS_OPERATOR_KEY` continues to apply to `raxis submit plan`; no schema change. |
| `key-revocation.md` | Operator key lookup at admission is unchanged; `signed_by` fingerprint resolves through the same `policy.operators` path. The set of FAIL codes a revoked key produces is unchanged. |
| `kernel-mechanics-prompt.md` | KSB rendering reads from `plan_bundle_artifacts` instead of `<data_dir>/plans/<initiative_id>/plan.toml`. The KSB content itself is unchanged; only the byte source moves into the SQLite store. |
| `custom-tools.md` | Already updated by D1: `command_sha256` removed entirely. Custom-tool scripts live in the operator's VM image; no host-side bundling of script bytes. |
| `v3/audit-retention.md` (V3) | Future spec MAY add a cold-storage tier for plan bundles per §10. |

---

## §12 — Implementation Checklist

### CLI side

- [ ] `raxis-cli submit plan <plan.toml> [--initiative-id <id>]` command implemented per §4.
- [ ] `raxis-cli plan sign` command removed; `raxis-cli plan submit <id> <dir>` rejected at arg parse with hint to new invocation.
- [ ] Plan-root canonicalization via `realpath(parent_dir(plan.toml))`.
- [ ] Path-resolution visitor over the parsed plan; in V2 the visitor's host-path field set is empty (forward-compatibility hook only).
- [ ] Path-resolution rejects per §5.2 with the §9 FAIL codes.
- [ ] Bundle construction streams artifact reads with `max_artifact_bytes + 1` cap; never reads an oversize file fully into memory.
- [ ] Canonical encoding implementation matches §3.2 byte-for-byte; pinned via `cli/tests/plan_bundle_canonical_roundtrip.rs`.
- [ ] Operator-key load + Ed25519 sign over `signing_input` per §3.2 / §4.3.
- [ ] IPC submit via `OperatorRequest::CreateInitiative` per §3.4.
- [ ] CLI failure messages include the **declared path** for path-related failures (§9 last paragraph).

### Kernel side

- [ ] `OperatorRequest::CreateInitiative` decoder accepts only the V2 wire shape; rejects V1 shape as unknown variant.
- [ ] Admission sequence per §8.1 implemented in order, with each step short-circuiting on failure.
- [ ] Defensive size-cap re-check per §7.3.
- [ ] Canonical-encoding parser matches the CLI's encoder byte-for-byte; pinned via cross-language fixture in `kernel/tests/plan_bundle_decode.rs`.
- [ ] `plan_bundles` and `plan_bundle_artifacts` SQL tables created; `initiatives.plan_bundle_sha256` column added.
- [ ] `plan_bundle::read_artifact` is the sole API for initiative-execution code to read plan-derived bytes; lint or compile-time guard against any kernel module opening a file under the plan root for an admitted initiative.
- [ ] `approve_plan` re-verification reads bundle bytes from SQLite, never disk.
- [ ] Crash recovery replays exclusively from `plan_bundles` / `plan_bundle_artifacts`.
- [ ] `[plan_bundle_limits]` policy section parsed and validated per §7.4; hard ceilings enforced.
- [ ] All §9 FAIL codes registered in `raxis-types::PlannerErrorCode` and surfaced through the operator socket.

### Operator-facing

- [ ] `raxis initiative show <id> --bundle` writes a stored bundle to stdout / a directory for forensic inspection.
- [ ] `raxis log --filter kind=InitiativeAdmissionFailed` shows `bundle_sha256`, `cap_violated`, `signed_by`.
- [ ] Documentation: migration guide for users moving from V1 `plan sign` + `plan submit` to V2 atomic `submit plan`.

### Tests

- [ ] Round-trip: build bundle in CLI, submit, read back from store, verify byte-identical.
- [ ] Path escape via `..` → `FAIL_PLAN_BUNDLE_PATH_ESCAPE`.
- [ ] Path escape via symlink to outside-plan-root → `FAIL_PLAN_BUNDLE_PATH_ESCAPE`.
- [ ] Symlink to inside-plan-root → OK; bundle name is the declared path, not the resolved path.
- [ ] Symlink loop → `FAIL_PLAN_BUNDLE_SYMLINK_LOOP`.
- [ ] Absolute path in plan field → `FAIL_PLAN_BUNDLE_ABSOLUTE_PATH`.
- [ ] Per-artifact size cap exceeded → `FAIL_PLAN_BUNDLE_ARTIFACT_TOO_LARGE`; CLI does not OOM.
- [ ] Total bundle size cap exceeded → `FAIL_PLAN_BUNDLE_TOO_LARGE`.
- [ ] Artifact count cap exceeded → `FAIL_PLAN_BUNDLE_TOO_MANY_ARTIFACTS`.
- [ ] Wire `bundle_sha256` mismatched → `FAIL_PLAN_BUNDLE_SHA256_MISMATCH`.
- [ ] Per-artifact `sha256` mismatched → `FAIL_PLAN_BUNDLE_ARTIFACT_HASH_MISMATCH`.
- [ ] Tampered first artifact name → `FAIL_PLAN_BUNDLE_FIRST_ARTIFACT_NOT_PLAN_TOML`.
- [ ] Signature verifies under operator key A; fails under key B → `FAIL_PLAN_SIGNATURE_INVALID`.
- [ ] Signed by revoked key → `FAIL_KEY_COMPROMISED` (per `key-revocation.md`).
- [ ] V1-shape `CreateInitiative` IPC arrives → rejected at decode.
- [ ] After admission, deleting / mutating / removing the operator's plan working tree does NOT affect `approve_plan`, KSB rendering, recovery, or audit reconstruction.
- [ ] Two initiatives with byte-identical bundles share a single `plan_bundles` row.
- [ ] Policy with `max_artifact_bytes = 100 GiB` → `FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING` at policy load.
- [ ] Initiative termination → `plan_bundles` / `plan_bundle_artifacts` rows remain (no GC).

---

## §13 — Invariants Index

This spec does not introduce a new invariant. It strengthens an
existing one:

| Invariant | Statement (one-line) | Strengthening |
|---|---|---|
| `INV-INIT-06` | Plan immutable post-admission. | V2 adds: *"Once admitted, the kernel reads plan-derived data exclusively from its internal content-addressed store. The host filesystem is NEVER consulted for plan files after admission."* The technical enforcement mechanism is **Plan Bundle Sealing** as defined in this spec. |

This composes with the broader RAXIS authority model:

- **`INV-CERT-01`** (operator certs mandatory) — the bundle's signature
  is verified against an operator key that is itself authenticated by
  the certificate chain.
- **`INV-04`** (audit-chain hashing) — every bundle's `bundle_sha256`
  appears in the `InitiativeCreated` audit event, anchoring the bundle
  bytes into the tamper-evident chain.
- **`INV-VM-CAP-03`** (OCI image-digest pinning) — covers the bytes
  inside the operator's Executor VM image, complementing Plan Bundle
  Sealing's coverage of the bytes outside the VM. Together they
  constitute end-to-end byte-level supply-chain integrity for the
  operator's intent.
- **`INV-POLICY-01`** (policy authority precedence) — bundle size caps
  are policy-configurable per §7.4; the policy layer's authority over
  bundle limits is exactly the same as its authority over every other
  per-initiative resource constraint.
