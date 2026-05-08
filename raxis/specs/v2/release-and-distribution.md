# RAXIS V2 — Release and Distribution Specification

> **Status:** V2 Draft. This file is the canonical home for the
> RAXIS release pipeline, the operator install UX (Homebrew tap), the
> macOS notarization story, the trust-anchor-population path, and the
> local-build signing flow that lets developers run a self-trusted
> kernel + image stack without touching the production keys.
>
> **Cross-references:**
>
> - `planner-harness.md §14.4` — image-build pipeline (the producer
>   side of the artefacts this spec consumes).
> - `system-requirements.md §1`, §11 — install-dir layout and
>   `raxis doctor` checks.
> - `canonical-images/build.rs` — the build-script implementation
>   that bakes the trust anchor + V1-fallback image digests into the
>   kernel binary.
> - `architectural-tensions.md §...` — the original distribution
>   tension this spec resolves.
> - `v2-deep-spec.md §Distribution` — the two-line normative seed
>   that authorised this work (`brew install raxis-kernel` /
>   notarized AVF execution).

---

## §1 — Why a standalone spec

The original V2 distribution direction was a two-line statement in
`v2-deep-spec.md`:

> The `raxis-planner` binary and the kernel must support notarized
> AVF execution, distributed via `brew` (`aegis-ai/tap/raxis`). The
> `raxis-kernel` formula depends on `raxis-planner` so that a single
> `brew install raxis-kernel` brings the complete stack.

That seed elides every concrete decision an implementation needs:
the formula structure, how images are fetched (resource block vs
post-install vs separate cask), the bottle strategy across
`arm64-darwin` / `x86_64-darwin` / `arm64-linux` / `x86_64-linux`,
how the kernel signing key reaches `cargo build` in CI without ever
materialising on disk on the build machine, what notarization
covers and what it does not, and how a developer on their own
laptop builds a self-trusted stack without the production keys.

This spec is normative for all of those decisions. Where any
earlier prose conflicts with anything written here, this spec wins.

---

## §2 — Scope

In scope:

- Release-pipeline structure (GitHub Actions, tag-driven).
- Artefact taxonomy (binaries, canonical images, manifests,
  formula files).
- Apple notarization of the macOS Mach-O binaries, including the
  Virtualization.framework entitlement requirement.
- Homebrew tap layout and formula structure (kernel, planner, CLI).
- Trust-anchor population — the build.rs path from
  `RAXIS_KERNEL_SIGNING_KEY_HEX` (and per-role image-digest
  variants) into the shipped kernel binary.
- Local-build signing flow — how a developer who is NOT the RAXIS
  release authority runs a self-trusted kernel + image stack on
  their own laptop.
- `raxis doctor` install-time verification of every artefact the
  formula deposited.

Out of scope:

- Linux-specific packaging (apt / dnf / nix / Snap). A future spec
  will cover those once the Homebrew path stabilises; the pieces
  here (signed manifests, build-pipeline-driven trust anchor) are
  package-manager-agnostic and reusable.
- Auto-update behaviour beyond what `brew upgrade` already provides.
- `raxis-egress` and `raxis-gateway` packaging — covered in a
  separate distribution annex once their boundaries solidify.
- Codesigning of operator-published images (the operator owns that
  signing key, not the RAXIS project; this spec only covers the
  RAXIS-canonical images).

---

## §3 — Distribution channels (matrix)

| Channel                 | Audience                          | Trust anchor                                    | Status     |
| ----------------------- | --------------------------------- | ----------------------------------------------- | ---------- |
| `aegis-ai/homebrew-tap` | macOS / Linux operators           | Production kernel signing key                   | TARGET     |
| GitHub Releases         | Operators wanting raw archives    | Production kernel signing key (same artefacts)  | TARGET     |
| `cargo build` (source)  | Developers, CI matrix runs        | Operator-supplied or all-zero placeholder       | LIVE       |
| Local-build self-trust  | Single-laptop hobbyist, CI fixtures| Developer-held keypair                          | DOCUMENTED |

The Homebrew tap and GitHub Releases ship the same byte-identical
artefacts; the tap is just a thin formula that points at release
URLs and pins their `sha256`. A lost or corrupted tap can be
reconstructed from the release pages alone.

---

## §4 — Artefact taxonomy

A single tagged release on `github.com/chika5105/aegis-ai` produces
the following artefacts. Every one of them is reproducible (same
inputs → byte-identical output) and every one of them carries an
integrity commitment that is enforceable at install / boot time
without any network access.

### §4.1 Native-binary archives

For each `(os, arch)` row in the build matrix
(`darwin-arm64`, `darwin-x86_64`, `linux-x86_64`, `linux-arm64`),
one tarball:

```
raxis-<version>-<os>-<arch>.tar.gz
  bin/raxis-kernel
  bin/raxis-cli
  bin/raxis-orchestrator
  bin/raxis-executor
  bin/raxis-reviewer
  bin/raxis-tproxy        (linux-only — macOS uses a stub)
  share/raxis/policy.toml.example
  share/raxis/SBOM.spdx.json
```

* All `bin/*` Mach-O binaries on the macOS rows are signed with the
  RAXIS Apple Developer ID and notarized (§6).
* All `bin/*` ELF binaries on the Linux rows are detached-signed
  with the RAXIS GPG release key (`.tar.gz.asc` sibling).
* The kernel binary inside the tarball was built with
  `RAXIS_KERNEL_SIGNING_KEY_HEX`, `RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX`,
  and `RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX` populated from
  GitHub Secrets (§5.3, §7.1).
* The four `bin/raxis-{orchestrator,executor,reviewer,tproxy}`
  binaries are duplicated into each tarball rather than relegated
  to a separate dependency. This is a deliberate trade-off: it
  makes a single tarball self-installable (no second download
  needed) at the cost of ~4× the binary bytes when an operator
  installs both kernel and CLI on the same machine. Homebrew's
  `link_overwrite` keyword reconciles the duplicate `bin/`
  entries; raw-tarball users overwrite once and move on.

### §4.2 Canonical-image archives

Three archives, one per role per release (kernel-version-locked):

```
raxis-reviewer-core-<version>.tar.gz
  reviewer-core.img
  reviewer-core.manifest.toml

raxis-orchestrator-core-<version>.tar.gz
  orchestrator-core.img
  orchestrator-core.manifest.toml

raxis-executor-starter-<version>.tar.gz
  executor-starter.img
  executor-starter.manifest.toml
```

Each manifest is signed by the kernel signing key (§7.1). The
shipped kernel binary's `EXPECTED_KERNEL_SIGNING_KEY_BYTES` will
verify these manifests at boot (per `canonical-images/src/lib.rs`).

### §4.3 Per-artefact integrity commitments

Every artefact in §4.1 / §4.2 is uploaded to the GitHub Release
together with:

* A `sha256` sum (printed on the release page; embedded into the
  Homebrew formula).
* A detached signature file (`.asc` for Linux GPG, the macOS
  notarization stapled into the binary's load commands).

The Homebrew formula consumes the `sha256` sum, not the signature
— Homebrew's own verification is `sha256` over the downloaded
tarball. The signature is for raw-archive users and for
`raxis doctor` post-install audits (§9.3).

---

## §5 — Release pipeline (GitHub Actions)

### §5.1 Trigger model

Two workflows live under `.github/workflows/`:

| Workflow                     | Trigger                                      | Effect                                                 |
| ---------------------------- | -------------------------------------------- | ------------------------------------------------------ |
| `build-images.yml`           | every PR + push to `main`                    | Reproducibility check; **no signing**, **no upload**.  |
| `release.yml`                | tag push matching `v[0-9]+.[0-9]+.[0-9]+*`   | Full signed build, notarize, upload, tap-update.       |

The strict trigger separation means a contributor sending a PR
cannot cause anything signed-by-RAXIS to be produced. The release
secrets are not made available to workflows triggered by
`pull_request`.

### §5.2 Build matrix

| Job              | Runner          | Outputs                                         |
| ---------------- | --------------- | ----------------------------------------------- |
| `build-darwin`   | `macos-14`      | `darwin-arm64` + `darwin-x86_64` (cross via target) |
| `build-linux`    | `ubuntu-22.04`  | `linux-x86_64` + `linux-arm64` (cross via target)   |
| `build-images`   | `ubuntu-22.04`  | The three canonical-image tarballs (deterministic)  |
| `notarize`       | `macos-14`      | Notarized + stapled darwin tarballs                 |
| `publish`        | `ubuntu-22.04`  | Upload to GitHub Releases + tap PR                  |

The `build-images` job is OS-agnostic — `mkfs.erofs`,
`SOURCE_DATE_EPOCH`, and the kernel signing key are the only
inputs. We pin it to Ubuntu so the EROFS bytes are stable across
release cuts.

### §5.3 Signing inputs

GitHub Secrets the release workflow consumes:

| Secret                                              | Format                                         | Source                            |
| --------------------------------------------------- | ---------------------------------------------- | --------------------------------- |
| `RAXIS_KERNEL_SIGNING_KEY_HEX`                      | 64 lowercase hex chars                         | Production HSM (release lead)     |
| `RAXIS_KERNEL_SIGNING_KEY_PRIV_PEM`                 | Ed25519 PEM                                    | Production HSM (release lead)     |
| `RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX`          | 64 lowercase hex chars                         | Computed by `build-images` job    |
| `RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX`      | 64 lowercase hex chars                         | Computed by `build-images` job    |
| `APPLE_DEVELOPER_ID_APPLICATION_P12`                | base64 of a `.p12` codesigning bundle          | Apple Developer account           |
| `APPLE_DEVELOPER_ID_APPLICATION_PASSWORD`           | password for the `.p12`                        | Apple Developer account           |
| `APPLE_NOTARIZATION_API_KEY_ID`, `_ISSUER_ID`, `_KEY_P8` | App Store Connect API credentials         | Apple Developer account           |
| `RAXIS_GPG_PRIVATE_KEY`                             | ASCII-armored secret key                       | Linux release lead                |
| `HOMEBREW_TAP_DEPLOY_KEY`                           | SSH private key for the tap repo               | RAXIS bot account                 |

Three principles govern this list:

1. **The kernel signing keypair is split.** The public half lives
   in `RAXIS_KERNEL_SIGNING_KEY_HEX` and is read by `build.rs` to
   bake `EXPECTED_KERNEL_SIGNING_KEY_BYTES` into the kernel binary.
   The private half lives in `RAXIS_KERNEL_SIGNING_KEY_PRIV_PEM`
   and is read by `raxis-image-builder --signing-key` to sign the
   three `<role>.manifest.toml` files. **The private half NEVER
   reaches the kernel build job** — the kernel job only gets the
   public hex; the manifest-signing job only gets the private PEM.
2. **No secret is materialised on disk.** Each secret is read from
   the GitHub Actions environment, used in-process, and never
   `echo`'d, never written to a workflow log, never persisted as
   an artefact. The `release.yml` workflow uses `mask: true` on
   every secret-handling step.
3. **The image-digest variables are computed mid-pipeline.** The
   `build-images` job runs first, computes the SHA-256 of the
   produced `.img` files, and exports them as `outputs.*` that
   downstream jobs pass to the kernel build via
   `RAXIS_EXPECTED_*_IMAGE_DIGEST_HEX`. This means the kernel
   binary always carries the digest of the exact image bytes
   shipped in the same release — they cannot drift.

### §5.4 Notarization gate

The `notarize` job:

1. Imports `APPLE_DEVELOPER_ID_APPLICATION_P12` into a transient
   keychain (deleted at job end).
2. Runs `codesign --force --options runtime --sign "Developer ID
   Application: …" --entitlements raxis.entitlements
   bin/raxis-kernel` (and similarly for every Mach-O binary).
3. Submits the signed binaries to Apple via `xcrun notarytool
   submit --wait`.
4. Staples the notarization ticket via `xcrun stapler staple`.
5. Re-tarballs the stapled binaries and exports the
   `darwin-{arm64,x86_64}.tar.gz` artefacts.

The entitlements file `release/raxis.entitlements` declares:

```xml
<key>com.apple.security.hypervisor</key><true/>
<key>com.apple.security.virtualization</key><true/>
<key>com.apple.security.network.client</key><true/>
<key>com.apple.security.network.server</key><true/>
```

These are the minimum entitlements `Virtualization.framework`
requires for a host process to call `VZVirtualMachine`'s start
APIs. Without notarization carrying these entitlements, the
kernel cannot spawn an AVF guest at all — the call returns
`-67050` (`errSecInternalError`) before any RAXIS code runs.

### §5.5 Tap update

After all artefacts upload, the `publish` job:

1. Computes `sha256` of every uploaded tarball.
2. Renders `Formula/raxis-kernel.rb` from
   `release/templates/raxis-kernel.rb.tmpl` substituting in the
   release version, the four `(os, arch)` URLs, and the four
   `sha256` values.
3. Renders `Formula/raxis-cli.rb` similarly.
4. Force-pushes the regenerated formulas to
   `chika5105/homebrew-tap` via the deploy key.

Tap pushes are **always force-pushes** of the formula files for the
released version; previous versions stay accessible via tag history
on the tap repo, not via separate formula files in `Formula/`. This
keeps the tap small (two files) and aligns with how
`homebrew-core` itself manages versioned formulas.

---

## §6 — Apple notarization (macOS)

### §6.1 Why required

`Virtualization.framework` (the host-side AVF API) refuses to
construct a `VZVirtualMachine` from a process that:

* lacks the `com.apple.security.hypervisor` entitlement, OR
* is signed with anything other than a Developer ID certificate
  carrying that entitlement, OR
* is run on macOS 13+ from outside `/Applications` /
  `~/Applications` while Gatekeeper is in its default
  `unsigned-executables-not-allowed` state.

A self-built `cargo build --release -p raxis-kernel` therefore runs
as far as the first `Virtualization.framework` API call and then
hangs / panics. Operators who `brew install raxis-kernel` get a
notarized binary that satisfies all three gates and can spawn AVF
guests immediately.

This is the single biggest reason RAXIS ships pre-built bottles on
macOS rather than telling operators to `cargo install`.

### §6.2 Apple Developer prerequisites

The RAXIS project holds:

1. An Apple Developer Program membership ($99/year) registered to
   the project's organisational entity. The membership is the only
   way to obtain a Developer ID Application certificate; ad-hoc
   `codesign --sign -` does not satisfy `com.apple.security.hypervisor`.
2. A Developer ID Application certificate exported as a
   `.p12` bundle. This is the secret material referenced as
   `APPLE_DEVELOPER_ID_APPLICATION_P12` in §5.3.
3. An App Store Connect API key (`.p8`) with the
   "Developer" role. `notarytool` reads this key to submit
   binaries; it never reads the `.p12` directly.

### §6.3 Per-binary notarization

The release pipeline notarises every Mach-O on the macOS rows:

* `bin/raxis-kernel`
* `bin/raxis-cli`
* `bin/raxis-orchestrator`
* `bin/raxis-executor`
* `bin/raxis-reviewer`

`bin/raxis-tproxy` is **not** built on macOS — the transparent
proxy is Linux-only because it depends on `nfqueue` and Netfilter.
The macOS tarball ships a `bin/raxis-tproxy` stub binary that
prints "tproxy is Linux-only; the macOS kernel uses host-routed
egress" and exits with status 70 (the convention §6.5 of
`vm-network-isolation.md` defines for "wrong host kernel").

### §6.4 Failure modes

The `notarize` job fails the entire release if:

| Failure                                     | Surface                                                          |
| ------------------------------------------- | ---------------------------------------------------------------- |
| Codesigning rejected (cert expired)         | `release.yml` red, no upload                                     |
| Notarization submission rejected (entitlement violation) | `release.yml` red, no upload                          |
| Staple step fails (Apple servers down)      | `release.yml` red, retry once after 5 min, then fail             |
| Notarized binary fails self-test            | `release.yml` red — see §6.5                                     |

### §6.5 Self-test

After notarization, the macOS runner executes the notarized binary
under Gatekeeper-strict (`spctl -a -t exec -vv bin/raxis-kernel`)
and asserts the output contains `accepted` and `Developer ID
Application: …`. This catches a notarisation that succeeded against
Apple's servers but does not actually pass the Gatekeeper that
operator laptops run.

---

## §7 — Trust-anchor pipeline

### §7.1 Production: GitHub Secret → build.rs → kernel binary

The trust anchor (the public half of the kernel signing keypair) is
fed into the build via `RAXIS_KERNEL_SIGNING_KEY_HEX`. Sequence:

```
GitHub Secret (32-byte hex)
   │
   ▼  (workflow `env:`)
RAXIS_KERNEL_SIGNING_KEY_HEX=…
   │
   ▼  (cargo build reads env)
canonical-images/build.rs
   │
   ▼  (decode_hex → [u8; 32])
$OUT_DIR/trust_anchor.rs
   │
   ▼  (include!())
canonical-images/src/lib.rs
   │
   ▼  (pub const)
EXPECTED_KERNEL_SIGNING_KEY_BYTES
   │
   ▼  (compiled into raxis-kernel)
shipped Mach-O / ELF
```

The `build.rs` rejects malformed input loudly (length mismatch,
non-hex chars) so a typo in the secret cannot silently degrade the
shipped kernel to "no trust anchor". A developer who sets the
variable wrong sees `cargo build` fail; an operator never sees
the placeholder branch in production.

### §7.2 Per-role image digests

`build.rs` reads `RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX` and
`RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX` the same way and
emits `GENERATED_REVIEWER_IMAGE_DIGEST` / `GENERATED_ORCHESTRATOR_IMAGE_DIGEST`,
which `lib.rs` aliases to the public V1-fallback constants
(`EXPECTED_REVIEWER_IMAGE_DIGEST` / `EXPECTED_ORCHESTRATOR_IMAGE_DIGEST`).
The V2 boot path uses the manifest signature (which carries the
canonical `image_artefact_sha256`) and does NOT consult these
constants; they exist for `verify_canonical_image_pinned`, for
`raxis doctor` diagnostics, and as stable kind-tagged identifiers
in audit-event payloads.

The release pipeline computes both image digests in the
`build-images` job and exports them as job outputs the kernel
build job consumes — the kernel binary therefore always carries
the digest of the exact image bytes shipped in the same release.

### §7.3 Why we never check in private keys

The `build.rs` only reads PUBLIC inputs:

* The kernel signing key public half (32 bytes).
* The image SHA-256 digests.

The corresponding **secret half** of the signing keypair never
enters any kernel build. It is materialised only in the manifest-
signing step and only on the `build-images` job, which:

1. Reads `RAXIS_KERNEL_SIGNING_KEY_PRIV_PEM` from the workflow
   environment.
2. Pipes it directly into `raxis-image-builder --signing-key /dev/stdin`.
3. Discards the file descriptor at job end.

The image-builder process is the ONLY place in the pipeline where
the secret material lives in process memory, and it lives there
for the duration of three `Ed25519::sign` calls (one per role
manifest) before the process exits.

This separation is what lets the trust anchor be a public-input
build-time bake while the actual signing remains a release-lead
operation. A compromised `cargo build` on a release runner cannot
exfiltrate the signing key — the build doesn't have it.

---

## §8 — Local-build signing flow

This section is the developer-facing counterpart to §7. It
documents how a developer who is NOT the RAXIS release authority
runs a self-trusted kernel + image stack on their own machine, with
ergonomics that match the production pipeline (no manual `lib.rs`
edits, no checked-in zero-byte placeholders sneaking through).

### §8.1 One-time keypair generation

```bash
# Pick a working directory OUTSIDE the repo. The signing key MUST
# never be checked in; placing it under `~/.config/raxis/keys/`
# keeps it out of the source tree by construction.
mkdir -p ~/.config/raxis/keys
cd      ~/.config/raxis/keys

# Generate an Ed25519 keypair. We use openssl rather than ssh-keygen
# because the PEM `-----BEGIN PRIVATE KEY-----` form is what
# `raxis-image-builder --signing-key` accepts.
openssl genpkey -algorithm ed25519 -out raxis-dev-signing.pem
chmod 0600                                  raxis-dev-signing.pem

# Extract the raw 32-byte public key half. The DER public-key
# encoding of an Ed25519 key is a 12-byte SPKI header followed by
# the raw key bytes; tail -c 32 strips the header.
openssl pkey -in raxis-dev-signing.pem -pubout -outform DER \
  | tail -c 32 \
  > raxis-dev-signing.pub
chmod 0644 raxis-dev-signing.pub
```

### §8.2 Configure `cargo build` to bake the developer key

```bash
# One-time: drop a shell snippet your interactive shell sources.
cat >> ~/.config/raxis/dev-env <<'EOF'
export RAXIS_KERNEL_SIGNING_KEY_HEX="$(xxd -p -c 64 \
  ~/.config/raxis/keys/raxis-dev-signing.pub)"
EOF
echo 'source ~/.config/raxis/dev-env' >> ~/.zshrc   # or .bashrc

# Subsequent shells now have the env var set; cargo build will
# bake the developer's public key as the kernel's trust anchor.
cargo build --release -p raxis-kernel
```

The `xxd -p -c 64` flag pair emits 64 hex chars on a single line
with no `:` separators — exactly the form `build.rs::decode_hex`
accepts. A misconfigured shell that strips the env var causes
`cargo build` to fall back to the all-zero placeholder; the kernel
then refuses to verify any image manifest at boot, surfacing
`SigningKeyFpNotPopulated`. This is the desired behaviour: a
developer who forgot to source the env file sees a loud failure
the first time they try to spawn an agent VM, not a silent
"agent ran but with no trust anchor" success.

### §8.3 Sign images with the developer keypair

```bash
# After cargo build, build the canonical images using the
# matching PRIVATE half. raxis-image-builder writes
# <role>.manifest.toml signed by --signing-key.
cargo run -p raxis-image-builder -- \
  build reviewer \
  --rootfs-dir   ./images/reviewer-core \
  --signing-key  ~/.config/raxis/keys/raxis-dev-signing.pem \
  --out-dir      ./out/images

cargo run -p raxis-image-builder -- \
  build orchestrator \
  --rootfs-dir   ./images/orchestrator-core \
  --signing-key  ~/.config/raxis/keys/raxis-dev-signing.pem \
  --out-dir      ./out/images
```

The kernel from §8.2 will accept these manifests because its
`EXPECTED_KERNEL_SIGNING_KEY_BYTES` constant equals the developer's
public key — the same trust chain as production, with the
developer in the release-authority role.

### §8.4 What the developer is now trusting

This flow makes the developer the **single source of trust** for
their RAXIS install. Anyone who installs the resulting kernel
binary implicitly trusts:

* Whatever images the developer signs with their private key.
* Whatever future kernel binaries the developer rebuilds (the trust
  anchor is hard-coded into each binary; rotating the keypair
  requires a kernel rebuild).

The security model is identical to production — the kernel
verifies a manifest signed by a key fingerprint baked at compile
time. The only thing that changes is whose key it is. Operators
who want the production guarantee install via Homebrew (§9); the
local-build flow exists for development, hobbyist self-hosting,
and CI fixtures.

---

## §9 — Operator install UX

### §9.1 First-install

```bash
brew tap     aegis-ai/raxis    git@github.com:chika5105/homebrew-tap
brew install raxis-kernel
```

The tap install pulls the formula repository; the formula install
downloads the platform-appropriate `raxis-<version>-<os>-<arch>.tar.gz`,
the three image archives (`raxis-{reviewer-core,orchestrator-core,executor-starter}-<version>.tar.gz`),
verifies every `sha256`, and lays out:

```
$HOMEBREW_PREFIX/bin/raxis-kernel
$HOMEBREW_PREFIX/bin/raxis-cli
$HOMEBREW_PREFIX/bin/raxis-orchestrator
$HOMEBREW_PREFIX/bin/raxis-executor
$HOMEBREW_PREFIX/bin/raxis-reviewer
$HOMEBREW_PREFIX/bin/raxis-tproxy            (linux-only via stub)
$HOMEBREW_PREFIX/share/raxis/images/reviewer-core-<version>.img
$HOMEBREW_PREFIX/share/raxis/images/reviewer-core-<version>.manifest.toml
$HOMEBREW_PREFIX/share/raxis/images/orchestrator-core-<version>.img
$HOMEBREW_PREFIX/share/raxis/images/orchestrator-core-<version>.manifest.toml
$HOMEBREW_PREFIX/share/raxis/images/executor-starter-<version>.img
$HOMEBREW_PREFIX/share/raxis/images/executor-starter-<version>.manifest.toml
$HOMEBREW_PREFIX/etc/raxis/policy.toml.example
```

`raxis-cli` is intentionally a separate formula whose only
dependency is `raxis-kernel` — operators who only need the CLI on
a machine that talks to a remote kernel can `brew install raxis-cli`
and get the binary without re-shipping the canonical images.

### §9.2 Post-install verification

The formula's `post_install` hook runs:

```bash
raxis doctor canonical-images
raxis doctor signing-key-fp
```

`raxis doctor canonical-images` confirms each `<role>.manifest.toml`
verifies against the kernel's compiled-in trust anchor and that the
on-disk `.img` matches the signed `image_artefact_sha256`. Failure
of either check during `post_install` aborts the install with a
diagnostic pointing at the artefact that did not verify; the
operator can `brew uninstall raxis-kernel && brew install raxis-kernel`
to re-pull and retry.

### §9.3 Upgrade

```bash
brew update            # refresh tap formula files
brew upgrade raxis-kernel
```

Old `share/raxis/images/<role>-<version>.img` files are deleted on
upgrade because they are kernel-version-locked (per
`canonical-images.md`); the tap formula always deposits the
images named with the new kernel version. Custom operator policy
under `$HOMEBREW_PREFIX/etc/raxis/` is **never** touched by upgrades.

### §9.4 Uninstall

```bash
brew uninstall raxis-kernel
brew uninstall raxis-cli
```

The formula's `caveats` block reminds the operator that
`$HOMEBREW_PREFIX/etc/raxis/`, `~/Library/Application Support/raxis/`
(macOS) and `~/.local/state/raxis/` (Linux) are NOT removed by
`brew uninstall` — they hold the SQLite store, audit chain, and
operator policy, all of which can be needed for forensics on a
machine after RAXIS is removed.

---

## §10 — Open issues / follow-ups

* **Linux distro packaging.** Once Homebrew is stable the same
  artefacts will feed Debian (`.deb`) and Fedora (`.rpm`) packages
  via separate workflows. The notarisation gate is macOS-only;
  Linux ships GPG-signed tarballs with no distro-side trust check
  required.
* **Auto-update beyond `brew upgrade`.** Out of scope for V2;
  reinvestigate after operator feedback.
* **Operator-published image registry.** Operator-built Executor
  / verifier images are pinned by `oci_digest` in `policy.toml` and
  pulled by the OCI image cache (`image-cache.md`, in flight at
  the time of writing). Their distribution is not RAXIS's concern.
* **`raxis-tproxy` macOS replacement.** A future iteration may
  ship a userspace shim that uses macOS's `pktap` / `pf` for the
  same egress-pinning role; tracked separately.

---

## §11 — Files to create / change

| File / dir                                              | Action     | Purpose                                                  |
| ------------------------------------------------------- | ---------- | -------------------------------------------------------- |
| `.github/workflows/build-images.yml`                    | NEW        | PR + main reproducibility check (no signing)             |
| `.github/workflows/release.yml`                         | NEW        | Tag-driven signed release pipeline (§5)                  |
| `release/raxis.entitlements`                            | NEW        | macOS Virtualization.framework entitlements (§6.3)       |
| `release/templates/raxis-kernel.rb.tmpl`                | NEW        | Homebrew formula template for `raxis-kernel`             |
| `release/templates/raxis-cli.rb.tmpl`                   | NEW        | Homebrew formula template for `raxis-cli`                |
| `release/scripts/render-formula.sh`                     | NEW        | Template renderer used by the `publish` job              |
| `release/scripts/notarize.sh`                           | NEW        | codesign + notarytool + staple wrapper                   |
| `xtask/src/release.rs`                                  | NEW        | Local helper: `cargo xtask release dry-run`              |
| `xtask/src/dev_keys.rs`                                 | NEW        | Local helper: `cargo xtask dev-keys init` (§8.1–§8.2)    |
| `cli/src/commands/doctor.rs`                            | MODIFY     | Add `signing-key-fp` subcommand (§9.2)                   |
| `raxis/specs/v2/release-and-distribution.md`            | THIS SPEC  | (you are here)                                            |
| Tap repo `chika5105/homebrew-tap` initial commit        | NEW        | Tap bootstrap with first-version formulas                |

The implementation roadmap mirrors this list — each row is one
PR-sized iteration, ordered by dependency. The first three rows
(workflows + entitlements) unblock the rest; the `release/scripts/*`
follow; the formula templates and `xtask` helpers can land in any
order once the workflow shape is fixed.


