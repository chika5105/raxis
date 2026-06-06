# RAXIS V2 — Release and Distribution Specification

> **Status:** V2 live release contract. This file is the canonical home
> for the RAXIS release pipeline, the operator install UX
> (`brew install raxis`), the macOS notarization story, the
> trust-anchor-population path, and the local-build signing flow that
> lets developers run a self-trusted kernel + image stack without
> touching the production keys.
>
> **Cross-references:**
>
> - [`planner-harness.md §14.4`](planner-harness.md) — image-build pipeline (the producer
>   side of the artefacts this spec consumes).
> - [`system-requirements.md §1`](system-requirements.md), §11 — install-dir layout and
>   `raxis doctor` checks.
> - `canonical-images/build.rs` — the build-script implementation
>   that bakes the trust anchor + V1-fallback image digests into the
>   kernel binary.
> - `architectural-tensions.md §...` — the original distribution
>   tension this spec resolves.
> - [`v2-deep-spec.md §Distribution`](v2-deep-spec.md) — the two-line normative seed
>   that authorised this work (`brew install raxis` /
>   notarized AVF execution).

---

## §1 — Why a standalone spec

The original V2 distribution direction was a two-line statement in
[`v2-deep-spec.md`](v2-deep-spec.md):

> The `raxis-planner` binary and the kernel must support notarized
> AVF execution, distributed via `brew` (`chika5105/raxis/raxis`). A
> single `brew install raxis` brings the complete stack.

That seed elides every concrete decision an implementation needs:
the formula structure, how images are fetched (resource block vs
post-install vs separate cask), the bottle strategy across
`arm64-darwin` / `x86_64-darwin` / `arm64-linux` / `x86_64-linux`,
how the kernel signing key reaches `cargo build` in CI without ever
materialising on disk on the build machine, what notarization
covers and what it does not, and how a developer on their own
laptop builds a self-trusted stack without the production keys.

This spec is normative for all of those decisions. Where any earlier
prose conflicts with anything written here, this spec wins.

## §1.1 — Current Public Release Contract

The public install target is:

```bash
brew tap chika5105/raxis
brew install raxis
brew services start raxis
```

That tap command maps to the GitHub repository
`chika5105/homebrew-raxis`. The release workflow can target a different
tap repository by setting the `HOMEBREW_TAP_REPOSITORY` repository
variable, but the default must remain compatible with the command above.

Each published runtime archive is a **complete runtime bundle** for one
host `(os, arch)`. The Homebrew bottles are generated from these same
complete runtime archives and re-laid into Homebrew's
`raxis/<version>/...` cellar shape:

```text
raxis-<version>-<os>-<arch>.tar.gz
  bin/raxis
  bin/raxis-cli
  bin/raxis-kernel
  bin/raxis-orchestrator
  bin/raxis-executor
  bin/raxis-reviewer
  bin/raxis-tproxy
  images/
    raxis-<canonical-role>-<version>.img
    raxis-<canonical-role>-<version>.manifest.toml
  kernel/
    vmlinux
    vmlinux.config
  share/raxis/policy.toml.example
```

The `images/` and `kernel/` directories are not optional in a release
tarball. A host-binary-only install can pass Homebrew download checks and
then fail later when the kernel tries to spawn a VM. The release workflow
therefore fails closed unless it can stage a guest runtime bundle for the
target architecture before creating the Homebrew bottle.

---

## §2 — Scope

In scope:

- Release-pipeline structure (GitHub Actions, tag-driven).
- Artefact taxonomy (binaries, canonical images, manifests,
  formula files).
- Apple notarization of the macOS Mach-O binaries, including the
  Virtualization.framework entitlement requirement.
- Homebrew tap layout and formula structure (single `raxis` formula).
- Trust-anchor population — the release workflow generates an
  Ed25519 image-signing keypair, signs manifests with the private
  half, and passes the public half through `RAXIS_KERNEL_SIGNING_KEY_HEX`
  into the shipped kernel binary.
- Local-build signing flow — how a developer who is NOT the RAXIS
  release authority runs a self-trusted kernel + image stack on
  their own laptop.
- `raxis doctor` install-time verification of every artefact the
  formula deposited.

Out of scope:

- Distro-native Linux packaging (apt / dnf / nix / Snap). Linux
  Homebrew is in scope and uses the same `raxis` formula as macOS.
- Auto-update behaviour beyond what `brew upgrade` already provides.
- `raxis-egress` packaging — covered in a separate distribution
  annex once its boundaries solidify.
- Codesigning of operator-published images (the operator owns that
  signing key, not the RAXIS project; this spec only covers the
  RAXIS-canonical images).

---

## §3 — Distribution channels (matrix)

| Channel                 | Audience                          | Trust anchor                                    | Status     |
| ----------------------- | --------------------------------- | ----------------------------------------------- | ---------- |
| `chika5105/homebrew-raxis` | macOS / Linux operators         | Per-release generated image-signing key         | LIVE TARGET |
| GitHub Releases         | Operators wanting raw archives    | Per-release generated image-signing key         | LIVE TARGET |
| `cargo build` (source)  | Developers, CI matrix runs        | Operator-supplied or all-zero placeholder       | LIVE       |
| Local-build self-trust  | Single-laptop hobbyist, CI fixtures| Developer-held keypair                          | DOCUMENTED |

The Homebrew tap is a thin formula that points at GitHub Release URLs
and pins their `sha256`. Raw runtime archives and Homebrew bottle
archives are both uploaded to the release page, so a lost or corrupted
tap can be reconstructed from release assets alone.

---

## §4 — Artefact taxonomy

A single tagged release on `github.com/chika5105/raxis` produces
the following artefacts. Every one of them is reproducible (same
inputs → byte-identical output) and every one of them carries an
integrity commitment that is enforceable at install / boot time
without any network access.

### §4.1 Complete runtime archives

For each `(os, arch)` row in the build matrix
(`darwin-arm64`, `darwin-x86_64`, `linux-x86_64`, `linux-arm64`),
one tarball:

```text
raxis-<version>-<os>-<arch>.tar.gz
  bin/raxis
  bin/raxis-kernel
  bin/raxis-cli
  bin/raxis-gateway
  bin/raxis-otel-pusher
  bin/raxis-supervisor
  bin/raxis-orchestrator
  bin/raxis-executor
  bin/raxis-reviewer
  bin/raxis-tproxy        (linux-only — macOS uses a stub)
  images/
  kernel/
  share/raxis/dashboard/
  share/raxis/policy.toml.example
  share/raxis/SBOM.spdx.json
```

* All `bin/*` Mach-O binaries on the macOS rows are signed with the
  RAXIS Apple Developer ID and notarized (§6).
* Linux integrity is enforced by the GitHub Release SHA-256 pinned in
  the Homebrew formula plus the manifest signatures inside `images/`.
  Detached Linux GPG signatures are a future additive channel, not a
  current release prerequisite.
* The kernel binary inside the tarball was built with the matching
  guest architecture's generated public image-signing key in
  `RAXIS_KERNEL_SIGNING_KEY_HEX`, plus per-role image digest env vars
  computed from the exact guest images shipped in that tarball (§5.3,
  §7.1).
* The gateway, telemetry pusher, supervisor, role binaries, and
  `raxis-tproxy` are duplicated into each tarball rather than
  relegated to separate dependencies. This is a deliberate trade-off:
  it makes a single tarball self-installable (no second download
  needed) at the cost of some duplicated binary bytes when an operator
  installs both kernel and CLI on the same machine. Homebrew's
  `link_overwrite` keyword reconciles the duplicate `bin/`
  entries; raw-tarball users overwrite once and move on.

### §4.2 Guest runtime bundles

The release workflow builds two guest runtime bundles, one per guest
architecture:

```text
raxis-guest-arm64.tar.gz
  images/
  kernel/

raxis-guest-x86_64.tar.gz
  images/
  kernel/
```

Each guest runtime bundle is built with `cargo xtask images bake
--target <linux-musl-triple>` and contains every canonical role image,
its signed `.manifest.toml`, `kernel/vmlinux`, and
`kernel/vmlinux.config`. The tagged workflow generates a release-local
Ed25519 keypair during each architecture's build. The private half signs
that architecture's manifests and never leaves the guest-runtime job;
the public half is exposed through metadata outputs and baked into
matching host kernels as `EXPECTED_KERNEL_SIGNING_KEY_BYTES` (per
`canonical-images/src/lib.rs`).

### §4.3 Per-artefact integrity commitments

Every artefact in §4.1 / §4.2 is uploaded to the GitHub Release
together with:

* A `sha256` sum (printed on the release page; embedded into the
  Homebrew formula for bottle and source-fallback URLs).
* macOS notarization accepted by Apple and verified by Gatekeeper
  assessment for each signed Mach-O binary.

The Homebrew formula consumes the `sha256` sum, not the signature.
Homebrew's preferred path is a bottle archive tagged for the operator's
OS/arch, for example `arm64_tahoe`, `arm64_sequoia`, `arm64_sonoma`,
or `x86_64_linux`. Source-fallback URLs point at the complete runtime
archives. The signature is for raw-archive users and for `raxis doctor`
post-install audits (§9.3).

---

## §5 — Release pipeline (GitHub Actions)

### §5.1 Trigger model

Two workflows live under `.github/workflows/`:

| Workflow                     | Trigger                                      | Effect                                                 |
| ---------------------------- | -------------------------------------------- | ------------------------------------------------------ |
| `build-images.yml`           | every PR + push to `main`                    | Reproducibility check; **no signing**, **no upload**.  |
| `release.yml`                | tag push matching `v[0-9]+.[0-9]+.[0-9]+*`   | Full signed build, notarize, upload, tap-update when `RAXIS_RELEASE_ENABLED` is enabled. |
| `dashboard-release.yml`      | manual `workflow_dispatch`                   | Dashboard-only patch release; rebuilds no host binaries or guest images. |

The strict trigger separation means a contributor sending a PR
cannot cause anything signed-by-RAXIS to be produced. The release
secrets are not made available to workflows triggered by
`pull_request`.

`release.yml` also has a repository-variable safety gate:
`RAXIS_RELEASE_ENABLED` must be `1` or `true` before any build,
signing, notarization, upload, or Homebrew tap update job runs. This
lets the complete workflow live on `main` while first-run Apple
notarization is still unresolved.

### §5.2 Build matrix

| Job              | Runner          | Outputs                                         |
| ---------------- | --------------- | ----------------------------------------------- |
| `build-dashboard` | `ubuntu-22.04` | Vite-built dashboard frontend bundle            |
| `build-darwin`   | `macos-26`, `macos-15`, `macos-14` | Tahoe, Sequoia, and Sonoma bottles for arm64 + x86_64 |
| `build-linux`    | `ubuntu-22.04`  | `linux-x86_64` + `linux-arm64` (cross via target)   |
| `build-images`   | `ubuntu-22.04`  | Fan-out guest runtime bundles for `arm64` and `x86_64`: Raxis-built Linux guest kernel, signed canonical images, and metadata artifacts |
| `collect-image-metadata` | `ubuntu-22.04` | Public trust anchors and per-role digest outputs for host builds |
| `notarize`       | matching macOS runner | Notarized darwin bottles and Tahoe raw tarballs |
| `publish`        | `ubuntu-22.04`  | Upload raw archives + bottles to GitHub Releases; push tap |

The `build-dashboard` job is OS-agnostic: it runs `npm ci` and the
Vite production build once, packages `dashboard-fe/dist/` as the
`raxis-dashboard-fe` artifact, and fans that artifact into every
`build-linux` / `build-darwin` matrix row.

The `build-images` job is OS-agnostic and fans out by guest
architecture. Each matrix row builds a pinned Cloud Hypervisor Linux
guest kernel, merges `images/kernel/raxis-guest-a3-netfilter.config`,
bakes the signed canonical initramfs images, and uploads both the
runtime bundle and a small metadata artifact. `collect-image-metadata`
turns those metadata artifacts into stable job outputs for host builds.
We pin both jobs to Ubuntu so the kernel/image toolchain and resulting
bytes are stable across release cuts.

### §5.3 Signing inputs

GitHub secrets the release system consumes:

| Secret                                              | Format                                         | Source                            |
| --------------------------------------------------- | ---------------------------------------------- | --------------------------------- |
| `APPLE_DEVELOPER_ID_APPLICATION_P12`                | base64 of a `.p12` codesigning bundle          | Apple Developer account           |
| `APPLE_DEVELOPER_ID_APPLICATION_PASSWORD`           | password for the `.p12`                        | Apple Developer account           |
| `APPLE_NOTARIZATION_API_KEY_ID`, `_ISSUER_ID`, `_KEY_P8` | App Store Connect API credentials         | Apple Developer account           |
| `HOMEBREW_TAP_DEPLOY_KEY`                           | SSH private key for the tap repo               | RAXIS bot account                 |

Repository variables the release workflow consumes:

| Variable | Format | Purpose |
| --- | --- | --- |
| `RAXIS_RELEASE_ENABLED` | `0` / `1` or `false` / `true` | Safety gate; defaults disabled. |
| `HOMEBREW_TAP_REPOSITORY` | `owner/repo` | Optional; defaults to `chika5105/homebrew-raxis`. |
| `APPLE_NOTARIZATION_TIMEOUT` | notarytool duration, e.g. `30m` or `90m` | Optional; defaults to `30m`. |

Three principles govern this list:

1. **The kernel signing keypairs are release-local.** Each
   architecture's guest-runtime job generates an Ed25519 keypair with
   `cargo xtask images bake`. The private half signs that
   architecture's `.manifest.toml` files and never leaves that job. The
   public half is emitted as `RAXIS_KERNEL_SIGNING_KEY_HEX` for host
   kernel builds of the same architecture, where `build.rs` bakes it
   into `EXPECTED_KERNEL_SIGNING_KEY_BYTES`.
2. **No long-lived secret is persisted.** Apple signing material is
   imported into a transient keychain that is deleted at job end. The
   Homebrew deploy key is written to `~/.ssh` only for the tap push. No
   secret or release image-signing private key is uploaded as a release
   artifact.
3. **Guest bundles are built before packaging.** The tag workflow
   refuses to package host binaries unless the architecture-specific
   guest runtime bundle exists and contains `images/` and
   `kernel/vmlinux`.

### §5.4 Notarization gate

The `notarize` job:

1. Imports `APPLE_DEVELOPER_ID_APPLICATION_P12` into a transient
   keychain (deleted at job end).
2. Runs `codesign --force --options runtime --sign "Developer ID
   Application: …" --entitlements raxis.entitlements
   bin/raxis-kernel` (and similarly for every Mach-O binary).
3. Submits a `.zip` containing the signed binaries to Apple via
   `xcrun notarytool submit --wait`. The wait timeout defaults to
   30 minutes and can be overridden with `APPLE_NOTARIZATION_TIMEOUT`.
4. Skips stapling for raw command-line Mach-O files: Apple's
   `stapler` supports UDIF disk images, signed executable bundles,
   and flat installer packages, not individual CLI binaries. The
   self-test verifies a strict Developer ID signature and checks the
   notarization ticket with Gatekeeper's install assessment path.
5. Re-tarballs the notarized binaries and exports the
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

1. Computes `sha256` of every raw runtime archive and Homebrew bottle.
2. Renders `Formula/raxis.rb` from
   `release/templates/raxis.rb.tmpl` substituting in the release
   version, the four source-fallback `(os, arch)` URLs, the bottle
   root URL, and every bottle `sha256`.
3. Pushes the regenerated formula to the configured tap repository
   (default `chika5105/homebrew-raxis`) via `HOMEBREW_TAP_DEPLOY_KEY`.

Tap pushes update the current formula file for the released version;
previous versions stay accessible via tag history on the tap repo, not
via separate formula files in `Formula/`.

### §5.6 Dashboard-only patch releases

Dashboard-only fixes are intentionally separated from the full release
train. A React/UI-only change must not force a rebuild of:

* host binaries,
* canonical guest images,
* guest Linux kernels,
* macOS code-signing and notarization outputs.

The `dashboard-release.yml` workflow is the middle-ground release path.
It takes a `base_version` (for example `v0.2.4`) and a Homebrew
`revision` integer. It then:

1. Builds only `dashboard-fe`.
2. Packages `dashboard-fe/dist` as a standalone
   `raxis-dashboard-fe-<base>-r<revision>.tar.gz` bundle with a small
   manifest.
3. Downloads the complete runtime archives and bottles from the base
   release.
4. Replaces only `share/raxis/dashboard` inside those archives.
5. Publishes the patched assets under
   `dashboard-<base_version>-r<revision>`.
6. Renders the Homebrew formula with the same core `version`, a
   `revision <N>` line, source-fallback URLs still pointing at the base
   full release, and bottle URLs pointing at the dashboard patch
   release.

This keeps Homebrew semantics clean: `brew upgrade raxis` can pick up a
UI-only fix through formula revision, while `raxis --version`, canonical
image trust anchors, and guest kernels remain tied to the base full
release.

For urgent local validation, operators may install a verified dashboard
bundle directly:

```bash
raxis dashboard install-bundle \
  --from-file raxis-dashboard-fe-local.tar.gz \
  --sha256 <64-hex>
```

The CLI verifies the archive digest, rejects unsafe tar entries, writes
the bundle under `<data_dir>/dashboard/releases/<sha256>/dist`, and
updates `<data_dir>/dashboard/current`. New kernel starts prefer that
data-dir bundle over the packaged static bundle. This is deliberately a
local operator action with an explicit hash pin; it does not silently
fetch or serve arbitrary dashboard JavaScript.

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

A self-built `cargo build --release -p raxis-kernel` therefore runs as
far as the first `Virtualization.framework` API call and then hangs /
panics unless the developer signs it locally with the required
entitlements. Operators who `brew install raxis` get a notarized binary
that satisfies all three gates and can spawn AVF guests immediately.

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
* `bin/raxis`
* `bin/raxis-cli`
* `bin/raxis-gateway`
* `bin/raxis-otel-pusher`
* `bin/raxis-supervisor`
* `bin/raxis-orchestrator`
* `bin/raxis-executor`
* `bin/raxis-reviewer`

`bin/raxis-tproxy` is **not** built on macOS — the transparent
proxy is Linux-only because it depends on `nfqueue` and Netfilter.
The macOS tarball ships a `bin/raxis-tproxy` stub binary that
prints "tproxy is Linux-only; the macOS kernel uses host-routed
egress" and exits with status 70 (the convention §6.5 of
[`vm-network-isolation.md`](vm-network-isolation.md) defines for "wrong host kernel").

### §6.4 Failure modes

The `notarize` job fails the entire release if:

| Failure                                     | Surface                                                          |
| ------------------------------------------- | ---------------------------------------------------------------- |
| Codesigning rejected (cert expired)         | `release.yml` red, no upload                                     |
| Notarization submission rejected (entitlement violation) | `release.yml` red, no upload                          |
| Notarization remains `In Progress` past timeout | `release.yml` red with submission id + `notarytool info/log` output |
| Notarized binary fails self-test            | `release.yml` red — see §6.5                                     |

### §6.5 Self-test

After notarization, the macOS runner verifies each Mach-O with
`codesign --verify --strict`, checks the signature authority and
hardened-runtime flag, then runs
`spctl --assess --type install -vv bin/raxis-kernel` and asserts the
output contains `accepted` and `Notarized Developer ID`. The install
assessment is intentional: `spctl --type exec` rejects raw command-line
Mach-O files as "not an app" even when Apple has accepted their
notarization.

---

## §7 — Trust-anchor pipeline

### §7.1 Production: release job output → build.rs → kernel binary

The trust anchor (the public half of the kernel signing keypair) is
generated by the matching guest-runtime build job and fed into same-arch
host builds via `RAXIS_KERNEL_SIGNING_KEY_HEX`. Sequence:

```text
guest-runtime arch job generated public key (32-byte hex)
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
non-hex chars) so a bad workflow output cannot silently degrade the
shipped kernel to "no trust anchor". A developer who sets the variable
wrong sees `cargo build` fail; an operator never sees the placeholder
branch in production.

### §7.2 Per-role image digests

`build.rs` reads `RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX` and
`RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX` the same way. The
verifier starter and verifier symbol-index digests follow the matching
`RAXIS_EXPECTED_VERIFIER_*` env vars. `lib.rs` aliases these generated
values to public V1-fallback constants. The V2 boot path uses the
manifest signature (which carries the canonical
`image_artefact_sha256`) and does NOT consult these constants; they
exist for `verify_canonical_image_pinned`, for `raxis doctor`
diagnostics, and as stable kind-tagged identifiers in audit-event
payloads.

The release pipeline computes image digests in the `build-images` arch
jobs and exports them via `collect-image-metadata` outputs consumed by
the kernel build jobs. The kernel binary therefore always carries digest
constants for the exact image bytes shipped in the same release.

### §7.3 Why we never check in private keys

The `build.rs` only reads PUBLIC inputs:

* The kernel signing key public half (32 bytes).
* The image SHA-256 digests.

The corresponding **secret half** of each signing keypair never enters
any kernel build. It is generated by `cargo xtask images bake` under
`.git/info/raxis-signing-key/sk.hex` on that architecture's
`build-images` runner, used to sign manifests in that same job, and then
discarded with the runner workspace. The only value crossing into host
build jobs is the public `pk.hex` string.

The image-builder process is the ONLY place in the pipeline where
the secret material lives in process memory, and it lives there
for the duration of the `Ed25519::sign` calls (one per role
manifest) before the process exits.

This separation is what lets the trust anchor be a public-input
build-time bake while the actual signing remains isolated to the
guest-runtime arch job. A compromised host `cargo build` on a release
runner cannot exfiltrate the signing key — the build doesn't have it.

---

## §8 — Local-build signing flow

This section is the developer-facing counterpart to §7. It
documents how a developer who is NOT the RAXIS release authority
runs a self-trusted kernel + image stack on their own machine, with
ergonomics that match the production pipeline (no manual `lib.rs`
edits, no checked-in zero-byte placeholders sneaking through).

### §8.1 One-time keypair generation

The recommended path uses the workspace's built-in helper:

```bash
cargo xtask dev-keys init
```

That command:

1. Creates `~/.config/raxis/keys/` (`0700`) if it does not exist.
2. Generates a fresh Ed25519 keypair using the OS RNG.
3. Writes the **private** half as 64 lowercase hex chars to
   `~/.config/raxis/keys/raxis-dev-signing.key.hex` at `0600`.
4. Writes the **public** half as 64 lowercase hex chars to
   `~/.config/raxis/keys/raxis-dev-signing.pub.hex` at `0644`.
5. Refuses to overwrite an existing keypair unless `--force` is
   passed (a developer who forgets they already generated one
   should not silently lose access to their previously-signed
   images).

The hex-file format matches what `raxis-image-builder` already
consumes via the `RAXIS_IMAGE_SIGNING_KEY` environment variable
(see `image-builder::main::load_signing_key`); we deliberately do
NOT use a PEM-wrapped PKCS#8 form, because:

* The image-builder verifier already speaks raw hex, so a PEM file
  would force `openssl pkey -in ... | tail -c 32 | xxd -p` round-
  trip plumbing the developer does not need.
* `RAXIS_KERNEL_SIGNING_KEY_HEX` (the kernel's `build.rs` input)
  also speaks raw hex, so a single file shape feeds both producer
  (image-builder) and consumer (kernel `build.rs`) sides.

A developer who insists on PEM (e.g. interop with an HSM that
exports PEM only) can run `openssl genpkey -algorithm ed25519 -out
raxis-dev-signing.pem` themselves, then derive the hex via
`openssl pkey -in raxis-dev-signing.pem -outform DER | tail -c 32
| xxd -p -c 64` for the private half and the matching `-pubout
-outform DER | tail -c 32 | xxd -p -c 64` for the public half.

### §8.2 Configure `cargo build` to bake the developer key

`cargo xtask dev-keys init` prints the exact recipe a developer
should add to their shell rc:

```bash
# One-time: drop a shell snippet your interactive shell sources.
cat >> ~/.config/raxis/dev-env <<'EOF'
export RAXIS_KERNEL_SIGNING_KEY_HEX="$(cat \
  ~/.config/raxis/keys/raxis-dev-signing.pub.hex)"
export RAXIS_IMAGE_SIGNING_KEY="$HOME/.config/raxis/keys/raxis-dev-signing.key.hex"
EOF
echo 'source ~/.config/raxis/dev-env' >> ~/.zshrc   # or .bashrc
```

Subsequent shells have both env vars set:

* `RAXIS_KERNEL_SIGNING_KEY_HEX` — read by
  `canonical-images/build.rs` to bake the developer's PUBLIC key
  as the kernel's compile-time trust anchor.
* `RAXIS_IMAGE_SIGNING_KEY` — read by
  `raxis-image-builder::load_signing_key` to load the developer's
  PRIVATE key for manifest signing.

```bash
cargo build --release -p raxis-kernel
# Kernel binary now trusts manifests signed by the developer's key.
```

A misconfigured shell that strips `RAXIS_KERNEL_SIGNING_KEY_HEX`
causes `cargo build` to fall back to the all-zero placeholder; the
kernel then refuses to verify any image manifest at boot,
surfacing `SigningKeyFpNotPopulated`. This is the desired
behaviour: a developer who forgot to source the env file sees a
loud failure the first time they try to spawn an agent VM, not a
silent "agent ran but with no trust anchor" success.

### §8.3 Sign images with the developer keypair

```bash
# After cargo build, build the canonical images using the
# matching PRIVATE half. raxis-image-builder writes
# <role>.manifest.toml signed by RAXIS_IMAGE_SIGNING_KEY.
cargo run -p raxis-image-builder -- \
  build reviewer \
  --inputs   ./images/reviewer-core/inputs.toml \
  --image-artefact ./out/reviewer-core.img \
  --out      ./out/reviewer-core.manifest.toml

cargo run -p raxis-image-builder -- \
  build orchestrator \
  --inputs   ./images/orchestrator-core/inputs.toml \
  --image-artefact ./out/orchestrator-core.img \
  --out      ./out/orchestrator-core.manifest.toml
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
brew tap chika5105/raxis
brew install raxis
brew services start raxis
```

The tap install pulls the formula repository; the formula install
downloads the platform-appropriate Homebrew bottle, verifies its
`sha256`, pours the complete runtime bundle, and lays out:

```text
$HOMEBREW_PREFIX/bin/raxis
$HOMEBREW_PREFIX/bin/raxis-kernel
$HOMEBREW_PREFIX/bin/raxis-cli
$HOMEBREW_PREFIX/bin/raxis-gateway
$HOMEBREW_PREFIX/bin/raxis-otel-pusher
$HOMEBREW_PREFIX/bin/raxis-supervisor
$HOMEBREW_PREFIX/bin/raxis-orchestrator
$HOMEBREW_PREFIX/bin/raxis-executor
$HOMEBREW_PREFIX/bin/raxis-reviewer
$HOMEBREW_PREFIX/bin/raxis-tproxy            (macOS uses a stub)
$HOMEBREW_PREFIX/share/raxis/images/
$HOMEBREW_PREFIX/share/raxis/kernel/vmlinux
$HOMEBREW_PREFIX/share/raxis/kernel/vmlinux.config
$HOMEBREW_PREFIX/share/raxis/dashboard/
$HOMEBREW_PREFIX/etc/raxis/policy.toml.example
```

The formula's service block launches `raxis-supervisor start`, sets
`PATH` to Homebrew's standard service path, sets `RAXIS_INSTALL_DIR`
to `$HOMEBREW_PREFIX/share/raxis`, sets `RAXIS_DATA_DIR` to
Homebrew's persistent `var/lib/raxis`, and sets
`RAXIS_SUPERVISOR_AUTO_RESTART=1` with
`RAXIS_SUPERVISOR_KERNEL_BINARY` pointing at the installed
`raxis-kernel`. The supervisor raises its own file-descriptor soft
limit before spawning the kernel because launchd user services
otherwise start below the kernel's production floor.

When a Homebrew-installed `raxis`, `raxis-kernel`, or
`raxis-supervisor` binary is run manually without `--data-dir` and
without `RAXIS_DATA_DIR`, it MUST infer the same persistent Homebrew
state directory from its executable path:
`$HOMEBREW_PREFIX/var/lib/raxis`. Source builds keep the developer
default of `~/.raxis`. This keeps `raxis credential ...`,
`raxis doctor`, the supervisor, and the long-running kernel pointed at
the same state store in production. `raxis doctor` and `raxis status`
MUST surface the detected install origin (`homebrew` or `source`) so
operators can confirm which binary family they are using.

The active tap formula and bottled Cellar formula must both contain this
full service block. Homebrew writes the installed plist or service unit
from the active formula during install, and later `brew services` runs
the generated keg service file when present. A tap-only formula edit
does not repair an already-poured keg service file. The release renderer
and bottle packager validate this service block before publishing.

When serving the operator dashboard frontend, the operator policy's
`[dashboard].static_dir` points at
`$HOMEBREW_PREFIX/share/raxis/dashboard`.

If `<data_dir>/dashboard/current/index.html` exists, the dashboard
server serves that data-dir bundle ahead of `[dashboard].static_dir`.
This is the fast UI patch override installed by
`raxis dashboard install-bundle`; it is scoped to the kernel data dir
and therefore to the operator's local installation, not to the immutable
Homebrew runtime bundle.

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
operator can `brew uninstall raxis && brew install raxis`
to re-pull and retry.

### §9.3 Upgrade

```bash
brew update            # refresh tap formula files
brew upgrade raxis
```

Old `share/raxis/images/<role>-<version>.img` files are deleted on
upgrade because they are kernel-version-locked (per
[`canonical-images.md`](canonical-images.md)); the tap formula always deposits the
images named with the new kernel version. Custom operator policy
under `$HOMEBREW_PREFIX/etc/raxis/` is **never** touched by upgrades.

### §9.4 Uninstall

```bash
brew uninstall raxis
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
  via separate workflows. The notarisation gate is macOS-only; Linux
  currently relies on the Homebrew/GitHub Release SHA-256 pins plus
  signed image manifests.
* **Auto-update beyond `brew upgrade`.** Out of scope for V2;
  reinvestigate after operator feedback.
* **Operator-published image registry.** Operator-built Executor
  / verifier images are pinned by `oci_digest` in `policy.toml` and
  pulled by the OCI image cache ([`image-cache.md`](image-cache.md)).
  Their distribution is not RAXIS's concern.
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
| `release/templates/raxis.rb.tmpl`                       | NEW        | Homebrew formula template for `raxis`                    |
| `release/scripts/render-formula.sh`                     | NEW        | Template renderer used by the `publish` job              |
| `release/scripts/notarize.sh`                           | NEW        | codesign + notarytool + Gatekeeper wrapper               |
| `xtask/src/release.rs`                                  | NEW        | Local helper: `cargo xtask release dry-run`              |
| `xtask/src/dev_keys.rs`                                 | NEW        | Local helper: `cargo xtask dev-keys init` (§8.1–§8.2)    |
| `cli/src/commands/doctor.rs`                            | MODIFY     | Add `signing-key-fp` subcommand (§9.2)                   |
| [`raxis/specs/v2/release-and-distribution.md`](release-and-distribution.md)            | THIS SPEC  | (you are here)                                            |
| Tap repo `chika5105/homebrew-raxis` initial commit      | NEW        | Tap bootstrap with first-version formula                 |

The implementation roadmap mirrors this list — each row is one
PR-sized iteration, ordered by dependency. The first three rows
(workflows + entitlements) unblock the rest; the `release/scripts/*`
follow; the formula templates and `xtask` helpers can land in any
order once the workflow shape is fixed.
