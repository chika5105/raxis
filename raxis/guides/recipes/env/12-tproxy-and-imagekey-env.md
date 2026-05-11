# `RAXIS_TPROXY_KERNEL_TCP`, `RAXIS_IMAGE_*_KEY` — niche env vars

> **Topic:** Environment variables | **Time to read:** ~2 min | **Complexity:** ⭐⭐⭐⭐ Expert

This recipe collects the env vars that exist for narrow workflows:
the transparent egress proxy's kernel-host TCP override, and the
image-builder's signing-key paths. Operators rarely set these
directly; they appear in build pipelines, dev iterations on the
egress proxy, or kernel-internal builds.

---

## `RAXIS_TPROXY_KERNEL_TCP`

### Read by

- `raxis-tproxy` — the transparent egress proxy that the kernel
  injects into VM netfilter chains.

### Effect

The default behaviour: the tproxy connects back to the kernel via
the standard UDS path under `<data-dir>/sockets/`. When the
operator (or test harness) needs the tproxy to use TCP instead of
UDS for the kernel side, set:

```bash
export RAXIS_TPROXY_KERNEL_TCP="127.0.0.1:5555"
raxis-tproxy
```

The tproxy connects to `127.0.0.1:5555` instead of the UDS. The
kernel side must be listening there.

### When to use

- **Test harnesses** that exercise the tproxy without a UDS
  filesystem (e.g., a sandbox that can't mount a fresh UDS for
  every test).
- **Cross-host development** where the tproxy runs in a container
  and the kernel runs on the host's loopback.

### Format

`<host>:<port>`. The host can be a numeric IP or a DNS name; the
tproxy resolves at startup. Malformed values exit with
`tproxy: invalid RAXIS_TPROXY_KERNEL_TCP value`.

---

## `RAXIS_IMAGE_SIGNING_KEY` and `RAXIS_IMAGE_VERIFY_KEY`

### Read by

- `raxis-image-builder` — the local OCI-image build helper for
  operator-published `[[vm_images]]`.

### Effect

The image-builder computes a per-image signature so the kernel can
verify pulls against operator-known keys. These env vars provide
the signing / verifying key file paths.

| Variable | Effect |
|---|---|
| `RAXIS_IMAGE_SIGNING_KEY` | Path to the **private** key used to sign images. The image-builder reads it once per build. Mode `0600` enforced. |
| `RAXIS_IMAGE_VERIFY_KEY` | Path to the **public** key used to verify a signature. Used when the image-builder runs in verify-only mode against a remote registry. |

Set them as paths, not key bytes:

```bash
export RAXIS_IMAGE_SIGNING_KEY="$HOME/raxis-keys/image-signer.key"
export RAXIS_IMAGE_VERIFY_KEY="$HOME/raxis-keys/image-signer.pub"

raxis-image-builder build \
  --source ./Dockerfile \
  --tag rust-toolchain:2026-05 \
  --out  rust-toolchain-2026-05.tgz
```

The output tarball includes the OCI bundle plus a sidecar
signature; the kernel verifies the signature at pull time.

### When to use

- Operating a private registry with end-to-end signed images.
- Multi-tenant image distribution where the image-builder runs in
  CI but the verifying key lives on every tenant's kernel host.

---

## `RAXIS_KERNEL_SIGNING_KEY_HEX` and `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH`

### Read by

- `raxis-canonical-images` `build.rs` — at compile time, ONLY.

### Effect

These are **build-time** variables that the canonical-images crate
uses to seal a fixed signing key into the binary. They are not
runtime-configurable. The kernel verifies operator-published
images against this key (when matching the operator-side
signature scheme).

| Variable | Format | Effect |
|---|---|---|
| `RAXIS_KERNEL_SIGNING_KEY_HEX` | 64 lowercase hex chars | The full 32-byte Ed25519 seed inline. Used by canonical-image builds. |
| `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` | path | Absolute path to a 32-byte raw key file. Alternative to inline hex. |

If neither is set at build time, the canonical-images crate falls
back to an embedded developer key — usable for `cargo build` but
NOT for production images.

These are kernel-build-team workflow vars; you don't set them as
an operator.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `tproxy: invalid RAXIS_TPROXY_KERNEL_TCP value` | Format must be `<host>:<port>`. Don't include `tcp://` prefix. |
| `image-builder: signing key file not found` | Path doesn't exist. `ls -l "$RAXIS_IMAGE_SIGNING_KEY"`. |
| `image-builder: signing key file mode 0644` | `chmod 600 "$RAXIS_IMAGE_SIGNING_KEY"`. |
| Kernel rejects pulled image with `signature_verify_failed` | Either the verifying key in policy doesn't match the signing key used at build, OR the image was tampered with. Investigate. |
| `RAXIS_KERNEL_SIGNING_KEY_HEX` build-time error | Operating outside the canonical-images crate's build script; the var is build-only and ignored at runtime. |

---

## Reference

| Surface | Purpose |
|---|---|
| `crates/canonical-images/build.rs` | Reads `RAXIS_KERNEL_SIGNING_KEY_*` at compile time. |
| `crates/image-builder/src/main.rs` | Reads `RAXIS_IMAGE_*_KEY` at runtime. |
| `tproxy/src/main.rs` | Reads `RAXIS_TPROXY_KERNEL_TCP` at startup. |

---

## Variations

- **None of these in normal operation.** Operators running prod
  RAXIS rarely touch any of these.
- **Image-build CI.** A CI job that produces operator-published
  images sets `RAXIS_IMAGE_SIGNING_KEY` from a CI secret.
- **Local kernel hacking.** Developers building their own
  canonical-images set `RAXIS_KERNEL_SIGNING_KEY_HEX` to a known
  test seed.
