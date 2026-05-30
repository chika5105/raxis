#!/bin/sh
# RAXIS Executor starter image — post-build verifier.
#
# Run by `raxis-image-builder build executor-starter`. The starter
# image is opt-in (planner-harness.md §10.6); this check ensures the
# generalist toolchain is intact rather than enforcing structural
# bans the way the Reviewer / Orchestrator verifiers do.

set -eu

ROOTFS="${1:?usage: verify.sh <rootfs-dir>}"

if [ ! -d "$ROOTFS" ]; then
    echo "verify: rootfs at $ROOTFS is not a directory" >&2
    exit 1
fi

# Required binaries: language toolchains.
for required in \
    "/usr/local/bin/raxis-planner-executor" \
    "/sbin/init" \
    "/bin/bash" \
    "/usr/bin/cargo" \
    "/usr/bin/cargo-clippy" \
    "/usr/bin/clippy-driver" \
    "/usr/bin/git" \
    "/usr/bin/curl" \
    "/usr/bin/rg" \
    "/usr/local/bin/fd" \
    "/usr/bin/wget" \
    "/usr/sbin/nft" \
    "/usr/bin/node" \
    "/usr/bin/python3" \
    "/usr/bin/rustc" \
    "/usr/bin/rustfmt" \
    "/usr/bin/make"; do
    if [ ! -e "$ROOTFS$required" ]; then
        echo "verify: missing required file $required" >&2
        exit 1
    fi
done

# INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01.
#
# The realistic-scenario `lint-runner-python` task (iter55 split)
# runs `python -m ruff check . && python -m ruff format --check .`
# inside an executor VM whose default egress allowlist is empty.
# `pip install ruff` at task time is structurally impossible
# (`INV-VM-EGRESS-01`), so the image MUST ship a `ruff` that is
# both on `$PATH` (as `/usr/local/bin/ruff`) and importable
# (`python -m ruff`). We assert both, plus that the pinned
# version matches the Containerfile pin so a silent transitive
# bump on a future pip layer doesn't go unnoticed.
RUFF_PINNED_VERSION="0.7.4"

if [ ! -e "$ROOTFS/usr/local/bin/ruff" ]; then
    echo "verify: missing /usr/local/bin/ruff (Python lint toolchain) — \
INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01 VIOLATED. Remediation: \
re-bake the executor-starter rootfs via \`cargo xtask images \
bake --role executor-starter\` against the current \
Containerfile, which pins ruff==$RUFF_PINNED_VERSION." >&2
    exit 1
fi

# Importability check: ruff must be reachable via `python -m ruff`,
# because the lint-runner-python task body uses exactly that
# invocation (NOT the standalone `ruff` binary). Run the importer
# under the rootfs as a sanity probe; we use `chroot`-style PATH
# manipulation but stay portable: invoke the rootfs's own python3
# with PYTHONHOME unset so it resolves its own site-packages.
#
# When the bake host is not Linux (macOS dev-host), the rootfs's
# python3 binary is ELF and cannot execute on the host. We fall
# back to a static-file check that asserts ruff's metadata file
# exists under one of the canonical site-packages roots; on a
# Linux host with a matching `dpkg --print-architecture` the
# dynamic check runs as a stronger witness.
HOST_OS="$(uname -s 2>/dev/null || echo unknown)"
case "$HOST_OS" in
    Linux)
        # Best-effort dynamic check: run the rootfs's python3 with
        # its own library paths. If the rootfs targets a different
        # arch than the host (cross-arch bake), this falls back to
        # the static check below — exec returns 126/127.
        if "$ROOTFS/usr/bin/python3" -c \
                "import ruff" >/dev/null 2>&1; then
            ACTUAL="$("$ROOTFS/usr/bin/python3" -m ruff --version \
                2>/dev/null | awk '{print $NF}')"
            if [ "$ACTUAL" != "$RUFF_PINNED_VERSION" ]; then
                echo "verify: ruff version drift — expected \
$RUFF_PINNED_VERSION, got '$ACTUAL'. \
INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01 VIOLATED." >&2
                exit 1
            fi
        fi
        ;;
    *)
        ;;
esac

# Static-file witness (works regardless of host arch). pip drops
# a dist-info dir for every wheel; we glob for ruff-<version>.
RUFF_DIST_GLOB="$(ls -d \
    "$ROOTFS/usr/lib/python3"*"/dist-packages/ruff-${RUFF_PINNED_VERSION}.dist-info" \
    "$ROOTFS/usr/local/lib/python3"*"/dist-packages/ruff-${RUFF_PINNED_VERSION}.dist-info" \
    2>/dev/null | head -n1)"
if [ -z "$RUFF_DIST_GLOB" ]; then
    echo "verify: ruff-$RUFF_PINNED_VERSION.dist-info not found under \
any python3 site-packages root in $ROOTFS — \
INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01 VIOLATED. Remediation: \
re-bake the executor-starter rootfs via \`cargo xtask images \
bake --role executor-starter\`; the Containerfile pins \
ruff==$RUFF_PINNED_VERSION via pip3 --break-system-packages." >&2
    exit 1
fi

# INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01.
#
# Parity with the Python toolchain block: the realistic-scenario
# `lint-runner-js` task runs `npx --no-install eslint` /
# `prettier` / `tsc` against the seed's `ts-pkg/` directory. The
# seed materializer ships no `node_modules/`, and the VM has no
# default egress, so the binaries MUST resolve from the image's
# global npm root (`/usr/lib/node_modules/<pkg>` with symlinks
# in `/usr/bin/` or `/usr/local/bin/`).
for js_pkg in eslint prettier typescript tsx @typescript-eslint/parser; do
    found=""
    for root in usr/lib/node_modules usr/local/lib/node_modules; do
        if [ -d "$ROOTFS/$root/$js_pkg" ]; then
            found="$root/$js_pkg"
            break
        fi
    done
    if [ -z "$found" ]; then
        echo "verify: missing global node_modules/$js_pkg under \
either /usr/lib/node_modules/ or /usr/local/lib/node_modules/ — \
INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 VIOLATED. Remediation: \
re-bake the executor-starter rootfs; the Containerfile pins \
eslint@9.15.0, prettier@3.3.3, typescript@5.6.3, tsx@4.19.2, \
@typescript-eslint/parser@8.15.0." >&2
        exit 1
    fi
done

# The CLI shims (eslint / prettier / tsc) must be on $PATH so that
# `npx --no-install <cmd>` falls through to the $PATH lookup the
# task body relies on. npm install -g symlinks them under
# `/usr/bin/` or `/usr/local/bin/`; we accept either.
for js_bin in eslint prettier tsc; do
    if [ ! -e "$ROOTFS/usr/bin/$js_bin" ] \
        && [ ! -e "$ROOTFS/usr/local/bin/$js_bin" ]; then
        echo "verify: missing /usr/bin/$js_bin and \
/usr/local/bin/$js_bin — INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 \
VIOLATED (npx --no-install $js_bin will fail at task time)." >&2
        exit 1
    fi
done

# INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-RUST-01.
#
# The realistic-scenario `lint-runner-rust` task invokes the standard
# Cargo subcommands (`cargo fmt --check`, `cargo clippy ...`). The
# image intentionally uses Debian's distro packages here instead of
# rustup: rustup's full toolchain tree made the initramfs exceed the
# guest boot envelope, so executor VMs panicked before planner vsock
# could bind. The required runtime contract is the binaries being on
# PATH, not the presence of rustup itself.
for rust_bin in cargo rustc rustfmt cargo-clippy clippy-driver; do
    if [ ! -e "$ROOTFS/usr/bin/$rust_bin" ]; then
        echo "verify: missing /usr/bin/$rust_bin — \
INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-RUST-01 VIOLATED. Remediation: \
re-bake the executor-starter rootfs; the Containerfile installs \
the distro Rust packages rustc/cargo/rustfmt/rust-clippy." >&2
        exit 1
    fi
done

echo "verify: executor-starter rootfs at $ROOTFS passes structural checks"
