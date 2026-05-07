#!/bin/sh
# RAXIS canonical Orchestrator image — post-build verifier.
#
# Run by `raxis-image-builder build orchestrator` after assembling
# the rootfs. Refuses to admit any image whose rootfs contains
# forbidden binaries.
#
# Normative reference: planner-harness.md §10.5 (image manifest) +
# §14.7 (raxis doctor canonical-images).

set -eu

ROOTFS="${1:?usage: verify.sh <rootfs-dir>}"

if [ ! -d "$ROOTFS" ]; then
    echo "verify: rootfs at $ROOTFS is not a directory" >&2
    exit 1
fi

# Required binaries (the kernel refuses to boot the VM without these).
for required in \
    "/sbin/init" \
    "/usr/local/bin/raxis-planner-orchestrator" \
    "/bin/bash" \
    "/bin/sh" \
    "/usr/bin/git" \
    "/usr/bin/rg" \
    "/etc/ssl/certs/ca-certificates.crt"; do
    if [ ! -e "$ROOTFS$required" ]; then
        echo "verify: missing required file $required" >&2
        exit 1
    fi
done

# Required POSIX coreutils (git's helper invocations rely on these).
for util in \
    "/usr/bin/cat" \
    "/usr/bin/head" \
    "/usr/bin/tail" \
    "/usr/bin/diff" \
    "/usr/bin/patch" \
    "/usr/bin/awk" \
    "/usr/bin/sed" \
    "/usr/bin/grep" \
    "/usr/bin/sort" \
    "/usr/bin/wc" \
    "/usr/bin/find" \
    "/usr/bin/xargs"; do
    if [ ! -e "$ROOTFS$util" ]; then
        echo "verify: missing coreutil $util" >&2
        exit 1
    fi
done

# Forbidden binaries (planner-harness.md §10.5 "Notably absent").
for forbidden in \
    "/usr/bin/python3" \
    "/usr/bin/node" \
    "/usr/bin/ruby" \
    "/usr/bin/perl" \
    "/usr/bin/lua" \
    "/usr/bin/rustc" \
    "/usr/bin/gcc" \
    "/usr/bin/clang" \
    "/usr/bin/tsc" \
    "/usr/bin/go" \
    "/usr/bin/npm" \
    "/usr/bin/cargo" \
    "/usr/bin/pip" \
    "/usr/bin/gem" \
    "/usr/bin/curl" \
    "/usr/bin/wget" \
    "/usr/bin/ssh" \
    "/usr/bin/nc" \
    "/usr/bin/vi" \
    "/usr/bin/nano" \
    "/usr/bin/emacs" \
    "/usr/bin/less" \
    "/usr/bin/make" \
    "/usr/bin/bazel" \
    "/usr/bin/meson" \
    "/usr/bin/ninja"; do
    if [ -e "$ROOTFS$forbidden" ]; then
        echo "verify: forbidden binary present: $forbidden" >&2
        exit 1
    fi
done

# Bash must NOT have `bg_*` style backgrounding paths. The harness
# build flag `--features=foreground-only-bash` is the structural
# guard; this is a post-build sanity check that the resulting binary
# does not link against any `bg_*` symbol exporters from
# `raxis-planner-tools`. The check is left to the
# `raxis-planner-orchestrator` build target's `cargo deny` lints; we
# only smoke-check the image structure here.

echo "verify: orchestrator-core rootfs at $ROOTFS passes structural checks"
