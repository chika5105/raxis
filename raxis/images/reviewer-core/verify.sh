#!/bin/sh
# RAXIS canonical Reviewer image — post-build verifier.
#
# Run by `raxis-image-builder build reviewer` after assembling the
# rootfs and signing the manifest. Refuses to admit any image whose
# rootfs contains forbidden binaries.
#
# Normative reference: planner-harness.md §10.4 (image manifest) +
# §14.7 (raxis doctor canonical-images).

set -eu

ROOTFS="${1:?usage: verify.sh <rootfs-dir>}"

if [ ! -d "$ROOTFS" ]; then
    echo "verify: rootfs at $ROOTFS is not a directory" >&2
    exit 1
fi

# Required files (absence is FAIL_REVIEWER_IMAGE_INVALID).
for required in \
    "/sbin/init" \
    "/usr/local/bin/raxis-planner-reviewer" \
    "/usr/bin/rg"; do
    if [ ! -e "$ROOTFS$required" ]; then
        echo "verify: missing required file $required" >&2
        exit 1
    fi
done

# Forbidden files (presence is FAIL_REVIEWER_IMAGE_INVALID).
for forbidden in \
    "/bin/sh" \
    "/bin/bash" \
    "/bin/dash" \
    "/bin/zsh" \
    "/usr/bin/busybox" \
    "/usr/bin/git" \
    "/usr/bin/curl" \
    "/usr/bin/wget" \
    "/usr/bin/ssh" \
    "/usr/bin/nc" \
    "/usr/bin/python3" \
    "/usr/bin/node" \
    "/usr/bin/ruby" \
    "/usr/bin/rustc" \
    "/usr/bin/gcc" \
    "/usr/bin/clang" \
    "/usr/bin/make" \
    "/usr/bin/vi" \
    "/usr/bin/nano" \
    "/usr/bin/emacs" \
    "/usr/bin/less"; do
    if [ -e "$ROOTFS$forbidden" ]; then
        echo "verify: forbidden file present: $forbidden" >&2
        exit 1
    fi
done

# `/sbin/init` must be a regular file (the spec calls for a static
# executable; symlinks are explicitly disallowed because the manifest
# walker rejects them).
if [ -L "$ROOTFS/sbin/init" ]; then
    echo "verify: /sbin/init must be a regular file, not a symlink" >&2
    exit 1
fi

echo "verify: reviewer-core rootfs at $ROOTFS passes structural checks"
