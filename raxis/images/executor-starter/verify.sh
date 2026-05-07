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
    "/usr/bin/git" \
    "/usr/bin/curl" \
    "/usr/bin/wget" \
    "/usr/bin/node" \
    "/usr/bin/python3" \
    "/usr/bin/make"; do
    if [ ! -e "$ROOTFS$required" ]; then
        echo "verify: missing required file $required" >&2
        exit 1
    fi
done

echo "verify: executor-starter rootfs at $ROOTFS passes structural checks"
