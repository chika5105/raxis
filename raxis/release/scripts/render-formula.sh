#!/usr/bin/env bash
# render-formula.sh — populate a Homebrew formula template under
# release/templates/ with the per-release version + per-(os, arch)
# URL/sha256 sums.
#
# Normative reference: raxis/specs/v2/release-and-distribution.md
# §5.5 ("Tap update").
#
# Inputs (environment variables, ALL required):
#   RAXIS_VERSION
#   RAXIS_DARWIN_ARM64_URL          RAXIS_DARWIN_ARM64_SHA256
#   RAXIS_DARWIN_X86_64_URL         RAXIS_DARWIN_X86_64_SHA256
#   RAXIS_LINUX_ARM64_URL           RAXIS_LINUX_ARM64_SHA256
#   RAXIS_LINUX_X86_64_URL          RAXIS_LINUX_X86_64_SHA256
#
# Inputs only required when rendering raxis-kernel:
#   RAXIS_REVIEWER_IMG_URL          RAXIS_REVIEWER_IMG_SHA256
#   RAXIS_ORCHESTRATOR_IMG_URL      RAXIS_ORCHESTRATOR_IMG_SHA256
#   RAXIS_EXECUTOR_STARTER_IMG_URL  RAXIS_EXECUTOR_STARTER_IMG_SHA256
#
# Argument: formula name without `.rb.tmpl` extension. Either:
#   raxis
#   raxis-kernel
#   raxis-cli
#
# Output: writes the rendered formula to stdout. The
# release.yml `publish` job redirects this into
# `Formula/<name>.rb` in the tap repo.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    cat >&2 <<EOF
usage: $0 <formula-name>
  formula-name: raxis | raxis-kernel | raxis-cli
EOF
    exit 64
fi

formula_name="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="${script_dir}/../templates/${formula_name}.rb.tmpl"

if [[ ! -f "${template}" ]]; then
    echo "render-formula.sh: template not found: ${template}" >&2
    exit 66
fi

# Required-everywhere variables.
required_vars=(
    RAXIS_VERSION
    RAXIS_DARWIN_ARM64_URL    RAXIS_DARWIN_ARM64_SHA256
    RAXIS_DARWIN_X86_64_URL   RAXIS_DARWIN_X86_64_SHA256
    RAXIS_LINUX_ARM64_URL     RAXIS_LINUX_ARM64_SHA256
    RAXIS_LINUX_X86_64_URL    RAXIS_LINUX_X86_64_SHA256
)

# raxis-kernel additionally needs the three image-archive variables.
case "${formula_name}" in
    raxis)
        : # single complete bundle: binaries + canonical images + guest kernel
        ;;
    raxis-kernel)
        required_vars+=(
            RAXIS_REVIEWER_IMG_URL              RAXIS_REVIEWER_IMG_SHA256
            RAXIS_ORCHESTRATOR_IMG_URL          RAXIS_ORCHESTRATOR_IMG_SHA256
            RAXIS_EXECUTOR_STARTER_IMG_URL      RAXIS_EXECUTOR_STARTER_IMG_SHA256
        )
        ;;
    raxis-cli)
        : # no additional vars
        ;;
    *)
        echo "render-formula.sh: unsupported formula: ${formula_name}" >&2
        exit 64
        ;;
esac

for v in "${required_vars[@]}"; do
    if [[ -z "${!v:-}" ]]; then
        echo "render-formula.sh: required env var not set: ${v}" >&2
        exit 78
    fi
done

# Validate every sha256 input is exactly 64 lowercase hex chars.
# Catches a misconfigured CI step that pasted a placeholder string.
for v in "${required_vars[@]}"; do
    case "${v}" in
        *_SHA256)
            value="${!v}"
            if [[ ! "${value}" =~ ^[0-9a-f]{64}$ ]]; then
                echo "render-formula.sh: ${v} is not 64 lowercase hex chars: ${value}" >&2
                exit 65
            fi
            ;;
    esac
done

# Substitute. Each @@VAR@@ token in the template is replaced with
# the env var's value via sed. We use `|` as the sed delimiter
# because URLs contain `/`.
out="$(cat "${template}")"
for v in "${required_vars[@]}"; do
    value="${!v}"
    # Refuse a value that contains the sed delimiter — would
    # silently corrupt the rendered file.
    if [[ "${value}" == *"|"* ]]; then
        echo "render-formula.sh: ${v} contains '|' which is the sed delimiter; aborting" >&2
        exit 65
    fi
    out="$(printf '%s' "${out}" | sed "s|@@${v}@@|${value}|g")"
done

# Sanity check: the rendered output must NOT contain any unsubstituted
# @@…@@ tokens. A surviving token is an upstream-template bug we
# want to catch loudly here rather than ship.
if printf '%s' "${out}" | grep -q '@@[A-Z_]\+@@'; then
    echo "render-formula.sh: rendered output still contains unsubstituted tokens:" >&2
    printf '%s' "${out}" | grep -o '@@[A-Z_]\+@@' | sort -u >&2
    exit 70
fi

printf '%s\n' "${out}"
