#!/usr/bin/env bash
# replace-dashboard-in-bottle.sh — rebuild an existing Homebrew bottle
# with only `share/raxis/dashboard` replaced by a dashboard bundle.
#
# Usage:
#   replace-dashboard-in-bottle.sh <bottle.tar.gz> <dashboard-bundle.tar.gz> <out-dir>

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <bottle.tar.gz> <dashboard-bundle.tar.gz> <out-dir>" >&2
    exit 64
fi

bottle_archive="$1"
dashboard_bundle="$2"
out_dir="$3"

[[ -f "${bottle_archive}" ]] || { echo "bottle archive not found: ${bottle_archive}" >&2; exit 66; }
[[ -f "${dashboard_bundle}" ]] || { echo "dashboard bundle not found: ${dashboard_bundle}" >&2; exit 66; }

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

bottle_root="${work}/bottle"
bundle_root="${work}/bundle"
mkdir -p "${bottle_root}" "${bundle_root}" "${out_dir}"

tar -xzf "${bottle_archive}" -C "${bottle_root}"
cellar="$(find "${bottle_root}/raxis" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null || true)"
if [[ -z "${cellar}" ]]; then
    echo "replace-dashboard-in-bottle.sh: bottle has no raxis/<version> cellar root" >&2
    exit 65
fi

tar -xzf "${dashboard_bundle}" -C "${bundle_root}"
if [[ -d "${bundle_root}/dist" && -f "${bundle_root}/dist/index.html" ]]; then
    dist_dir="${bundle_root}/dist"
else
    dist_index="$(find "${bundle_root}" -mindepth 1 -maxdepth 3 -type f -name index.html -path '*/dist/index.html' -print -quit)"
    if [[ -z "${dist_index}" ]]; then
        echo "replace-dashboard-in-bottle.sh: bundle has no dist/index.html" >&2
        exit 65
    fi
    dist_dir="$(dirname "${dist_index}")"
fi

rm -rf "${cellar}/share/raxis/dashboard"
mkdir -p "${cellar}/share/raxis"
cp -R "${dist_dir}" "${cellar}/share/raxis/dashboard"

installed_formula="${cellar}/.brew/raxis.rb"
if [[ -n "${RAXIS_REVISION:-}" && -f "${installed_formula}" ]]; then
    if [[ ! "${RAXIS_REVISION}" =~ ^[1-9][0-9]*$ ]]; then
        echo "replace-dashboard-in-bottle.sh: RAXIS_REVISION must be a positive integer when set" >&2
        exit 65
    fi
    tmp_formula="${installed_formula}.tmp"
    awk -v revision="${RAXIS_REVISION}" '
      /^[[:space:]]*revision[[:space:]]+[0-9]+[[:space:]]*$/ { next }
      { print }
      /^[[:space:]]*version[[:space:]]+"/ {
        print "  revision " revision
      }
    ' "${installed_formula}" > "${tmp_formula}"
    mv "${tmp_formula}" "${installed_formula}"
fi

out="${out_dir}/$(basename "${bottle_archive}")"
tar -C "${bottle_root}" -czf "${out}" raxis
printf '%s\n' "${out}"
