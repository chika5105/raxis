#!/usr/bin/env bash
# replace-dashboard-in-runtime.sh — produce a runtime archive with
# only the dashboard static bundle replaced. Native binaries, guest
# images, kernel, and policy examples are preserved byte-for-byte as
# extracted from the input archive.
#
# Usage:
#   replace-dashboard-in-runtime.sh <runtime-tar.gz> <dashboard-bundle.tar.gz> <out-dir>

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <runtime-tar.gz> <dashboard-bundle.tar.gz> <out-dir>" >&2
    exit 64
fi

runtime_archive="$1"
dashboard_bundle="$2"
out_dir="$3"

[[ -f "${runtime_archive}" ]] || { echo "runtime archive not found: ${runtime_archive}" >&2; exit 66; }
[[ -f "${dashboard_bundle}" ]] || { echo "dashboard bundle not found: ${dashboard_bundle}" >&2; exit 66; }

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

runtime_root="${work}/runtime"
bundle_root="${work}/bundle"
mkdir -p "${runtime_root}" "${bundle_root}" "${out_dir}"

tar -xzf "${runtime_archive}" -C "${runtime_root}"
pkg_dir="$(find "${runtime_root}" -mindepth 1 -maxdepth 1 -type d -name 'raxis-*' -print -quit)"
if [[ -z "${pkg_dir}" ]]; then
    echo "replace-dashboard-in-runtime.sh: archive has no raxis-* root dir" >&2
    exit 65
fi

tar -xzf "${dashboard_bundle}" -C "${bundle_root}"
if [[ -d "${bundle_root}/dist" && -f "${bundle_root}/dist/index.html" ]]; then
    dist_dir="${bundle_root}/dist"
else
    dist_dir="$(find "${bundle_root}" -mindepth 1 -maxdepth 3 -type f -name index.html -path '*/dist/index.html' -print -quit)"
    if [[ -z "${dist_dir}" ]]; then
        echo "replace-dashboard-in-runtime.sh: bundle has no dist/index.html" >&2
        exit 65
    fi
    dist_dir="$(dirname "${dist_dir}")"
fi

rm -rf "${pkg_dir}/share/raxis/dashboard"
mkdir -p "${pkg_dir}/share/raxis"
cp -R "${dist_dir}" "${pkg_dir}/share/raxis/dashboard"

out="${out_dir}/$(basename "${runtime_archive}")"
tar -C "${runtime_root}" -czf "${out}" "$(basename "${pkg_dir}")"
printf '%s\n' "${out}"
