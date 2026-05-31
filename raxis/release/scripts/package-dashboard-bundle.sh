#!/usr/bin/env bash
# package-dashboard-bundle.sh — package a Vite dashboard `dist/`
# directory as a standalone UI-only release bundle.
#
# Usage:
#   package-dashboard-bundle.sh <dist-dir> <version-or-label> <out-dir>

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <dist-dir> <version-or-label> <out-dir>" >&2
    exit 64
fi

dist_dir="$1"
label="$2"
out_dir="$3"

if [[ ! -f "${dist_dir}/index.html" ]]; then
    echo "package-dashboard-bundle.sh: ${dist_dir}/index.html not found" >&2
    exit 66
fi

mkdir -p "${out_dir}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

cp -R "${dist_dir}" "${work}/dist"

source_commit="${GITHUB_SHA:-}"
if [[ -z "${source_commit}" ]] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    source_commit="$(git rev-parse HEAD)"
fi
source_commit="${source_commit:-unknown}"
built_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

cat > "${work}/dashboard-bundle.json" <<EOF
{
  "kind": "raxis-dashboard-bundle",
  "version": "${label}",
  "source_commit": "${source_commit}",
  "built_at": "${built_at}",
  "root": "dist"
}
EOF

out="${out_dir}/raxis-dashboard-fe-${label}.tar.gz"
tar -C "${work}" -czf "${out}" dashboard-bundle.json dist
sha="$(shasum -a 256 "${out}" | awk '{print $1}')"
printf '%s  %s\n' "${sha}" "$(basename "${out}")" > "${out}.sha256"
printf '%s\n' "${out}"
