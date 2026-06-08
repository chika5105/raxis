#!/usr/bin/env bash
# replace-dashboard-in-bottle.sh — rebuild an existing Homebrew bottle
# with `share/raxis/dashboard` replaced by a dashboard bundle and,
# when `RAXIS_REVISION` is set, refresh the bottled `.brew/raxis.rb`
# from the current formula template.
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
cellar_version="$(basename "${cellar}")"
formula_version="${cellar_version%%_*}"

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

refresh_installed_formula() {
    local installed_formula="$1"
    local formula_version="$2"
    local revision="$3"
    local script_dir template revision_line tmp_formula
    local -a urls=()
    local -a shas=()

    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    template="${script_dir}/../templates/raxis.rb.tmpl"
    if [[ ! -f "${template}" ]]; then
        echo "replace-dashboard-in-bottle.sh: formula template not found: ${template}" >&2
        exit 66
    fi

    while IFS= read -r value; do
        urls+=("${value}")
    done < <(grep -E '^[[:space:]]*url "' "${installed_formula}" | sed -E 's/^[[:space:]]*url "([^"]+)".*$/\1/')
    while IFS= read -r value; do
        shas+=("${value}")
    done < <(grep -E '^[[:space:]]*sha256 "' "${installed_formula}" | sed -E 's/^[[:space:]]*sha256 "([^"]+)".*$/\1/')
    if [[ "${#urls[@]}" -ne 4 || "${#shas[@]}" -ne 4 ]]; then
        echo "replace-dashboard-in-bottle.sh: installed formula does not expose four platform urls and sha256s" >&2
        exit 65
    fi
    for sha in "${shas[@]}"; do
        if [[ ! "${sha}" =~ ^[0-9a-f]{64}$ ]]; then
            echo "replace-dashboard-in-bottle.sh: installed formula sha256 is not 64 lowercase hex chars: ${sha}" >&2
            exit 65
        fi
    done

    revision_line=""
    if [[ -n "${revision}" && "${revision}" != "0" ]]; then
        if [[ ! "${revision}" =~ ^[1-9][0-9]*$ ]]; then
            echo "replace-dashboard-in-bottle.sh: RAXIS_REVISION must be a positive integer when set" >&2
            exit 65
        fi
        revision_line="  revision ${revision}"
    fi

    tmp_formula="${installed_formula}.tmp"
    awk '
      /^[[:space:]]*bottle do$/ { in_bottle = 1; next }
      in_bottle && /^[[:space:]]*end$/ { in_bottle = 0; next }
      !in_bottle { print }
    ' "${template}" |
        sed \
            -e "s|@@RAXIS_VERSION@@|${formula_version}|g" \
            -e "s|@@RAXIS_REVISION_LINE@@|${revision_line}|g" \
            -e "s|@@RAXIS_DARWIN_ARM64_URL@@|${urls[0]}|g" \
            -e "s|@@RAXIS_DARWIN_X86_64_URL@@|${urls[1]}|g" \
            -e "s|@@RAXIS_LINUX_ARM64_URL@@|${urls[2]}|g" \
            -e "s|@@RAXIS_LINUX_X86_64_URL@@|${urls[3]}|g" \
            -e "s|@@RAXIS_DARWIN_ARM64_SHA256@@|${shas[0]}|g" \
            -e "s|@@RAXIS_DARWIN_X86_64_SHA256@@|${shas[1]}|g" \
            -e "s|@@RAXIS_LINUX_ARM64_SHA256@@|${shas[2]}|g" \
            -e "s|@@RAXIS_LINUX_X86_64_SHA256@@|${shas[3]}|g" \
        > "${tmp_formula}"
    if grep -Eq '@@[A-Z_]+@@' "${tmp_formula}"; then
        echo "replace-dashboard-in-bottle.sh: refreshed formula still contains template tokens" >&2
        grep -Eo '@@[A-Z_]+@@' "${tmp_formula}" | sort -u >&2
        exit 70
    fi
    ruby -c "${tmp_formula}" >/dev/null
    mv "${tmp_formula}" "${installed_formula}"
}

installed_formula="${cellar}/.brew/raxis.rb"
if [[ -n "${RAXIS_REVISION:-}" && -f "${installed_formula}" ]]; then
    if [[ ! "${RAXIS_REVISION}" =~ ^[1-9][0-9]*$ ]]; then
        echo "replace-dashboard-in-bottle.sh: RAXIS_REVISION must be a positive integer when set" >&2
        exit 65
    fi
    refresh_installed_formula "${installed_formula}" "${formula_version}" "${RAXIS_REVISION}"
    revised_cellar="${bottle_root}/raxis/${formula_version}_${RAXIS_REVISION}"
    if [[ "${cellar}" != "${revised_cellar}" ]]; then
        rm -rf "${revised_cellar}"
        mv "${cellar}" "${revised_cellar}"
        cellar="${revised_cellar}"
    fi
fi

out_name="$(basename "${bottle_archive}")"
if [[ -n "${RAXIS_REVISION:-}" ]]; then
    out_name="${out_name/raxis-${cellar_version}./raxis-${formula_version}_${RAXIS_REVISION}.}"
fi
out="${out_dir}/${out_name}"
tar -C "${bottle_root}" -czf "${out}" raxis
printf '%s\n' "${out}"
