#!/usr/bin/env bash
# package-homebrew-bottle.sh — re-layout a complete RAXIS runtime
# archive into the bottle tarball shape Homebrew pours directly.
#
# Usage:
#   package-homebrew-bottle.sh <runtime-tar.gz> <formula-version> <bottle-tag> <out-dir>
#
# Example bottle tags:
#   arm64_tahoe, tahoe, arm64_linux, x86_64_linux

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <runtime-tar.gz> <formula-version> <bottle-tag> <out-dir>" >&2
    exit 64
fi

runtime_archive="$1"
formula_version="$2"
bottle_tag="$3"
out_dir="$4"

if [[ ! -f "${runtime_archive}" ]]; then
    echo "package-homebrew-bottle.sh: archive not found: ${runtime_archive}" >&2
    exit 66
fi

case "${bottle_tag}" in
    arm64_tahoe|tahoe|arm64_sequoia|sequoia|arm64_sonoma|sonoma|arm64_linux|x86_64_linux) ;;
    *)
        echo "package-homebrew-bottle.sh: unsupported bottle tag: ${bottle_tag}" >&2
        exit 64
        ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

src_root="${work}/src"
bottle_root="${work}/bottle"
mkdir -p "${src_root}" "${bottle_root}" "${out_dir}"

tar -xzf "${runtime_archive}" -C "${src_root}"
pkg_dir="$(find "${src_root}" -mindepth 1 -maxdepth 1 -type d -name 'raxis-*' -print -quit)"
if [[ -z "${pkg_dir}" ]]; then
    echo "package-homebrew-bottle.sh: runtime archive has no raxis-* root dir" >&2
    exit 65
fi

cellar="${bottle_root}/raxis/${formula_version}"
mkdir -p "${cellar}/bin" "${cellar}/share/raxis" "${cellar}/.brew"

cp -p "${pkg_dir}/bin/"* "${cellar}/bin/"
chmod 0755 "${cellar}/bin/"*
cp -R "${pkg_dir}/images" "${cellar}/share/raxis/images"
cp -R "${pkg_dir}/kernel" "${cellar}/share/raxis/kernel"

if [[ -d "${pkg_dir}/share/raxis/dashboard" ]]; then
    cp -R "${pkg_dir}/share/raxis/dashboard" "${cellar}/share/raxis/dashboard"
fi

if [[ -f "${pkg_dir}/share/raxis/install.sh" ]]; then
    cp "${pkg_dir}/share/raxis/install.sh" "${cellar}/share/raxis/install.sh"
    chmod 0755 "${cellar}/share/raxis/install.sh"
fi

if [[ -f "${pkg_dir}/share/raxis/policy.toml.example" ]]; then
    cp "${pkg_dir}/share/raxis/policy.toml.example" \
       "${cellar}/share/raxis/policy.toml.example"
fi

release_tag="v${formula_version}"
release_base_url="${RAXIS_RELEASE_BASE_URL:-https://github.com/chika5105/raxis/releases/download/${release_tag}}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="${script_dir}/../templates/raxis.rb.tmpl"
runtime_sha="$(shasum -a 256 "${runtime_archive}" | awk '{print $1}')"
placeholder_sha="0000000000000000000000000000000000000000000000000000000000000000"
darwin_arm64_sha="${placeholder_sha}"
darwin_x86_64_sha="${placeholder_sha}"
linux_arm64_sha="${placeholder_sha}"
linux_x86_64_sha="${placeholder_sha}"

case "${bottle_tag}" in
    arm64_tahoe|arm64_sequoia|arm64_sonoma)
        darwin_arm64_sha="${runtime_sha}"
        ;;
    tahoe|sequoia|sonoma)
        darwin_x86_64_sha="${runtime_sha}"
        ;;
    arm64_linux)
        linux_arm64_sha="${runtime_sha}"
        ;;
    x86_64_linux)
        linux_x86_64_sha="${runtime_sha}"
        ;;
esac

# Homebrew reloads the installed Cellar formula when running
# `brew postinstall` and `brew services`. A five-line metadata stub is
# not enough: the loader requires an active URL, and services/postinstall
# need the formula methods. The bottle copy omits the bottle block itself
# to avoid circular sha256s; only the active platform URL needs a real sha.
render_installed_formula() {
    awk '
      /^[[:space:]]*bottle do$/ { in_bottle = 1; next }
      in_bottle && /^[[:space:]]*end$/ { in_bottle = 0; next }
      !in_bottle { print }
    ' "${template}" |
        sed \
            -e "s|@@RAXIS_VERSION@@|${formula_version}|g" \
            -e "s|@@RAXIS_DARWIN_ARM64_URL@@|${release_base_url}/raxis-${release_tag}-darwin-arm64.tar.gz|g" \
            -e "s|@@RAXIS_DARWIN_X86_64_URL@@|${release_base_url}/raxis-${release_tag}-darwin-x86_64.tar.gz|g" \
            -e "s|@@RAXIS_LINUX_ARM64_URL@@|${release_base_url}/raxis-${release_tag}-linux-arm64.tar.gz|g" \
            -e "s|@@RAXIS_LINUX_X86_64_URL@@|${release_base_url}/raxis-${release_tag}-linux-x86_64.tar.gz|g" \
            -e "s|@@RAXIS_DARWIN_ARM64_SHA256@@|${darwin_arm64_sha}|g" \
            -e "s|@@RAXIS_DARWIN_X86_64_SHA256@@|${darwin_x86_64_sha}|g" \
            -e "s|@@RAXIS_LINUX_ARM64_SHA256@@|${linux_arm64_sha}|g" \
            -e "s|@@RAXIS_LINUX_X86_64_SHA256@@|${linux_x86_64_sha}|g"
}

installed_formula="${cellar}/.brew/raxis.rb"
render_installed_formula > "${installed_formula}"

if grep -Eq '@@[A-Z_]+@@' "${installed_formula}"; then
    echo "package-homebrew-bottle.sh: installed formula still contains template tokens" >&2
    grep -Eo '@@[A-Z_]+@@' "${installed_formula}" | sort -u >&2
    exit 70
fi

required_service_snippets=(
    'run [opt_bin/"raxis-supervisor", "start"]'
    'environment_variables PATH: std_service_path_env,'
    'RAXIS_DATA_DIR: (var/"lib/raxis").to_s,'
    'RAXIS_ENV: "default",'
    'RAXIS_SUPERVISOR_REQUIRE_INITIALIZED_DATA_DIR: "1",'
    'RAXIS_SUPERVISOR_KERNEL_BINARY: (opt_bin/"raxis-kernel").to_s'
)

for snippet in "${required_service_snippets[@]}"; do
    if ! grep -Fq "${snippet}" "${installed_formula}"; then
        echo "package-homebrew-bottle.sh: installed formula missing required service snippet: ${snippet}" >&2
        exit 70
    fi
done

out="${out_dir}/raxis-${formula_version}.${bottle_tag}.bottle.tar.gz"
tar -C "${bottle_root}" -czf "${out}" raxis
printf '%s\n' "${out}"
