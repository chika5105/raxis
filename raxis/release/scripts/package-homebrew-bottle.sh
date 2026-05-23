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

if [[ -f "${pkg_dir}/share/raxis/policy.toml.example" ]]; then
    cp "${pkg_dir}/share/raxis/policy.toml.example" \
       "${cellar}/share/raxis/policy.toml.example"
fi

cat > "${cellar}/.brew/raxis.rb" <<EOF
class Raxis < Formula
  desc     "Runtime Attestation eXchange for Intelligent Systems"
  homepage "https://raxis.io"
  version  "${formula_version}"
  license  "SSPL-1.0"
end
EOF

out="${out_dir}/raxis-${formula_version}.${bottle_tag}.bottle.tar.gz"
tar -C "${bottle_root}" -czf "${out}" raxis
printf '%s\n' "${out}"
