#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: build-guest-kernel.sh --arch arm64|x86_64 --kernel-out PATH --config-out PATH [--workdir DIR]

Builds the Raxis Linux guest kernel used by release packages.

The source is pinned to the Cloud Hypervisor Linux branch commit named
by RAXIS_LINUX_KERNEL_COMMIT. The build starts from ch_defconfig,
merges images/kernel/raxis-guest-a3-netfilter.config, and writes the
resulting bootable kernel plus the exact .config used to build it.
EOF
}

arch=""
kernel_out=""
config_out=""
workdir="${RAXIS_KERNEL_BUILD_WORKDIR:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --arch)
      shift
      arch="${1:-}"
      ;;
    --kernel-out)
      shift
      kernel_out="${1:-}"
      ;;
    --config-out)
      shift
      config_out="${1:-}"
      ;;
    --workdir)
      shift
      workdir="${1:-}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
  shift
done

if [ -z "$arch" ] || [ -z "$kernel_out" ] || [ -z "$config_out" ]; then
  usage
  exit 2
fi

case "$arch" in
  arm64|aarch64)
    arch_key="arm64"
    kbuild_arch="arm64"
    cross_compile="aarch64-linux-gnu-"
    make_target="Image"
    kernel_rel="arch/arm64/boot/Image"
    ;;
  x86_64|amd64)
    arch_key="x86_64"
    kbuild_arch="x86"
    cross_compile=""
    make_target="vmlinux"
    kernel_rel="vmlinux"
    ;;
  *)
    echo "unsupported --arch $arch; expected arm64 or x86_64" >&2
    exit 2
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
raxis_dir="$(cd "${script_dir}/../.." && pwd)"
fragment="${RAXIS_KERNEL_CONFIG_FRAGMENT:-${raxis_dir}/images/kernel/raxis-guest-a3-netfilter.config}"
repo="${RAXIS_LINUX_KERNEL_REPO:-https://github.com/cloud-hypervisor/linux.git}"
commit="${RAXIS_LINUX_KERNEL_COMMIT:-46b5aab6f24a7e31a861d66dfe9b559b310a6c2d}"
jobs="${RAXIS_KERNEL_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"

if [ -z "$workdir" ]; then
  workdir="${RUNNER_TEMP:-/tmp}/raxis-linux-kernel-${arch_key}"
fi

src="${workdir}/src"
out="${workdir}/out-${arch_key}"

mkdir -p "$(dirname "$kernel_out")" "$(dirname "$config_out")" "$workdir"

if [ ! -d "${src}/.git" ]; then
  rm -rf "$src"
  git init "$src"
  git -C "$src" remote add origin "$repo"
fi

git -C "$src" fetch --depth 1 origin "$commit"
git -C "$src" checkout --force FETCH_HEAD
git -C "$src" clean -ffdx

rm -rf "$out"
mkdir -p "$out"

export KBUILD_BUILD_TIMESTAMP="${KBUILD_BUILD_TIMESTAMP:-1970-01-01 00:00:00 +0000}"
export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-raxis}"
export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-github-actions}"

make_args=(-C "$src" O="$out" ARCH="$kbuild_arch")
if [ -n "$cross_compile" ]; then
  make_args+=(CROSS_COMPILE="$cross_compile")
fi

make "${make_args[@]}" ch_defconfig
"${src}/scripts/kconfig/merge_config.sh" -O "$out" -m "$out/.config" "$fragment"

# Keep CI hosts from inheriting distro-local certificate/BTF settings
# that require files or tools outside the pinned source checkout.
"${src}/scripts/config" --file "$out/.config" \
  --set-str SYSTEM_TRUSTED_KEYS "" \
  --set-str SYSTEM_REVOCATION_KEYS "" \
  --disable DEBUG_INFO_BTF

make "${make_args[@]}" olddefconfig
make "${make_args[@]}" -j "$jobs" "$make_target"

install -m 0644 "${out}/${kernel_rel}" "$kernel_out"
install -m 0644 "${out}/.config" "$config_out"

printf 'Raxis guest kernel built: arch=%s kernel=%s config=%s\n' \
  "$arch_key" "$kernel_out" "$config_out"
