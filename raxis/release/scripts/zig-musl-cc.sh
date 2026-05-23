#!/usr/bin/env bash
set -euo pipefail

target="${RAXIS_ZIG_MUSL_TARGET:-}"
if [ -z "$target" ]; then
  echo "RAXIS_ZIG_MUSL_TARGET is required, e.g. aarch64-linux-musl" >&2
  exit 2
fi

args=()
skip_next=0
for arg in "$@"; do
  if [ "$skip_next" -eq 1 ]; then
    skip_next=0
    continue
  fi

  case "$arg" in
    --target=*|-target=*)
      # cc-rs may forward the Rust target triple. Zig's spelling is
      # supplied explicitly below and rejects aarch64-unknown-linux-musl.
      continue
      ;;
    --target|-target)
      skip_next=1
      continue
      ;;
    -nostartfiles)
      # Rust's musl target passes its self-contained CRT objects. Zig's
      # musl driver also injects CRT startup objects, so keep one source
      # of truth by letting Zig provide them and dropping Rust's copies.
      continue
      ;;
    */lib/rustlib/*/lib/self-contained/crt*.o|*/lib/self-contained/crt*.o)
      continue
      ;;
  esac

  args+=("$arg")
done

exec zig cc -target "$target" "${args[@]}"
