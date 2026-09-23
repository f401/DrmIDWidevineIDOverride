#!/usr/bin/env bash
# Build libdrmdaemon-hook.so (arm64) and install it into template/lib/.
#
#   ANDROID_NDK=/path/to/android-ndk ./build.sh
#
# The unstripped library is kept next to the source as
# src/main/cpp/libdrmdaemon-hook.so so that on-device tombstones can be
# symbolized with llvm-addr2line; the stripped one is what ships.
set -eu

API="${API:-26}"
NDK="${ANDROID_NDK:-${ANDROID_NDK_HOME:-}}"
[ -n "$NDK" ] || { echo "ERROR: set ANDROID_NDK (or ANDROID_NDK_HOME)" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
CPP="$HERE/src/main/cpp"
TC="$(echo "$NDK"/toolchains/llvm/prebuilt/* | tr ' ' '\n' | head -n1)"
[ -d "$TC" ] || { echo "ERROR: no llvm toolchain under $NDK/toolchains/llvm/prebuilt" >&2; exit 1; }

CXX="$TC/bin/aarch64-linux-android${API}-clang++"
STRIP="$TC/bin/llvm-strip"
[ -x "$CXX" ] || { echo "ERROR: $CXX not found" >&2; exit 1; }

echo "== toolchain: $TC"
echo "== api: $API"

# -static-libstdc++            bundle libc++_static (+ libc++abi): the target
#                              process has no libc++_shared.so, and a NEEDED on
#                              it makes Zygisk Next's dlopen fail silently.
# -Bsymbolic-functions         bind intra-library calls directly. Without it the
#   --exclude-libs,ALL         bundled libc++ members are WEAK exports, so every
#                              internal call goes through a PLT; the companion
#                              process (zn-companion64) does not bias those GOT
#                              slots and the module jumps to a link-time address.
# -z now                       resolve everything at load time (no lazy stubs).
"$CXX" -shared -fPIC -O2 -std=c++20 \
  -fno-exceptions -fno-rtti \
  -fvisibility=hidden -fvisibility-inlines-hidden \
  -ffunction-sections -fdata-sections \
  -Wall -Wextra -Wno-unused-parameter \
  -I"$CPP" \
  -o "$CPP/libdrmdaemon-hook.so" "$CPP/hook.cpp" \
  -static-libstdc++ \
  -Wl,-Bsymbolic-functions \
  -Wl,--exclude-libs,ALL \
  -Wl,-z,now -Wl,-z,relro \
  -Wl,--gc-sections \
  -Wl,-z,max-page-size=16384 \
  -llog -ldl -lpthread

# Keep an unstripped copy for symbolication, ship a stripped one.
"$STRIP" --strip-unneeded -o "$HERE/template/lib/libdrmdaemon-hook.so" "$CPP/libdrmdaemon-hook.so"

echo
echo "== self-check (template/lib/libdrmdaemon-hook.so)"
SO="$HERE/template/lib/libdrmdaemon-hook.so"
file "$SO" | grep -q 'ARM aarch64' && echo "  arch            OK"
echo "  NEEDED:         $(readelf -dW "$SO" | grep NEEDED | sed 's/.*\[\(.*\)\]/\1/' | tr '\n' ' ')"
readelf -dW "$SO" | grep -q BIND_NOW && echo "  BIND_NOW        OK"
for sym in zn_module zn_companion_module zygisk_companion_entry; do
  readelf --dyn-syms -W "$SO" | grep -q " $sym\$" && echo "  export $sym OK" \
    || { echo "  export $sym MISSING" >&2; exit 1; }
done
n=$(objdump -d "$SO" | grep '@plt>:' | grep -c 'St6__ndk1' || true)
[ "$n" = "0" ] && echo "  intra-lib PLT   0 (OK)" \
  || { echo "  intra-lib PLT   $n  <-- the companion will crash; check the link flags" >&2; exit 1; }
ls -l "$SO"
