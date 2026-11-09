#!/usr/bin/env bash
# Builds the two native PQC shared libraries loaded by crypto_engine.py via ctypes:
#   libmlkem512.so : ML-KEM-512 (FIPS 203), mlkem-native v2.0.0
#   libmldsa44.so  : ML-DSA-44  (FIPS 204), mldsa-native v1.0.0-beta2
#
# Works OFFLINE: it compiles the C sources bundled in ../arduino_libraries/, with the
# same *_native_config.h the ESP32 firmware uses (parameter sets, REDUCE_RAM, ...).
# The only difference from the ESP32 build is randomness: host_shim/ provides
# esp_fill_random() from the operating system's CSPRNG instead of the ESP32 TRNG.
# So the laptop gateway and the ESP32 run exactly the same ML-KEM / ML-DSA code.
#
# Usage:  ./build_native_libs.sh          (needs a C compiler: cc / gcc / clang)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBS="$HERE/../arduino_libraries"
SHIM="$HERE/host_shim"
OUT_DIR="${OUT_DIR:-$HERE}"
CC="${CC:-cc}"
CFLAGS=(-O2 -fPIC -shared -std=c99)

build() {  # build <name> <library src dir> <native sub-folder>
  local name="$1" src="$2" native="$3"
  if [[ ! -d "$src/$native" ]]; then
    echo "ERROR: bundled sources not found at $src/$native" >&2
    exit 1
  fi
  "$CC" "${CFLAGS[@]}" -I"$SHIM" -I"$src" -I"$src/$native" \
      "$src/$native"/*.c "$src/$native"/fips202/*.c "$SHIM/host_random.c" \
      -o "$OUT_DIR/$name"
  echo "      -> $OUT_DIR/$name"
}

echo "[1/2] Building libmlkem512.so (mlkem-native v2.0.0, ML-KEM-512) ..."
build libmlkem512.so "$LIBS/MLKEM512/src" mlkem_native

echo "[2/2] Building libmldsa44.so (mldsa-native v1.0.0-beta2, ML-DSA-44) ..."
build libmldsa44.so "$LIBS/MLDSA44/src" mldsa_native
