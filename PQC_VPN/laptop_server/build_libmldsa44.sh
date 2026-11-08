#!/usr/bin/env bash
# Builds libmldsa44.so for the PQC laptop gateway (Linux x86-64).
#
# The gateway (crypto_engine.py) loads this library with ctypes, so the laptop
# runs exactly the same ML-DSA-44 C code (FIPS 204) as the ESP32 clients.
#
# Source: the "mldsa" Arduino library, https://github.com/NeuraiProject/mldsa-esp32
#         (v0.2.0, the version the ESP32 client is built with).
#
# Usage:
#   ./build_libmldsa44.sh                         # uses ~/Arduino/libraries/mldsa/src
#   ./build_libmldsa44.sh /path/to/mldsa/src      # or point it at the library's src/ folder
#
# Requires: gcc
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-$HOME/Arduino/libraries/mldsa/src}"
OUT="${OUT:-$HERE/libmldsa44.so}"

if [[ ! -f "$SRC/MLDSA44.h" ]]; then
  echo "ERROR: ML-DSA library source not found at: $SRC" >&2
  echo "Install the 'mldsa' library (https://github.com/NeuraiProject/mldsa-esp32) or pass its src/ folder." >&2
  exit 1
fi

# All library C files except:
#   randombytes.c        - ESP32-only RNG (replaced by linux_randombytes.c)
#   mldsa65/87_build.c   - other security levels, not used by this VPN
SOURCES=()
for f in "$SRC"/*.c "$SRC"/fips202/*.c; do
  case "$(basename "$f")" in
    randombytes.c|mldsa65_build.c|mldsa87_build.c) ;;
    *) SOURCES+=("$f") ;;
  esac
done

gcc -O3 -fPIC -shared -I"$SRC" -I"$SRC/fips202" "${SOURCES[@]}" "$HERE/linux_randombytes.c" -o "$OUT"
echo "Built: $OUT"
