#!/usr/bin/env bash
# flash_footprint.sh - program (flash) size each signature algorithm adds on its own.
#
# Builds firmware/sig_bench_unified 8 times with the same compiler and settings:
#   * "none": the benchmark harness with no algorithm (the baseline)
#   * each algorithm alone (only that one ENABLE_... = 1)
#   * "all": every algorithm (the firmware that is actually run)
# The cost of an algorithm = its build size - baseline. It includes everything that
# algorithm pulls in (e.g. mbedTLS big-number code for ECDSA and for RSA, each counted
# fully), which is what a drone firmware using only that algorithm would pay.
#
# Run from Drone_Auth_Research/:   bash tools/flash_footprint.sh
# All 8 builds leave out the test-only code (FOOTPRINT_BUILD=1: known-answer tests,
# their test vectors, the RSA key DER writer), so only real algorithm code is counted.
# Output: results/e1/flash_footprint.csv
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${ARDUINO_CLI:-/opt/arduino-ide/resources/app/lib/backend/resources/arduino-cli}"
CFG="${ARDUINO_CONFIG:-$HOME/.arduinoIDE/arduino-cli.yaml}"
FQBN="esp32:esp32:esp32"
BUILD="$(mktemp -d)"
OUT="$ROOT/results/e1/flash_footprint.csv"
mkdir -p "$(dirname "$OUT")"
trap 'rm -rf "$BUILD"' EXIT

ALGS=(ED25519 ECDSA_P256 RSA3072 MLDSA44 MLDSA65 MLDSA87)

build_size() {   # $1 = extra compiler flags; prints the flash bytes
  "$CLI" --config-file "$CFG" compile --fqbn "$FQBN" --build-path "$BUILD" \
    --libraries "$ROOT/arduino_libraries" --build-property "compiler.cpp.extra_flags=$1" \
    "$ROOT/firmware/sig_bench_unified" 2>&1 |
    awk '/Sketch uses/ {print $3}'
}

flags_only() {   # all ENABLE_ flags 0 except $1 (or none)
  local f="-DFOOTPRINT_BUILD=1"
  for a in "${ALGS[@]}"; do
    if [ "$a" = "${1:-}" ]; then f="$f -DENABLE_$a=1"; else f="$f -DENABLE_$a=0"; fi
  done
  echo "$f"
}

base_flash=$(build_size "$(flags_only)")
echo "variant,flash_bytes,flash_added_bytes" > "$OUT"
echo "none (harness only),$base_flash,0" >> "$OUT"
echo "baseline: $base_flash bytes"
for a in "${ALGS[@]}"; do
  f=$(build_size "$(flags_only "$a")")
  echo "$a,$f,$((f - base_flash))" >> "$OUT"
  echo "$a: $f bytes (+$((f - base_flash)))"
done
f=$(build_size "-DFOOTPRINT_BUILD=1")
echo "all six,$f,$((f - base_flash))" >> "$OUT"
echo "all: $f bytes (+$((f - base_flash)))"
echo "Saved $OUT"
