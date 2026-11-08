#!/usr/bin/env bash
# Builds the two native PQC shared libraries loaded by crypto_engine.py via ctypes:
#   libmlkem512.so : mlkem-native v2.0.0, ML-KEM-512, deterministic API only
#                    (server passes os.urandom coins to enc_derand, so no C RNG is needed)
#   libmldsa44.so  : mldsa-native v1.0.0-beta2, ML-DSA-44 (same ABI as PQC_VPN/laptop_server:
#                    signature(sig, &siglen, ...) / verify(sig, siglen, ...))
#
# Usage:  ./build_native_libs.sh            # builds both
#         SKIP_MLDSA=1 ./build_native_libs.sh   # only ML-KEM (reuse your existing libmldsa44.so)
set -euo pipefail

MLKEM_TAG="v2.0.0"
MLDSA_TAG="v1.0.0-beta2"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-cc}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[1/2] Building libmlkem512.so from mlkem-native ${MLKEM_TAG} ..."
git -c advice.detachedHead=false clone -q --depth 1 --branch "$MLKEM_TAG" \
    https://github.com/pq-code-package/mlkem-native.git "$WORK/mlkem-native"
"$CC" -O2 -fPIC -shared -std=c99 \
    -DMLK_CONFIG_PARAMETER_SET=512 \
    -DMLK_CONFIG_NO_RANDOMIZED_API \
    -I"$WORK/mlkem-native/mlkem" \
    "$WORK/mlkem-native/mlkem/mlkem_native.c" \
    -o "$OUT_DIR/libmlkem512.so"
echo "      -> $OUT_DIR/libmlkem512.so"

if [[ "${SKIP_MLDSA:-0}" == "1" ]]; then
  echo "[2/2] Skipping libmldsa44.so (SKIP_MLDSA=1)"
  exit 0
fi

echo "[2/2] Building libmldsa44.so from mldsa-native ${MLDSA_TAG} ..."
git -c advice.detachedHead=false clone -q --depth 1 --branch "$MLDSA_TAG" \
    https://github.com/pq-code-package/mldsa-native.git "$WORK/mldsa-native"
# ML-DSA signing is hedged (randomized), so mldsa-native needs randombytes() from the OS CSPRNG.
cat > "$WORK/randombytes_os.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/random.h>
#endif
int randombytes(uint8_t *out, size_t outlen) {
  while (outlen > 0) {
    size_t n = outlen > 256 ? 256 : outlen; /* getentropy() is capped at 256 bytes per call */
    if (getentropy(out, n) != 0) return -1;
    out += n;
    outlen -= n;
  }
  return 0;
}
EOF
"$CC" -O2 -fPIC -shared -std=c99 \
    -DMLD_CONFIG_PARAMETER_SET=44 \
    -I"$WORK/mldsa-native/mldsa" \
    "$WORK/mldsa-native/mldsa/mldsa_native.c" "$WORK/randombytes_os.c" \
    -o "$OUT_DIR/libmldsa44.so"
echo "      -> $OUT_DIR/libmldsa44.so"
