/*
 * Builds the unmodified mldsa-native v1.0.0-beta2 sources (../mldsa_native/)
 * as ML-DSA-44, using the library's own multi-level build option.
 * This unit also builds the code shared by all levels (Keccak/SHAKE, constant-time helpers).
 * Public functions are named DRONE_MLDSA44_keypair, _signature, _verify, ...
 */
#define MLD_CONFIG_PARAMETER_SET 44
#define MLD_CONFIG_MULTILEVEL_BUILD
#define MLD_CONFIG_MULTILEVEL_WITH_SHARED
#define MLD_CONFIG_NAMESPACE_PREFIX DRONE_MLDSA

#include "../mldsa_native/ct.c"
#include "../mldsa_native/debug.c"
#include "../mldsa_native/packing.c"
#include "../mldsa_native/poly.c"
#include "../mldsa_native/poly_kl.c"
#include "../mldsa_native/polyvec.c"
#include "../mldsa_native/polyvec_lazy.c"
#include "../mldsa_native/sign.c"
#include "../mldsa_native/fips202/fips202.c"
#include "../mldsa_native/fips202/fips202x4.c"
#include "../mldsa_native/fips202/keccakf1600.c"
