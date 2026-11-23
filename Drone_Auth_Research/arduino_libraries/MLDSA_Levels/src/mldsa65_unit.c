/*
 * Builds the unmodified mldsa-native v1.0.0-beta2 sources (../mldsa_native/)
 * as ML-DSA-65, using the library's own multi-level build option.
 * Shared code (Keccak/SHAKE, constant-time helpers) comes from the ML-DSA-44 unit.
 * Public functions are named DRONE_MLDSA65_keypair, _signature, _verify, ...
 */
#define MLD_CONFIG_PARAMETER_SET 65
#define MLD_CONFIG_MULTILEVEL_BUILD
#define MLD_CONFIG_MULTILEVEL_NO_SHARED
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
