#ifndef SECP256K1_FROST_H
#define SECP256K1_FROST_H

#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** This code is currently a work in progress. It's not secure nor stable.  IT
 * IS EXTREMELY DANGEROUS AND RECKLESS TO USE THIS MODULE IN PRODUCTION!

 * This module implements Flexible Round-Optimized Schnorr Threshold Signatures
 * (FROST) by Chelsea Komlo and Ian Goldberg
 * (https://crysp.uwaterloo.ca/software/frost/).
 */

/** A FROST secret share. Created with `secp256k1_frost_keygen_init` for a
 * specific set of signers. Secret shares should *never* be reused across
 * multiple signer sets.
 *
 * This data structure is guaranteed to be a 32-byte byte array; it is a
 * separate type from ordinary secret keys to help prevent API users confusing
 * shares with complete keys or using the non-FROST API in place of the FROST
 * API, which would result in mysteriously invalid signatures being produced.
 */
typedef struct {
    unsigned char data[32];
} secp256k1_frost_share;

SECP256K1_API int secp256k1_frost_keygen_init(
    const secp256k1_context *ctx,
    secp256k1_scalar *coefficients,
    secp256k1_xonly_pubkey *commitments,
    const size_t threshold,
    const size_t n_signers,
    const unsigned char *seckey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(6);

SECP256K1_API void secp256k1_frost_generate_shares(
    secp256k1_frost_share *shares,
    const secp256k1_scalar *coefficients,
    const size_t threshold,
    const size_t n_signers
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

SECP256K1_API int secp256k1_frost_pubkey_combine(
    const secp256k1_context *ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_xonly_pubkey *combined_pk,
    const secp256k1_xonly_pubkey *pubkeys,
    size_t n_pubkeys
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_FROST_H */
