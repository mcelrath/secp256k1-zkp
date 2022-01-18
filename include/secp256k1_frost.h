#ifndef SECP256K1_FROST_H
#define SECP256K1_FROST_H

#include "secp256k1_extrakeys.h"
#include "secp256k1_musig.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** This code is currently a work in progress. It's not secure nor stable.  IT
 * IS EXTREMELY DANGEROUS AND RECKLESS TO USE THIS MODULE IN PRODUCTION!

 * This module implements a modified version of Flexible Round-Optimized
 * Schnorr Threshold Signatures (FROST) by Chelsea Komlo and Ian Goldberg
 * (https://crysp.uwaterloo.ca/software/frost/).
 */

/** A FROST secret share. Created with `secp256k1_frost_share_gen` for a
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

SECP256K1_API int secp256k1_frost_share_gen(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubcoeff,
    secp256k1_frost_share *shares,
    size_t threshold,
    size_t n_participants,
    const secp256k1_keypair *keypair,
    const secp256k1_musig_keyagg_cache *keyagg_cache
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7);

SECP256K1_API int secp256k1_frost_share_agg(
    const secp256k1_context* ctx,
    secp256k1_frost_share *agg_share,
    unsigned char *vss_hash,
    const secp256k1_frost_share * const* shares,
    const secp256k1_pubkey * const* pubcoeffs,
    size_t n_shares,
    size_t threshold,
    size_t my_index
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);


SECP256K1_API int secp256k1_frost_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_sig *partial_sig,
    secp256k1_musig_secnonce *secnonce,
    const secp256k1_frost_share *agg_share,
    const secp256k1_musig_session *session,
    size_t n_signers,
    size_t *indexes,
    size_t my_index
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(7);

/* TODO: serialization APIs */

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_FROST_H */
