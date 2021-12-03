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

typedef struct {
    unsigned char data[64];
} secp256k1_frost_secnonce;

typedef struct {
    unsigned char data[32];
} secp256k1_frost_partial_signature;

typedef struct {
    size_t my_index;
    secp256k1_scalar nonce;
    secp256k1_ge nonce_ge;
    int nonce_parity;
    unsigned char msg[32];
    secp256k1_xonly_pubkey combined_pk;
    secp256k1_frost_share agg_share;
} secp256k1_frost_sign_session;

SECP256K1_API int secp256k1_frost_keygen_init(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubcoeff,
    secp256k1_frost_share *shares,
    const size_t threshold,
    const size_t n_signers,
    const unsigned char *seckey32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(6);

SECP256K1_API int secp256k1_frost_keygen_finalize(
    const secp256k1_context *ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_frost_share *agg_share,
    secp256k1_xonly_pubkey *combined_pk,
    const secp256k1_frost_share *shares,
    const secp256k1_pubkey *pubcoeff,
    const size_t n_signers,
    const size_t threshold
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);


/* TODO: optionally allow nonce to be loaded into the function for pre-generated nonces */
SECP256K1_API int secp256k1_frost_sign_init(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubnonce,
    secp256k1_frost_sign_session *session,
    const unsigned char *session_id32,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *combined_pk,
    secp256k1_frost_share *agg_share,
    const size_t my_index
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

/* TODO: this n_signers means something different than the other n_signers */
SECP256K1_API int secp256k1_frost_partial_sign(
    const secp256k1_context *ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_frost_partial_signature *partial_sig,
    secp256k1_xonly_pubkey *combined_pubnonce,
    secp256k1_frost_sign_session *session,
    const secp256k1_pubkey *rec_pubnonce,
    const size_t n_signers,
    const size_t *indexes
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(8);

int secp256k1_frost_aggregate_partial_sigs(
    const secp256k1_context *ctx,
    unsigned char sig[64],
    const secp256k1_frost_partial_signature *p_sigs,
    const secp256k1_xonly_pubkey *combined_pubnonce,
    const size_t n_sigs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/* TODO: serialization APIs that facilitate communication rounds */

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_FROST_H */
