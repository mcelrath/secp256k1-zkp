/**********************************************************************
 * Copyright (c) 2021 Jesse Posner                                    *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_MAIN_H
#define SECP256K1_MODULE_FROST_MAIN_H

#include <stdint.h>
#include "include/secp256k1.h"
#include "include/secp256k1_frost.h"
#include "hash.h"

int secp256k1_frost_keygen_init(const secp256k1_context *ctx, secp256k1_scalar *coefficients, secp256k1_xonly_pubkey *commitments, const size_t threshold, const size_t n_signers, const unsigned char *seckey) {
     secp256k1_sha256 sha;
     size_t i;
     unsigned char rngseed[32];

     VERIFY_CHECK(ctx != NULL);
     ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
     ARG_CHECK(seckey != NULL);

     if (threshold == 0 || threshold > n_signers) {
         return 0;
     }

     /* Compute a random seed which commits to all inputs */
     /* TODO: allow user suplied function that takes seckey, threshold, and n_signers as inputs and supplies the rngseed */
     secp256k1_sha256_initialize(&sha);
     secp256k1_sha256_write(&sha, seckey, 32);
     for (i = 0; i < 8; i++) {
         rngseed[i + 0] = threshold / (1ull << (i * 8));
         rngseed[i + 8] = n_signers / (1ull << (i * 8));
     }
     secp256k1_sha256_write(&sha, rngseed, 16);
     secp256k1_sha256_finalize(&sha, rngseed);

     /* Derive coefficients from the seed. */
     for (i = 0; i < threshold; i++) {
         secp256k1_scalar rand[2];
         secp256k1_gej rj;
         secp256k1_ge rp;

         if (i % 2 == 0) {
             secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, i);
         }
         coefficients[i] = rand[i % 2];
         /* Compute commitment to each coefficient */
         secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &rand[i % 2]);
         secp256k1_ge_set_gej(&rp, &rj);
         secp256k1_xonly_pubkey_save(&commitments[i], &rp);
     }

     return 1;
 }

void secp256k1_frost_generate_shares(secp256k1_frost_share *shares, const secp256k1_scalar *coefficients, const size_t threshold, const size_t n_signers) {
    size_t i;

    for (i = 0; i < n_signers; i++) {
        size_t j;
        secp256k1_scalar share_i;
        secp256k1_scalar scalar_i;

        /* Horner's method */
        secp256k1_scalar_clear(&share_i);
        secp256k1_scalar_set_int(&scalar_i, i + 1);
        for (j = threshold; j > 0; j--) {
            secp256k1_scalar_mul(&share_i, &share_i, &scalar_i);
            secp256k1_scalar_add(&share_i, &share_i, &coefficients[j - 1]);
        }
        secp256k1_scalar_get_b32(shares[i].data, &share_i);
    }
}

void secp256k1_frost_aggregate_shares(secp256k1_frost_share *aggregate_share, secp256k1_frost_share *shares, const size_t n_signers) {
    size_t i;
    secp256k1_scalar acc;

    secp256k1_scalar_clear(&acc);
    for (i = 0; i < n_signers; i++) {
        secp256k1_scalar share_i;
        secp256k1_scalar_set_b32(&share_i, shares[i].data, NULL);
        secp256k1_scalar_add(&acc, &acc, &share_i);
    }
    secp256k1_scalar_get_b32(aggregate_share->data, &acc);
}

typedef struct {
    const secp256k1_context *ctx;
    const secp256k1_xonly_pubkey *pks;
} secp256k1_frost_pubkey_combine_ecmult_data;

static int secp256k1_frost_pubkey_combine_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_pubkey_combine_ecmult_data *ctx = (secp256k1_frost_pubkey_combine_ecmult_data *) data;
    secp256k1_scalar_set_int(sc, 1);
    return secp256k1_xonly_pubkey_load(ctx->ctx, pt, &ctx->pks[idx]);
}

int secp256k1_frost_pubkey_combine(const secp256k1_context *ctx, secp256k1_scratch_space *scratch, secp256k1_xonly_pubkey *combined_pk, const secp256k1_xonly_pubkey *pubkeys, size_t n_pubkeys) {
    secp256k1_frost_pubkey_combine_ecmult_data ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(n_pubkeys > 0);

    ecmult_data.ctx = ctx;
    ecmult_data.pks = pubkeys;

    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &pkj, NULL, secp256k1_frost_pubkey_combine_callback, (void *) &ecmult_data, n_pubkeys)) {
        return 0;
    }

    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_fe_normalize(&pkp.y);
    secp256k1_extrakeys_ge_even_y(&pkp);
    secp256k1_xonly_pubkey_save(combined_pk, &pkp);

    return 1;
}

static void secp256k1_frost_lagrange_coefficient(secp256k1_scalar *r, const size_t *participant_indexes, const size_t n_participants, const size_t my_index) {
    size_t i;
    secp256k1_scalar num;
    secp256k1_scalar den;

    secp256k1_scalar_set_int(&num, 1);
    secp256k1_scalar_set_int(&den, 1);
    for (i = 0; i < n_participants; i++) {
        secp256k1_scalar mul, sum;
        if ((int) participant_indexes[i] == (int) my_index) {
            continue;
        }
        secp256k1_scalar_set_int(&mul, (int) participant_indexes[i]);
        secp256k1_scalar_mul(&num, &num, &mul);
        secp256k1_scalar_set_int(&mul, (int) my_index);
        secp256k1_scalar_negate(&mul, &mul);
        secp256k1_scalar_set_int(&sum, (int) participant_indexes[i]);
        secp256k1_scalar_add(&mul, &mul, &sum);
        secp256k1_scalar_mul(&den, &den, &mul);
     }

    secp256k1_scalar_inverse_var(&den, &den);
    secp256k1_scalar_mul(r, &num, &den);
 }

#endif
