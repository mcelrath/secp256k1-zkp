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

int secp256k1_frost_keygen_init(const secp256k1_context *ctx, secp256k1_frost_keygen_session *session, secp256k1_scalar *privcoeff, secp256k1_pubkey *pubcoeff, const size_t threshold, const size_t n_signers, const size_t my_index, const unsigned char *seckey32) {
     secp256k1_sha256 sha;
     size_t i;
     unsigned char rngseed[32];

     VERIFY_CHECK(ctx != NULL);
     ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
     ARG_CHECK(seckey32 != NULL);

     if (threshold == 0 || threshold > n_signers) {
         return 0;
     }

     session->threshold = threshold;
     session->my_index = my_index;
     session->n_signers = n_signers;

     /* Compute a random seed which commits to all inputs */
     /* TODO: allow user suplied function that takes seckey, threshold, and n_signers as inputs and supplies the rngseed */
     secp256k1_sha256_initialize(&sha);
     secp256k1_sha256_write(&sha, seckey32, 32);
     for (i = 0; i < 8; i++) {
         rngseed[i + 0] = threshold / (1ull << (i * 8));
         rngseed[i + 8] = n_signers / (1ull << (i * 8));
         rngseed[i + 16] = my_index / (1ull << (i * 8));
     }
     secp256k1_sha256_write(&sha, rngseed, 24);
     secp256k1_sha256_finalize(&sha, rngseed);

     /* Derive coefficients from the seed. */
     for (i = 0; i < threshold; i++) {
         secp256k1_scalar rand[2];
         secp256k1_gej rj;
         secp256k1_ge rp;

         if (i % 2 == 0) {
             secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, i);
         }
         privcoeff[i] = rand[i % 2];
         /* Compute commitment to each coefficient */
         secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &rand[i % 2]);
         secp256k1_ge_set_gej(&rp, &rj);
         secp256k1_pubkey_save(&pubcoeff[i], &rp);

         if (i == 0) {
            secp256k1_pubkey_save(&session->coeff_pk, &rp);
         }
     }

     return 1;
 }

void secp256k1_frost_generate_shares(secp256k1_frost_share *shares, secp256k1_scalar *coeff, const secp256k1_frost_keygen_session *session) {
    size_t i;

    /* Invert the first coeeficient if the combined pubkey has an odd Y coordinate. We can't wait for signing to invert because it must be done prior to generating the polynomial from which the shares will be derived. */
    if (session->pk_parity) {
        /* TODO: do this without overwriting by writing to new scalar value */
        /* do this within the loop so we only do this check once */
        /* update test because when it reads from privcoeff it will no longer */
        /* be inverted */
        secp256k1_scalar_negate(&coeff[0], &coeff[0]);

    }

    for (i = 0; i < session->n_signers; i++) {
        size_t j;
        secp256k1_scalar share_i;
        secp256k1_scalar scalar_i;

        /* Horner's method */
        secp256k1_scalar_clear(&share_i);
        secp256k1_scalar_set_int(&scalar_i, i + 1);
        for (j = session->threshold; j > 0; j--) {
            secp256k1_scalar_mul(&share_i, &share_i, &scalar_i);
            secp256k1_scalar_add(&share_i, &share_i, &coeff[j - 1]);
        }
        secp256k1_scalar_get_b32(shares[i].data, &share_i);
    }
}

void secp256k1_frost_aggregate_shares(secp256k1_frost_share *aggregate_share, const secp256k1_frost_share *shares, const secp256k1_frost_keygen_session *session) {
    size_t i;
    secp256k1_scalar acc;

    secp256k1_scalar_clear(&acc);
    for (i = 0; i < session->n_signers; i++) {
        secp256k1_scalar share_i;
        secp256k1_scalar_set_b32(&share_i, shares[i].data, NULL);
        secp256k1_scalar_add(&acc, &acc, &share_i);
    }
    secp256k1_scalar_get_b32(aggregate_share->data, &acc);
}

typedef struct {
    const secp256k1_context *ctx;
    const secp256k1_pubkey *pks;
} secp256k1_frost_pubkey_combine_ecmult_data;

static int secp256k1_frost_pubkey_combine_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_pubkey_combine_ecmult_data *ctx = (secp256k1_frost_pubkey_combine_ecmult_data *) data;
    secp256k1_scalar_set_int(sc, 1);
    return secp256k1_pubkey_load(ctx->ctx, pt, &ctx->pks[idx]);
}

int secp256k1_frost_pubkey_combine(const secp256k1_context *ctx, secp256k1_scratch_space *scratch, secp256k1_frost_keygen_session *session, const secp256k1_pubkey *pubkeys) {
    secp256k1_frost_pubkey_combine_ecmult_data ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(session->n_signers > 0);

    ecmult_data.ctx = ctx;
    ecmult_data.pks = pubkeys;

    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &pkj, NULL, secp256k1_frost_pubkey_combine_callback, (void *) &ecmult_data, session->n_signers)) {
        return 0;
    }

    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_fe_normalize_var(&pkp.y);
    session->pk_parity = secp256k1_extrakeys_ge_even_y(&pkp);
    secp256k1_xonly_pubkey_save(&session->combined_pk, &pkp);

    return 1;
}

static void secp256k1_frost_lagrange_coefficient(secp256k1_scalar *r, const size_t *participant_indexes, const size_t n_participants, const size_t my_index) {
    size_t i;
    secp256k1_scalar num;
    secp256k1_scalar den;
    secp256k1_scalar idx;

    secp256k1_scalar_set_int(&num, 1);
    secp256k1_scalar_set_int(&den, 1);
    secp256k1_scalar_set_int(&idx, (int) my_index);
    for (i = 0; i < n_participants; i++) {
        secp256k1_scalar mul;
        if ((int) participant_indexes[i] == (int) my_index) {
            continue;
        }
        secp256k1_scalar_set_int(&mul, (int) participant_indexes[i]);
        secp256k1_scalar_negate(&mul, &mul);
        secp256k1_scalar_mul(&num, &num, &mul);

        secp256k1_scalar_add(&mul, &mul, &idx);
        secp256k1_scalar_mul(&den, &den, &mul);
     }

    secp256k1_scalar_inverse_var(&den, &den);
    secp256k1_scalar_mul(r, &num, &den);
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("FROST/non")||SHA256("FROST/non"). */
/* TODO: get correct midstate */
static void secp256k1_nonce_function_frost_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x791dae43ul;
    sha->s[1] = 0xe52d3b44ul;
    sha->s[2] = 0x37f9edeaul;
    sha->s[3] = 0x9bfd2ab1ul;
    sha->s[4] = 0xcfb0f44dul;
    sha->s[5] = 0xccf1d880ul;
    sha->s[6] = 0xd18f2c13ul;
    sha->s[7] = 0xa37b9024ul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("FROST/aux")||SHA256("FROST/aux"). */
/* TODO: get correct midstate */
static void secp256k1_nonce_function_frost_sha256_tagged_aux(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0xd14c7bd9ul;
    sha->s[1] = 0x095d35e6ul;
    sha->s[2] = 0xb8490a88ul;
    sha->s[3] = 0xfb00ef74ul;
    sha->s[4] = 0x0baa488ful;
    sha->s[5] = 0x69366693ul;
    sha->s[6] = 0x1c81c5baul;
    sha->s[7] = 0xc33b296aul;

    sha->bytes = 64;
}

/* algo argument for nonce_function_frost to derive the nonce using a tagged hash function. */
static const unsigned char frost_algo[9] = "FROST/non";

static int secp256k1_nonce_function_frost(secp256k1_frost_secnonce *k, const unsigned char *session_id, const unsigned char *key32, const unsigned char *msg32, const unsigned char *combined_pk, const unsigned char *algo, size_t algolen, void *data) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];
    unsigned char rngseed[32];
    secp256k1_scalar rand[2];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        secp256k1_nonce_function_frost_sha256_tagged_aux(&sha);
        secp256k1_sha256_write(&sha, data, 32);
        secp256k1_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithims. An optimized tagging implementation is used if the default
     * tag is provided. */
    if (algolen == sizeof(frost_algo)
            && secp256k1_memcmp_var(algo, frost_algo, algolen) == 0) {
        secp256k1_nonce_function_frost_sha256_tagged(&sha);
    } else {
        secp256k1_sha256_initialize_tagged(&sha, algo, algolen);
    }

    secp256k1_sha256_write(&sha, session_id, 32);
    if (data != NULL) {
        secp256k1_sha256_write(&sha, masked_key, 32);
    } else {
        secp256k1_sha256_write(&sha, key32, 32);
    }
    secp256k1_sha256_write(&sha, combined_pk, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, rngseed);

    /* Derive nonce from the seed. */
    /* TODO: it would be nice if we could allow an iteration, perhaps in a different function */
    /* and index as an optional argument to this one */
    secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, 0);
    secp256k1_scalar_get_b32(k->data, &rand[0]);
    secp256k1_scalar_get_b32(&k->data[32], &rand[1]);

    return 1;
}

#endif
