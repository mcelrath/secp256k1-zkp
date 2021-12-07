/**********************************************************************
 * Copyright (c) 2021 Jesse Posner, Andrew Poelstra                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_MAIN_H
#define SECP256K1_MODULE_FROST_MAIN_H

#include <stdint.h>
#include "include/secp256k1.h"
#include "include/secp256k1_frost.h"
#include "hash.h"

static int secp256k1_frost_generate_shares(secp256k1_frost_share *shares, const secp256k1_scalar *secret, const unsigned char *rngseed, const size_t n_signers, const size_t threshold) {
    size_t i;

    for (i = 0; i < n_signers; i++) {
        size_t j;
        secp256k1_scalar share_i;
        secp256k1_scalar scalar_i;
        secp256k1_scalar rand[2];

        secp256k1_scalar_clear(&share_i);
        secp256k1_scalar_set_int(&scalar_i, i + 1);
        for (j = 0; j < threshold - 1; j++) {
            if (j % 2 == 0) {
                secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, j);
            }

            /* Horner's method to evaluate polynomial to derive shares */
            secp256k1_scalar_add(&share_i, &share_i, &rand[j % 2]);
            secp256k1_scalar_mul(&share_i, &share_i, &scalar_i);
        }
        secp256k1_scalar_add(&share_i, &share_i, secret);
        secp256k1_scalar_get_b32(shares[i].data, &share_i);
    }

    return 1;
}

int secp256k1_frost_keygen_init(const secp256k1_context *ctx, secp256k1_pubkey *pubcoeff, secp256k1_frost_share *shares, const size_t threshold, const size_t n_signers, const unsigned char *seckey32) {
    secp256k1_sha256 sha;
    size_t i;
    int overflow;
    secp256k1_scalar const_term;
    secp256k1_gej rj;
    secp256k1_ge rp;
    unsigned char rngseed[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(seckey32 != NULL);

    if (threshold == 0 || threshold > n_signers) {
        return 0;
    }

    /* Compute seed which commits to all inputs */
    /* TODO: allow user suplied function that takes seckey, threshold, and n_signers as inputs and supplies the rngseed */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, seckey32, 32);
    for (i = 0; i < 8; i++) {
        rngseed[i + 0] = threshold / (1ull << (i * 8));
        rngseed[i + 8] = n_signers / (1ull << (i * 8));
    }
    secp256k1_sha256_write(&sha, rngseed, 16);
    secp256k1_sha256_finalize(&sha, rngseed);

    secp256k1_scalar_set_b32(&const_term, seckey32, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &const_term);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(&pubcoeff[0], &rp);

    /* Derive coefficients from the seed. */
    for (i = 0; i < threshold - 1; i++) {
        secp256k1_scalar rand[2];

        if (i % 2 == 0) {
            secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, i);
        }
        /* Compute commitment to each coefficient */
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &rand[i % 2]);
        secp256k1_ge_set_gej(&rp, &rj);
        secp256k1_pubkey_save(&pubcoeff[i + 1], &rp);
    }

    if (!secp256k1_frost_generate_shares(shares, &const_term, rngseed, n_signers, threshold)) {
        return 0;
    }

    return 1;
}

typedef struct {
    const secp256k1_context *ctx;
    const secp256k1_pubkey *pks;
    size_t threshold;
} secp256k1_frost_pubkey_combine_ecmult_data;

static int secp256k1_frost_pubkey_combine_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_pubkey_combine_ecmult_data *ctx = (secp256k1_frost_pubkey_combine_ecmult_data *) data;
    secp256k1_scalar_set_int(sc, 1);
    /* the public key is the first index of each set of coefficients */
    return secp256k1_pubkey_load(ctx->ctx, pt, ctx->pks + (idx * ctx->threshold));
}

int secp256k1_frost_keygen_finalize(const secp256k1_context *ctx, secp256k1_scratch_space *scratch, secp256k1_frost_share *agg_share, secp256k1_xonly_pubkey *combined_pk, const secp256k1_frost_share *shares, const secp256k1_pubkey *pubcoeff, const size_t n_signers, const size_t threshold) {
    secp256k1_frost_pubkey_combine_ecmult_data ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;
    int pk_parity;
    size_t i;
    secp256k1_scalar acc;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubcoeff != NULL);
    ARG_CHECK(n_signers > 0);

    /* Combine pubkeys */
    ecmult_data.ctx = ctx;
    ecmult_data.pks = pubcoeff;
    ecmult_data.threshold = threshold;

    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &pkj, NULL, secp256k1_frost_pubkey_combine_callback, (void *) &ecmult_data, n_signers)) {
        return 0;
    }

    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_fe_normalize_var(&pkp.y);
    pk_parity = secp256k1_extrakeys_ge_even_y(&pkp);
    secp256k1_xonly_pubkey_save(combined_pk, &pkp);

    /* Compute combined shares */
    secp256k1_scalar_clear(&acc);
    for (i = 0; i < n_signers; i++) {
        secp256k1_scalar share_i;

        secp256k1_scalar_set_b32(&share_i, shares[i].data, NULL);
        secp256k1_scalar_add(&acc, &acc, &share_i);
    }

    /* Invert the aggregate share if the combined pubkey has an odd Y coordinate. */
    if (pk_parity == 1) {
        secp256k1_scalar_negate(&acc, &acc);
    }
    secp256k1_scalar_get_b32((unsigned char *) agg_share->data, &acc);

    return 1;
}

static void secp256k1_frost_lagrange_coefficient(secp256k1_scalar *r, const size_t *participant_indexes, const size_t n_participants, const size_t my_index) {
    size_t i;
    secp256k1_scalar num;
    secp256k1_scalar den;
    secp256k1_scalar idx;

    secp256k1_scalar_set_int(&num, 1);
    secp256k1_scalar_set_int(&den, 1);
    secp256k1_scalar_set_int(&idx, my_index);
    for (i = 0; i < n_participants; i++) {
        secp256k1_scalar mul;
        if (participant_indexes[i] == my_index) {
            continue;
        }
        secp256k1_scalar_set_int(&mul, participant_indexes[i]);
        secp256k1_scalar_negate(&mul, &mul);
        secp256k1_scalar_mul(&num, &num, &mul);

        secp256k1_scalar_add(&mul, &mul, &idx);
        secp256k1_scalar_mul(&den, &den, &mul);
    }

    secp256k1_scalar_inverse_var(&den, &den);
    secp256k1_scalar_mul(r, &num, &den);
}

static int secp256k1_frost_pubnonce_combine_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_pubkey_combine_ecmult_data *ctx = (secp256k1_frost_pubkey_combine_ecmult_data *) data;
    secp256k1_scalar_set_int(sc, 1);
    return secp256k1_pubkey_load(ctx->ctx, pt, &ctx->pks[idx]);
}

int secp256k1_frost_partial_sign(const secp256k1_context *ctx, secp256k1_scratch_space *scratch, secp256k1_frost_partial_signature *partial_sig, secp256k1_xonly_pubkey *combined_pubnonce, secp256k1_frost_sign_session *session, const secp256k1_pubkey *pubnonce, const size_t n_signers, const size_t *indexes) {
    secp256k1_frost_pubkey_combine_ecmult_data ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;
    unsigned char buf[32];
    unsigned char pk[32];
    secp256k1_scalar s, x, l;
    int pubnonce_parity;

    /* Combine pubkeys */
    ecmult_data.ctx = ctx;
    ecmult_data.pks = pubnonce;
    ecmult_data.threshold = n_signers;

    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &pkj, NULL, secp256k1_frost_pubnonce_combine_callback, (void *) &ecmult_data, n_signers)) {
        return 0;
    }

    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_fe_normalize_var(&pkp.y);
    pubnonce_parity = secp256k1_extrakeys_ge_even_y(&pkp);
    secp256k1_xonly_pubkey_save(combined_pubnonce, &pkp);

    if (!secp256k1_xonly_pubkey_serialize(ctx, buf, combined_pubnonce)) {
        return 0;
    }

    if (!secp256k1_xonly_pubkey_serialize(ctx, pk, &session->combined_pk)) {
        return 0;
    }

    /* compute challenge hash */
    secp256k1_schnorrsig_challenge(&s, buf, session->msg, pk);
    secp256k1_scalar_set_b32(&x, session->agg_share.data, NULL);
    secp256k1_frost_lagrange_coefficient(&l, indexes, n_signers, session->my_index);
    secp256k1_scalar_mul(&x, &x, &l);
    secp256k1_scalar_mul(&s, &s, &x);

    if (pubnonce_parity) {
        /* TODO: don't overwite nonce */
        secp256k1_scalar_negate(&session->nonce, &session->nonce);
    }
    secp256k1_scalar_add(&s, &s, &session->nonce);
    secp256k1_scalar_get_b32(partial_sig->data, &s);

    return 1;
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

int secp256k1_frost_sign_init(const secp256k1_context *ctx, secp256k1_pubkey *pubnonce, secp256k1_frost_sign_session *session, const unsigned char *session_id32, const unsigned char *msg32, const secp256k1_xonly_pubkey *combined_pk, secp256k1_frost_share *agg_share, const size_t my_index) {
    secp256k1_frost_secnonce k;
    secp256k1_gej rj;
    secp256k1_ge nonce_ge;

    session->my_index = my_index;
    memcpy(session->msg, msg32, 32);
    memcpy(session->combined_pk.data, combined_pk->data, 64);
    memcpy(session->agg_share.data, agg_share->data, 32);

    if (!secp256k1_nonce_function_frost(&k, session_id32, agg_share->data, msg32, combined_pk->data, frost_algo, 9, NULL)) {
        return 0;
    };
    secp256k1_scalar_set_b32(&session->nonce, k.data, NULL);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &session->nonce);
    secp256k1_ge_set_gej(&nonce_ge, &rj);
    secp256k1_pubkey_save(pubnonce, &nonce_ge);

    return 1;
}

int secp256k1_frost_aggregate_partial_sigs(const secp256k1_context *ctx, unsigned char sig[64], const secp256k1_frost_partial_signature *p_sigs, const secp256k1_xonly_pubkey *combined_pubnonce, const size_t n_sigs) {
    secp256k1_scalar s1, s2;
    size_t i;

    secp256k1_scalar_clear(&s1);
    for (i = 0; i < n_sigs; i++) {
        secp256k1_scalar_set_b32(&s2, p_sigs[i].data, NULL);
        secp256k1_scalar_add(&s1, &s1, &s2);
    }
    secp256k1_scalar_get_b32(&sig[32], &s1);

    if (!secp256k1_xonly_pubkey_serialize(ctx, &sig[0], combined_pubnonce)) {
        return 0;
    };

    return 1;
}

#endif
