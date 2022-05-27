/**********************************************************************
 * Copyright (c) 2021, 2022 Jesse Posner                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_KEYGEN_IMPL_H
#define SECP256K1_MODULE_FROST_KEYGEN_IMPL_H

#include "keygen.h"

/* Generate polynomial coefficients, coefficient commitments, and shares, from
 * a seed and a secret key. */
static int secp256k1_frost_share_gen_internal(const secp256k1_context *ctx, secp256k1_pubkey *pubcoeff, secp256k1_frost_share *shares, uint16_t threshold, uint16_t n_participants, const unsigned char *seckey32) {
    secp256k1_sha256 sha;
    uint16_t i;
    int overflow;
    secp256k1_scalar const_term;
    secp256k1_gej rj;
    secp256k1_ge rp;
    unsigned char rngseed[32];

    ARG_CHECK(seckey32 != NULL);

    /* Compute seed which commits to all inputs */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, seckey32, 32);
    for (i = 0; i < 8; i++) {
        rngseed[i + 0] = threshold / (1ull << (i * 8));
        rngseed[i + 8] = n_participants / (1ull << (i * 8));
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

    /* Derive coefficients from the seed */
    for (i = 0; i < threshold - 1; i++) {
        secp256k1_scalar rand[2];

        if (i % 2 == 0) {
            secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, i);
        }
        /* Compute commitment to each coefficient */
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &rand[i % 2]);
        secp256k1_ge_set_gej(&rp, &rj);
        secp256k1_pubkey_save(&pubcoeff[threshold - i - 1], &rp);
    }

    for (i = 0; i < n_participants; i++) {
        uint16_t j;
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
        secp256k1_scalar_add(&share_i, &share_i, &const_term);
        secp256k1_scalar_get_b32(shares[i].data, &share_i);
    }

    return 1;
}

/* TODO: add optional aux data */
int secp256k1_frost_share_gen(const secp256k1_context *ctx, secp256k1_pubkey *pubcoeff, secp256k1_frost_share *shares, uint16_t threshold, uint16_t n_participants, const secp256k1_keypair *keypair) {
    secp256k1_scalar sk;
    secp256k1_ge pk;
    unsigned char buf[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(pubcoeff != NULL);
    ARG_CHECK(shares != NULL);
    ARG_CHECK(n_participants > 0);
    ARG_CHECK(keypair != NULL);

    if (threshold == 0 || threshold > n_participants) {
        return 0;
    }

    if (!secp256k1_keypair_load(ctx, &sk, &pk, keypair)) {
        return 0;
    }
    secp256k1_scalar_get_b32(buf, &sk);

    if (!secp256k1_frost_share_gen_internal(ctx, pubcoeff, shares, threshold, n_participants, buf)) {
        return 0;
    }

    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("VSS list")||SHA256("VSS list"). */
static void secp256k1_frost_vsslist_sha256(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);

    sha->s[0] = 0x3c261fccul;
    sha->s[1] = 0xeeec1555ul;
    sha->s[2] = 0x6bb6cfc8ul;
    sha->s[3] = 0x678ade57ul;
    sha->s[4] = 0xfb4b11f9ul;
    sha->s[5] = 0x9627b131ul;
    sha->s[6] = 0xbf978156ul;
    sha->s[7] = 0xfc1263cdul;
    sha->bytes = 64;
}

/* Computes vss_hash = tagged_hash(pk[0], ..., pk[np-1]) */
static int secp256k1_frost_compute_vss_hash(const secp256k1_context *ctx, unsigned char *vss_hash, const secp256k1_pubkey * const* pk, uint16_t np, uint16_t t) {
    secp256k1_sha256 sha;
    uint16_t i, j;
    size_t size = 33;

    secp256k1_frost_vsslist_sha256(&sha);
    for (i = 0; i < np; i++) {
        for (j = 0; j < t; j++) {
            unsigned char ser[33];
            if (!secp256k1_ec_pubkey_serialize(ctx, ser, &size, &pk[i][j], SECP256K1_EC_COMPRESSED)) {
                return 0;
            }
            secp256k1_sha256_write(&sha, ser, 33);
        }
    }
    secp256k1_sha256_finalize(&sha, vss_hash);

    return 1;
}

typedef struct {
    const secp256k1_context *ctx;
    secp256k1_scalar idx;
    secp256k1_scalar idxn;
    const secp256k1_pubkey * const* pubcoeff;
} secp256k1_frost_verify_share_ecmult_data;

typedef struct {
    const secp256k1_context *ctx;
    const secp256k1_pubkey * const* pks;
    uint16_t threshold;
} secp256k1_frost_pubkey_combine_ecmult_data;

static int secp256k1_frost_verify_share_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_verify_share_ecmult_data *ctx = (secp256k1_frost_verify_share_ecmult_data *) data;
    int ret;

    ret = secp256k1_pubkey_load(ctx->ctx, pt, *(ctx->pubcoeff)+idx);
    VERIFY_CHECK(ret);
    *sc = ctx->idxn;
    secp256k1_scalar_mul(&ctx->idxn, &ctx->idxn, &ctx->idx);

    return 1;
}

static int secp256k1_frost_pubkey_combine_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_frost_pubkey_combine_ecmult_data *ctx = (secp256k1_frost_pubkey_combine_ecmult_data *) data;

    secp256k1_scalar_set_int(sc, 1);
    /* the public key is the first index of each set of coefficients */
    return secp256k1_pubkey_load(ctx->ctx, pt, &ctx->pks[idx][0]);
}

static int vss_verify(const secp256k1_context* ctx, uint16_t threshold, uint16_t my_index, const secp256k1_scalar *share, const secp256k1_pubkey * const* vss_commitment) {
    secp256k1_scalar share_neg;
    secp256k1_gej tmpj;
    secp256k1_frost_verify_share_ecmult_data verify_share_ecmult_data;

    /* Use an EC multi-multiplication to verify the following equation:
     *   0 = - share_i*G + my_index^0*vss_commitment[0]
     *                   + ...
     *                   + my_index^(threshold - 1)*vss_commitment[threshold - 1]*/
    verify_share_ecmult_data.ctx = ctx;
    verify_share_ecmult_data.pubcoeff = vss_commitment;
    /* Evaluate the public polynomial at the index */
    secp256k1_scalar_set_int(&verify_share_ecmult_data.idx, my_index);
    secp256k1_scalar_set_int(&verify_share_ecmult_data.idxn, 1);
    secp256k1_scalar_negate(&share_neg, share);
    /* TODO: add scratch */
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, &tmpj, &share_neg, secp256k1_frost_verify_share_ecmult_callback, (void *) &verify_share_ecmult_data, threshold)) {
        return 0;
    }
    return secp256k1_gej_is_infinity(&tmpj);
}

int secp256k1_frost_share_agg(const secp256k1_context* ctx, secp256k1_frost_share *agg_share, secp256k1_xonly_pubkey *agg_pk, unsigned char *vss_hash, const secp256k1_frost_share * const* shares, const secp256k1_pubkey * const* pubcoeffs, uint16_t n_shares, uint16_t threshold, uint16_t my_index) {
    secp256k1_frost_pubkey_combine_ecmult_data pubkey_combine_ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;
    int pk_parity;
    secp256k1_scalar acc;
    uint16_t i;
    int overflow;


    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(agg_share != NULL);
    ARG_CHECK(agg_pk != NULL);
    ARG_CHECK(vss_hash != NULL);
    ARG_CHECK(shares != NULL);
    ARG_CHECK(pubcoeffs != NULL);
    ARG_CHECK(n_shares > 0);
    ARG_CHECK(my_index > 0);

    if (threshold == 0 || threshold > n_shares) {
        return 0;
    }

    secp256k1_scalar_clear(&acc);
    for (i = 0; i < n_shares; i++) {
        secp256k1_scalar share_i;

        secp256k1_scalar_set_b32(&share_i, shares[i]->data, &overflow);
        if (overflow) {
            return 0;
        }
        if (!vss_verify(ctx, threshold, my_index, &share_i, &pubcoeffs[i])) {
            return 0;
        }
        secp256k1_scalar_add(&acc, &acc, &share_i);
    }
    if (!secp256k1_frost_compute_vss_hash(ctx, vss_hash, pubcoeffs, n_shares, threshold)) {
        return 0;
    }

    /* Combine pubkeys */
    pubkey_combine_ecmult_data.ctx = ctx;
    pubkey_combine_ecmult_data.pks = pubcoeffs;
    pubkey_combine_ecmult_data.threshold = threshold;

    /* TODO: add scratch */
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, &pkj, NULL, secp256k1_frost_pubkey_combine_callback, (void *) &pubkey_combine_ecmult_data, n_shares)) {
        return 0;
    }

    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_fe_normalize_var(&pkp.y);
    pk_parity = secp256k1_extrakeys_ge_even_y(&pkp);
    secp256k1_xonly_pubkey_save(agg_pk, &pkp);

    /* Invert the aggregate share if the combined pubkey has an odd Y coordinate. */
    if (pk_parity == 1) {
        secp256k1_scalar_negate(&acc, &acc);
    }
    secp256k1_scalar_get_b32((unsigned char *) agg_share->data, &acc);

    return 1;
}

#endif
