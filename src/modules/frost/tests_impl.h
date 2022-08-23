/***********************************************************************
 * Copyright (c) 2022 Jesse Posner                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_FROST_TESTS_IMPL_H
#define SECP256K1_MODULE_FROST_TESTS_IMPL_H

#include <stdlib.h>
#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_frost.h"

#include "session.h"
#include "keygen.h"
#include "../../scalar.h"
#include "../../scratch.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../util.h"

static int frost_create_keypair_and_pk(secp256k1_keypair *keypair, secp256k1_xonly_pubkey *pk, const unsigned char *sk) {
    int ret;
    secp256k1_keypair keypair_tmp;
    ret = secp256k1_keypair_create(ctx, &keypair_tmp, sk);
    ret &= secp256k1_keypair_xonly_pub(ctx, pk, NULL, &keypair_tmp);
    if (keypair != NULL) {
        *keypair = keypair_tmp;
    }
    return ret;
}

/* Simple (non-adaptor, non-tweaked) 3-of-5 FROST aggregate, sign, verify
 * test. */
void frost_simple_test(void) {
    unsigned char sk[5][32];
    secp256k1_keypair keypair[5];
    secp256k1_frost_pubnonce pubnonce[5];
    const secp256k1_frost_pubnonce *pubnonce_ptr[5];
    unsigned char msg[32];
    secp256k1_pubkey vss_commitment[5][3];
    const secp256k1_pubkey *vss_ptr[5];
    unsigned char vss_hash[32];
    secp256k1_xonly_pubkey agg_pk;
    unsigned char session_id[5][32];
    secp256k1_frost_share share[5][5];
    const secp256k1_frost_share *share_ptr[5];
    secp256k1_frost_share agg_share[5];
    secp256k1_frost_secnonce secnonce[5];
    secp256k1_xonly_pubkey pk[5];
    const secp256k1_xonly_pubkey *pk_ptr[5];
    secp256k1_pubkey share_pk[5];
    secp256k1_frost_partial_sig partial_sig[5];
    const secp256k1_frost_partial_sig *partial_sig_ptr[5];
    unsigned char final_sig[64];
    secp256k1_frost_session session;
    int i,j;

    for (i = 0; i < 5; i++) {
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        pk_ptr[i] = &pk[i];
        vss_ptr[i] = vss_commitment[i];
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];

        CHECK(frost_create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
    }
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            CHECK(secp256k1_frost_share_gen(ctx, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], &pk[j], 3) == 1);
        }
    }
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            share_ptr[j] = &share[j][i];
            CHECK(secp256k1_frost_share_verify(ctx, 3, pk_ptr[i], share_ptr[j], &vss_ptr[j]) == 1);
            CHECK(secp256k1_frost_compute_pubshare(ctx, &share_pk[j], 3, pk_ptr[j], vss_ptr, 5) == 1);
        }
        CHECK(secp256k1_frost_share_agg(ctx, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
    }

    secp256k1_testrand256(msg);
    for (i = 0; i < 3; i++) {
        secp256k1_testrand256(session_id[i]);

        CHECK(secp256k1_frost_nonce_gen(ctx, &secnonce[i], &pubnonce[i], session_id[i], &agg_share[i], NULL, NULL, NULL) == 1);
    }
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_frost_nonce_process(ctx, &session, pubnonce_ptr, 3, msg, &agg_pk, pk_ptr[i], pk_ptr, NULL, NULL) == 1);
        CHECK(secp256k1_frost_partial_sign(ctx, &partial_sig[i], &secnonce[i], &agg_share[i], &session, NULL) == 1);
        CHECK(secp256k1_frost_partial_sig_verify(ctx, &partial_sig[i], &pubnonce[i], &share_pk[i], &session, NULL) == 1);
    }
    CHECK(secp256k1_frost_partial_sig_agg(ctx, final_sig, &session, partial_sig_ptr, 3) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig, msg, sizeof(msg), &agg_pk) == 1);
}

void frost_pubnonce_summing_to_inf(secp256k1_frost_pubnonce *pubnonce) {
    secp256k1_ge ge[2];
    int i;
    secp256k1_gej summed_nonces[2];
    const secp256k1_frost_pubnonce *pubnonce_ptr[2];

    ge[0] = secp256k1_ge_const_g;
    ge[1] = secp256k1_ge_const_g;

    for (i = 0; i < 2; i++) {
        secp256k1_frost_pubnonce_save(&pubnonce[i], ge);
        pubnonce_ptr[i] = &pubnonce[i];
        secp256k1_ge_neg(&ge[0], &ge[0]);
        secp256k1_ge_neg(&ge[1], &ge[1]);
    }

    secp256k1_frost_sum_nonces(ctx, summed_nonces, pubnonce_ptr, 2);
    CHECK(secp256k1_gej_is_infinity(&summed_nonces[0]));
    CHECK(secp256k1_gej_is_infinity(&summed_nonces[1]));
}

int frost_memcmp_and_randomize(unsigned char *value, const unsigned char *expected, size_t len) {
    int ret;
    size_t i;
    ret = secp256k1_memcmp_var(value, expected, len);
    for (i = 0; i < len; i++) {
        value[i] = secp256k1_testrand_bits(8);
    }
    return ret;
}

void frost_api_tests(void) {
    secp256k1_frost_partial_sig invalid_partial_sig;
    unsigned char sk[5][32];
    secp256k1_keypair keypair[5];
    secp256k1_keypair invalid_keypair;
    unsigned char max64[64];
    unsigned char zeros68[68] = { 0 };
    unsigned char session_id[5][32];
    secp256k1_frost_secnonce secnonce[5];
    secp256k1_frost_secnonce invalid_secnonce;
    secp256k1_frost_pubnonce pubnonce[5];
    secp256k1_frost_pubnonce inf_pubnonce[5];
    secp256k1_frost_pubnonce invalid_pubnonce;
    unsigned char msg[32];
    secp256k1_xonly_pubkey agg_pk;
    secp256k1_pubkey full_agg_pk;
    secp256k1_frost_tweak_cache tweak_cache;
    secp256k1_frost_tweak_cache invalid_tweak_cache;
    secp256k1_xonly_pubkey pk[5];
    const secp256k1_xonly_pubkey *pk_ptr[5];
    secp256k1_xonly_pubkey invalid_pk;
    unsigned char tweak[32];
    unsigned char sec_adaptor[32];
    secp256k1_pubkey adaptor;
    secp256k1_pubkey vss_commitment[5][3];
    secp256k1_pubkey invalid_vss_commitment[5][3];
    const secp256k1_pubkey *vss_ptr[5];
    const secp256k1_pubkey *invalid_vss_ptr[5];
    secp256k1_pubkey invalid_vss_pk;
    secp256k1_frost_share share[5][5];
    secp256k1_frost_share invalid_share;
    secp256k1_frost_share agg_share[5];
    unsigned char vss_hash[32];
    const secp256k1_frost_share *share_ptr[5];
    const secp256k1_frost_share *invalid_share_ptr[5];
    secp256k1_pubkey share_pk;
    int i, j;

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *sttc = secp256k1_context_clone(secp256k1_context_no_precomp);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sttc, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sttc, counting_illegal_callback_fn, &ecount);

    memset(max64, 0xff, sizeof(max64));
    memset(&invalid_share, 0xff, sizeof(invalid_share));
    /* Simulate structs being uninitialized by setting it to 0s. We don't want
     * to produce undefined behavior by actually providing uninitialized
     * structs. */
    memset(&invalid_keypair, 0, sizeof(invalid_keypair));
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_secnonce, 0, sizeof(invalid_secnonce));
    memset(&invalid_partial_sig, 0, sizeof(invalid_partial_sig));
    memset(&invalid_pubnonce, 0, sizeof(invalid_pubnonce));
    memset(&invalid_vss_pk, 0, sizeof(invalid_vss_pk));
    memset(&invalid_tweak_cache, 0, sizeof(invalid_tweak_cache));
    frost_pubnonce_summing_to_inf(inf_pubnonce);

    secp256k1_testrand256(sec_adaptor);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(tweak);
    CHECK(secp256k1_ec_pubkey_create(ctx, &adaptor, sec_adaptor) == 1);
    for (i = 0; i < 5; i++) {
        pk_ptr[i] = &pk[i];
        vss_ptr[i] = vss_commitment[i];
        invalid_vss_ptr[i] = invalid_vss_commitment[i];
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        CHECK(create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
    }
    invalid_share_ptr[0] = &invalid_share;
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 3; j++) {
            invalid_vss_commitment[i][j] = invalid_vss_pk;
        }
    }

    /** main test body **/

    /** Key generation **/
    ecount = 0;
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            CHECK(secp256k1_frost_share_gen(none, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(sign, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(vrfy, NULL, &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], NULL, session_id[i], &keypair[i], pk_ptr[j], 3) == 0);
            CHECK(ecount == (i*35)+(j*7)+1);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], NULL, &keypair[i], pk_ptr[j], 3) == 0);
            CHECK(ecount == (i*35)+(j*7)+2);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], NULL, pk_ptr[j], 3) == 0);
            CHECK(ecount == (i*35)+(j*7)+3);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], NULL, 3) == 0);
            CHECK(ecount == (i*35)+(j*7)+4);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], &invalid_pk, 3) == 0);
            CHECK(ecount == (i*35)+(j*7)+5);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 0) == 0);
            CHECK(ecount == (i*35)+(j*7)+6);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, NULL, &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 0) == 0);
            CHECK(ecount == (i*35)+(j*7)+7);
            CHECK(frost_memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);

            CHECK(secp256k1_frost_share_gen(none, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(sign, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 3) == 1);
        }
    }
    CHECK(ecount == 175);

    /* Share aggregation */
    ecount = 0;
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            share_ptr[j] = &share[j][i];
        }
        CHECK(secp256k1_frost_share_agg(none, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
        CHECK(secp256k1_frost_share_agg(sign, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
        CHECK(secp256k1_frost_share_agg(vrfy, NULL, &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+1);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], NULL, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+2);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, NULL, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+3);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, NULL, vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+4);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, NULL, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+5);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, invalid_vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+6);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, NULL) == 0);
        CHECK(ecount == (i*13)+7);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, &invalid_pk) == 0);
        CHECK(ecount == (i*13)+8);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, invalid_share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+9);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 0, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+10);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, NULL, vss_ptr, 0, 3, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+11);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 0, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+12);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, NULL, 5, 0, pk_ptr[i]) == 0);
        CHECK(ecount == (i*13)+13);
        CHECK(frost_memcmp_and_randomize(agg_share[i].data, zeros68, sizeof(agg_share[i].data)) == 0);
        CHECK(frost_memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);

        CHECK(secp256k1_frost_share_agg(none, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
        CHECK(secp256k1_frost_share_agg(sign, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
        CHECK(secp256k1_frost_share_agg(vrfy, &agg_share[i], &agg_pk, vss_hash, share_ptr, vss_ptr, 5, 3, pk_ptr[i]) == 1);
    }
    CHECK(ecount == 65);

    /* Share verification */
    ecount = 0;
    CHECK(secp256k1_frost_share_verify(none, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(sign, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[0], &vss_ptr[1]) == 0);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, NULL, share_ptr[0], &vss_ptr[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, &invalid_pk, share_ptr[0], &vss_ptr[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], NULL, &vss_ptr[1]) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], &invalid_share, &vss_ptr[0]) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[0], NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[0], &invalid_vss_ptr[0]) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_frost_share_verify(vrfy, 0, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 0);
    CHECK(ecount == 7);

    CHECK(secp256k1_frost_share_verify(none, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(sign, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[0], &vss_ptr[0]) == 1);
    CHECK(secp256k1_frost_share_verify(vrfy, 3, pk_ptr[4], share_ptr[1], &vss_ptr[1]) == 1);

    /* Compute public verification share */
    ecount = 0;
    CHECK(secp256k1_frost_compute_pubshare(none, &share_pk, 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(sign, &share_pk, 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &share_pk, 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, NULL, 3, pk_ptr[0], vss_ptr, 5) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &share_pk, 3, NULL, vss_ptr, 5) == 0);
    CHECK(ecount == 2);
    CHECK(frost_memcmp_and_randomize(share_pk.data, zeros68, sizeof(share_pk.data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &share_pk, 3, &invalid_pk, vss_ptr, 5) == 0);
    CHECK(ecount == 3);
    CHECK(frost_memcmp_and_randomize(share_pk.data, zeros68, sizeof(share_pk.data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &share_pk, 3, pk_ptr[0], NULL, 5) == 0);
    CHECK(ecount == 4);
    CHECK(frost_memcmp_and_randomize(share_pk.data, zeros68, sizeof(share_pk.data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &share_pk, 3, pk_ptr[0], invalid_vss_ptr, 5) == 0);
    CHECK(ecount == 5);
    CHECK(frost_memcmp_and_randomize(share_pk.data, zeros68, sizeof(share_pk.data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &share_pk, 0, pk_ptr[0], invalid_vss_ptr, 5) == 0);
    CHECK(ecount == 6);
    CHECK(frost_memcmp_and_randomize(share_pk.data, zeros68, sizeof(share_pk.data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &share_pk, 0, pk_ptr[0], NULL, 5) == 0);
    CHECK(ecount == 7);
    CHECK(frost_memcmp_and_randomize(share_pk.data, zeros68, sizeof(share_pk.data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &share_pk, 3, pk_ptr[0], invalid_vss_ptr, 0) == 0);
    CHECK(ecount == 8);
    CHECK(frost_memcmp_and_randomize(share_pk.data, zeros68, sizeof(share_pk.data)) == 0);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &share_pk, 3, pk_ptr[0], NULL, 0) == 0);
    CHECK(ecount == 9);
    CHECK(frost_memcmp_and_randomize(share_pk.data, zeros68, sizeof(share_pk.data)) == 0);

    CHECK(secp256k1_frost_compute_pubshare(none, &share_pk, 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(sign, &share_pk, 3, pk_ptr[0], vss_ptr, 5) == 1);
    CHECK(secp256k1_frost_compute_pubshare(vrfy, &share_pk, 3, pk_ptr[0], vss_ptr, 5) == 1);

    /* pubkey_get */
    ecount = 0;
    CHECK(secp256k1_frost_pubkey_get(none, &full_agg_pk, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_get(none, NULL, &agg_pk) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_pubkey_get(none, &full_agg_pk, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_memcmp_var(&full_agg_pk, zeros68, sizeof(full_agg_pk)) == 0);

    /** Tweaking **/

    /* pubkey_tweak */
    ecount = 0;
    CHECK(secp256k1_frost_pubkey_tweak(none, &tweak_cache, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_tweak(sign, &tweak_cache, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_tweak(vrfy, &tweak_cache, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_tweak(vrfy, NULL, &agg_pk) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_pubkey_tweak(vrfy, &tweak_cache, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_pubkey_tweak(vrfy, &tweak_cache, &invalid_pk) == 0);
    CHECK(ecount == 3);

    CHECK(secp256k1_frost_pubkey_tweak(none, &tweak_cache, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_tweak(sign, &tweak_cache, &agg_pk) == 1);
    CHECK(secp256k1_frost_pubkey_tweak(vrfy, &tweak_cache, &agg_pk) == 1);

    /* tweak_add */
    {
        int (*tweak_func[2]) (const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_frost_tweak_cache *tweak_cache, const unsigned char *tweak32);
        tweak_func[0] = secp256k1_frost_pubkey_ec_tweak_add;
        tweak_func[1] = secp256k1_frost_pubkey_xonly_tweak_add;
        CHECK(secp256k1_frost_pubkey_tweak(ctx, &tweak_cache, &agg_pk) == 1);
        for (i = 0; i < 2; i++) {
            secp256k1_pubkey tmp_output_pk;
            secp256k1_frost_tweak_cache tmp_tweak_cache = tweak_cache;
            ecount = 0;
            CHECK((*tweak_func[i])(ctx, &tmp_output_pk, &tmp_tweak_cache, tweak) == 1);
            /* Reset tweak_cache */
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(none, &tmp_output_pk, &tmp_tweak_cache, tweak) == 1);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(sign, &tmp_output_pk, &tmp_tweak_cache, tweak) == 1);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &tmp_tweak_cache, tweak) == 1);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(vrfy, NULL, &tmp_tweak_cache, tweak) == 1);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, NULL, tweak) == 0);
            CHECK(ecount == 1);
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &tmp_tweak_cache, NULL) == 0);
            CHECK(ecount == 2);
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_tweak_cache = tweak_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &tmp_tweak_cache, max64) == 0);
            CHECK(ecount == 2);
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_tweak_cache = tweak_cache;
            /* Uninitialized tweak_cache */
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &invalid_tweak_cache, tweak) == 0);
            CHECK(ecount == 3);
            CHECK(frost_memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
        }
    }

    /** Session creation **/
    ecount = 0;
    CHECK(secp256k1_frost_nonce_gen(none, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, max64) == 1);
    CHECK(secp256k1_frost_nonce_gen(vrfy, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, max64) == 1);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, max64) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_frost_nonce_gen(sttc, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, max64) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_frost_nonce_gen(sign, NULL, &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, max64) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], NULL, session_id[0], &agg_share[0], msg, &agg_pk, max64) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], NULL, &agg_share[0], msg, &agg_pk, max64) == 0);
    CHECK(ecount == 4);
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    /* no seckey and session_id is 0 */
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], zeros68, NULL, msg, &agg_pk, max64) == 0);
    CHECK(ecount == 4);
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    /* session_id 0 is fine when a seckey is provided */
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], zeros68, &agg_share[0], msg, &agg_pk, max64) == 1);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], NULL, msg, &agg_pk, max64) == 1);
    CHECK(ecount == 4);
    /* invalid agg_share */
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &invalid_share, msg, &agg_pk, max64) == 0);
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], NULL, &agg_pk, max64) == 1);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, NULL, max64) == 1);
    CHECK(ecount == 5);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &invalid_pk, max64) == 0);
    CHECK(ecount == 6);
    CHECK(frost_memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], &agg_share[0], msg, &agg_pk, NULL) == 1);
    CHECK(ecount == 6);

    /* Every in-argument except session_id can be NULL */
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], NULL, NULL, NULL, NULL) == 1);
    CHECK(secp256k1_frost_nonce_gen(sign, &secnonce[1], &pubnonce[1], session_id[1], &agg_share[1], NULL, NULL, NULL) == 1);

    /** cleanup **/
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(sttc);
}

void run_frost_tests(void) {
    int i;

    for (i = 0; i < count; i++) {
        frost_simple_test();
    }
    frost_api_tests();
}

#endif
