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
    secp256k1_frost_partial_sig partial_sig[5];
    const secp256k1_frost_partial_sig *partial_sig_ptr[5];
    secp256k1_frost_partial_sig invalid_partial_sig;
    const secp256k1_frost_partial_sig *invalid_partial_sig_ptr[5];
    unsigned char sk[5][32];
    secp256k1_keypair keypair[5];
    secp256k1_keypair invalid_keypair;
    unsigned char max64[64];
    unsigned char zeros68[68] = { 0 };
    unsigned char session_id[5][32];
    secp256k1_frost_secnonce invalid_secnonce;
    secp256k1_frost_pubnonce pubnonce[5];
    const secp256k1_frost_pubnonce *pubnonce_ptr[5];
    secp256k1_frost_pubnonce inf_pubnonce[5];
    const secp256k1_frost_pubnonce *inf_pubnonce_ptr[5];
    secp256k1_frost_pubnonce invalid_pubnonce;
    const secp256k1_frost_pubnonce *invalid_pubnonce_ptr[1];
    unsigned char msg[32];
    secp256k1_frost_session invalid_session;
    secp256k1_xonly_pubkey pk[5];
    const secp256k1_xonly_pubkey *pk_ptr[5];
    secp256k1_xonly_pubkey invalid_pk;
    unsigned char tweak[32];
    unsigned char sec_adaptor[32];
    secp256k1_pubkey adaptor;
    secp256k1_pubkey vss_commitment[5][3];
    const secp256k1_pubkey *vss_ptr[5];
    secp256k1_frost_share share[5][5];
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
    memset(&invalid_keypair, 0, sizeof(invalid_keypair));
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_secnonce, 0, sizeof(invalid_secnonce));
    memset(&invalid_partial_sig, 0, sizeof(invalid_partial_sig));
    frost_pubnonce_summing_to_inf(inf_pubnonce);
    /* Simulate structs being uninitialized by setting it to 0s. We don't want
     * to produce undefined behavior by actually providing uninitialized
     * structs. */
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_pubnonce, 0, sizeof(invalid_pubnonce));
    memset(&invalid_session, 0, sizeof(invalid_session));

    secp256k1_testrand256(sec_adaptor);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(tweak);
    CHECK(secp256k1_ec_pubkey_create(ctx, &adaptor, sec_adaptor) == 1);
    for (i = 0; i < 5; i++) {
        pk_ptr[i] = &pk[i];
        pubnonce_ptr[i] = &pubnonce[i];
        inf_pubnonce_ptr[i] = &inf_pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        invalid_partial_sig_ptr[i] = &partial_sig[i];
        vss_ptr[i] = vss_commitment[i];
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        CHECK(create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
    }
    invalid_pubnonce_ptr[0] = &invalid_pubnonce;
    invalid_partial_sig_ptr[0] = &invalid_partial_sig;

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
            CHECK(memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], NULL, pk_ptr[j], 3) == 0);
            CHECK(ecount == (i*35)+(j*7)+3);
            CHECK(memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], NULL, 3) == 0);
            CHECK(ecount == (i*35)+(j*7)+4);
            CHECK(memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], &invalid_pk, 3) == 0);
            CHECK(ecount == (i*35)+(j*7)+5);
            CHECK(memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 0) == 0);
            CHECK(ecount == (i*35)+(j*7)+6);
            CHECK(memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);
            CHECK(secp256k1_frost_share_gen(vrfy, NULL, &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 0) == 0);
            CHECK(ecount == (i*35)+(j*7)+7);
            CHECK(memcmp_and_randomize(share[i][j].data, zeros68, sizeof(share[i][j].data)) == 0);

            CHECK(secp256k1_frost_share_gen(none, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(sign, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 3) == 1);
            CHECK(secp256k1_frost_share_gen(vrfy, vss_commitment[i], &share[i][j], session_id[i], &keypair[i], pk_ptr[j], 3) == 1);
        }
    }
    CHECK(ecount == 175);
}

void run_frost_tests(void) {
    int i;

    for (i = 0; i < count; i++) {
        frost_simple_test();
    }
    frost_api_tests();
}

#endif
