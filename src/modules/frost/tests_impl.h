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

void run_frost_tests(void) {
    int i;

    for (i = 0; i < count; i++) {
        frost_simple_test();
    }
}

#endif
