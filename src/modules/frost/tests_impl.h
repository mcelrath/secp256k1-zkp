#ifndef SECP256K1_MODULE_FROST_TESTS_H
#define SECP256K1_MODULE_FROST_TESTS_H

#include "include/secp256k1_frost.h"
#include <secp256k1_musig.h>

 /* Number of public keys involved in creating the aggregate signature */
#define N_SIGNERS 3

 /* Threshold required in creating the aggregate signature */
#define THRESHOLD 2

void run_frost_tests(void) {
    /* TODO: c.f. musig, example.c */
    unsigned char pk1[33];
    unsigned char pk2[33];
    unsigned char sig[64];
    unsigned char msg[32];
    unsigned char id[32];
    unsigned char sk[32];
    unsigned char p_sigs[THRESHOLD][32];
    size_t participants[THRESHOLD];
    size_t size = 33;
    secp256k1_scalar privcoeff[N_SIGNERS][THRESHOLD];
    secp256k1_pubkey pubcoeff[N_SIGNERS][THRESHOLD];
    secp256k1_pubkey pubkeys[N_SIGNERS];
    secp256k1_frost_share shares[N_SIGNERS][N_SIGNERS];
    secp256k1_frost_share agg_shares[N_SIGNERS];
    secp256k1_scalar l;
    secp256k1_scalar s1, s2;
    secp256k1_gej rj;
    secp256k1_ge rp;
    secp256k1_keypair keypair;
    secp256k1_frost_secnonce k;
    secp256k1_frost_keygen_session sessions[N_SIGNERS];
    int i, j;

    /* Round 1.1, 1.2, 1.3, and 1.4 */
    for (i = 0; i < N_SIGNERS; i++) {
        secp256k1_testrand256(sk);
        CHECK(secp256k1_frost_keygen_init(ctx, &sessions[i], privcoeff[i], pubcoeff[i], THRESHOLD, N_SIGNERS, i+1, sk));
        pubkeys[i] = sessions[i].coeff_pk;
    }
    /* Round 2.4 */
    for (i = 0; i < N_SIGNERS; i++) {
        CHECK(secp256k1_frost_pubkey_combine(ctx, NULL, &sessions[i], pubkeys));
    }
    /* Round 2.1 */
    for (i = 0; i < N_SIGNERS; i++) {
        secp256k1_frost_generate_shares(shares[i], privcoeff[i], &sessions[i]);
    }
    /* Round 2.3 */
    for (i = 0; i < N_SIGNERS; i++) {
        secp256k1_frost_share rec_shares[N_SIGNERS];

        for (j = 0; j < N_SIGNERS; j++) {
            rec_shares[j] = shares[j][sessions[i].my_index - 1];
        }

        /* TODO: pull participant share from session */
        secp256k1_frost_aggregate_shares(&agg_shares[i], rec_shares, &sessions[i]);
    }

    /* Reconstruct secret */
    for (i = 0; i < THRESHOLD; i++) {
        participants[i] = sessions[i].my_index;
    }
    secp256k1_scalar_clear(&s2);
    for (i = 0; i < THRESHOLD; i++) {
        secp256k1_frost_lagrange_coefficient(&l, participants, THRESHOLD, sessions[i].my_index);
        secp256k1_scalar_set_b32(&s1, agg_shares[i].data, NULL);
        secp256k1_scalar_mul(&s1, &s1, &l);
        secp256k1_scalar_add(&s2, &s2, &s1);
    }

    /* Test secret */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &s2);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(&pubkeys[0], &rp);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, pk1, &size, &pubkeys[0], SECP256K1_EC_COMPRESSED));
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, pk2, &sessions[0].combined_pk));
    CHECK(secp256k1_memcmp_var(&pk1[1], pk2, 32) == 0);
    secp256k1_scalar_clear(&s1);
    for (i = 0; i < N_SIGNERS; i++) {
        secp256k1_scalar_add(&s1, &s1, &privcoeff[i][0]);
    }
    CHECK(secp256k1_scalar_eq(&s1, &s2));

    /* Test signing */
    secp256k1_testrand256(msg);

    secp256k1_scalar_get_b32(sk, &s1);
    CHECK(secp256k1_keypair_create(ctx, &keypair, sk));
    CHECK(secp256k1_schnorrsig_sign(ctx, sig, msg, &keypair, NULL, NULL));
    CHECK(secp256k1_schnorrsig_verify(ctx, sig, msg, &sessions[0].combined_pk));

    /* Generate nonces */
    /* TODO: need a noncegen session object */
    /* TODO: use separate ID for each participant */
    secp256k1_testrand256(id);
    for (i = 0; i < THRESHOLD; i++) {
        secp256k1_nonce_function_frost(&k, id, agg_shares[i].data, msg, pk2, frost_algo, 9, NULL);
        secp256k1_scalar_set_b32(&s1, k.data, NULL);
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &s1);
        secp256k1_ge_set_gej(&rp, &rj);
        secp256k1_pubkey_save(&pubkeys[i], &rp);
    }
    sessions[0].n_signers = THRESHOLD;
    CHECK(secp256k1_frost_pubkey_combine(ctx, NULL, &sessions[0], pubkeys));
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, pk2, &sessions[0].combined_pk));
    /* sign */
    for (i = 0; i < THRESHOLD; i++) {
        /* compute challenge hash */
        secp256k1_schnorrsig_challenge(&s2, pk2, msg, &pk1[1]);

        secp256k1_scalar_set_b32(&s1, agg_shares[i].data, NULL);
        secp256k1_frost_lagrange_coefficient(&l, participants, THRESHOLD, sessions[i].my_index);
        secp256k1_scalar_mul(&s1, &s1, &l);
        secp256k1_scalar_mul(&s2, &s2, &s1);
        CHECK(secp256k1_xonly_pubkey_serialize(ctx, pk2, &sessions[0].combined_pk));
        secp256k1_nonce_function_frost(&k, id, agg_shares[i].data, msg, &pk1[1], frost_algo, 9, NULL);
        secp256k1_scalar_set_b32(&s1, k.data, NULL);
        if (sessions[0].pk_parity) {
            secp256k1_scalar_negate(&s1, &s1);

        }
        secp256k1_scalar_add(&s2, &s2, &s1);
        secp256k1_scalar_get_b32(p_sigs[i], &s2);
    }
    /* combine sigs */
    secp256k1_scalar_clear(&s1);
    for (i = 0; i < THRESHOLD; i++) {
        secp256k1_scalar_set_b32(&s2, p_sigs[i], NULL);
        secp256k1_scalar_add(&s1, &s1, &s2);
    }
    secp256k1_scalar_get_b32(&sig[32], &s1);
    memcpy(&sig[0], pk2, 32);

    CHECK(secp256k1_schnorrsig_verify(ctx, sig, msg, &sessions[1].combined_pk));
}

#endif /* SECP256K1_MODULE_FROST_TESTS_H */
