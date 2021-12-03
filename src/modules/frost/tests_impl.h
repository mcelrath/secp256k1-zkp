#ifndef SECP256K1_MODULE_FROST_TESTS_H
#define SECP256K1_MODULE_FROST_TESTS_H

#include "include/secp256k1_frost.h"

 /* Number of public keys involved in creating the aggregate signature */
#define N_SIGNERS 5

 /* Threshold required in creating the aggregate signature */
#define THRESHOLD 3

struct signer_secrets_t {
    unsigned char sk[32];
};

void run_frost_tests(void) {
    struct signer_secrets_t signer_secrets[N_SIGNERS];
    unsigned char pk1[33];
    unsigned char pk2[33];
    unsigned char sig[64];
    unsigned char msg[32];
    unsigned char sk[32];
    unsigned char id[32];
    secp256k1_frost_partial_signature partial_sigs[THRESHOLD];
    size_t participants[THRESHOLD];
    size_t size = 33;
    secp256k1_pubkey pubcoeff[N_SIGNERS][THRESHOLD];
    secp256k1_pubkey pubkeys[N_SIGNERS];
    secp256k1_frost_share shares[N_SIGNERS][N_SIGNERS];
    secp256k1_frost_share agg_shares[N_SIGNERS];
    secp256k1_scalar l;
    secp256k1_scalar s1, s2;
    secp256k1_gej rj;
    secp256k1_ge rp;
    secp256k1_keypair keypair;
    secp256k1_frost_sign_session sign_sessions[THRESHOLD];
    secp256k1_xonly_pubkey combined_nonce;
    secp256k1_xonly_pubkey combined_pk;
    int i, j;

    /* Round 1.1, 1.2, 1.3, and 1.4 */
    for (i = 0; i < N_SIGNERS; i++) {
        secp256k1_testrand256(signer_secrets[i].sk);
        CHECK(secp256k1_frost_keygen_init(ctx, pubcoeff[i], shares[i], THRESHOLD, N_SIGNERS, signer_secrets[i].sk));
    }

    for (i = 0; i < N_SIGNERS; i++) {
        secp256k1_frost_share my_shares[N_SIGNERS];

        for (j = 0; j < N_SIGNERS; j++) {
            memcpy(&my_shares[j], &shares[j][i], sizeof(my_shares[j]));
        }
        /* TODO: sort pubkeys to determine index */
        CHECK(secp256k1_frost_keygen_finalize(ctx, NULL, &agg_shares[i], &combined_pk, my_shares, &pubcoeff[0][0], N_SIGNERS, THRESHOLD));
    }

    /* Reconstruct secret */
    for (i = 0; i < THRESHOLD; i++) {
        participants[i] = i+1;
    }
    secp256k1_scalar_clear(&s2);
    for (i = 0; i < THRESHOLD; i++) {
        secp256k1_frost_lagrange_coefficient(&l, participants, THRESHOLD, i+1);
        secp256k1_scalar_set_b32(&s1, agg_shares[i].data, NULL);
        secp256k1_scalar_mul(&s1, &s1, &l);
        secp256k1_scalar_add(&s2, &s2, &s1);
    }

    /* Test secret */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &s2);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(&pubkeys[0], &rp);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, pk1, &size, &pubkeys[0], SECP256K1_EC_COMPRESSED));
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, pk2, &combined_pk));
    CHECK(secp256k1_memcmp_var(&pk1[1], pk2, 32) == 0);

    /* Test signing */
    secp256k1_testrand256(msg);

    secp256k1_scalar_get_b32(sk, &s2);
    CHECK(secp256k1_keypair_create(ctx, &keypair, sk));
    CHECK(secp256k1_schnorrsig_sign(ctx, sig, msg, &keypair, NULL, NULL));
    CHECK(secp256k1_schnorrsig_verify(ctx, sig, msg, &combined_pk));

    /* Generate nonces */
    for (i = 0; i < THRESHOLD; i++) {
        secp256k1_testrand256(id);
        CHECK(secp256k1_frost_sign_init(ctx, &pubkeys[i], &sign_sessions[i], id, msg, &combined_pk, &agg_shares[i], i+1));
    }

    for (i = 0; i < THRESHOLD; i++) {
        CHECK(secp256k1_frost_partial_sign(ctx, NULL, &partial_sigs[i], &combined_nonce, &sign_sessions[i], pubkeys, THRESHOLD, participants));
    }

    /* combine sigs */
    CHECK(secp256k1_frost_aggregate_partial_sigs(ctx, sig, partial_sigs, &combined_nonce, THRESHOLD));
    CHECK(secp256k1_schnorrsig_verify(ctx, sig, msg, &combined_pk));
}

#endif /* SECP256K1_MODULE_FROST_TESTS_H */
