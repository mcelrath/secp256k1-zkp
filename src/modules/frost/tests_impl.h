#ifndef SECP256K1_MODULE_FROST_TESTS_H
#define SECP256K1_MODULE_FROST_TESTS_H

#include "include/secp256k1_frost.h"
#include <secp256k1_musig.h>

void run_frost_tests(void) {
    unsigned char sk1[32];
    unsigned char sk2[32];
    unsigned char sk3[32];
    unsigned char pk1[32];
    unsigned char pk2[32];
    size_t participants[2];
    secp256k1_scalar coefficients1[2];
    secp256k1_scalar coefficients2[2];
    secp256k1_scalar coefficients3[2];
    secp256k1_xonly_pubkey commitments1[2];
    secp256k1_xonly_pubkey commitments2[2];
    secp256k1_xonly_pubkey commitments3[2];
    secp256k1_frost_share shares1[3];
    secp256k1_frost_share shares2[3];
    secp256k1_frost_share shares3[3];
    secp256k1_frost_share agg1, agg2, agg3;
    secp256k1_frost_share share_buf[3];
    secp256k1_xonly_pubkey key_buf[3];
    secp256k1_scalar l1, l2;
    secp256k1_scalar s1, s2;
    secp256k1_xonly_pubkey combined_pk;
    secp256k1_gej rj;
    secp256k1_ge rp;

    secp256k1_testrand256(sk1);
    secp256k1_testrand256(sk2);
    secp256k1_testrand256(sk3);
    /* Round 1.1, 1.2, 1.3, and 1.4 */
    CHECK(secp256k1_frost_keygen_init(ctx, coefficients1, commitments1, 2, 3, sk1));
    CHECK(secp256k1_frost_keygen_init(ctx, coefficients2, commitments2, 2, 3, sk2));
    CHECK(secp256k1_frost_keygen_init(ctx, coefficients3, commitments3, 2, 3, sk3));
    /* Round 2.1 */
    secp256k1_frost_generate_shares(shares1, coefficients1, 2, 3);
    secp256k1_frost_generate_shares(shares2, coefficients2, 2, 3);
    secp256k1_frost_generate_shares(shares3, coefficients3, 2, 3);
    /* Round 2.3 */
    share_buf[0] = shares1[0];
    share_buf[1] = shares2[0];
    share_buf[2] = shares3[0];
    secp256k1_frost_aggregate_shares(&agg1, share_buf, 3);
    share_buf[0] = shares1[1];
    share_buf[1] = shares2[1];
    share_buf[2] = shares3[1];
    secp256k1_frost_aggregate_shares(&agg2, share_buf, 3);
    share_buf[0] = shares1[2];
    share_buf[1] = shares2[2];
    share_buf[2] = shares3[2];
    secp256k1_frost_aggregate_shares(&agg3, share_buf, 3);
    /* Round 2.4 */
    key_buf[0] = commitments1[0];
    key_buf[1] = commitments2[0];
    key_buf[2] = commitments3[0];
    CHECK(secp256k1_frost_pubkey_combine(ctx, NULL, &combined_pk, key_buf, 3));

    /* Reconstruct secret */
    participants[0] = 1;
    participants[1] = 2;
    secp256k1_frost_lagrange_coefficient(&l1, participants, 2, 1);
    secp256k1_frost_lagrange_coefficient(&l2, participants, 2, 2);
    secp256k1_scalar_set_b32(&s1, agg1.data, NULL);
    secp256k1_scalar_set_b32(&s2, agg2.data, NULL);
    secp256k1_scalar_mul(&s1, &s1, &l1);
    secp256k1_scalar_mul(&s2, &s2, &l2);
    secp256k1_scalar_add(&s1, &s1, &s2);

    /* Test secret */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &s1);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_xonly_pubkey_save(&key_buf[0], &rp);
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, pk1, &key_buf[0]));
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, pk2, &combined_pk));
    CHECK(secp256k1_memcmp_var(pk1, pk2, sizeof(pk1)) == 0);
    secp256k1_scalar_clear(&s2);
    secp256k1_scalar_add(&s2, &s2, &coefficients1[0]);
    secp256k1_scalar_add(&s2, &s2, &coefficients2[0]);
    secp256k1_scalar_add(&s2, &s2, &coefficients3[0]);
    CHECK(secp256k1_scalar_eq(&s1, &s2));
}

#endif /* SECP256K1_MODULE_FROST_TESTS_H */
