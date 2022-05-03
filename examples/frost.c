/***********************************************************************
 * Copyright (c) 2021, 2022 Jesse Posner                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

/**
 * This file demonstrates how to use the FROST module to create a threshold
 * signature. Additionally, see the documentation in include/secp256k1_frost.h.
 */

#include <stdio.h>
#include <assert.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_frost.h>

 /* Number of public keys involved in creating the aggregate signature */
#define N_SIGNERS 5

 /* Threshold required in creating the aggregate signature */
#define THRESHOLD 3

struct signer_secrets {
    secp256k1_keypair keypair;
    secp256k1_frost_share agg_share;
    secp256k1_frost_secnonce secnonce;
};

struct signer {
    secp256k1_xonly_pubkey pubkey;
    secp256k1_frost_pubnonce pubnonce;
    secp256k1_frost_partial_sig partial_sig;
    secp256k1_pubkey pubcoeff[THRESHOLD];
    unsigned char vss_hash[32];
};

 /* Create a key pair and store it in seckey and pubkey */
int create_keypair(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer) {
    unsigned char seckey[32];
    FILE *frand = fopen("/dev/urandom", "r");
    if (frand == NULL) {
        return 0;
    }
    do {
        if(!fread(seckey, sizeof(seckey), 1, frand)) {
             fclose(frand);
             return 0;
         }
    /* The probability that this not a valid secret key is approximately 2^-128 */
    } while (!secp256k1_ec_seckey_verify(ctx, seckey));
    fclose(frand);
    if (!secp256k1_keypair_create(ctx, &signer_secrets->keypair, seckey)) {
        return 0;
    }
    if (!secp256k1_keypair_xonly_pub(ctx, &signer->pubkey, NULL, &signer_secrets->keypair)) {
        return 0;
    }
    return 1;
}

 /* Create shares and coefficient commitments */
int create_shares(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer, secp256k1_xonly_pubkey *agg_pk) {
    int i;
    secp256k1_frost_share shares[N_SIGNERS][N_SIGNERS];
    const secp256k1_pubkey *pubcoeffs[N_SIGNERS];

    for (i = 0; i < N_SIGNERS; i++) {
        /* Generate a polynomial share for each participant */
        if (!secp256k1_frost_share_gen(ctx, signer[i].pubcoeff, shares[i], THRESHOLD, N_SIGNERS, &signer_secrets[i].keypair)) {
            return 0;
        }
        pubcoeffs[i] = signer[i].pubcoeff;
    }

    /* KeyGen communication round 1: exchange shares, nonce commitments, and
     * coefficient commitments */
    for (i = 0; i < N_SIGNERS; i++) {
        int j;
        const secp256k1_frost_share *assigned_shares[N_SIGNERS];

        /* Each participant receives a share from each participant (including
         * themselves) corresponding to their index. */
        for (j = 0; j < N_SIGNERS; j++) {
            assigned_shares[j] = &shares[j][i];
        }
        /* Each participant aggregates the shares they received. */
        if (!secp256k1_frost_share_agg(ctx, &signer_secrets[i].agg_share, agg_pk, signer[i].vss_hash, assigned_shares, pubcoeffs, N_SIGNERS, THRESHOLD, i+1)) {
            return 0;
        }
    }

    return 1;
}

/* Sign the VSS commitments */
int sign_vss(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer, unsigned char sigs[N_SIGNERS][64]) {
    int i;

    for (i = 0; i < N_SIGNERS; i++) {
        FILE *frand;
        unsigned char session_id[32];

        frand = fopen("/dev/urandom", "r");
        if(frand == NULL) {
            return 0;
        }
        if (!fread(session_id, 32, 1, frand)) {
            fclose(frand);
            return 0;
        }
        fclose(frand);

        if (!secp256k1_schnorrsig_sign32(ctx, sigs[i], signer[i].vss_hash, &signer_secrets[i].keypair, session_id)) {
            return 0;
        }
    }

    return 1;
}

/* Sign a message hash with the given threshold and aggregate shares and store
 * the result in sig */
int sign(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer, const unsigned char* msg32, secp256k1_xonly_pubkey *agg_pk, unsigned char *sig64) {
    uint16_t i;
    const secp256k1_frost_pubnonce *pubnonces[N_SIGNERS];
    const secp256k1_frost_partial_sig *partial_sigs[N_SIGNERS];
    /* The same for all signers */
    secp256k1_frost_session session;

    for (i = 0; i < N_SIGNERS; i++) {
        FILE *frand;
        unsigned char seckey[32];
        unsigned char session_id[32];
        /* Create random session ID. It is absolutely necessary that the session ID
         * is unique for every call of secp256k1_frost_nonce_gen. Otherwise
         * it's trivial for an attacker to extract the secret key! */
        frand = fopen("/dev/urandom", "r");
        if(frand == NULL) {
            return 0;
        }
        if (!fread(session_id, 32, 1, frand)) {
            fclose(frand);
            return 0;
        }
        fclose(frand);
        if (!secp256k1_keypair_sec(ctx, seckey, &signer_secrets[i].keypair)) {
            return 0;
        }
        /* Initialize session and create secret nonce for signing and public
         * nonce to send to the other signers. */
        if (!secp256k1_frost_nonce_gen(ctx, &signer_secrets[i].secnonce, &signer[i].pubnonce, session_id, i+1, &signer_secrets[i].agg_share, msg32, NULL, NULL)) {
            return 0;
        }
        pubnonces[i] = &signer[i].pubnonce;
    }

    /* Signing communication round 1: Exchange nonces */
    for (i = 0; i < THRESHOLD; i++) {
        secp256k1_frost_aggnonce agg_pubnonce;

        if (!secp256k1_frost_nonce_agg(ctx, &agg_pubnonce, pubnonces, THRESHOLD)) {
            return 0;
        }

        if (!secp256k1_frost_nonce_process(ctx, &session, &agg_pubnonce, pubnonces, THRESHOLD, msg32, agg_pk, i+1)) {
            return 0;
        }
        /* partial_sign will clear the secnonce by setting it to 0. That's because
         * you must _never_ reuse the secnonce (or use the same session_id to
         * create a secnonce). If you do, you effectively reuse the nonce and
         * leak the secret key. */
        if (!secp256k1_frost_partial_sign(ctx, &signer[i].partial_sig, &signer_secrets[i].secnonce, &signer_secrets[i].agg_share, &session)) {
            return 0;
        }
        partial_sigs[i] = &signer[i].partial_sig;
    }
    /* Signing communication round 2: Exchange partial signatures */
    return secp256k1_frost_partial_sig_agg(ctx, sig64, &session, partial_sigs, THRESHOLD);
}

int main(void) {
    secp256k1_context* ctx;
    int i;
    struct signer_secrets signer_secrets[N_SIGNERS];
    struct signer signers[N_SIGNERS];
    unsigned char sigs[N_SIGNERS][64];
    secp256k1_xonly_pubkey agg_pk;
    unsigned char msg[32] = "this_could_be_the_hash_of_a_msg!";
    unsigned char sig[64];

    /* Create a context for signing and verification */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    printf("Creating key pairs......");
    for (i = 0; i < N_SIGNERS; i++) {
        if (!create_keypair(ctx, &signer_secrets[i], &signers[i])) {
            printf("FAILED\n");
            return 1;
        }
    }
    printf("ok\n");
    printf("Creating shares......");
    if (!create_shares(ctx, signer_secrets, signers, &agg_pk)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Signing VSS proofs......");
    if (!sign_vss(ctx, signer_secrets, signers, sigs)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Verifying VSS proof signatures.....");
    for (i = 0; i < N_SIGNERS; i++) {
        if (!secp256k1_schnorrsig_verify(ctx, sigs[i], signers[0].vss_hash, 32, &signers[i].pubkey)) {
            printf("FAILED\n");
            return 1;
        }
    }
    printf("ok\n");
    printf("Signing message with FROST.........");
    if (!sign(ctx, signer_secrets, signers, msg, &agg_pk, sig)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Verifying signature.....");
    if (!secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &agg_pk)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    secp256k1_context_destroy(ctx);
    return 0;
}
