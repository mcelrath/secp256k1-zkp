/***********************************************************************
 * Copyright (c) 2021 Jesse Posner, Jonas Nick                         *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

/**
 * This file demonstrates how to use the FROST module to create a threshold signature.
 * Additionally, see the documentation in include/secp256k1_frost.h.
 */

#include <stdio.h>
#include <assert.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>
#include <secp256k1_frost.h>

struct signer_secrets {
    secp256k1_keypair keypair;
    secp256k1_frost_share agg_share;
    secp256k1_musig_secnonce secnonce;
};

struct signer {
    /* secp256k1_pubkey pubkey; */
    secp256k1_xonly_pubkey pubkey;
    secp256k1_musig_pubnonce pubnonce;
    secp256k1_musig_partial_sig partial_sig;
};

 /* Number of public keys involved in creating the aggregate signature */
#define N_SIGNERS 5

 /* Threshold required in creating the aggregate signature */
#define THRESHOLD 3

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
int create_shares(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, const secp256k1_musig_keyagg_cache *keyagg_cache) {
    int i;
    secp256k1_frost_share shares[N_SIGNERS][N_SIGNERS];
    secp256k1_pubkey pubcoeff[N_SIGNERS][THRESHOLD];

    for (i = 0; i < N_SIGNERS; i++) {
        if (!secp256k1_frost_share_gen(ctx, pubcoeff[i], shares[i], THRESHOLD, N_SIGNERS, &signer_secrets[i].keypair, keyagg_cache)) {
            return 0;
        }
    }

    for (i = 0; i < N_SIGNERS; i++) {
        int j;
        const secp256k1_frost_share *assigned_shares[N_SIGNERS];

        for (j = 0; j < N_SIGNERS; j++) {
            assigned_shares[j] = &shares[j][i];
        }
        if (!secp256k1_frost_share_agg(ctx, &signer_secrets[i].agg_share, assigned_shares, N_SIGNERS)) {
            return 0;
        }
    }

    return 1;
}

/* Sign a message hash with the given key pairs and store the result in sig */
int sign(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer, const unsigned char* msg32, unsigned char *sig64) {
    int i;
    const secp256k1_xonly_pubkey *pubkeys[N_SIGNERS];
    const secp256k1_musig_pubnonce *pubnonces[N_SIGNERS];
    const secp256k1_musig_partial_sig *partial_sigs[N_SIGNERS];
    /* The same for all signers */
    secp256k1_musig_keyagg_cache cache;
    secp256k1_musig_session session;
    size_t participants[THRESHOLD];

    for (i = 0; i < N_SIGNERS; i++) {
        FILE *frand;
        unsigned char seckey[32];
        unsigned char session_id[32];
        /* Create random session ID. It is absolutely necessary that the session ID
         * is unique for every call of secp256k1_musig_nonce_gen. Otherwise
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
        if (!secp256k1_musig_nonce_gen(ctx, &signer_secrets[i].secnonce, &signer[i].pubnonce, session_id, seckey, msg32, NULL, NULL)) {
            return 0;
        }
        pubkeys[i] = &signer[i].pubkey;
        pubnonces[i] = &signer[i].pubnonce;
    }

    for (i = 0; i < THRESHOLD; i++) {
        participants[i] = i+1;
    }
    if (!secp256k1_musig_pubkey_agg(ctx, NULL, NULL, &cache, pubkeys, N_SIGNERS)) {
        return 0;
    }

    /* Communication round 1: Exchange nonces */
    for (i = 0; i < THRESHOLD; i++) {
        secp256k1_musig_aggnonce agg_pubnonce;

        /* Aggregate nonce and initialize signer data */
        if (!secp256k1_musig_nonce_agg(ctx, &agg_pubnonce, pubnonces, THRESHOLD)) {
            return 0;
        }
        if (!secp256k1_musig_nonce_process(ctx, &session, &agg_pubnonce, msg32, &cache, NULL)) {
            return 0;
        }
        /* partial_sign will clear the secnonce by setting it to 0. That's because
         * you must _never_ reuse the secnonce (or use the same session_id to
         * create a secnonce). If you do, you effectively reuse the nonce and
         * leak the secret key. */
        if (!secp256k1_frost_partial_sign(ctx, &signer[i].partial_sig, &signer_secrets[i].secnonce, &signer_secrets[i].agg_share, &session, THRESHOLD, participants, i+1)) {
            return 0;
        }
        partial_sigs[i] = &signer[i].partial_sig;
    }
    /* Communication round 2: Exchange partial signatures */
    return secp256k1_musig_partial_sig_agg(ctx, sig64, &session, partial_sigs, THRESHOLD);
}

 int main(void) {
    secp256k1_context* ctx;
    int i;
    struct signer_secrets signer_secrets[N_SIGNERS];
    struct signer signers[N_SIGNERS];
    const secp256k1_xonly_pubkey *pubkeys_ptr[N_SIGNERS];
    secp256k1_musig_keyagg_cache cache;
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
        pubkeys_ptr[i] = &signers[i].pubkey;
    }
    printf("ok\n");
    printf("Combining public keys...");
    if (!secp256k1_musig_pubkey_agg(ctx, NULL, &agg_pk, &cache, pubkeys_ptr, N_SIGNERS)) {
        printf("FAILED\n");
        return 1;
    }
    printf("Creating shares......");
    if (!create_shares(ctx, signer_secrets, &cache)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Signing message.........");
    if (!sign(ctx, signer_secrets, signers, msg, sig)) {
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
