#ifndef SECP256K1_FROST_H
#define SECP256K1_FROST_H

#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** This code is currently a work in progress. It's not secure nor stable.  IT
 * IS EXTREMELY DANGEROUS AND RECKLESS TO USE THIS MODULE IN PRODUCTION!

 * This module implements a modified version of Flexible Round-Optimized
 * Schnorr Threshold Signatures (FROST) by Chelsea Komlo and Ian Goldberg
 * (https://crysp.uwaterloo.ca/software/frost/). Signatures are compatible with
 * BIP-340 ("Schnorr"). There's an example C source file in the module's
 * directory (examples/frost.c) that demonstrates how it can be used.
 *
 * Following the convention used in the MuSig module, the API uses the singular
 * term "nonce" to refer to the two "nonces" used by the FROST scheme.
 */

/** Opaque data structures
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. If you
 *  need to convert to a format suitable for storage, transmission, or
 *  comparison, use the corresponding serialization and parsing functions.
 */

/** Opaque data structure that holds the y-coordinate of a polynomial share.
 *
 *  Guaranteed to be 32 bytes in size. It can be safely copied/moved.
 */
typedef struct {
    unsigned char data[32];
} secp256k1_frost_share;

/** Opaque data structure that holds a signer's _secret_ nonce.
 *
 *  Guaranteed to be 68 bytes in size.
 *
 *  WARNING: This structure MUST NOT be copied or read or written to directly. A
 *  signer who is online throughout the whole process and can keep this
 *  structure in memory can use the provided API functions for a safe standard
 *  workflow. See
 *  https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/ for
 *  more details about the risks associated with serializing or deserializing
 *  this structure.
 *
 *  We repeat, copying this data structure can result in nonce reuse which will
 *  leak the secret signing key.
 */
typedef struct {
    unsigned char data[68];
} secp256k1_frost_secnonce;

/** Opaque data structure that holds a signer's public nonce.
*
*  Guaranteed to be 132 bytes in size. It can be safely copied/moved. Serialized
*  and parsed with `frost_pubnonce_serialize` and `frost_pubnonce_parse`.
*/
typedef struct {
    unsigned char data[132];
} secp256k1_frost_pubnonce;

/** Opaque data structure that holds an aggregate public nonce.
 *
 *  Guaranteed to be 132 bytes in size. It can be safely copied/moved.
 *  Serialized and parsed with `frost_aggnonce_serialize` and
 *  `frost_aggnonce_parse`.
 */
typedef struct {
    unsigned char data[132];
} secp256k1_frost_aggnonce;

/** Opaque data structure that holds a FROST session.
 *
 *  This structure is not required to be kept secret for the signing protocol to
 *  be secure. Guaranteed to be 133 bytes in size. It can be safely
 *  copied/moved. No serialization and parsing functions.
 */
typedef struct {
    unsigned char data[133];
} secp256k1_frost_session;

/** Opaque data structure that holds a partial MuSig signature.
 *
 *  Guaranteed to be 36 bytes in size. Serialized and parsed with
 *  `frost_partial_sig_serialize` and `frost_partial_sig_parse`.
 */
typedef struct {
    unsigned char data[36];
} secp256k1_frost_partial_sig;

/** Parse a signer's public nonce.
 *
 *  Returns: 1 when the nonce could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:   nonce: pointer to a nonce object
 *  In:     in66: pointer to the 66-byte nonce to be parsed
 */
SECP256K1_API int secp256k1_frost_pubnonce_parse(
    const secp256k1_context* ctx,
    secp256k1_frost_pubnonce* nonce,
    const unsigned char *in66
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a signer's public nonce
 *
 *  Returns: 1 when the nonce could be serialized, 0 otherwise
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out66: pointer to a 66-byte array to store the serialized nonce
 *  In:    nonce: pointer to the nonce
 */
SECP256K1_API int secp256k1_frost_pubnonce_serialize(
    const secp256k1_context* ctx,
    unsigned char *out66,
    const secp256k1_frost_pubnonce* nonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse an aggregate public nonce.
 *
 *  Returns: 1 when the nonce could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:   nonce: pointer to a nonce object
 *  In:     in66: pointer to the 66-byte nonce to be parsed
 */
SECP256K1_API int secp256k1_frost_aggnonce_parse(
    const secp256k1_context* ctx,
    secp256k1_frost_aggnonce* nonce,
    const unsigned char *in66
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize an aggregate public nonce
 *
 *  Returns: 1 when the nonce could be serialized, 0 otherwise
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out66: pointer to a 66-byte array to store the serialized nonce
 *  In:    nonce: pointer to the nonce
 */
SECP256K1_API int secp256k1_frost_aggnonce_serialize(
    const secp256k1_context* ctx,
    unsigned char *out66,
    const secp256k1_frost_aggnonce* nonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a FROST partial signature
 *
 *  Returns: 1 when the signature could be serialized, 0 otherwise
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out32: pointer to a 32-byte array to store the serialized signature
 *  In:      sig: pointer to the signature
 */
SECP256K1_API int secp256k1_frost_partial_sig_serialize(
    const secp256k1_context* ctx,
    unsigned char *out32,
    const secp256k1_frost_partial_sig* sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a FROST partial signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:     sig: pointer to a signature object
 *  In:     in32: pointer to the 32-byte signature to be parsed
 *
 *  After the call, sig will always be initialized. If parsing failed or the
 *  encoded numbers are out of range, signature verification with it is
 *  guaranteed to fail for every message and public key.
 */
SECP256K1_API int secp256k1_frost_partial_sig_parse(
    const secp256k1_context* ctx,
    secp256k1_frost_partial_sig* sig,
    const unsigned char *in32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Derives a polynomial share and coefficient commitments
 *
 *  The share is derived deterministically from the input parameters. The
 *  private key belonging to the keypair will be used as the first coefficient
 *  of the polynomial used to generate the shares and commitments.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:            ctx: pointer to a context object initialized for
 *                        verification
 *  Out:  vss_commitment: the coefficient commitments. The length of this array
 *                        should be equal to the threshold (can be NULL).
 *                 share: pointer to the polynomial share
 *   In:    session_id32: a 32-byte session_id32 as explained above
 *               keypair: pointer to a keypair used to generate the polynomial
 *                        that derives the shares
 *                    pk: pointer to the public key of the share recipient
 *             threshold: the minimum number of shares required to produce a
 *                        signature
 */
SECP256K1_API int secp256k1_frost_share_gen(
    const secp256k1_context *ctx,
    secp256k1_pubkey *vss_commitment,
    secp256k1_frost_share *share,
    const unsigned char *session_id32,
    const secp256k1_keypair *keypair,
    const secp256k1_xonly_pubkey *pk,
    size_t threshold
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Aggregates shares
 *
 *  As part of the key generation protocol, each participant receives a share
 *  from each participant, including a share they "receive" from themselves.
 *  This function verifies those shares against their verifiable secret sharing
 *  ("VSS") commitments, aggregates the shares, and then aggregates the
 *  commitments to each participant's first polynomial coefficient to derive
 *  the aggregate public key.
 *
 *  This function outputs a vss_hash, which is a sha256 image of coefficient
 *  commitments of all participants. vss_commitments must be sorted by participant
 *  index, otherwise the vss_hash generated will be invalid.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise (which does NOT mean
 *           the resulting signature verifies).
 *  Args:         ctx: pointer to a context object
 *  Out:    agg_share: the aggregated share
 *           share_pk: the public verification share of the aggregated share
 *             agg_pk: the aggregated x-only public key
 *           vss_hash: sha256 image of the coefficient commitments
 *  In:        shares: all polynomial shares for the partcipant's index
 *    vss_commitments: coefficient commitments of all participants ordered by
 *                     index
 *           n_shares: the total number of shares
 *          threshold: the minimum number of shares required to produce a
 *                     signature
 *                 pk: the public key of the participant whose shares are being
 *                     aggregated
 */
SECP256K1_API int secp256k1_frost_share_agg(
    const secp256k1_context* ctx,
    secp256k1_frost_share *agg_share,
    secp256k1_pubkey *share_pk,
    secp256k1_xonly_pubkey *agg_pk,
    unsigned char *vss_hash,
    const secp256k1_frost_share * const* shares,
    const secp256k1_pubkey * const* vss_commitments,
    size_t n_shares,
    size_t threshold,
    const secp256k1_xonly_pubkey *pk
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(10);

/** Starts a signing session by generating a nonce
 *
 *  This function outputs a secret nonce that will be required for signing and a
 *  corresponding public nonce that is intended to be sent to other signers.
 *
 *  FROST, like MuSig, differs from regular Schnorr signing in that
 *  implementers _must_ take special care to not reuse a nonce. This can be
 *  ensured by following these rules:
 *
 *  1. Each call to this function must have a UNIQUE session_id32 that must NOT BE
 *     REUSED in subsequent calls to this function.
 *     If you do not provide a seckey, session_id32 _must_ be UNIFORMLY RANDOM
 *     AND KEPT SECRET (even from other signers). If you do provide a seckey,
 *     session_id32 can instead be a counter (that must never repeat!). However,
 *     it is recommended to always choose session_id32 uniformly at random.
 *  2. If you already know the seckey, message or aggregate public key
 *     cache, they can be optionally provided to derive the nonce and increase
 *     misuse-resistance. The extra_input32 argument can be used to provide
 *     additional data that does not repeat in normal scenarios, such as the
 *     current time.
 *  3. Avoid copying (or serializing) the secnonce. This reduces the possibility
 *     that it is used more than once for signing.
 *
 *  Remember that nonce reuse will leak the secret key!
 *  Note that using the same agg_share for multiple FROST sessions is fine.
 *
 *  Returns: 0 if the arguments are invalid and 1 otherwise
 *  Args:         ctx: pointer to a context object, initialized for signing
 *  Out:     secnonce: pointer to a structure to store the secret nonce
 *           pubnonce: pointer to a structure to store the public nonce
 *  In:  session_id32: a 32-byte session_id32 as explained above. Must be
 *                     unique to this call to secp256k1_frost_nonce_gen and
 *                     must be uniformly random unless you really know what you
 *                     are doing.
 *          agg_share: the aggregated share that will later be used for
 *                     signing, if already known (can be NULL)
 *              msg32: the 32-byte message that will later be signed, if
 *                     already known (can be NULL)
 *             agg_pk: the FROST-aggregated public key
 *      extra_input32: an optional 32-byte array that is input to the nonce
 *                     derivation function (can be NULL)
 */
SECP256K1_API int secp256k1_frost_nonce_gen(
    const secp256k1_context* ctx,
    secp256k1_frost_secnonce *secnonce,
    secp256k1_frost_pubnonce *pubnonce,
    const unsigned char *session_id32,
    const secp256k1_frost_share *agg_share,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *agg_pk,
    const unsigned char *extra_input32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Takes the public nonces of all signers and computes a session that is
 *  required for signing and verification of partial signatures.
 *
 *  Returns: 0 if the arguments are invalid or if some signer sent invalid
 *           pubnonces, 1 otherwise
 *  Args:          ctx: pointer to a context object, initialized for
 *                      verification
 *  Out:       session: pointer to a struct to store the session
 *  In:      pubnonces: array of pointers to public nonces sent by the signers
 *         n_pubnonces: number of elements in the pubnonces array. Must be
 *                      greater than 0.
 *               msg32: the 32-byte message to sign
 *              agg_pk: the FROST-aggregated public key
 *                  pk: the public key of the participant who will use the
 *                      session for signing
 *             pubkeys: array of pointers to public keys of the signers
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_nonce_process(
    const secp256k1_context* ctx,
    secp256k1_frost_session *session,
    const secp256k1_frost_pubnonce * const* pubnonces,
    size_t n_pubnonces,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *agg_pk,
    const secp256k1_xonly_pubkey *pk,
    const secp256k1_xonly_pubkey * const* pubkeys
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

/** Produces a partial signature
 *
 *  This function overwrites the given secnonce with zeros and will abort if given a
 *  secnonce that is all zeros. This is a best effort attempt to protect against nonce
 *  reuse. However, this is of course easily defeated if the secnonce has been
 *  copied (or serialized). Remember that nonce reuse will leak the secret key!
 *
 *  Returns: 0 if the arguments are invalid or the provided secnonce has already
 *           been used for signing, 1 otherwise
 *  Args:         ctx: pointer to a context object
 *  Out:  partial_sig: pointer to struct to store the partial signature
 *  In/Out:  secnonce: pointer to the secnonce struct created in
 *                     frost_nonce_gen that has been never used in a
 *                     partial_sign call before
 *  In:     agg_share: the aggregated share
 *            session: pointer to the session that was created with
 *                     frost_nonce_process
 */
SECP256K1_API int secp256k1_frost_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_frost_partial_sig *partial_sig,
    secp256k1_frost_secnonce *secnonce,
    const secp256k1_frost_share *agg_share,
    const secp256k1_frost_session *session
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verifies an individual signer's partial signature
 *
 *  The signature is verified for a specific signing session. In order to avoid
 *  accidentally verifying a signature from a different or non-existing signing
 *  session, you must ensure the following:
 *    1. The `pubnonces` includes the identical [TODO: FIX].
 *    2. The `pubkey` argument must be identical to the one sent by the signer
 *       before aggregating it with `frost_pubkey_agg` to create the
 *       `keyagg_cache`. [TODO: FIX]
 *    3. The `pubnonce` argument must be identical to the one sent by the signer
 *       before aggregating it with `frost_nonce_agg` and using the result to
 *       create the `session` with `frost_nonce_process` [TODO: FIX].
 *
 *  This function is essential when using protocols with adaptor signatures.
 *  However, it is not essential for regular FROST sessions, in the sense that if any
 *  partial signature does not verify, the full signature will not verify either, so the
 *  problem will be caught. But this function allows determining the specific party
 *  who produced an invalid signature.
 *
 *  Returns: 0 if the arguments are invalid or the partial signature does not
 *           verify, 1 otherwise
 *  Args         ctx: pointer to a context object, initialized for verification
 *  In:  partial_sig: pointer to partial signature to verify, sent by
 *                    the signer associated with `pubnonce` and `pubkey`
 *          pubnonce: public nonce of the signer in the signing session
 *          share_pk: public verification share of the signer in the signing
 *                    session
 *           session: pointer to the session that was created with
 *                    `frost_nonce_process`
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_partial_sig_verify(
    const secp256k1_context* ctx,
    const secp256k1_frost_partial_sig *partial_sig,
    const secp256k1_frost_pubnonce *pubnonce,
    const secp256k1_pubkey *share_pk,
    const secp256k1_frost_session *session
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Aggregates partial signatures
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise (which does NOT mean
 *           the resulting signature verifies).
 *  Args:         ctx: pointer to a context object
 *  Out:        sig64: complete (but possibly invalid) Schnorr signature
 *  In:       session: pointer to the session that was created with
 *                     frost_nonce_process
 *       partial_sigs: array of pointers to partial signatures to aggregate
 *             n_sigs: number of elements in the partial_sigs array. Must be
 *                     greater than 0.
 */
SECP256K1_API int secp256k1_frost_partial_sig_agg(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const secp256k1_frost_session *session,
    const secp256k1_frost_partial_sig * const* partial_sigs,
    size_t n_sigs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif
