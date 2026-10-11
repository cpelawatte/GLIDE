/*
 * device_auth.c — ECQV+DID device authentication implementation.
 *
 * Measurement instrumentation:
 *   ENERGEST blocks mark the authentication window for energy measurement.
 *   RTIMER_NOW() calls mark latency measurement points.
 *   ROM/RAM footprint measured via msp430-size on the compiled binary.
 *
 * Crypto dependencies:
 *   - micro-ecc (uECC) for P-256 ECDSA sign/verify and ECDH
 *   - bundled sha256_impl.c for SHA-256, used in streaming mode
 *   - Contiki-NG os/lib/cbor.h for CBOR encoding/decoding
 */

#include "device_auth.h"
#include "credentials.h"
#include "hkdf_sha256.h"

#include "contiki.h"
#include "sys/energest.h"
#include "sys/rtimer.h"
#include "os/lib/cbor.h"
#include "os/net/security/micro-ecc/uECC.h"
#include "sha256_impl.h"

#include <string.h>
#include <stdio.h>
#include "sys/log.h"
#define LOG_MODULE "DeviceAuth"
#define LOG_LEVEL  LOG_LEVEL_INFO

/* ---------------------------------------------------------------------------
 * CBOR message type tags (must match Python cbor_codec.py)
 * --------------------------------------------------------------------------- */
#define PROTOCOL_VERSION    1
#define MSG_EDHOC_1         0x05
#define MSG_EDHOC_2         0x06

/* CBOR map keys (must match Python cbor_codec.py) */
#define KEY_VERSION         0
#define KEY_TYPE            1
#define KEY_CERT_INFO       3
#define KEY_R               4
#define KEY_SIGNATURE       7
#define KEY_EPHEMERAL       8
#define KEY_NONCE_D         9
#define KEY_NONCE_G         10

/* ---------------------------------------------------------------------------
 * Streaming SHA-256.
 * Every hash in this file is computed by feeding the pieces from where they
 * already are (init -> update ... -> final) instead of first copying them
 * into one large buffer: same bytes, same digest, far less stack. These
 * three wrappers are the only place that names the SHA-256 implementation,
 * so the backend can be swapped in one place.
 * --------------------------------------------------------------------------- */
static void hash_init(sha256_impl_ctx_t *ctx)
{
    sha256_impl_init(ctx);
}

static void hash_update(sha256_impl_ctx_t *ctx, const uint8_t *data, size_t len)
{
    sha256_impl_update(ctx, data, len);
}

static void hash_final(sha256_impl_ctx_t *ctx, uint8_t *digest)
{
    sha256_impl_final(ctx, digest);
}

/* ---------------------------------------------------------------------------
 * ECDSA over a precomputed 32-byte SHA-256 digest, using micro-ecc.
 * Signature is 64 bytes (r||s).
 * public_key_uncompressed: 64 bytes (x||y), no 0x04 prefix.
 * --------------------------------------------------------------------------- */
static int ecdsa_sign_hash(const uint8_t *private_key, const uint8_t *digest,
                           uint8_t *signature)
{
    if(!uECC_sign(private_key, digest, 32, signature, uECC_secp256r1())) {
        return AUTH_ERR_CRYPTO;
    }
    return AUTH_OK;
}

static int ecdsa_verify_hash(const uint8_t *public_key_uncompressed,
                             const uint8_t *digest, const uint8_t *signature)
{
    if(!uECC_verify(public_key_uncompressed, digest, 32, signature,
                    uECC_secp256r1())) {
        return AUTH_ERR_VERIFY;
    }
    return AUTH_OK;
}

/* ---------------------------------------------------------------------------
 * Decompress 33-byte compressed point to 64-byte uncompressed (x||y).
 * --------------------------------------------------------------------------- */
static void decompress_point(const uint8_t *compressed, uint8_t *uncompressed)
{
    uECC_Curve curve = uECC_secp256r1();
    uECC_decompress(compressed, uncompressed, curve);
}

/* ---------------------------------------------------------------------------
 * device_auth_build_msg1
 *
 * Builds EDHOC MSG_1 using pre-provisioned credentials from credentials.h.
 * Measures energy and latency via ENERGEST and RTIMER.
 * Returns number of bytes written on success, negative error code on failure.
 * --------------------------------------------------------------------------- */
int device_auth_build_msg1(device_auth_state_t *state,
                            uint8_t *buf, size_t buf_len)
{
    uECC_Curve curve = uECC_secp256r1();
    uint8_t E_d_uncompressed[64];
    uint8_t E_d_compressed[33];
    uint8_t nonce_d[AUTH_NONCE_LEN];
    uint8_t digest[32];
    uint8_t signature[AUTH_SIGNATURE_LEN];
    cbor_writer_state_t cbor;
    rtimer_clock_t t_start, t_end;
    size_t msg1_len;
    int ret;
    int i;

    t_start = RTIMER_NOW();
    ENERGEST_ON(ENERGEST_TYPE_CPU);

    /* Step 1: Generate ephemeral keypair */
    if(!uECC_make_key(E_d_uncompressed, state->e_d, curve)) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_CRYPTO;
    }
    uECC_compress(E_d_uncompressed, E_d_compressed, curve);

    /* Step 2: Generate device nonce (fixed pattern for simulation) */
    for(i = 0; i < AUTH_NONCE_LEN; i++) {
        nonce_d[i] = (uint8_t)(i ^ 0xA5);
    }

    /* Step 3: Hash the signed content E_d || R || cert_info || nonce_d || Q_gw
     * piece by piece (no signing buffer). state->msg1_hash serves as scratch
     * here; it is re-initialised for MSG_1 in Step 6.
     *
     * Q_gw binds the signature to the intended gateway, so a captured MSG_1
     * is rejected by any other gateway pinning the same issuer. Q_gw is
     * pre-provisioned on both sides and is NOT transmitted: zero wire cost. */
    hash_init(&state->msg1_hash);
    hash_update(&state->msg1_hash, E_d_compressed, 33);
    hash_update(&state->msg1_hash, DEVICE_CERT_R, DEVICE_CERT_R_LEN);
    hash_update(&state->msg1_hash, DEVICE_CERT_INFO, DEVICE_CERT_INFO_LEN);
    hash_update(&state->msg1_hash, nonce_d, AUTH_NONCE_LEN);
    hash_update(&state->msg1_hash, GATEWAY_PUBLIC_KEY, GATEWAY_PUBLIC_KEY_LEN);
    hash_final(&state->msg1_hash, digest);

    /* Step 4: Sign with device long-term private key d */
    ret = ecdsa_sign_hash(DEVICE_PRIVATE_KEY, digest, signature);
    if(ret != AUTH_OK) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return ret;
    }

    /* Step 5: CBOR-encode MSG_1 */
    cbor_init_writer(&cbor, buf, buf_len);
    cbor_open_map(&cbor);

    cbor_write_unsigned(&cbor, KEY_VERSION);
    cbor_write_unsigned(&cbor, PROTOCOL_VERSION);

    cbor_write_unsigned(&cbor, KEY_TYPE);
    cbor_write_unsigned(&cbor, MSG_EDHOC_1);

    cbor_write_unsigned(&cbor, KEY_CERT_INFO);
    cbor_write_data(&cbor, DEVICE_CERT_INFO, DEVICE_CERT_INFO_LEN);

    cbor_write_unsigned(&cbor, KEY_R);
    cbor_write_data(&cbor, DEVICE_CERT_R, DEVICE_CERT_R_LEN);

    cbor_write_unsigned(&cbor, KEY_SIGNATURE);
    cbor_write_data(&cbor, signature, AUTH_SIGNATURE_LEN);

    cbor_write_unsigned(&cbor, KEY_EPHEMERAL);
    cbor_write_data(&cbor, E_d_compressed, 33);

    cbor_write_unsigned(&cbor, KEY_NONCE_D);
    cbor_write_data(&cbor, nonce_d, AUTH_NONCE_LEN);

    cbor_close_map(&cbor);
    msg1_len = cbor_end_writer(&cbor);

    if(msg1_len == 0) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_CBOR;
    }
    if(msg1_len > AUTH_MSG1_MAX_LEN) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_BUFFER_SMALL;
    }

    /* Step 6: Absorb MSG_1 once. process_msg2 copies this state for both
     * hashes that start with MSG_1 (signature check and transcript). */
    hash_init(&state->msg1_hash);
    hash_update(&state->msg1_hash, buf, msg1_len);

    ENERGEST_OFF(ENERGEST_TYPE_CPU);
    t_end = RTIMER_NOW();

    LOG_INFO("[AUTH] MSG_1 built: %u bytes, %lu rtimer ticks\n",
           (unsigned)msg1_len,
           (unsigned long)(t_end - t_start));

    return (int)msg1_len;
}

/* ---------------------------------------------------------------------------
 * device_auth_process_msg2
 *
 * Parses EDHOC MSG_2, verifies gateway signature, performs ECDH,
 * derives 16-byte session key via HKDF-SHA256.
 * Returns AUTH_OK on success, negative error code on failure.
 * --------------------------------------------------------------------------- */
int device_auth_process_msg2(device_auth_state_t *state,
                              const uint8_t *msg2, size_t msg2_len,
                              uint8_t *session_key)
{
    uECC_Curve curve = uECC_secp256r1();
    cbor_reader_state_t reader;
    /* E_g, nonce_g and the signature are used in place inside msg2:
     * cbor_read_data() returns pointers into the input buffer, which stays
     * valid for this whole call. Nothing is copied out. */
    const uint8_t *E_g_compressed = NULL;
    const uint8_t *nonce_g = NULL;
    const uint8_t *sig_g = NULL;
    uint8_t point[64];          /* uncompressed point: first Q_gw, then E_g */
    uint8_t shared_secret[32];
    uint8_t digest[32];         /* signature-check digest, then the HKDF salt */
    sha256_impl_ctx_t ctx;
    static const uint8_t HKDF_INFO[] = "edhoc-subset-v1-session-key";
    rtimer_clock_t t_start, t_end;
    size_t map_len;
    int ret;
    size_t i;

    ENERGEST_ON(ENERGEST_TYPE_CPU);
    t_start = RTIMER_NOW();

    /* Parse MSG_2 CBOR map */
    cbor_init_reader(&reader, msg2, msg2_len);
    map_len = cbor_read_map(&reader);
    if(map_len == SIZE_MAX) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_CBOR;
    }

    for(i = 0; i < map_len; i++) {
        uint64_t key = 0;
        cbor_read_unsigned(&reader, &key);

        if(key == KEY_EPHEMERAL) {
            size_t dlen = 0;
            const uint8_t *d = cbor_read_data(&reader, &dlen);
            if(d && dlen == 33) {
                E_g_compressed = d;
            }
        } else if(key == KEY_NONCE_G) {
            size_t dlen = 0;
            const uint8_t *d = cbor_read_data(&reader, &dlen);
            if(d && dlen == AUTH_NONCE_LEN) {
                nonce_g = d;
            }
        } else if(key == KEY_SIGNATURE) {
            size_t dlen = 0;
            const uint8_t *d = cbor_read_data(&reader, &dlen);
            if(d && dlen == AUTH_SIGNATURE_LEN) {
                sig_g = d;
            }
        } else {
            /* Skip version and type fields */
            uint64_t dummy = 0;
            cbor_read_unsigned(&reader, &dummy);
        }
    }

    if(!E_g_compressed || !nonce_g || !sig_g) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_CBOR;
    }

    /* Verify gateway signature over (MSG_1 || E_g || nonce_g): start from
     * the stored MSG_1 hash state and add the two new pieces. */
    ctx = state->msg1_hash;
    hash_update(&ctx, E_g_compressed, 33);
    hash_update(&ctx, nonce_g, AUTH_NONCE_LEN);
    hash_final(&ctx, digest);

    decompress_point(GATEWAY_PUBLIC_KEY, point);
    ret = ecdsa_verify_hash(point, digest, sig_g);
    if(ret != AUTH_OK) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return ret;
    }

    /* ECDH: shared_secret = e_d * E_g */
    decompress_point(E_g_compressed, point);
    if(!uECC_shared_secret(point, state->e_d, shared_secret, curve)) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_CRYPTO;
    }

    /* HKDF: session_key = HKDF(salt = SHA256(MSG1||MSG2), IKM = shared_secret).
     * The transcript hash also starts from the stored MSG_1 state. */
    ctx = state->msg1_hash;
    hash_update(&ctx, msg2, msg2_len);
    hash_final(&ctx, digest);

    ret = hkdf_sha256_derive(
        shared_secret, sizeof(shared_secret),
        digest,        sizeof(digest),
        HKDF_INFO,     sizeof(HKDF_INFO) - 1,
        session_key,   AUTH_SESSION_KEY_LEN
    );

    ENERGEST_OFF(ENERGEST_TYPE_CPU);
    t_end = RTIMER_NOW();

    if(ret != 0) {
        return AUTH_ERR_CRYPTO;
    }

    LOG_INFO("[AUTH] MSG_2 OK. Session key derived. %lu ticks\n",
           (unsigned long)(t_end - t_start));
    LOG_INFO("[AUTH] Key: ");
    for(i = 0; i < AUTH_SESSION_KEY_LEN; i++) {
        printf("%02x", session_key[i]);
    }
    printf("\n");

    return AUTH_OK;
}