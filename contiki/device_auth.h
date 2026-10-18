/*
 * device_auth.h — ECQV+DID device authentication for Contiki-NG.
 *
 * Implements the device side of the L-ECQV + DID-based EDHOC subset
 * authentication protocol described in the FYP.
 *
 * Uses:
 *   - micro-ecc (os/net/security/micro-ecc) for P-256 operations
 *   - Contiki-NG os/lib/cbor.h for CBOR encoding
 *   - hkdf_sha256.h for session key derivation
 *   - credentials.h for pre-provisioned device identity
 */

#ifndef DEVICE_AUTH_H_
#define DEVICE_AUTH_H_

#include <stdint.h>
#include <stddef.h>
#include "sha256_impl.h"

/* Wire sizes matching Python cbor_codec.py */
#define AUTH_NONCE_LEN          16
#define AUTH_SIGNATURE_LEN      64
#define AUTH_COMPRESSED_PT_LEN  33
#define AUTH_SESSION_KEY_LEN    16
#define AUTH_BEACON_LEN         20   /* Fix 2: 4 B epoch (big-endian) + 16 B random value */

/* MSG_1 buffer size. MSG_1 is always 174 B (fixed-size fields); 176 keeps
 * 4-byte alignment. A larger MSG_1 fails closed (AUTH_ERR_CBOR or
 * AUTH_ERR_BUFFER_SMALL) and the host / e2e / bridge tests fail. */
#define AUTH_MSG1_MAX_LEN  176

/* MSG_2 input buffer size. MSG_2 is always 126 B; a longer input line is
 * dropped by device_auth_main.c (and the e2e / bridge tests fail). */
#define AUTH_MSG2_MAX_LEN  128

/* Return codes */
#define AUTH_OK                  0
#define AUTH_ERR_CRYPTO         -1
#define AUTH_ERR_CBOR           -2
#define AUTH_ERR_VERIFY         -3
#define AUTH_ERR_BUFFER_SMALL   -4
#define AUTH_ERR_RNG            -5   /* no usable random source: nothing built */
#define AUTH_ERR_NO_BEACON      -6   /* no epoch beacon held: nothing built (Fix 2) */

/*
 * device_auth_state_t:
 *   State retained by the device between MSG_1 send and MSG_2 receive.
 *   Must NOT be transmitted.
 *
 *   e_d        ephemeral private key, needed for ECDH when MSG_2 arrives.
 *   msg1_hash  SHA-256 state after absorbing the MSG_1 bytes. Both hashes the
 *              device needs later -- the MSG_2 signature check over
 *              MSG_1 || E_g || nonce_g, and the transcript MSG_1 || MSG_2 --
 *              start with MSG_1, so MSG_1 is hashed once and this state is
 *              copied for each. Replaces a 256 B copy of MSG_1.
 *   (Removed: E_d[64], never read after MSG_1 is built; nonce_d[16], already
 *    inside MSG_1; msg1[256] and msg1_len, replaced by msg1_hash.)
 */
typedef struct {
    uint8_t           e_d[32];
    sha256_impl_ctx_t msg1_hash;
} device_auth_state_t;

/*
 * device_auth_build_msg1:
 *   Builds EDHOC MSG_1 using pre-provisioned credentials.
 *   Populates `state` which must be retained for MSG_2 processing.
 *
 *   beacon:      the latest gateway epoch beacon the device holds, exactly
 *                AUTH_BEACON_LEN bytes as broadcast. Signed over (last),
 *                never sent. NULL -> AUTH_ERR_NO_BEACON, nothing built.
 *                The device cannot check a beacon; a stale or fake one
 *                only makes the gateway reject this MSG_1.
 *   buf/buf_len: output buffer for the CBOR-encoded MSG_1
 *   Returns number of bytes written, or negative on error.
 */
int device_auth_build_msg1(device_auth_state_t *state,
                            const uint8_t *beacon,
                            uint8_t *buf, size_t buf_len);

/*
 * device_auth_process_msg2:
 *   Verifies MSG_2 from gateway and derives the session key.
 *
 *   msg2/msg2_len: received CBOR-encoded MSG_2
 *   session_key:   output buffer for the 16-byte AES-128 session key
 *   Returns AUTH_OK on success, negative on error.
 */
int device_auth_process_msg2(device_auth_state_t *state,
                              const uint8_t *msg2, size_t msg2_len,
                              uint8_t *session_key);

#endif /* DEVICE_AUTH_H_ */