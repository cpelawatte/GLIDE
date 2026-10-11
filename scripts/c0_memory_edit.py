#!/usr/bin/env python3
"""
c0_memory_edit.py -- Phase C0: firmware memory diet (same protocol, less memory).

Run from the repo root (~/Desktop/FYP).
    python3 scripts/c0_memory_edit.py --diff     # show the diff, write nothing
    python3 scripts/c0_memory_edit.py --apply    # write contiki/device_auth.c and .h

Changes (no wire change, no cryptographic change; identical bytes are hashed):
  1. SHA-256 is streamed (init/update/final) instead of copying pieces into
     verify_payload[305], transcript[448] and signing_payload[125].
  2. MSG_1 is hashed once; the hash state is stored and copied for the two
     hashes that start with MSG_1 (signature check, transcript).
  3. device_auth_state_t drops msg1[256]+msg1_len, E_d[64] (never read) and
     nonce_d[16] (already inside MSG_1).
  4. E_g, nonce_g and sig_g are used in place inside MSG_2 (cbor_read_data
     returns pointers into the input buffer) instead of being copied.
  5. One 64 B point buffer is reused for Q_gw then E_g; one 32 B digest is
     reused for the signature check then the HKDF salt.
Safety: every edit must match its stated count or NOTHING is written;
refuses to run twice.
"""
import difflib, sys
from pathlib import Path

H, C = "contiki/device_auth.h", "contiki/device_auth.c"
EDITS = []
def e(f, label, old, new, n=1): EDITS.append((f, label, old, new, n))

# ------------------------------------------------------------------ header
e(H, "include sha256_impl.h",
  "#include <stdint.h>\n#include <stddef.h>\n",
  "#include <stdint.h>\n#include <stddef.h>\n#include \"sha256_impl.h\"\n")
e(H, "slim device_auth_state_t",
  """/*
 * device_auth_state_t:
 *   State retained by the device between MSG_1 send and MSG_2 receive.
 *   Holds the ephemeral private key needed for session key derivation.
 *   Must NOT be transmitted.
 */
typedef struct {
    uint8_t e_d[32];           /* Ephemeral private key */
    uint8_t E_d[64];           /* Ephemeral public key (uncompressed x,y) */
    uint8_t nonce_d[16];       /* Device nonce */
    uint8_t msg1[AUTH_MSG1_MAX_LEN]; /* Saved MSG_1 bytes for transcript */
    size_t  msg1_len;
} device_auth_state_t;""",
  """/*
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
} device_auth_state_t;""")

# ------------------------------------------------------------------ source
e(C, "header comment: SHA-256 source",
  " *   - Contiki-NG native lib/sha256.h for SHA-256 (no mbedTLS needed)\n",
  " *   - bundled sha256_impl.c for SHA-256, used in streaming mode\n")

e(C, "streaming hash wrappers + ECDSA over a digest",
  """/* ---------------------------------------------------------------------------
 * SHA-256 using Contiki-NG native lib/sha256.h
 * --------------------------------------------------------------------------- */
static int sha256_hash(const uint8_t *data, size_t len, uint8_t *out)
{
    sha256_impl_hash(data, len, out);
    return 0;
}



/* ---------------------------------------------------------------------------
 * ECDSA signing using micro-ecc.
 * Hashes payload with SHA-256 first, then signs the 32-byte hash.
 * Produces 64-byte signature (r||s).
 * --------------------------------------------------------------------------- */
static int ecdsa_sign(
    const uint8_t *private_key,
    const uint8_t *payload,
    size_t         payload_len,
    uint8_t       *signature)
{
    uint8_t hash[32];
    uECC_Curve curve = uECC_secp256r1();

    sha256_hash(payload, payload_len, hash);

    if(!uECC_sign(private_key, hash, sizeof(hash), signature, curve)) {
        return AUTH_ERR_CRYPTO;
    }
    return AUTH_OK;
}

/* ---------------------------------------------------------------------------
 * ECDSA verification using micro-ecc.
 * public_key_uncompressed: 64 bytes (x||y), no 0x04 prefix.
 * --------------------------------------------------------------------------- */
static int ecdsa_verify(
    const uint8_t *public_key_uncompressed,
    const uint8_t *payload,
    size_t         payload_len,
    const uint8_t *signature)
{
    uint8_t hash[32];
    uECC_Curve curve = uECC_secp256r1();

    sha256_hash(payload, payload_len, hash);

    if(!uECC_verify(public_key_uncompressed, hash, sizeof(hash),
                    signature, curve)) {
        return AUTH_ERR_VERIFY;
    }
    return AUTH_OK;
}
""",
  """/* ---------------------------------------------------------------------------
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
""")

e(C, "build_msg1 locals: no signing buffer",
  """    uint8_t E_d_compressed[33];
    uint8_t signing_payload[33 + 33 + DEVICE_CERT_INFO_LEN + AUTH_NONCE_LEN + GATEWAY_PUBLIC_KEY_LEN];
    uint8_t signature[AUTH_SIGNATURE_LEN];
    cbor_writer_state_t cbor;
    rtimer_clock_t t_start, t_end;
    size_t sp_len = 0;
    size_t msg1_len;
""",
  """    uint8_t E_d_compressed[33];
    uint8_t nonce_d[AUTH_NONCE_LEN];
    uint8_t digest[32];
    uint8_t signature[AUTH_SIGNATURE_LEN];
    cbor_writer_state_t cbor;
    rtimer_clock_t t_start, t_end;
    size_t msg1_len;
""")

e(C, "drop unused E_d copy into state",
  "    memcpy(state->E_d, E_d_uncompressed, 64);\n", "")

e(C, "nonce_d is a local",
  "        state->nonce_d[i] = (uint8_t)(i ^ 0xA5);\n",
  "        nonce_d[i] = (uint8_t)(i ^ 0xA5);\n")

e(C, "stream the signing hash",
  """    /* Step 3: Build signing payload = E_d || R || cert_info || nonce_d || Q_gw
     *
     * Q_gw binds the signature to the intended gateway, so a captured MSG_1
     * is rejected by any other gateway pinning the same issuer. Q_gw is
     * pre-provisioned on both sides and is NOT transmitted: zero wire cost. */

    memcpy(signing_payload + sp_len, E_d_compressed, 33);
    sp_len += 33;
    memcpy(signing_payload + sp_len, DEVICE_CERT_R, DEVICE_CERT_R_LEN);
    sp_len += DEVICE_CERT_R_LEN;
    memcpy(signing_payload + sp_len, DEVICE_CERT_INFO, DEVICE_CERT_INFO_LEN);
    sp_len += DEVICE_CERT_INFO_LEN;
    memcpy(signing_payload + sp_len, state->nonce_d, AUTH_NONCE_LEN);
    sp_len += AUTH_NONCE_LEN;
    memcpy(signing_payload + sp_len, GATEWAY_PUBLIC_KEY, GATEWAY_PUBLIC_KEY_LEN);
    sp_len += GATEWAY_PUBLIC_KEY_LEN;

    /* Step 4: Sign with device long-term private key d */
    ret = ecdsa_sign(DEVICE_PRIVATE_KEY, signing_payload, sp_len, signature);
""",
  """    /* Step 3: Hash the signed content E_d || R || cert_info || nonce_d || Q_gw
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
""")

e(C, "CBOR nonce from the local",
  "    cbor_write_data(&cbor, state->nonce_d, AUTH_NONCE_LEN);\n",
  "    cbor_write_data(&cbor, nonce_d, AUTH_NONCE_LEN);\n")

e(C, "absorb MSG_1 once instead of copying it",
  """    /* Save MSG_1 bytes for transcript hash in MSG_2 processing */
    memcpy(state->msg1, buf, msg1_len);
    state->msg1_len = msg1_len;
""",
  """    /* Step 6: Absorb MSG_1 once. process_msg2 copies this state for both
     * hashes that start with MSG_1 (signature check and transcript). */
    hash_init(&state->msg1_hash);
    hash_update(&state->msg1_hash, buf, msg1_len);
""")

e(C, "process_msg2 locals: pointers, shared buffers, no copy buffers",
  """    cbor_reader_state_t reader;
    uint8_t E_g_compressed[33];
    uint8_t nonce_g[AUTH_NONCE_LEN];
    uint8_t sig_g[AUTH_SIGNATURE_LEN];
    uint8_t gw_pubkey_uncompressed[64];
    uint8_t E_g_uncompressed[64];
    uint8_t shared_secret[32];
    uint8_t verify_payload[AUTH_MSG1_MAX_LEN + 33 + AUTH_NONCE_LEN];
    uint8_t transcript[AUTH_MSG1_MAX_LEN + AUTH_MSG2_MAX_LEN];
    uint8_t salt[32];
    static const uint8_t HKDF_INFO[] = "edhoc-subset-v1-session-key";
    rtimer_clock_t t_start, t_end;
    size_t map_len;
    size_t verify_payload_len;
    size_t transcript_len;
    int got_E_g = 0, got_nonce_g = 0, got_sig = 0;
    int ret;
    size_t i;

    memset(E_g_compressed, 0, sizeof(E_g_compressed));
    memset(nonce_g, 0, sizeof(nonce_g));
    memset(sig_g, 0, sizeof(sig_g));
""",
  """    cbor_reader_state_t reader;
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
""")

e(C, "E_g used in place",
  """            if(d && dlen == 33) {
                memcpy(E_g_compressed, d, 33);
                got_E_g = 1;
            }""",
  """            if(d && dlen == 33) {
                E_g_compressed = d;
            }""")
e(C, "nonce_g used in place",
  """            if(d && dlen == AUTH_NONCE_LEN) {
                memcpy(nonce_g, d, AUTH_NONCE_LEN);
                got_nonce_g = 1;
            }""",
  """            if(d && dlen == AUTH_NONCE_LEN) {
                nonce_g = d;
            }""")
e(C, "signature used in place",
  """            if(d && dlen == AUTH_SIGNATURE_LEN) {
                memcpy(sig_g, d, AUTH_SIGNATURE_LEN);
                got_sig = 1;
            }""",
  """            if(d && dlen == AUTH_SIGNATURE_LEN) {
                sig_g = d;
            }""")
e(C, "presence check on pointers",
  "    if(!got_E_g || !got_nonce_g || !got_sig) {\n",
  "    if(!E_g_compressed || !nonce_g || !sig_g) {\n")

e(C, "stream the MSG_2 signature digest",
  """    /* Verify gateway signature over (MSG_1 || E_g || nonce_g) */
    decompress_point(GATEWAY_PUBLIC_KEY, gw_pubkey_uncompressed);

    verify_payload_len = state->msg1_len + 33 + AUTH_NONCE_LEN;
    memcpy(verify_payload, state->msg1, state->msg1_len);
    memcpy(verify_payload + state->msg1_len, E_g_compressed, 33);
    memcpy(verify_payload + state->msg1_len + 33, nonce_g, AUTH_NONCE_LEN);

    ret = ecdsa_verify(gw_pubkey_uncompressed,
                       verify_payload, verify_payload_len, sig_g);
""",
  """    /* Verify gateway signature over (MSG_1 || E_g || nonce_g): start from
     * the stored MSG_1 hash state and add the two new pieces. */
    ctx = state->msg1_hash;
    hash_update(&ctx, E_g_compressed, 33);
    hash_update(&ctx, nonce_g, AUTH_NONCE_LEN);
    hash_final(&ctx, digest);

    decompress_point(GATEWAY_PUBLIC_KEY, point);
    ret = ecdsa_verify_hash(point, digest, sig_g);
""")

e(C, "ECDH reuses the point buffer",
  """    decompress_point(E_g_compressed, E_g_uncompressed);
    if(!uECC_shared_secret(E_g_uncompressed, state->e_d, shared_secret, curve)) {""",
  """    decompress_point(E_g_compressed, point);
    if(!uECC_shared_secret(point, state->e_d, shared_secret, curve)) {""")

e(C, "stream the transcript hash",
  """    /* HKDF: session_key = HKDF(SHA256(MSG1||MSG2), shared_secret) */
    transcript_len = state->msg1_len + msg2_len;
    memcpy(transcript, state->msg1, state->msg1_len);
    memcpy(transcript + state->msg1_len, msg2, msg2_len);
    sha256_hash(transcript, transcript_len, salt);

    ret = hkdf_sha256_derive(
        shared_secret, sizeof(shared_secret),
        salt,          sizeof(salt),
""",
  """    /* HKDF: session_key = HKDF(salt = SHA256(MSG1||MSG2), IKM = shared_secret).
     * The transcript hash also starts from the stored MSG_1 state. */
    ctx = state->msg1_hash;
    hash_update(&ctx, msg2, msg2_len);
    hash_final(&ctx, digest);

    ret = hkdf_sha256_derive(
        shared_secret, sizeof(shared_secret),
        digest,        sizeof(digest),
""")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("--diff", "--apply"):
        print(__doc__); return 2
    orig = {f: Path(f).read_text() for f in (H, C)}
    if "msg1_hash" in orig[H]:
        print("ABORT: already applied (device_auth.h has msg1_hash)."); return 1
    new, bad = dict(orig), []
    for f, label, old, rep, n in EDITS:
        got = new[f].count(old)
        print(f"  [{'ok ' if got == n else 'BAD'}] {f}: {label}  (expected {n}, found {got})")
        if got == n:
            new[f] = new[f].replace(old, rep)
        else:
            bad.append(label)
    leftovers = [w for w in ("verify_payload", "transcript[", "signing_payload", "state->msg1_len",
                             "state->nonce_d", "state->E_d", "got_E_g", "sha256_hash(")
                 if w in new[C]]
    if leftovers:
        bad.append("leftover references: " + ", ".join(leftovers))
        print("  [BAD] leftover references in device_auth.c:", ", ".join(leftovers))
    if bad:
        print(f"\nABORT: {len(bad)} problem(s); NOTHING was written."); return 1
    if sys.argv[1] == "--diff":
        for f in (H, C):
            sys.stdout.writelines(difflib.unified_diff(orig[f].splitlines(True), new[f].splitlines(True),
                                                       fromfile="a/" + f, tofile="b/" + f))
        print("\n(diff only: nothing written)"); return 0
    for f in (H, C):
        Path(f).write_text(new[f]); print("  wrote", f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
