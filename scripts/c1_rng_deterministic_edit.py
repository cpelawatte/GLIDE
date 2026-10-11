#!/usr/bin/env python3
"""
c1_rng_deterministic_edit.py -- Phase C1-C4: randomness foundation for the firmware.

Run from the repo root (~/Desktop/FYP), after Phase C0.
    python3 scripts/c1_rng_deterministic_edit.py --diff     # show the diff, write nothing
    python3 scripts/c1_rng_deterministic_edit.py --apply    # write the files

  C1  ECDSA signing becomes deterministic (uECC_sign_deterministic): the
      per-signature secret k comes from an RFC 6979-style HMAC-DRBG over d and
      the digest, so a weak or repeating random source can never reveal the
      long-term key d. NOT byte-identical to RFC 6979: micro-ecc reads k in
      native (little-endian) byte order and does not reduce H(m) mod n
      (uECC.c, comment above uECC_sign_deterministic).
      The HMAC-SHA-256 it needs borrows the device's existing scratch hash
      state (no extra 104 B); only the 128 B HMAC-DRBG buffer is new.
  C2  The random source is chosen explicitly and checked: Contiki-NG's CSPRNG
      on CC2538, micro-ecc's host default elsewhere (Cooja native mote).
      No source -> AUTH_ERR_RNG and nothing is built (fail closed).
  C3  contiki/project-conf.h (new): CSPRNG_CONF_ENABLED 1 on CC2538 only.
      Seeded from radio I/Q noise at boot by cc2538-rf.c; no PM2 (the SRAM
      seeder would cap usable RAM at 16 KB).
  C4  nonce_d is drawn from the random source (replaces the fixed i ^ 0xA5
      pattern), first, so an unseeded source is reported as AUTH_ERR_RNG.
Safety: every edit must match its stated count or NOTHING is written;
refuses to run twice; refuses to overwrite an existing project-conf.h.
"""
import difflib, sys
from pathlib import Path

H, C, P = "contiki/device_auth.h", "contiki/device_auth.c", "contiki/project-conf.h"
EDITS = []
def e(f, label, old, new, n=1): EDITS.append((f, label, old, new, n))

PROJECT_CONF = """/*
 * project-conf.h -- build configuration for the GLIDE device firmware.
 * Picked up automatically by Contiki-NG's Makefile.include for every target
 * built from contiki/; target-specific settings are guarded below.
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#ifdef CONTIKI_TARGET_CC2538DK
/* Cryptographic random source for e_d and nonce_d: Contiki-NG's AES-based
 * CSPRNG (os/lib/csprng.c), seeded at boot from radio I/Q noise by
 * cc2538-rf.c (iq_seeder_seed). If seeding fails the radio driver asserts,
 * and csprng_rand() returns false while unseeded, so the device fails closed.
 * Deliberately NOT LPM_CONF_MAX_PM 2: that would add the SRAM seeder but
 * restrict all RAM to the 16 KB retention half (cc2538.lds). */
#define CSPRNG_CONF_ENABLED 1
#endif /* CONTIKI_TARGET_CC2538DK */

#endif /* PROJECT_CONF_H_ */
"""

# ------------------------------------------------------------------ header
e(H, "AUTH_ERR_RNG return code",
  "#define AUTH_ERR_BUFFER_SMALL   -4\n",
  "#define AUTH_ERR_BUFFER_SMALL   -4\n"
  "#define AUTH_ERR_RNG            -5   /* no usable random source: nothing built */\n")

# ------------------------------------------------------------------ source
e(C, "header comment: RFC 6979 + random source",
  " *   - micro-ecc (uECC) for P-256 ECDSA sign/verify and ECDH\n",
  " *   - micro-ecc (uECC) for P-256 ECDSA sign/verify and ECDH; signing is\n"
  " *     deterministic (RFC 6979-style, micro-ecc variant), so d never\n"
  " *     depends on the random source\n"
  " *   - random source for e_d and nonce_d: Contiki-NG CSPRNG on CC2538\n"
  " *     (project-conf.h, seeded from radio noise at boot), micro-ecc's host\n"
  " *     default elsewhere (Cooja native mote); none -> AUTH_ERR_RNG\n")

e(C, "include csprng.h",
  '#include "sha256_impl.h"\n',
  '#include "sha256_impl.h"\n#include "lib/csprng.h"\n')

e(C, "RFC 6979 signing + random-source selection",
  """static int ecdsa_sign_hash(const uint8_t *private_key, const uint8_t *digest,
                           uint8_t *signature)
{
    if(!uECC_sign(private_key, digest, 32, signature, uECC_secp256r1())) {
        return AUTH_ERR_CRYPTO;
    }
    return AUTH_OK;
}
""",
  """/* Deterministic signing. micro-ecc derives the per-signature secret k from d
 * and the digest with an RFC 6979-style HMAC-SHA-256 DRBG instead of drawing
 * it from the random source, so a weak or repeating random source can never
 * reveal d. Not byte-identical to RFC 6979 (micro-ecc reads k in native byte
 * order and does not reduce H(m) mod n), so signatures differ from an RFC
 * 6979 signer's; they verify normally.
 * micro-ecc calls back into these three functions for its HMAC; they run on
 * a borrowed scratch hash state, so signing needs no second 104 B context. */
typedef struct {
    uECC_HashContext   uecc;   /* first member: micro-ecc passes &uecc back */
    sha256_impl_ctx_t *sha;    /* borrowed scratch hash state */
} rfc6979_hash_t;

static void rfc6979_init(const uECC_HashContext *base)
{
    hash_init(((const rfc6979_hash_t *)base)->sha);
}

static void rfc6979_update(const uECC_HashContext *base,
                           const uint8_t *message, unsigned message_size)
{
    hash_update(((const rfc6979_hash_t *)base)->sha, message, message_size);
}

static void rfc6979_finish(const uECC_HashContext *base, uint8_t *hash_result)
{
    hash_final(((const rfc6979_hash_t *)base)->sha, hash_result);
}

static int ecdsa_sign_hash(const uint8_t *private_key, const uint8_t *digest,
                           uint8_t *signature, sha256_impl_ctx_t *scratch)
{
    uint8_t tmp[2 * 32 + 64];   /* HMAC-DRBG K, V and one SHA-256 block */
    rfc6979_hash_t h = {
        { rfc6979_init, rfc6979_update, rfc6979_finish, 64, 32, tmp },
        scratch
    };

    if(!uECC_sign_deterministic(private_key, digest, 32, &h.uecc, signature,
                                uECC_secp256r1())) {
        return AUTH_ERR_CRYPTO;
    }
    return AUTH_OK;
}

/* ---------------------------------------------------------------------------
 * Random source for e_d and nonce_d. Fail closed: with no source, nothing is
 * built.
 *   CC2538 (CSPRNG_ENABLED via project-conf.h): Contiki-NG's CSPRNG, seeded
 *     from radio I/Q noise at boot; csprng_rand() returns false until seeded.
 *   Cooja native mote and host builds: micro-ecc's built-in default (the
 *     host's /dev/urandom), registered automatically by micro-ecc.
 * --------------------------------------------------------------------------- */
#if CSPRNG_ENABLED
static int csprng_source(uint8_t *dest, unsigned size)
{
    return csprng_rand(dest, size) ? 1 : 0;
}
#endif /* CSPRNG_ENABLED */

static uECC_RNG_Function random_source(void)
{
#if CSPRNG_ENABLED
    if(uECC_get_rng() != csprng_source) {
        uECC_set_rng(csprng_source);
    }
#endif /* CSPRNG_ENABLED */
    return uECC_get_rng();
}
""")

e(C, "build_msg1: check the random source, draw nonce_d first",
  """    int ret;
    int i;

    t_start = RTIMER_NOW();
    ENERGEST_ON(ENERGEST_TYPE_CPU);

    /* Step 1: Generate ephemeral keypair */
""",
  """    int ret;
    uECC_RNG_Function rng = random_source();

    if(rng == NULL) {
        return AUTH_ERR_RNG;              /* no random source: build nothing */
    }

    t_start = RTIMER_NOW();
    ENERGEST_ON(ENERGEST_TYPE_CPU);

    /* Step 1: Fresh device nonce from the random source. Drawn first, so an
     * unseeded source is reported as AUTH_ERR_RNG before any other work. */
    if(!rng(nonce_d, AUTH_NONCE_LEN)) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_RNG;
    }

    /* Step 2: Generate ephemeral keypair */
""")

e(C, "remove the fixed nonce pattern",
  """    /* Step 2: Generate device nonce (fixed pattern for simulation) */
    for(i = 0; i < AUTH_NONCE_LEN; i++) {
        nonce_d[i] = (uint8_t)(i ^ 0xA5);
    }

""", "")

e(C, "sign deterministically, borrowing the scratch hash state",
  "    ret = ecdsa_sign_hash(DEVICE_PRIVATE_KEY, digest, signature);\n",
  "    ret = ecdsa_sign_hash(DEVICE_PRIVATE_KEY, digest, signature,\n"
  "                          &state->msg1_hash);   /* scratch until Step 6 */\n")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("--diff", "--apply"):
        print(__doc__); return 2
    orig = {f: Path(f).read_text() for f in (H, C)}
    if "msg1_hash" not in orig[H]:
        print("ABORT: Phase C0 is not applied yet (device_auth.h has no msg1_hash)."); return 1
    if "AUTH_ERR_RNG" in orig[H]:
        print("ABORT: already applied (device_auth.h has AUTH_ERR_RNG)."); return 1
    if Path(P).exists():
        print(f"ABORT: {P} already exists; not overwriting it."); return 1
    new, bad = dict(orig), []
    for f, label, old, rep, n in EDITS:
        got = new[f].count(old)
        print(f"  [{'ok ' if got == n else 'BAD'}] {f}: {label}  (expected {n}, found {got})")
        if got == n:
            new[f] = new[f].replace(old, rep)
        else:
            bad.append(label)
    leftovers = [w for w in ("i ^ 0xA5", "uECC_sign(", "int i;") if w in new[C]]
    if leftovers:
        bad.append("leftovers: " + ", ".join(leftovers))
        print("  [BAD] leftovers in device_auth.c:", ", ".join(leftovers))
    if bad:
        print(f"\nABORT: {len(bad)} problem(s); NOTHING was written."); return 1
    if sys.argv[1] == "--diff":
        for f in (H, C):
            sys.stdout.writelines(difflib.unified_diff(orig[f].splitlines(True), new[f].splitlines(True),
                                                       fromfile="a/" + f, tofile="b/" + f))
        sys.stdout.writelines(difflib.unified_diff([], PROJECT_CONF.splitlines(True),
                                                   fromfile="/dev/null", tofile="b/" + P))
        print("\n(diff only: nothing written)"); return 0
    for f in (H, C):
        Path(f).write_text(new[f]); print("  wrote", f)
    Path(P).write_text(PROJECT_CONF); print("  wrote", P)
    return 0


if __name__ == "__main__":
    sys.exit(main())
