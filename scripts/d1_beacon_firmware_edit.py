#!/usr/bin/env python3
"""
d1_beacon_firmware_edit.py -- Fix 2, Phase D1: the device signs over the beacon.

  * contiki/device_auth.h / .c: PROTOCOL_VERSION 2; device_auth_build_msg1()
    takes the 20-byte beacon the device holds and adds it LAST to the signed
    hash (E_d || R || cert_info || nonce_d || Q_gw || beacon, 145 B, same
    order as src/edhoc_subset.py). Not transmitted. NULL beacon ->
    AUTH_ERR_NO_BEACON (-6), nothing built.
  * contiki/test/host/test_main.c, host_test.py: replaced. The host test now
    also runs the C device against the REAL Python gateway and EpochState.

NOT touched: device_auth_main.c, device_auth_main_footprint.c,
device_auth_main_cc2538.c and the bridge. Their build_msg1 calls no longer
compile until Phase D3 rewrites them (same as the bridge after Fix 2 Python).

Run from the repo root (~/Desktop/FYP).

    python3 scripts/d1_beacon_firmware_edit.py --diff contiki/device_auth.c
    python3 scripts/d1_beacon_firmware_edit.py --diff
    python3 scripts/d1_beacon_firmware_edit.py --apply

Safety rules:
  * Every edit states how many times its target must match; whole-file
    replacements state the SHA-256 the current file must have. If anything is
    off, the script aborts before writing ANY file.
  * Refuses to run twice (detects AUTH_BEACON_LEN in contiki/device_auth.h).
"""
import difflib
import hashlib
import sys
from pathlib import Path

ROOT = Path.cwd()
FILES = [
    "contiki/device_auth.h",
    "contiki/device_auth.c",
    "contiki/test/host/test_main.c",
    "contiki/test/host/host_test.py",
]

EDITS = []   # (file, label, old, new, expected_count)
WHOLE = []   # (file, label, expected_old_sha256, new_text)


def lit(f, label, old, new, n=1):
    EDITS.append((f, label, old, new, n))


# =========================================================================
# contiki/device_auth.h
# =========================================================================
DH = "contiki/device_auth.h"

lit(DH, "AUTH_BEACON_LEN",
    "#define AUTH_SESSION_KEY_LEN    16\n",
    "#define AUTH_SESSION_KEY_LEN    16\n"
    "#define AUTH_BEACON_LEN         20   /* Fix 2: 4 B epoch (big-endian) + 16 B random value */\n")

lit(DH, "AUTH_ERR_NO_BEACON",
    "#define AUTH_ERR_RNG            -5   /* no usable random source: nothing built */\n",
    "#define AUTH_ERR_RNG            -5   /* no usable random source: nothing built */\n"
    "#define AUTH_ERR_NO_BEACON      -6   /* no epoch beacon held: nothing built (Fix 2) */\n")

lit(DH, "build_msg1 prototype: beacon parameter",
    " *   Builds EDHOC MSG_1 using pre-provisioned credentials.\n"
    " *   Populates `state` which must be retained for MSG_2 processing.\n"
    " *\n"
    " *   buf/buf_len: output buffer for the CBOR-encoded MSG_1\n"
    " *   Returns number of bytes written, or negative on error.\n"
    " */\n"
    "int device_auth_build_msg1(device_auth_state_t *state,\n"
    "                            uint8_t *buf, size_t buf_len);\n",
    " *   Builds EDHOC MSG_1 using pre-provisioned credentials.\n"
    " *   Populates `state` which must be retained for MSG_2 processing.\n"
    " *\n"
    " *   beacon:      the latest gateway epoch beacon the device holds, exactly\n"
    " *                AUTH_BEACON_LEN bytes as broadcast. Signed over (last),\n"
    " *                never sent. NULL -> AUTH_ERR_NO_BEACON, nothing built.\n"
    " *                The device cannot check a beacon; a stale or fake one\n"
    " *                only makes the gateway reject this MSG_1.\n"
    " *   buf/buf_len: output buffer for the CBOR-encoded MSG_1\n"
    " *   Returns number of bytes written, or negative on error.\n"
    " */\n"
    "int device_auth_build_msg1(device_auth_state_t *state,\n"
    "                            const uint8_t *beacon,\n"
    "                            uint8_t *buf, size_t buf_len);\n")

# =========================================================================
# contiki/device_auth.c
# =========================================================================
DC = "contiki/device_auth.c"

lit(DC, "PROTOCOL_VERSION 2",
    "#define PROTOCOL_VERSION    1\n",
    "#define PROTOCOL_VERSION    2   /* v2 (Fix 2): MSG_1 signature also covers the beacon */\n")

lit(DC, "build_msg1 definition: beacon parameter",
    "int device_auth_build_msg1(device_auth_state_t *state,\n"
    "                            uint8_t *buf, size_t buf_len)\n"
    "{\n",
    "int device_auth_build_msg1(device_auth_state_t *state,\n"
    "                            const uint8_t *beacon,\n"
    "                            uint8_t *buf, size_t buf_len)\n"
    "{\n")

lit(DC, "fail closed without a beacon",
    "    if(rng == NULL) {\n"
    "        return AUTH_ERR_RNG;              /* no random source: build nothing */\n"
    "    }\n",
    "    if(beacon == NULL) {\n"
    "        return AUTH_ERR_NO_BEACON;        /* no beacon held: build nothing */\n"
    "    }\n"
    "    if(rng == NULL) {\n"
    "        return AUTH_ERR_RNG;              /* no random source: build nothing */\n"
    "    }\n")

lit(DC, "step 3: hash the beacon last",
    "    /* Step 3: Hash the signed content E_d || R || cert_info || nonce_d || Q_gw\n"
    "     * piece by piece (no signing buffer). state->msg1_hash serves as scratch\n"
    "     * here; it is re-initialised for MSG_1 in Step 6.\n"
    "     *\n"
    "     * Q_gw binds the signature to the intended gateway, so a captured MSG_1\n"
    "     * is rejected by any other gateway pinning the same issuer. Q_gw is\n"
    "     * pre-provisioned on both sides and is NOT transmitted: zero wire cost. */\n",
    "    /* Step 3: Hash the signed content\n"
    "     *   E_d || R || cert_info || nonce_d || Q_gw || beacon\n"
    "     * piece by piece (no signing buffer). state->msg1_hash serves as scratch\n"
    "     * here; it is re-initialised for MSG_1 in Step 6.\n"
    "     *\n"
    "     * Q_gw binds the signature to the intended gateway, so a captured MSG_1\n"
    "     * is rejected by any other gateway pinning the same issuer. The beacon\n"
    "     * binds it to one epoch (Fix 2): the gateway checks against ITS OWN\n"
    "     * current beacon, so a recorded MSG_1 stops verifying once the epoch\n"
    "     * rolls. Neither is transmitted: zero wire cost. Same order as\n"
    "     * src/edhoc_subset.py _msg1_signing_bytes(); the beacon is last. */\n")

lit(DC, "step 3: hash_update(beacon)",
    "    hash_update(&state->msg1_hash, GATEWAY_PUBLIC_KEY, GATEWAY_PUBLIC_KEY_LEN);\n"
    "    hash_final(&state->msg1_hash, digest);\n",
    "    hash_update(&state->msg1_hash, GATEWAY_PUBLIC_KEY, GATEWAY_PUBLIC_KEY_LEN);\n"
    "    hash_update(&state->msg1_hash, beacon, AUTH_BEACON_LEN);\n"
    "    hash_final(&state->msg1_hash, digest);\n")

# =========================================================================
# contiki/test/host/ -- whole-file replacements
# =========================================================================
WHOLE.append(("contiki/test/host/test_main.c", "host driver: beacon argument",
              "2f8ef1add11eb8797f2548d50ab82961c35f4ed325a37272748a37d6de319230",
              r'''/* host-test driver for device_auth.c.
 * argv: seed mode beacon
 *   mode   = testrng | norng | default (whatever random_source() picks)
 *   beacon = 40 hex chars (the 20-byte epoch beacon) | none (NULL beacon)
 * Builds MSG_1 twice under that beacon, then processes one MSG_2 (hex) per
 * stdin line against the second MSG_1's state. */
#include "device_auth.h"
#include "os/net/security/micro-ecc/uECC.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t s;
static int rng(uint8_t *d, unsigned n){ for(unsigned i=0;i<n;i++){ s=s*6364136223846793005ULL+1442695040888963407ULL; d[i]=(uint8_t)(s>>56);} return 1; }
static void hex(const char*l,const uint8_t*b,size_t n){printf("%s ",l);for(size_t i=0;i<n;i++)printf("%02x",b[i]);printf("\n");fflush(stdout);}
static int unhex(const char*h,uint8_t*out,size_t max){ size_t L=strlen(h); if(L%2||L/2>max) return -1;
  for(size_t i=0;i<L/2;i++){unsigned v; if(sscanf(h+2*i,"%02x",&v)!=1) return -1; out[i]=(uint8_t)v;} return (int)(L/2); }
int main(int argc,char**argv){
  device_auth_state_t st; uint8_t m1[256], m2[512], key[16], beacon[AUTH_BEACON_LEN]; char line[2048];
  const uint8_t *bp = NULL;
  if(argc!=4){ fprintf(stderr,"usage: seed mode beacon\n"); return 2; }
  s=strtoull(argv[1],0,10);
  if(!strcmp(argv[2],"testrng")) uECC_set_rng(rng);
  if(!strcmp(argv[2],"norng"))   uECC_set_rng(NULL);
  if(strcmp(argv[3],"none")){ if(unhex(argv[3],beacon,sizeof beacon)!=AUTH_BEACON_LEN){ fprintf(stderr,"bad beacon\n"); return 2; } bp=beacon; }
  for(int round=0; round<2; round++){
    memset(m1,0xEE,sizeof m1);
    int n=device_auth_build_msg1(&st,bp,m1,sizeof m1);
    if(n<0){ int untouched=1; for(size_t i=0;i<sizeof m1;i++) if(m1[i]!=0xEE) untouched=0;
             printf("ERR1 %d untouched=%d\n",n,untouched); fflush(stdout); return 0; }
    hex(round? "MSG1B":"MSG1",m1,(size_t)n);
  }
  while(fgets(line,sizeof line,stdin)){ size_t L=strlen(line); while(L&&(line[L-1]=='\n'||line[L-1]=='\r'))line[--L]=0;
    int k=unhex(line,m2,sizeof m2); if(k<0){ printf("ERR2 bad-hex\n"); fflush(stdout); continue; }
    int r=device_auth_process_msg2(&st,m2,(size_t)k,key); if(r==0)hex("KEY",key,16); else {printf("ERR2 %d\n",r);fflush(stdout);} }
  return 0; }
'''))

WHOLE.append(("contiki/test/host/host_test.py", "host test: beacon + real gateway",
              "231eba69790f265259a7f62eee99b9051c5e7ebd678c9ec0b668743263aa1e7c",
              r'''#!/usr/bin/env python3
"""
host_test.py -- run the real device_auth.c on the host against the real Python gateway.

Usage (repo root):  python3 contiki/test/host/host_test.py [path/to/contiki-ng]
                    (default contiki-ng path: ../contiki-ng)

Compiles contiki/device_auth.c with YOUR contiki/sha256_impl.c and
contiki/hkdf_sha256.c, plus micro-ecc and CBOR from your Contiki-NG tree, with
AddressSanitizer + UBSan, in a temporary directory. Uses a throwaway issuer,
device credential and gateway identity made for this run with src/ (never your
credentials.h or keystore). Checks:
  * MSG_1 carries protocol version 2 and its signature covers
    E_d || R || cert_info || nonce_d || Q_gw || beacon (Fix 2); the signature
    equals a Python model of micro-ecc's deterministic signing
  * nonce_d is fresh (all distinct, never the old fixed pattern)
  * session key equals the gateway's; bad signature / missing nonce in MSG_2
    are rejected
  * fail closed: no beacon -> AUTH_ERR_NO_BEACON; no random source, or an
    unseeded CSPRNG -> AUTH_ERR_RNG; output buffer untouched in each case
  * end to end with the REAL gateway (src/edhoc_subset.py + src/beacon.py):
    the C MSG_1 is accepted under the gateway's beacon, the C device derives
    the gateway's key, a repeated MSG_1 gets the identical stored MSG_2 (T2),
    a stale or fake beacon is SIGNATURE_INVALID, the per-device cap holds
Prints verdicts only.
"""
import hashlib, hmac, os, secrets, shutil, subprocess, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path
import cbor2
from ecdsa import BadSignatureError, NIST256p, SigningKey, VerifyingKey
from ecdsa.util import sigencode_string, sigdecode_string

N, G = NIST256p.order, NIST256p.generator
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
CNG = Path(sys.argv[1] if len(sys.argv) > 1 else REPO.parent / "contiki-ng").resolve()

sys.path.insert(0, str(REPO))
from src.beacon import Beacon, EpochState                                       # noqa: E402
from src.cert_info import encode_cert_info                                      # noqa: E402
from src.ecqv_core import (device_derive_private_key, device_generate_contribution,  # noqa: E402
                           issuer_generate_cert, issuer_generate_keypair, point_to_compressed)
from src.edhoc_subset import gateway_process_msg1_build_msg2                   # noqa: E402
from src.gateway_keystore import (Keystore, PinnedIssuer, _compute_q_ca_hash,  # noqa: E402
                                  _generate_gateway_identity)
from src.gateway_verifier import AuthFailureReason                             # noqa: E402

ISSUER_DID = "did:web:host-test.invalid"


def H(k, m): return hmac.new(k, m, hashlib.sha256).digest()


def sign_uecc_model(x: int, h: bytes) -> bytes:
    """micro-ecc uECC_sign_deterministic: RFC 6979-style HMAC-DRBG over (x, H(m)),
    H(m) not reduced mod n, k read little-endian from the DRBG output."""
    xb = x.to_bytes(32, "big"); K, V = b"\0" * 32, b"\1" * 32
    K = H(K, V + b"\0" + xb + h); V = H(K, V)
    K = H(K, V + b"\1" + xb + h); V = H(K, V)
    while True:
        V = H(K, V); k = int.from_bytes(V, "little")
        if 0 < k < N:
            break
        K = H(K, V + b"\0"); V = H(K, V)
    r = (k * G).x() % N
    s = pow(k, -1, N) * (int.from_bytes(h, "big") + r * x) % N
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verifies(vk, sig, digest):
    """True/False instead of an exception, so a bad signature is a verdict, not a crash."""
    try:
        return vk.verify_digest(sig, digest, sigdecode=sigdecode_string)
    except BadSignatureError:
        return False


def comp(P): return VerifyingKey.from_public_point(P, curve=NIST256p).to_string("compressed")
def dec(b): return VerifyingKey.from_string(b, curve=NIST256p).pubkey.point
def carr(n, b): return f"#define {n}_LEN {len(b)}\nstatic const uint8_t {n}[{n}_LEN] = {{{', '.join('0x%02x' % x for x in b)}}};\n"


def throwaway_identity():
    """A real ECQV device credential and gateway keystore, made with src/ for this run."""
    now = datetime.now(timezone.utc)
    issuer = issuer_generate_keypair()
    contribution = device_generate_contribution()
    cert = issuer_generate_cert(contribution.U, encode_cert_info(ISSUER_DID, now, 24), issuer)
    d = device_derive_private_key(contribution, cert)
    pinned = PinnedIssuer(issuer_did=ISSUER_DID, Q_ca=issuer.Q_ca,
                          Q_ca_hash_hex=_compute_q_ca_hash(issuer.Q_ca),
                          bootstrap_mode="pinned", bootstrapped_at=now.isoformat())
    keystore = Keystore(pinned_issuer=pinned, gateway_identity=_generate_gateway_identity(lifetime_days=90))
    return issuer, cert, d, keystore


def main() -> int:
    for need in (CNG / "os/net/security/micro-ecc/uECC.c", CNG / "os/lib/cbor.c"):
        if not need.exists():
            print("ABORT: not found:", need); return 1
    work = Path(tempfile.mkdtemp(prefix="glide_host_"))
    try:
        for f in ("device_auth.c", "device_auth.h", "sha256_impl.c", "sha256_impl.h",
                  "hkdf_sha256.c", "hkdf_sha256.h"):
            shutil.copy(REPO / "contiki" / f, work / f)     # compiled from work/, so the
        issuer, cert, d, keystore = throwaway_identity()     # throwaway credentials.h below
        gw = keystore.gateway_identity.private_key           # is the one that gets included
        Qgw = point_to_compressed(keystore.gateway_identity.public_key)
        R, cert_info = point_to_compressed(cert.R), cert.cert_info
        (work / "credentials.h").write_text(
            "#pragma once\n#include <stdint.h>\n" + carr("DEVICE_PRIVATE_KEY", d.to_bytes(32, "big"))
            + carr("DEVICE_CERT_R", R) + carr("DEVICE_CERT_INFO", cert_info)
            + carr("GATEWAY_PUBLIC_KEY", Qgw) + carr("ISSUER_PUBLIC_KEY", point_to_compressed(issuer.Q_ca)))
        flags = ("-std=gnu11 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer "
                 "-DuECC_SUPPORTS_secp256r1=1 -DuECC_SUPPORT_COMPRESSED_POINT=1 -DuECC_OPTIMIZATION_LEVEL=2").split()
        inc = ["-I", str(work), "-I", str(HERE / "stub"), "-I", str(CNG), "-I", str(CNG / "os")]
        srcs = [str(HERE / "test_main.c"), str(work / "device_auth.c"), str(work / "sha256_impl.c"),
                str(work / "hkdf_sha256.c"), str(CNG / "os/lib/cbor.c"),
                str(CNG / "os/net/security/micro-ecc/uECC.c"), str(HERE / "csprng_stub.c")]
        for name, extra in (("host", []), ("csprng", ["-DCSPRNG_CONF_ENABLED=1"])):
            r = subprocess.run(["gcc", *flags, *extra, *inc, "-o", str(work / name), *srcs], capture_output=True, text=True)
            warn = [l for l in r.stderr.splitlines() if "device_auth.c" in l and "warning" in l]
            print(f"compile ({name}): {'ok' if r.returncode == 0 else 'FAILED'}, device_auth.c warnings: {len(warn)}")
            if r.returncode:
                print(r.stderr[-2500:]); return 1

        # The gateway's beacon for this run, and a gateway holding it.
        beacon = Beacon(secrets.randbelow(2 ** 32), os.urandom(16))
        B = beacon.to_bytes()

        def gateway():
            return EpochState(300, max_devices=8, value_source=lambda n: beacon.value,
                              first_epoch=beacon.epoch)

        def run(binary, seed, mode, lines="", seeded=None, bcn=B):
            env = dict(os.environ)
            if seeded is not None:
                env["GLIDE_SEEDED"] = seeded
            arg = "none" if bcn is None else bcn.hex()
            p = subprocess.run([str(work / binary), str(seed), mode, arg], input=lines, capture_output=True,
                               text=True, env=env, timeout=120)
            if "AddressSanitizer" in p.stderr or "runtime error" in p.stderr or p.returncode:
                return None
            return [l for l in p.stdout.splitlines() if l.startswith(("MSG1", "KEY ", "ERR"))]

        def msg1s(out):
            return [bytes.fromhex(out[i].split()[1]) for i in (0, 1)]

        def hkdf16(ikm, salt):
            prk = H(salt, ikm); return H(prk, b"edhoc-subset-v1-session-key\x01")[:16]

        def msg2_for(msg1, tamper=None):
            m = cbor2.loads(msg1); E_d = dec(m[8])
            e_g = secrets.randbelow(N - 1) + 1; E_g = comp(e_g * G); n_g = os.urandom(16)
            sig = SigningKey.from_secret_exponent(gw, curve=NIST256p).sign_deterministic(
                msg1 + E_g + n_g, hashfunc=hashlib.sha256, sigencode=sigencode_string)
            f = {0: 2, 1: 6, 8: E_g, 10: n_g, 7: sig}
            if tamper == "drop_nonce":
                del f[10]
            m2 = cbor2.dumps(f)
            if tamper == "flip_sig":
                m2 = m2[:-1] + bytes([m2[-1] ^ 1])
            return m2, hkdf16((e_g * E_d).x().to_bytes(32, "big"), hashlib.sha256(msg1 + m2).digest())

        # ---- 1. device-side properties over 20 seeds (model gateway) ----
        fails, nonces, sizes = [], set(), set()
        vk = SigningKey.from_secret_exponent(d, curve=NIST256p).get_verifying_key()
        fixed = bytes(i ^ 0xA5 for i in range(16))
        for seed in range(1, 21):
            out = run("host", seed, "testrng")
            if out is None:
                fails.append(f"sanitizer error (seed {seed})"); continue
            m1a, m1b = msg1s(out)
            for m1 in (m1a, m1b):
                m = cbor2.loads(m1); sizes.add(len(m1))
                if m[0] != 2:
                    fails.append(f"seed {seed}: MSG_1 version {m[0]} != 2")
                h = hashlib.sha256(m[8] + m[4] + m[3] + m[9] + Qgw + B).digest()
                if not verifies(vk, m[7], h):
                    fails.append(f"seed {seed}: signature does not verify over ... || Q_gw || beacon")
                if m[7] != sign_uecc_model(d, h):
                    fails.append(f"seed {seed}: signature != deterministic model")
                if m[9] == fixed:
                    fails.append(f"seed {seed}: fixed nonce pattern")
                nonces.add(m[9])
            cases = [msg2_for(m1b), msg2_for(m1b, "flip_sig"), msg2_for(m1b, "drop_nonce")]
            out2 = run("host", seed, "testrng", "".join(c[0].hex() + "\n" for c in cases))
            if out2 is None:
                fails.append(f"sanitizer error in MSG_2 (seed {seed})"); continue
            if out2[2] != f"KEY {cases[0][1].hex()}":
                fails.append(f"seed {seed}: session key != gateway's")
            if out2[3:5] != ["ERR2 -3", "ERR2 -2"]:
                fails.append(f"seed {seed}: bad MSG_2 not rejected as expected: {out2[3:5]}")
        if len(nonces) != 40:
            fails.append(f"nonces not all distinct ({len(nonces)}/40)")

        # ---- 2. end to end with the REAL gateway ----
        e2e = {}
        out = run("host", 101, "testrng")
        if out is None:
            fails.append("sanitizer error (real gateway)")
        else:
            m1a, m1b = msg1s(out)
            state = gateway()
            first = gateway_process_msg1_build_msg2(keystore, m1b, epoch_state=state)
            again = gateway_process_msg1_build_msg2(keystore, m1b, epoch_state=state)
            e2e["real gateway accepts the C MSG_1 under its beacon"] = first.success
            e2e["repeated C MSG_1 -> RETRANSMISSION, identical MSG_2 (T2)"] = (
                again.reason is AuthFailureReason.RETRANSMISSION
                and again.msg2_bytes == first.msg2_bytes and state.occupancy == 1)
            if first.success:
                keys = run("host", 101, "testrng", first.msg2_bytes.hex() + "\n" + again.msg2_bytes.hex() + "\n")
                want = f"KEY {first.session_key.hex()}"
                e2e["C device derives the gateway's session key, also from the resent MSG_2"] = (
                    keys is not None and keys[2:4] == [want, want])
            second = gateway_process_msg1_build_msg2(keystore, m1a, epoch_state=state)
            third_out = run("host", 102, "testrng")
            third = gateway_process_msg1_build_msg2(keystore, msg1s(third_out)[1], epoch_state=state) \
                if third_out else None
            e2e["per-device cap: 2nd accepted, 3rd DEVICE_RATE_LIMITED"] = (
                second.success and third is not None
                and third.reason is AuthFailureReason.DEVICE_RATE_LIMITED)

            bad_ok = True
            for label, wrong in (("stale value", Beacon(beacon.epoch, os.urandom(16))),
                                 ("next epoch label", Beacon((beacon.epoch + 1) % 2 ** 32, beacon.value))):
                fresh = gateway()
                o = run("host", 103, "testrng", bcn=wrong.to_bytes())
                r = gateway_process_msg1_build_msg2(keystore, msg1s(o)[1], epoch_state=fresh) if o else None
                if r is None or r.reason is not AuthFailureReason.SIGNATURE_INVALID or fresh.occupancy:
                    bad_ok = False
            e2e["stale or fake beacon -> SIGNATURE_INVALID, nothing recorded"] = bad_ok

        checks = [
            ("no beacon -> AUTH_ERR_NO_BEACON, nothing written",
             run("host", 1, "testrng", bcn=None) == ["ERR1 -6 untouched=1"]),
            ("no random source -> AUTH_ERR_RNG, nothing written", run("host", 1, "norng") == ["ERR1 -5 untouched=1"]),
            ("host default random source works", (run("host", 1, "default") or [""])[0].startswith("MSG1")),
            ("CSPRNG enabled + unseeded -> AUTH_ERR_RNG, nothing written",
             run("csprng", 1, "default", seeded="0") == ["ERR1 -5 untouched=1"]),
            ("CSPRNG enabled + seeded -> works, and is the source used",
             (lambda a, b: bool(a) and a[0].startswith("MSG1") and a[0] != (b or [""])[0])(
                 run("csprng", 1, "testrng", seeded="1"), run("host", 1, "testrng"))),
            *e2e.items(),
        ]
        if len(e2e) != 5:
            fails.append(f"real-gateway section ran {len(e2e)}/5 checks")
        for label, ok in checks:
            print(f"  [{'ok ' if ok else 'BAD'}] {label}")
            if not ok:
                fails.append(label)
        print(f"\nC MSG_1 size: {sorted(sizes)} B (protocol version 2, beacon signed, not sent)")
        print("20 runs x 2 MSG_1 + 3 MSG_2 cases + real-gateway run: signature valid and deterministic,")
        print("nonce fresh, session key == gateway, bad MSG_2 rejected, ASan/UBSan clean:",
              "ALL PASS" if not fails else f"{len(fails)} FAILURE(S)")
        for f in fails[:10]:
            print("   ", f)
        return 1 if fails else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
'''))


# =========================================================================
def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("--diff", "--apply"):
        print(__doc__)
        return 2
    mode, only = sys.argv[1], sys.argv[2:]

    original, edited = {}, {}
    for f in FILES:
        p = ROOT / f
        if not p.exists():
            print(f"ABORT: {f} not found (run from the repo root)")
            return 1
        original[f] = edited[f] = p.read_text()

    if "AUTH_BEACON_LEN" in original["contiki/device_auth.h"]:
        print("ABORT: edits already applied (device_auth.h defines AUTH_BEACON_LEN).")
        return 1

    bad = []
    for f, label, old, new, n in EDITS:
        got = edited[f].count(old)
        if got == n:
            edited[f] = edited[f].replace(old, new)
        ok = got == n
        print(f"  [{'ok ' if ok else 'BAD'}] {f}: {label}  (expected {n}, found {got})")
        if not ok:
            bad.append(label)
    for f, label, sha, new in WHOLE:
        got = hashlib.sha256(original[f].encode()).hexdigest()
        ok = got == sha
        print(f"  [{'ok ' if ok else 'BAD'}] {f}: {label}  (current sha256 {'matches' if ok else 'DIFFERS: ' + got[:12]})")
        if ok:
            edited[f] = new
        else:
            bad.append(label)

    if bad:
        print(f"\nABORT: {len(bad)} edit(s) did not match exactly; NOTHING was written.")
        return 1

    if mode == "--diff":
        for f in FILES:
            if only and f not in only:
                continue
            sys.stdout.writelines(difflib.unified_diff(
                original[f].splitlines(True), edited[f].splitlines(True),
                fromfile=f"a/{f}", tofile=f"b/{f}"))
        print("\n(diff only: nothing written)")
        return 0

    for f in FILES:
        if edited[f] != original[f]:
            (ROOT / f).write_text(edited[f])
            print(f"  wrote {f}")
    print("\nApplied. Next: python3 contiki/test/host/host_test.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
