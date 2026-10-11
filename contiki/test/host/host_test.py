#!/usr/bin/env python3
"""
host_test.py -- run the real device_auth.c on the host against a Python gateway.

Usage (repo root):  python3 contiki/test/host/host_test.py [path/to/contiki-ng]
                    (default contiki-ng path: ../contiki-ng)

Compiles contiki/device_auth.c with YOUR contiki/sha256_impl.c and
contiki/hkdf_sha256.c, plus micro-ecc and CBOR from your Contiki-NG tree, with
AddressSanitizer + UBSan, in a temporary directory. Uses throwaway keys
generated for this run (never your credentials.h). Checks:
  * MSG_1 signature verifies, and equals a Python model of micro-ecc's
    deterministic signing (so k does not depend on the random source)
  * nonce_d is fresh (all distinct, never the old fixed pattern)
  * session key equals the Python gateway's; bad signature / missing nonce
    in MSG_2 are rejected
  * fail closed: no random source, or an unseeded CSPRNG -> AUTH_ERR_RNG,
    output buffer untouched; with CSPRNG enabled the CSPRNG is the source
Prints verdicts only.
"""
import hashlib, hmac, os, secrets, shutil, subprocess, sys, tempfile
from pathlib import Path
import cbor2
from ecdsa import NIST256p, SigningKey, VerifyingKey
from ecdsa.util import sigencode_string, sigdecode_string

N, G = NIST256p.order, NIST256p.generator
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
CNG = Path(sys.argv[1] if len(sys.argv) > 1 else REPO.parent / "contiki-ng").resolve()


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


def comp(P): return VerifyingKey.from_public_point(P, curve=NIST256p).to_string("compressed")
def dec(b): return VerifyingKey.from_string(b, curve=NIST256p).pubkey.point
def carr(n, b): return f"#define {n}_LEN {len(b)}\nstatic const uint8_t {n}[{n}_LEN] = {{{', '.join('0x%02x' % x for x in b)}}};\n"


def main() -> int:
    for need in (CNG / "os/net/security/micro-ecc/uECC.c", CNG / "os/lib/cbor.c"):
        if not need.exists():
            print("ABORT: not found:", need); return 1
    work = Path(tempfile.mkdtemp(prefix="glide_host_"))
    try:
        for f in ("device_auth.c", "device_auth.h", "sha256_impl.c", "sha256_impl.h",
                  "hkdf_sha256.c", "hkdf_sha256.h"):
            shutil.copy(REPO / "contiki" / f, work / f)     # compiled from work/, so the
        d = secrets.randbelow(N - 1) + 1                     # throwaway credentials.h below
        gw = secrets.randbelow(N - 1) + 1                    # is the one that gets included
        Qgw = comp(gw * G)
        (work / "credentials.h").write_text(
            "#pragma once\n#include <stdint.h>\n" + carr("DEVICE_PRIVATE_KEY", d.to_bytes(32, "big"))
            + carr("DEVICE_CERT_R", comp(secrets.randbelow(N - 1) * G)) + carr("DEVICE_CERT_INFO", os.urandom(10))
            + carr("GATEWAY_PUBLIC_KEY", Qgw) + carr("ISSUER_PUBLIC_KEY", comp(5 * G)))
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

        def run(binary, seed, mode, lines="", seeded=None):
            env = dict(os.environ)
            if seeded is not None:
                env["GLIDE_SEEDED"] = seeded
            p = subprocess.run([str(work / binary), str(seed), mode], input=lines, capture_output=True,
                               text=True, env=env, timeout=120)
            if "AddressSanitizer" in p.stderr or "runtime error" in p.stderr:
                return None
            return [l for l in p.stdout.splitlines() if l.startswith(("MSG1", "KEY ", "ERR"))]

        def hkdf16(ikm, salt):
            prk = H(salt, ikm); return H(prk, b"edhoc-subset-v1-session-key\x01")[:16]

        def msg2_for(msg1, tamper=None):
            m = cbor2.loads(msg1); E_d = dec(m[8])
            e_g = secrets.randbelow(N - 1) + 1; E_g = comp(e_g * G); n_g = os.urandom(16)
            sig = SigningKey.from_secret_exponent(gw, curve=NIST256p).sign_deterministic(
                msg1 + E_g + n_g, hashfunc=hashlib.sha256, sigencode=sigencode_string)
            f = {0: 1, 1: 6, 8: E_g, 10: n_g, 7: sig}
            if tamper == "drop_nonce":
                del f[10]
            m2 = cbor2.dumps(f)
            if tamper == "flip_sig":
                m2 = m2[:-1] + bytes([m2[-1] ^ 1])
            return m2, hkdf16((e_g * E_d).x().to_bytes(32, "big"), hashlib.sha256(msg1 + m2).digest())

        fails, nonces = [], set()
        vk = SigningKey.from_secret_exponent(d, curve=NIST256p).get_verifying_key()
        fixed = bytes(i ^ 0xA5 for i in range(16))
        for seed in range(1, 21):
            out = run("host", seed, "testrng")
            if out is None:
                fails.append(f"sanitizer error (seed {seed})"); continue
            m1a, m1b = (bytes.fromhex(out[i].split()[1]) for i in (0, 1))
            for m1 in (m1a, m1b):
                m = cbor2.loads(m1); h = hashlib.sha256(m[8] + m[4] + m[3] + m[9] + Qgw).digest()
                if not vk.verify_digest(m[7], h, sigdecode=sigdecode_string):
                    fails.append(f"seed {seed}: signature does not verify")
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
        checks = [
            ("no random source -> AUTH_ERR_RNG, nothing written", run("host", 1, "norng") == ["ERR1 -5 untouched=1"]),
            ("host default random source works", (run("host", 1, "default") or [""])[0].startswith("MSG1")),
            ("CSPRNG enabled + unseeded -> AUTH_ERR_RNG, nothing written",
             run("csprng", 1, "default", seeded="0") == ["ERR1 -5 untouched=1"]),
            ("CSPRNG enabled + seeded -> works, and is the source used",
             (lambda a, b: bool(a) and a[0].startswith("MSG1") and a[0] != (b or [""])[0])(
                 run("csprng", 1, "testrng", seeded="1"), run("host", 1, "testrng"))),
        ]
        for label, ok in checks:
            print(f"  [{'ok ' if ok else 'BAD'}] {label}")
            if not ok:
                fails.append(label)
        print("\n20 runs x 2 MSG_1 + 3 MSG_2 cases: signature valid and deterministic, nonce fresh,")
        print("session key == Python gateway, bad MSG_2 rejected, ASan/UBSan clean:",
              "ALL PASS" if not fails else f"{len(fails)} FAILURE(S)")
        for f in fails[:10]:
            print("   ", f)
        return 1 if fails else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
