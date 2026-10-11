#!/usr/bin/env python3
"""
e2e_test.py -- the REAL device firmware (device_auth_main.c, TARGET=native)
against the REAL Python gateway, over a serial-style pipe.

Usage (repo root):  python3 contiki/test/host/e2e_test.py [path/to/contiki-ng]
                    (default contiki-ng path: ../contiki-ng)

Builds contiki/ for Contiki-NG's native target in a temporary directory, with
a throwaway credential made with src/ (never your credentials.h), short
settings (epoch 10 s, beacon repeat 1 s) and AddressSanitizer + UBSan. Each
scenario starts a fresh device process and plays the gateway with
src/edhoc_subset.py + src/beacon.py:

  S1 happy path: beacon -> MSG_1 (version 2, 174 B) -> MSG_2 -> KCV matches
     the gateway's key; the session key never appears in the device output
  S2 lost MSG_2 (T2): the device resends the identical MSG_1; the gateway
     answers RETRANSMISSION with the stored MSG_2; same key
  S3 forged MSG_2 first: rejected, attempt not cancelled; the real one works
  S4 rule C: a conflicting beacon stops resends and nothing is signed until
     the next beacon; the new epoch's MSG_1 is accepted
  S5 junk input (bad prefix, bad hex, short / odd-length beacon, over-long
     lines) is ignored; no MSG_1 without a beacon; the device still works afterwards
Prints verdicts only.
"""
import hashlib, os, queue, re, secrets, shutil, subprocess, sys, tempfile, threading, time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
CNG = Path(sys.argv[1] if len(sys.argv) > 1 else REPO.parent / "contiki-ng").resolve()
sys.path.insert(0, str(REPO))

import cbor2                                                                   # noqa: E402
from src.beacon import Beacon, EpochState                                      # noqa: E402
from src.cert_info import encode_cert_info                                     # noqa: E402
from src.ecqv_core import (device_derive_private_key, device_generate_contribution,  # noqa: E402
                           issuer_generate_cert, issuer_generate_keypair, point_to_compressed)
from src.edhoc_subset import gateway_process_msg1_build_msg2                  # noqa: E402
from src.gateway_keystore import (Keystore, PinnedIssuer, _compute_q_ca_hash, # noqa: E402
                                  _generate_gateway_identity)
from src.gateway_verifier import AuthFailureReason                            # noqa: E402

ISSUER_DID = "did:web:host-test.invalid"
EPOCH_S, REPEAT_S = 10, 1


def carr(n, b):
    return f"#define {n}_LEN {len(b)}\nstatic const uint8_t {n}[{n}_LEN] = {{{', '.join('0x%02x' % x for x in b)}}};\n"


def kcv(key: bytes) -> str:
    return hashlib.sha256(b"GLIDE-KCV" + key).digest()[:4].hex()


class FakeClock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, s): self.t += s


class Device:
    """One native device process; lines from its stdout arrive on a queue."""
    def __init__(self, exe):
        self.p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, bufsize=1)
        self.q, self.seen = queue.Queue(), []
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.q.put(line.rstrip("\n"))

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def wait_for(self, pattern, timeout):
        """Next line matching `pattern` (regex) within `timeout` s, else None."""
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return None
            try:
                line = self.q.get(timeout=left)
            except queue.Empty:
                return None
            self.seen.append(line)
            if re.search(pattern, line):
                return line

    def quiet(self, pattern, seconds):
        """True if no line matching `pattern` appears for `seconds`."""
        return self.wait_for(pattern, seconds) is None

    def close(self):
        self.p.kill()
        self.p.wait()
        err = self.p.stderr.read()
        return "AddressSanitizer" not in err and "runtime error" not in err


def msg1_of(line):
    return bytes.fromhex(line.split("MSG1:", 1)[1]) if line else None


def main() -> int:
    for need in (CNG / "Makefile.include", CNG / "arch/platform/native"):
        if not need.exists():
            print("ABORT: not found:", need); return 1
    work = Path(tempfile.mkdtemp(prefix="glide_e2e_"))
    try:
        src = work / "contiki"
        src.mkdir()
        for f in (REPO / "contiki").iterdir():
            if f.is_file() and f.suffix in (".c", ".h") and f.name != "credentials.h":
                shutil.copy(f, src / f.name)
        shutil.copy(REPO / "contiki" / "Makefile", src / "Makefile")

        now = datetime.now(timezone.utc)
        issuer = issuer_generate_keypair()
        contribution = device_generate_contribution()
        cert = issuer_generate_cert(contribution.U, encode_cert_info(ISSUER_DID, now, 24), issuer)
        d = device_derive_private_key(contribution, cert)
        keystore = Keystore(
            pinned_issuer=PinnedIssuer(issuer_did=ISSUER_DID, Q_ca=issuer.Q_ca,
                                       Q_ca_hash_hex=_compute_q_ca_hash(issuer.Q_ca),
                                       bootstrap_mode="pinned", bootstrapped_at=now.isoformat()),
            gateway_identity=_generate_gateway_identity(lifetime_days=90))
        (src / "credentials.h").write_text(
            "#pragma once\n#include <stdint.h>\n" + carr("DEVICE_PRIVATE_KEY", d.to_bytes(32, "big"))
            + carr("DEVICE_CERT_R", point_to_compressed(cert.R)) + carr("DEVICE_CERT_INFO", cert.cert_info)
            + carr("GATEWAY_PUBLIC_KEY", point_to_compressed(keystore.gateway_identity.public_key))
            + carr("ISSUER_PUBLIC_KEY", point_to_compressed(issuer.Q_ca)))

        env = dict(os.environ, CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer",
                   LDFLAGS="-fsanitize=address,undefined")
        r = subprocess.run(["make", "-j4", "TARGET=native", "MAKE_NET=MAKE_NET_NULLNET",
                            f"CONTIKI_NG_PATH={CNG}",
                            f"DEFINES=GLIDE_EPOCH_S={EPOCH_S},GLIDE_BEACON_REPEAT_S={REPEAT_S}"],
                           cwd=src, capture_output=True, text=True, env=env)
        warn = [l for l in (r.stdout + r.stderr).splitlines()
                if "warning" in l and ("device_auth" in l or "beacon_client" in l)]
        print(f"build (native, ASan/UBSan): {'ok' if r.returncode == 0 else 'FAILED'}, "
              f"GLIDE source warnings: {len(warn)}")
        if r.returncode:
            print((r.stdout + r.stderr)[-2500:]); return 1
        exe = src / "build/native/device_auth_main.native"

        values = iter(secrets.token_bytes(16) for _ in range(100))
        results = {}

        def gateway():
            clock = FakeClock()
            return EpochState(EPOCH_S, max_devices=8, clock=clock,
                              value_source=lambda n: next(values)), clock

        def beacon_line(b):
            return "BEACON:" + b.to_bytes().hex()

        def finish(dev, label, ok, key=None):
            clean = dev.close()
            if key is not None:
                ok = ok and not any(key.hex() in l for l in dev.seen)
            results[label] = ok and clean

        # ---- S1 happy path ----
        gw, _ = gateway(); dev = Device(exe)
        dev.send(beacon_line(gw.current_beacon()))
        m1 = msg1_of(dev.wait_for(r"^MSG1:", 10))
        ok = m1 is not None and len(m1) == 174 and cbor2.loads(m1)[0] == 2
        res = gateway_process_msg1_build_msg2(keystore, m1, epoch_state=gw) if ok else None
        ok = ok and res.success
        if ok:
            dev.send("MSG2:" + res.msg2_bytes.hex())
            ok = dev.wait_for(r"^KCV:", 10) == f"KCV:{kcv(res.session_key)}" \
                and dev.wait_for(r"=== Done ===", 5) is not None
        finish(dev, "S1 beacon -> MSG_1 (v2, 174 B) -> MSG_2 -> KCV == gateway; key never printed",
               ok, res.session_key if res else None)

        # ---- S2 lost MSG_2: identical resend, stored MSG_2 ----
        gw, _ = gateway(); dev = Device(exe); b = gw.current_beacon()
        dev.send(beacon_line(b))
        m1 = msg1_of(dev.wait_for(r"^MSG1:", 10))
        first = gateway_process_msg1_build_msg2(keystore, m1, epoch_state=gw) if m1 else None
        t0 = time.monotonic(); again = None                 # the first MSG_2 is "lost"
        while time.monotonic() - t0 < 6 and again is None:
            dev.send(beacon_line(b))                         # repeats keep coming
            again = msg1_of(dev.wait_for(r"^MSG1:", REPEAT_S))
        ok = bool(first and first.success and again == m1 and 2.0 <= time.monotonic() - t0 <= 4.5)
        if ok:
            r2 = gateway_process_msg1_build_msg2(keystore, again, epoch_state=gw)
            ok = (r2.reason is AuthFailureReason.RETRANSMISSION and r2.msg2_bytes == first.msg2_bytes
                  and gw.occupancy == 1)
            dev.send("MSG2:" + r2.msg2_bytes.hex())
            ok = ok and dev.wait_for(r"^KCV:", 10) == f"KCV:{kcv(first.session_key)}"
        finish(dev, "S2 lost MSG_2: same MSG_1 resent after 2-3 s, RETRANSMISSION, same key",
               ok, first.session_key if first else None)

        # ---- S3 forged MSG_2 first ----
        gw, _ = gateway(); dev = Device(exe)
        dev.send(beacon_line(gw.current_beacon()))
        m1 = msg1_of(dev.wait_for(r"^MSG1:", 10))
        res = gateway_process_msg1_build_msg2(keystore, m1, epoch_state=gw) if m1 else None
        ok = bool(res and res.success)
        if ok:
            forged = res.msg2_bytes[:-1] + bytes([res.msg2_bytes[-1] ^ 1])
            dev.send("MSG2:" + forged.hex())
            ok = dev.wait_for(r"MSG_2 rejected", 5) is not None and dev.quiet(r"^KCV:", 0.5)
            dev.send("MSG2:" + res.msg2_bytes.hex())
            ok = ok and dev.wait_for(r"^KCV:", 10) == f"KCV:{kcv(res.session_key)}"
        finish(dev, "S3 forged MSG_2 rejected without cancelling; real MSG_2 then works",
               ok, res.session_key if res else None)

        # ---- S4 rule C ----
        gw, clock = gateway(); dev = Device(exe); b1 = gw.current_beacon()
        dev.send(beacon_line(b1))
        m1 = msg1_of(dev.wait_for(r"^MSG1:", 10))
        fake = Beacon(b1.epoch, secrets.token_bytes(16))
        dev.send(beacon_line(fake))
        ok = m1 is not None and dev.wait_for(r"beacon conflict", 5) is not None
        ok = ok and dev.quiet(r"^MSG1:", 4.0)                # no resends, nothing signed
        clock.advance(EPOCH_S); b2 = gw.current_beacon()     # the gateway's next epoch
        dev.send(beacon_line(b2))
        m1b = msg1_of(dev.wait_for(r"^MSG1:", 10))
        res = gateway_process_msg1_build_msg2(keystore, m1b, epoch_state=gw) if m1b else None
        ok = ok and m1b is not None and m1b != m1 and bool(res and res.success)
        if ok:
            dev.send("MSG2:" + res.msg2_bytes.hex())
            ok = dev.wait_for(r"^KCV:", 10) == f"KCV:{kcv(res.session_key)}"
        finish(dev, "S4 rule C: conflict stops resends, nothing signed; next epoch's MSG_1 accepted",
               ok, res.session_key if res else None)

        # ---- S5 junk input ----
        gw, _ = gateway(); dev = Device(exe)
        for junk in ("HELLO:00", "MSG2:zz", "BEACON:00", "BEACON:" + "ab" * 21, "X" * 1000,
                     "MSG2:" + "00" * 400, "BEACON" + "00" * 20, "MSG2:abc",
                     "BEACON:" + "ab" * 20 + "c", "beacon:" + "ab" * 20):
            dev.send(junk)
        ok = dev.quiet(r"^MSG1:", 3.0)                      # no beacon held -> nothing signed
        dev.send(beacon_line(gw.current_beacon()))
        m1 = msg1_of(dev.wait_for(r"^MSG1:", 10))
        res = gateway_process_msg1_build_msg2(keystore, m1, epoch_state=gw) if m1 else None
        ok = ok and bool(res and res.success)
        if ok:
            dev.send("MSG2:" + res.msg2_bytes.hex())
            ok = dev.wait_for(r"^KCV:", 10) == f"KCV:{kcv(res.session_key)}"
        finish(dev, "S5 junk lines ignored, nothing signed without a beacon, then normal",
               ok, res.session_key if res else None)

        for label, ok in results.items():
            print(f"  [{'ok ' if ok else 'BAD'}] {label}")
        good = len(results) == 5 and all(results.values())
        print("device firmware (native) <-> real gateway, ASan/UBSan clean:",
              "ALL PASS" if good else "FAILURES")
        return 0 if good else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
