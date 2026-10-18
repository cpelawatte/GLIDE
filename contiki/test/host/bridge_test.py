#!/usr/bin/env python3
"""
bridge_test.py -- scripts/cooja_serial_bridge.py against the REAL device
firmware, without Cooja.

Usage (repo root):  python3 contiki/test/host/bridge_test.py [path/to/contiki-ng]
                    (default contiki-ng path: ../contiki-ng)

Builds device_auth_main.c for Contiki-NG's native target (throwaway
credential made with src/, epoch 10 s, repeat 1 s, ASan/UBSan) and connects it
to the bridge's serve() loop through a socket pair, exactly where Cooja's
Serial Socket would be. Checks:
  T1 the mote authenticates; bridge KCV check = MATCH
  T2 --drop-msg2 1: the mote resends MSG_1, the bridge resends the stored
     MSG_2 (RETRANSMISSION), KCV MATCH
  T3 settings mismatch (bridge repeat 2 s, firmware 1 s) is detected and stops
  T4 --replay: the captured MSG_1 replayed in the same epoch gives no new
     acceptance; after the epoch rolls it is refused (signature_invalid)
and that the session key never appears in mote or bridge output.
Prints verdicts only.
"""
import os, shutil, socket, subprocess, sys, tempfile, threading, time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
CNG = Path(sys.argv[1] if len(sys.argv) > 1 else REPO.parent / "contiki-ng").resolve()
sys.path.insert(0, str(REPO))

import scripts.cooja_serial_bridge as cb                                      # noqa: E402
from scripts.cooja_serial_bridge import Bridge, serve                        # noqa: E402
from src.beacon import EpochState                                            # noqa: E402
from src.cert_info import encode_cert_info                                   # noqa: E402
from src.ecqv_core import (device_derive_private_key, device_generate_contribution,  # noqa: E402
                           issuer_generate_cert, issuer_generate_keypair, point_to_compressed)
from src.gateway_keystore import (Keystore, PinnedIssuer, _compute_q_ca_hash,  # noqa: E402
                                  _generate_gateway_identity)

ISSUER_DID = "did:web:host-test.invalid"
EPOCH_S, REPEAT_S = 10, 1

# Record every session key the gateway derives, so the test can prove that
# none of them ever appears in the mote's or the bridge's output.
KEYS = []
_real_gateway = cb.gateway_process_msg1_build_msg2


def _recording_gateway(*a, **k):
    r = _real_gateway(*a, **k)
    if r.session_key:
        KEYS.append(r.session_key.hex())
    return r


cb.gateway_process_msg1_build_msg2 = _recording_gateway


def carr(n, b):
    return f"#define {n}_LEN {len(b)}\nstatic const uint8_t {n}[{n}_LEN] = {{{', '.join('0x%02x' % x for x in b)}}};\n"


def build(work):
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
    return (src / "build/native/device_auth_main.native") if r.returncode == 0 else None, keystore, r


def run(exe, keystore, *, repeat_s=REPEAT_S, duration, **opts):
    """One mote process wired to one Bridge through a socket pair."""
    gw_end, mote_end = socket.socketpair()
    p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, bufsize=0)
    seen = []

    def to_mote():
        while True:
            try:
                data = mote_end.recv(4096)
            except OSError:
                return
            if not data:
                return
            try:
                p.stdin.write(data); p.stdin.flush()
            except (BrokenPipeError, ValueError):
                return

    def from_mote():
        for line in iter(p.stdout.readline, b""):
            try:
                mote_end.sendall(line)
            except OSError:
                return

    threading.Thread(target=to_mote, daemon=True).start()
    threading.Thread(target=from_mote, daemon=True).start()
    bridge = Bridge(keystore, EpochState(EPOCH_S, 8), lambda l: gw_end.sendall((l + "\n").encode()),
                    epoch_s=EPOCH_S, repeat_s=repeat_s, log=seen.append, **opts)

    stop_when_done = opts.get("replay") is not True
    start = time.monotonic()

    def done():
        if bridge.result == "SETTINGS_MISMATCH":
            return True
        if stop_when_done:
            return bridge.result is not None
        return any("after the epoch rolled" in l for l in seen)

    # serve() in slices so the test can stop as soon as the outcome is known
    while time.monotonic() - start < duration and not done():
        serve(gw_end, bridge, duration=0.5)
    p.kill(); p.wait()
    err = p.stderr.read().decode(errors="replace")
    gw_end.close(); mote_end.close()
    clean = "AddressSanitizer" not in err and "runtime error" not in err
    return bridge, seen, clean


def main() -> int:
    for need in (CNG / "Makefile.include", CNG / "arch/platform/native"):
        if not need.exists():
            print("ABORT: not found:", need); return 1
    work = Path(tempfile.mkdtemp(prefix="glide_bridge_"))
    try:
        exe, keystore, r = build(work)
        print(f"build (native, ASan/UBSan): {'ok' if exe else 'FAILED'}")
        if not exe:
            print((r.stdout + r.stderr)[-2500:]); return 1
        results = {}

        def no_key(seen):
            return bool(KEYS) and not any(k in l for k in KEYS for l in seen)

        b, seen, clean = run(exe, keystore, duration=20)
        results["T1 mote authenticates through the bridge; KCV MATCH"] = (
            b.result == "MATCH" and b.counts["accepted"] == 1 and clean and no_key(seen))

        b, seen, clean = run(exe, keystore, duration=25, drop_msg2=1)
        results["T2 --drop-msg2 1: mote resends, stored MSG_2 resent, KCV MATCH"] = (
            b.result == "MATCH" and b.counts["dropped_msg2"] == 1
            and b.counts["retransmissions"] >= 1 and b.counts["accepted"] == 1 and clean and no_key(seen))

        b, seen, clean = run(exe, keystore, duration=10, repeat_s=2)
        results["T3 settings mismatch detected; bridge stops"] = b.result == "SETTINGS_MISMATCH" and clean

        b, seen, clean = run(exe, keystore, duration=EPOCH_S + 15, replay=True)
        same = [l for l in seen if l.startswith("[REPLAY]   ->")]
        after = [l for l in seen if "after the epoch rolled" in l]
        results["T4 --replay: no new acceptance in-epoch; signature_invalid after rollover"] = (
            b.result == "MATCH" and bool(same) and "new acceptance: no" in same[0]
            and bool(after) and "signature_invalid" in after[0] and "new acceptance: no" in after[0]
            and clean and no_key(seen))

        for label, ok in results.items():
            print(f"  [{'ok ' if ok else 'BAD'}] {label}")
        good = all(results.values())
        print("bridge <-> device firmware (native), ASan/UBSan clean:", "ALL PASS" if good else "FAILURES")
        return 0 if good else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
