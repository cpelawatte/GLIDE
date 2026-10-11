#!/usr/bin/env python3
"""
beacon_client_test.py -- unit tests for contiki/beacon_client.c on the host.

Usage (repo root):  python3 contiki/test/host/beacon_client_test.py

Compiles contiki/beacon_client.c with beacon_client_test.c under
AddressSanitizer + UBSan, at the default settings and at a short-epoch
setting, and runs it. Pure logic: no Contiki tree, no keys. Covers decision 3
(hold latest, never sign on hearing, rule C, no older-epoch rule, sliding
attempt cap on the device timer), decision 4 (stale wait) and T2 (resend
schedule, stop on beacon change), also across the 32-bit millisecond wrap.
"""
import subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTIKI = HERE.parent.parent

def main() -> int:
    flags = "-std=gnu11 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer".split()
    ok = True
    with tempfile.TemporaryDirectory(prefix="glide_bc_") as work:
        for label, defs in (("defaults (300 s epoch, 30 s repeat)", []),
                            ("short (60 s epoch, 10 s repeat)", ["-DGLIDE_EPOCH_S=60", "-DGLIDE_BEACON_REPEAT_S=10"])):
            exe = Path(work) / "bc"
            r = subprocess.run(["gcc", *flags, *defs, "-I", str(CONTIKI), "-o", str(exe),
                                str(HERE / "beacon_client_test.c"), str(CONTIKI / "beacon_client.c")],
                               capture_output=True, text=True)
            warn = [l for l in r.stderr.splitlines() if "beacon_client.c" in l and "warning" in l]
            if r.returncode:
                print(f"compile ({label}): FAILED"); print(r.stderr[-2000:]); return 1
            p = subprocess.run([str(exe)], capture_output=True, text=True, timeout=120)
            san = "AddressSanitizer" in p.stderr or "runtime error" in p.stderr
            res = [l for l in p.stdout.splitlines() if l.startswith("BC_RESULT")]
            fails = [l for l in p.stdout.splitlines() if l.startswith("FAIL")]
            n, f = (int(x) for x in res[0].split()[1:]) if res else (0, -1)
            good = bool(res) and f == 0 and not san and p.returncode == 0 and not warn
            ok &= good
            print(f"  [{'ok ' if good else 'BAD'}] {label}: {n} checks, {f} failed, "
                  f"beacon_client.c warnings {len(warn)}, sanitizer {'ERROR' if san else 'clean'}")
            for line in fails[:10]:
                print("     ", line)
    print("beacon_client:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
