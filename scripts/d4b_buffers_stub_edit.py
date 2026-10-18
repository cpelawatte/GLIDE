#!/usr/bin/env python3
"""
d4b_buffers_stub_edit.py -- D4b: tighter message buffers, dead stub removed.

  * contiki/device_auth.h: AUTH_MSG1_MAX_LEN 256 -> 176 and AUTH_MSG2_MAX_LEN
    192 -> 128. MSG_1 is always 174 B and MSG_2 always 126 B (fixed-size
    fields, measured in every test run). Saves 144 B of RAM in
    device_auth_main.c (msg1_buf, in_buf). If a message ever grows, it fails
    closed: build_msg1 returns an error, an over-long input line is dropped,
    and host_test / e2e_test / bridge_test all fail.
  * contiki/syscalls_stub.c: DELETED, and its block in contiki/Makefile. Its
    only function (_exit) was needed by the scanf that D3a removed; the CC2538
    image links without it (measured in D4).

Run from the repo root (~/Desktop/FYP).

    python3 scripts/d4b_buffers_stub_edit.py --diff
    python3 scripts/d4b_buffers_stub_edit.py --apply

Every edit must match exactly once and the stub must be the known two-line
file; otherwise nothing is written or deleted. Refuses to run twice.
"""
import difflib
import sys
from pathlib import Path

ROOT = Path.cwd()
FILES = ["contiki/device_auth.h", "contiki/Makefile"]
STUB = "contiki/syscalls_stub.c"
STUB_MARKER = "void _exit(int s){(void)s;while(1);}"
EDITS = []


def lit(f, label, old, new, n=1):
    EDITS.append((f, label, old, new, n))


lit("contiki/device_auth.h", "AUTH_MSG1_MAX_LEN 176",
    "/* MSG_1 maximum size (conservative upper bound) */\n"
    "#define AUTH_MSG1_MAX_LEN  256\n",
    "/* MSG_1 buffer size. MSG_1 is always 174 B (fixed-size fields); 176 keeps\n"
    " * 4-byte alignment. A larger MSG_1 fails closed (AUTH_ERR_CBOR or\n"
    " * AUTH_ERR_BUFFER_SMALL) and the host / e2e / bridge tests fail. */\n"
    "#define AUTH_MSG1_MAX_LEN  176\n")

lit("contiki/device_auth.h", "AUTH_MSG2_MAX_LEN 128",
    "/* MSG_2 maximum size */\n"
    "#define AUTH_MSG2_MAX_LEN  192\n",
    "/* MSG_2 input buffer size. MSG_2 is always 126 B; a longer input line is\n"
    " * dropped by device_auth_main.c (and the e2e / bridge tests fail). */\n"
    "#define AUTH_MSG2_MAX_LEN  128\n")

lit("contiki/Makefile", "remove syscalls_stub.c",
    "ifeq ($(TARGET),cc2538dk)\n"
    "PROJECT_SOURCEFILES += syscalls_stub.c\n"
    "endif\n",
    "")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("--diff", "--apply"):
        print(__doc__)
        return 2
    for f in FILES:
        if not (ROOT / f).exists():
            print(f"ABORT: {f} not found (run from the repo root)")
            return 1
    original = {f: (ROOT / f).read_text() for f in FILES}
    if "AUTH_MSG1_MAX_LEN  176" in original["contiki/device_auth.h"]:
        print("ABORT: already applied (AUTH_MSG1_MAX_LEN is 176).")
        return 1
    edited = dict(original)
    bad = []
    for f, label, old, new, n in EDITS:
        got = edited[f].count(old)
        if got == n:
            edited[f] = edited[f].replace(old, new)
        print(f"  [{'ok ' if got == n else 'BAD'}] {f}: {label}  (expected {n}, found {got})")
        if got != n:
            bad.append(label)
    stub = ROOT / STUB
    stub_ok = stub.exists() and STUB_MARKER in stub.read_text() and len(stub.read_text().splitlines()) <= 3
    print(f"  [{'ok ' if stub_ok else 'BAD'}] {STUB}: delete  ({'known stub' if stub_ok else 'missing or not the known stub'})")
    if not stub_ok:
        bad.append(STUB)
    if bad:
        print(f"\nABORT: {len(bad)} check(s) failed; NOTHING was written or deleted.")
        return 1
    if sys.argv[1] == "--diff":
        for f in FILES:
            sys.stdout.writelines(difflib.unified_diff(
                original[f].splitlines(True), edited[f].splitlines(True),
                fromfile=f"a/{f}", tofile=f"b/{f}"))
        print(f"--- a/{STUB}\n+++ /dev/null   (deleted)")
        print("\n(diff only: nothing written)")
        return 0
    for f in FILES:
        (ROOT / f).write_text(edited[f])
        print(f"  wrote {f}")
    stub.unlink()
    print(f"  deleted {STUB}")
    print("\nApplied. Next: run the three host tests and the CC2538 build.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
