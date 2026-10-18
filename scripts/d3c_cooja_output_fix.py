#!/usr/bin/env python3
"""
d3c_cooja_output_fix.py -- Fix 2, Phase D3c: make Cooja show formatted output.

Cause (reproduced): Ubuntu's GCC enables _FORTIFY_SOURCE by default when
optimising, so printf() with a format compiles to __printf_chk(). Cooja's
native-mote platform only redirects printf/puts/putchar into the mote log
(-Wl,--wrap in arch/platform/cooja/Makefile.cooja), so every formatted line
(MSG1:<hex>, LOG_INFO with %s/%u, Contiki-NG's own boot lines) went to Cooja's
process stdout instead of Mote output and the Serial Socket. Only constant
strings (compiled to puts/putchar) got through.

  * contiki/Makefile: -U_FORTIFY_SOURCE for TARGET=cooja only. Host hardening
    has no meaning for a simulated mote; cc2538dk and native are unchanged.
  * contiki/device_auth.c: two comments corrected (position change): on Cooja
    the random source is Contiki-NG's CSPRNG, which the Cooja platform
    enables and seeds from the simulation's random seed -- not micro-ecc's
    /dev/urandom default as the comments said. No code change.

Run from the repo root (~/Desktop/FYP).

    python3 scripts/d3c_cooja_output_fix.py --diff
    python3 scripts/d3c_cooja_output_fix.py --apply

Every edit must match exactly once; otherwise nothing is written. Refuses to
run twice (detects _FORTIFY_SOURCE in contiki/Makefile).
"""
import difflib
import sys
from pathlib import Path

ROOT = Path.cwd()
FILES = ["contiki/Makefile", "contiki/device_auth.c"]
EDITS = []


def lit(f, label, old, new, n=1):
    EDITS.append((f, label, old, new, n))


lit("contiki/Makefile", "-U_FORTIFY_SOURCE for Cooja",
    "CFLAGS += -Os\n",
    "CFLAGS += -Os\n"
    "# Cooja native motes: Ubuntu's GCC enables _FORTIFY_SOURCE by default, which\n"
    "# turns printf() into __printf_chk(). Cooja only redirects printf/puts/putchar\n"
    "# into the mote log (-Wl,--wrap), so formatted output would bypass Mote output\n"
    "# and the Serial Socket. Host hardening has no meaning for a simulated mote.\n"
    "ifeq ($(TARGET),cooja)\n"
    "CFLAGS += -U_FORTIFY_SOURCE\n"
    "endif\n")

lit("contiki/device_auth.c", "header comment: Cooja random source",
    " *   - random source for e_d and nonce_d: Contiki-NG CSPRNG on CC2538\n"
    " *     (project-conf.h, seeded from radio noise at boot), micro-ecc's host\n"
    " *     default elsewhere (Cooja native mote); none -> AUTH_ERR_RNG\n",
    " *   - random source for e_d and nonce_d: Contiki-NG's CSPRNG where it is\n"
    " *     enabled -- CC2538 (project-conf.h, seeded from radio noise at boot)\n"
    " *     and Cooja (enabled by the platform, seeded from the simulation's\n"
    " *     random seed: reproducible, simulation only); micro-ecc's host\n"
    " *     default (/dev/urandom) on native and host-test builds;\n"
    " *     none -> AUTH_ERR_RNG\n")

lit("contiki/device_auth.c", "random_source comment: Cooja",
    " *   Cooja native mote and host builds: micro-ecc's built-in default (the\n"
    " *     host's /dev/urandom), registered automatically by micro-ecc.\n",
    " *   Cooja native mote: the Cooja platform enables the same CSPRNG and seeds\n"
    " *     it from the simulation's random seed (deterministic, simulation only).\n"
    " *   Native and host-test builds: micro-ecc's built-in default (the host's\n"
    " *     /dev/urandom), registered automatically by micro-ecc.\n")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("--diff", "--apply"):
        print(__doc__)
        return 2
    for f in FILES:
        if not (ROOT / f).exists():
            print(f"ABORT: {f} not found (run from the repo root)")
            return 1
    original = {f: (ROOT / f).read_text() for f in FILES}
    if "_FORTIFY_SOURCE" in original["contiki/Makefile"]:
        print("ABORT: already applied (contiki/Makefile mentions _FORTIFY_SOURCE).")
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
    if bad:
        print(f"\nABORT: {len(bad)} edit(s) did not match exactly; NOTHING was written.")
        return 1
    if sys.argv[1] == "--diff":
        for f in FILES:
            sys.stdout.writelines(difflib.unified_diff(
                original[f].splitlines(True), edited[f].splitlines(True),
                fromfile=f"a/{f}", tofile=f"b/{f}"))
        print("\n(diff only: nothing written)")
        return 0
    for f in FILES:
        (ROOT / f).write_text(edited[f])
        print(f"  wrote {f}")
    print("\nApplied. Next: rebuild for Cooja (see the instructions).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
