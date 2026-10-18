#!/usr/bin/env python3
"""
footprint_breakdown.py -- where the CC2538 image's bytes go, from the linker map.

Usage:  python3 scripts/footprint_breakdown.py <image.map> <image.elf>

Reads the GNU ld map file (build with LDFLAGS="-Wl,-Map=<file>") and adds up
every input section that the linker KEPT, per object file and per component:
  ROM  = .text + .ARM.exidx + .flashcca + .data (initial values live in flash)
  RAM  = .data + .bss + .socdata, with the fixed 2,048 B .stack shown apart.
Merged string sections are counted once (first contributor in address order).
Self-check: the output-section sizes from the map must equal
`arm-none-eabi-size -A` for the same ELF, and every byte must be attributed to
an object or to alignment padding (0 unattributed); the script prints MATCH or
MISMATCH, so a parsing error cannot pass silently.
"""
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROM_SECTIONS = {".text", ".ARM.exidx", ".flashcca"}
DATA_SECTIONS = {".data"}
BSS_SECTIONS = {".bss", ".socdata"}
STACK_SECTIONS = {".stack"}
COUNTED = ROM_SECTIONS | DATA_SECTIONS | BSS_SECTIONS | STACK_SECTIONS

GLIDE = {"device_auth.o", "beacon_client.o", "device_auth_main.o",
         "hkdf_sha256.o", "sha256_impl.o", "syscalls_stub.o"}
GROUPS = [
    ("GLIDE: device_auth (protocol)", {"device_auth.o"}),
    ("GLIDE: beacon_client (Fix 2 rules)", {"beacon_client.o"}),
    ("GLIDE: device_auth_main (serial glue)", {"device_auth_main.o"}),
    ("GLIDE: SHA-256 + HKDF", {"sha256_impl.o", "hkdf_sha256.o"}),
    ("GLIDE: syscalls_stub", {"syscalls_stub.o"}),
    ("micro-ecc (P-256)", {"uECC.o"}),
    ("Contiki-NG CBOR", {"cbor.o"}),
    ("CSPRNG + AES + seeding", {"csprng.o", "aes-128.o", "iq-seeder.o", "cc2538-aes-128.o", "aes.o"}),
]

head_re = re.compile(r"^(\.\S+)(?:\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+))?")
item_re = re.compile(r"^ (\S+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)(?:\s+(\S.*))?$")
name_only_re = re.compile(r"^ (\S+)$")
cont_re = re.compile(r"^\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\S.*)$")


def object_name(path: str) -> str:
    path = path.strip()
    m = re.search(r"\(([^)]+)\)$", path)          # libc.a(lib_a-memcpy.o)
    if m:
        lib = Path(path.split("(")[0]).name
        return f"{lib}:{m.group(1)}"
    return Path(path).name


def parse(map_path):
    """Attribute every byte of each counted output section exactly once.

    Input sections are swept in address order and each byte goes to the first
    object that covers it. This matters for merged string sections
    (.rodata.str1.1): the map lists every contributor at the same address
    with its pre-merge size, so plain addition would count shared strings
    several times. Bytes no input section covers are 'unattributed'."""
    lines = Path(map_path).read_text(errors="replace").splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("Linker script and memory map"))
    except StopIteration:
        sys.exit("not a GNU ld map file (no 'Linker script and memory map')")
    sections = {}                     # out -> (addr, size, [(addr, size, obj)])
    out, prev = None, ""
    for line in lines[start + 1:]:
        if line.startswith(".") or line.startswith("/DISCARD/"):
            h = head_re.match(line)
            out = h.group(1) if h else None
            if out in COUNTED:
                if h.group(2):
                    sections[out] = [int(h.group(2), 16), int(h.group(3), 16), []]
                else:
                    sections[out] = [None, None, []]     # wrapped header
            prev = line
            continue
        if out not in COUNTED:
            prev = line
            continue
        sec = sections[out]
        if sec[0] is None:                               # wrapped header values
            c = re.match(r"^\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)", line)
            if c:
                sec[0], sec[1] = int(c.group(1), 16), int(c.group(2), 16)
            prev = line
            continue
        m = item_re.match(line)
        if m and m.group(1) != "*fill*" and m.group(4):
            sec[2].append((int(m.group(2), 16), int(m.group(3), 16), object_name(m.group(4))))
        elif m and m.group(1) == "*fill*":
            sec[2].append((int(m.group(2), 16), int(m.group(3), 16), "(alignment padding)"))
        else:
            c = cont_re.match(line)
            if c and name_only_re.match(prev) and not prev.strip().startswith("*("):
                sec[2].append((int(c.group(1), 16), int(c.group(2), 16), object_name(c.group(3))))
        prev = line

    sizes = defaultdict(lambda: defaultdict(int))
    totals = {}
    for out, (addr, size, items) in sections.items():
        totals[out] = size
        cursor, end = addr, addr + size
        for a, s, obj in sorted(items):
            lo, hi = max(a, cursor), min(a + s, end)
            if hi > lo:
                sizes[obj][out] += hi - lo
                cursor = hi
        covered = sum(v[out] for v in sizes.values())
        if size - covered:
            sizes["(unattributed)"][out] += size - covered
    return sizes, totals


def size_A(elf):
    tool = "arm-none-eabi-size"
    r = subprocess.run([tool, "-A", elf], capture_output=True, text=True, check=True)
    got = {}
    for l in r.stdout.splitlines():
        p = l.split()
        if len(p) >= 2 and p[0].startswith(".") and p[1].isdigit():
            got[p[0]] = int(p[1])
    return got


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sizes, totals = parse(sys.argv[1])
    ref = size_A(sys.argv[2])
    ok = all(totals.get(s, 0) == ref.get(s, 0) for s in COUNTED)
    for s in sorted(COUNTED):
        ok = ok and sizes["(unattributed)"][s] == 0
        print(f"  {s:<11} map {totals.get(s, 0):>7}  size -A {ref.get(s, 0):>7}  "
              f"unattributed {sizes['(unattributed)'][s]:>5}")
    print("self-check:", "MATCH" if ok else "MISMATCH (do not use these numbers)")

    def rom(d): return sum(d[s] for s in ROM_SECTIONS) + sum(d[s] for s in DATA_SECTIONS)
    def ram(d): return sum(d[s] for s in DATA_SECTIONS | BSS_SECTIONS)

    print(f"\n{'component':<40}{'ROM':>8}{'RAM':>8}")
    grouped = set()
    for label, objs in GROUPS:
        r = sum(rom(sizes[o]) for o in objs if o in sizes)
        m = sum(ram(sizes[o]) for o in objs if o in sizes)
        grouped |= objs
        print(f"{label:<40}{r:>8}{m:>8}")
    libc = [o for o in sizes if ":" in o]
    pad = ["(alignment padding)", "(unattributed)"]
    rest = [o for o in sizes if o not in grouped and o not in libc and o not in pad]
    for label, objs in (("C library + libgcc", libc), ("Contiki-NG OS, net stack, CPU/board", rest),
                        ("alignment padding / unattributed", pad)):
        r = sum(rom(sizes[o]) for o in objs)
        m = sum(ram(sizes[o]) for o in objs)
        print(f"{label:<40}{r:>8}{m:>8}")
    allr = sum(rom(sizes[o]) for o in sizes)
    allm = sum(ram(sizes[o]) for o in sizes)
    print(f"{'TOTAL (stack reserved separately)':<40}{allr:>8}{allm:>8}   + .stack {totals.get('.stack', 0)}")
    glide_rom = sum(rom(sizes[o]) for o in GLIDE if o in sizes)
    glide_ram = sum(ram(sizes[o]) for o in GLIDE if o in sizes)
    print(f"{'  of which GLIDE sources':<40}{glide_rom:>8}{glide_ram:>8}")

    print("\nlargest 15 objects (ROM):")
    for o in sorted(sizes, key=lambda o: -rom(sizes[o]))[:15]:
        print(f"  {o:<44}{rom(sizes[o]):>8}{ram(sizes[o]):>8}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
