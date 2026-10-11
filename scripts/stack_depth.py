#!/usr/bin/env python3
"""stack_depth.py -- worst-case static stack depth from GCC -fcallgraph-info=su output.

Usage: python3 stack_depth.py <build_dir> <root_function> [<root_function> ...]

Reads every *.ci file under build_dir, joins nodes across files by name, and reports
the deepest call chain from each root (sum of per-function static frames).
Limits, printed with the result:
  * indirect calls (function pointers) cannot be followed -- listed, not counted;
  * functions with no frame info (assembly, library code) count as 0 B -- listed;
  * dynamic frames (alloca/VLAs) are flagged; recursion is reported and cut.
"""
import re, sys
from pathlib import Path

node_re = re.compile(r'node:\s*\{\s*title:\s*"([^"]+)"\s*label:\s*"([^"]*)"')
edge_re = re.compile(r'edge:\s*\{\s*sourcename:\s*"([^"]+)"\s*targetname:\s*"([^"]+)"')

frame, kind, calls = {}, {}, {}
for ci in Path(sys.argv[1]).rglob("*.ci"):
    for line in ci.read_text(errors="replace").splitlines():
        m = node_re.search(line)
        if m:
            name, label = m.groups()
            b = re.search(r"(\d+) bytes \((\w+)", label)
            if b:                                   # a definition with frame info wins
                frame[name] = int(b.group(1)); kind[name] = b.group(2)
            calls.setdefault(name, set())
            continue
        m = edge_re.search(line)
        if m:
            calls.setdefault(m.group(1), set()).add(m.group(2))

memo, unknown, indirect, recursion = {}, set(), set(), set()
def depth(fn, stack=()):
    if fn in stack:
        recursion.add(fn); return 0, [fn + " (RECURSION, cut)"]
    if fn in memo:
        return memo[fn]
    if fn == "__indirect_call":
        indirect.add(stack[-1] if stack else "?"); return 0, ["<indirect call: not followed>"]
    own = frame.get(fn)
    if own is None:
        unknown.add(fn); own = 0
    best, best_path = 0, []
    for callee in sorted(calls.get(fn, ())):
        d, p = depth(callee, stack + (fn,))
        if d > best:
            best, best_path = d, p
    res = (own + best, [f"{fn} [{frame.get(fn, '?')} B{', ' + kind[fn] if kind.get(fn, 'static') != 'static' else ''}]"] + best_path)
    memo[fn] = res
    return res

for want in sys.argv[2:]:
    names = set(calls) | set(frame)
    hits = [want] if want in names else sorted(n for n in names if n.endswith(":" + want) or n.endswith(want))
    if not hits:
        print(f"\n{want}: NOT FOUND in call graph"); continue
    root = max(hits, key=lambda n: depth(n)[0])
    total, path = depth(root)
    print(f"\nworst-case static stack from {root}: {total} B")
    for i, step in enumerate(path):
        print("   " + "  " * i + step)

print("\nindirect calls not followed (from):", ", ".join(sorted(indirect)) or "none")
print("non-static (dynamic/bounded) frames:", ", ".join(f"{k}={v}" for k, v in kind.items() if v != "static") or "none")
print("recursion:", ", ".join(sorted(recursion)) or "none")
reach_unknown = sorted(u for u in unknown if not u.startswith("__"))
print(f"called functions with no frame info, counted as 0 B ({len(reach_unknown)}):", ", ".join(reach_unknown[:15]) + (" ..." if len(reach_unknown) > 15 else ""))
