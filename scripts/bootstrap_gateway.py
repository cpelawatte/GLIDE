#!/usr/bin/env python3
"""bootstrap_gateway.py -- (re)create gateway_keystore.json pinned to the CURRENT issuer.

Requires the registry to be running first:   python -m src.did_registry
The expected Q_ca hash is computed locally from issuer_key.json (via `issuer_cli
export`): that is the out-of-band value DESIGN_DECISIONS.md DD-001 requires.
bootstrap_pinned() then fetches the DID document over HTTP and refuses unless it
matches. A fresh gateway keypair is generated at the same time.

Usage (repo root):  python scripts/bootstrap_gateway.py [--domain 127.0.0.1%3A5000] [--force]
Prints the DID and hash prefixes only; never key material.
"""
import argparse, os, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ecqv_core import compressed_to_point                      # noqa: E402
from src.gateway_keystore import _compute_q_ca_hash, bootstrap_pinned  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", default="127.0.0.1%3A5000")
    ap.add_argument("--keystore", default="gateway_keystore.json")
    ap.add_argument("--force", action="store_true", help="overwrite an existing keystore")
    a = ap.parse_args()

    out = subprocess.run([sys.executable, "-m", "src.issuer_cli", "export", "--domain", a.domain],
                         capture_output=True, text=True, check=True).stdout
    m = re.search(r"\b0[23][0-9a-fA-F]{64}\b", out)
    if not m:
        print("ABORT: no compressed Q_ca in `issuer_cli export` output"); return 1
    expected = _compute_q_ca_hash(compressed_to_point(bytes.fromhex(m.group(0))))

    url = f"http://{a.domain.replace('%3A', ':')}/.well-known/did.json"
    ks = bootstrap_pinned(Path(a.keystore), url, expected, force=a.force)
    os.chmod(a.keystore, 0o600)
    print("expected Q_ca hash prefix:", expected[:16])
    print("pinned   Q_ca hash prefix:", ks.pinned_issuer.Q_ca_hash_hex[:16], "| DID:", ks.pinned_issuer.issuer_did)
    return 0


if __name__ == "__main__":
    sys.exit(main())
