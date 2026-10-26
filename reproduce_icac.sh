#!/usr/bin/env bash
# Reproduces the GLIDE figures for this checkout:  bash reproduce_icac.sh
# Raw outputs go to evidence/<timestamp>/ . Optional environment variables:
#   CONTIKI_NG_PATH  Contiki-NG checkout (default: value in contiki/Makefile)
#   MAUDE            Maude binary for Tamarin (default: "maude" on PATH)
#   MAUDE_ALT        second Maude binary for a cross-engine check (optional)
#   MODEL            Tamarin model (default: paper/sections/tamarin_model_pfs.spthy)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1
OUT="$ROOT/evidence/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
MODEL="${MODEL:-paper/sections/tamarin_model_pfs.spthy}"
MAUDE_BIN="${MAUDE:-maude}"
banner() { printf '\n=== %s ===\n' "$1"; }
lemma_lines() { grep -oE "^ *[A-Za-z_0-9]+ \([a-z-]+\): (verified|falsified)[^(]*\([0-9]+ steps\)" "$1"; }

banner "0. Provenance"
{
  echo "Date:         $(date -Is)"
  echo "Commit:       $(git rev-parse --short HEAD) ($(git describe --tags --always 2>/dev/null))"
  echo "Uncommitted:  $(git status --short | grep -v ' evidence/' | wc -l) file(s)"
  echo "src imported: $(python -c 'import src.edhoc_subset as m; print(m.__file__)' 2>&1)"
  echo "Python:       $(python3 --version 2>&1)"
  echo "arm-none-eabi:$(arm-none-eabi-gcc --version 2>&1 | head -1)"
  echo "Tamarin:      $(tamarin-prover --version 2>&1 | grep -m1 -i tamarin)"
  echo "Maude:        $("$MAUDE_BIN" --version 2>&1 | head -1)"
  echo "Contiki-NG:   $(git -C "${CONTIKI_NG_PATH:-/home/csp/Desktop/contiki-ng}" log -1 --format='%h %ad' --date=short 2>&1)"
  echo "Model:        $MODEL"
} | tee "$OUT/00_provenance.txt"

banner "1. Credential size (benchmark issuer did:web:issuer.example)"
python3 -c "
import sys; sys.path.insert(0, '.')
from tests.test_edhoc_subset import _make_cert_info
ci = _make_cert_info()
print(f'cert_info = {len(ci)} B; credential = R(33) + cert_info = {33+len(ci)} B')
" 2>&1 | tee "$OUT/01_credential_size.txt"

banner "2. Handshake wire sizes"
python -m pytest tests/test_edhoc_subset.py::test_e2e_handshake_happy_path -s 2>&1 \
  | grep -E "SIZES|passed|failed" | tee "$OUT/02_wire_sizes.txt"

banner "3. Test suite"
python -m pytest -q 2>&1 | tail -5 | tee "$OUT/03_test_suite.txt"
banner "3b. Test names matching rejection keywords (heuristic only, NOT a paper number)"
python -m pytest -q --collect-only 2>&1 | grep -ciE "reject|invalid|expired|revoked|mismatch|malformed" \
  | tee "$OUT/03b_rejection_heuristic.txt"

build_size() {   # $1 = label, rest = extra make arguments
  local label="$1"; shift
  ( cd "$ROOT/contiki" || exit 1
    make TARGET=cc2538dk CONTIKI_PROJECT=device_auth_main_footprint "$@" clean >/dev/null 2>&1
    make TARGET=cc2538dk CONTIKI_PROJECT=device_auth_main_footprint "$@" > "$OUT/04_build_${label}.log" 2>&1 \
      || echo "BUILD FAILED, see $OUT/04_build_${label}.log"
    arm-none-eabi-size build/cc2538dk/device_auth_main_footprint.cc2538dk
    if [ "$label" = full ]; then
      echo "RPL symbols in full image: $(arm-none-eabi-nm build/cc2538dk/device_auth_main_footprint.cc2538dk | grep -ci rpl)"
      arm-none-eabi-nm build/cc2538dk/device_auth_main_footprint.cc2538dk | grep -i rpl | head -5
    fi
  ) 2>&1 | tee "$OUT/04_footprint_${label}.txt"
}
banner "4a. Footprint, full image (Makefile defaults). ROM = text, RAM = data + bss"
build_size full
banner "4b. Footprint, protocol isolated (NullNet, no routing)"
build_size isolated MAKE_NET=MAKE_NET_NULLNET MAKE_ROUTING=MAKE_ROUTING_NULLROUTING

run_tamarin() {  # $1 = label, $2 = maude binary
  { time timeout 900 tamarin-prover --prove --derivcheck-timeout=600 \
      --with-maude="$2" "$MODEL" ; } > "$OUT/05_tamarin_$1.txt" 2>&1
  lemma_lines "$OUT/05_tamarin_$1.txt" | tee "$OUT/05_tamarin_$1_lemmas.txt"
  echo "warnings (must be 0): $(grep -ciE 'derivation checks timed out|wellformedness checks* failed' "$OUT/05_tamarin_$1.txt")"
  grep -E "^real" "$OUT/05_tamarin_$1.txt"
}
banner "5a. Tamarin, main Maude ($MAUDE_BIN)"
run_tamarin main "$(command -v "$MAUDE_BIN" || echo "$MAUDE_BIN")"
if [ -n "${MAUDE_ALT:-}" ]; then
  banner "5b. Tamarin, second Maude ($MAUDE_ALT)"
  run_tamarin alt "$MAUDE_ALT"
  diff "$OUT/05_tamarin_main_lemmas.txt" "$OUT/05_tamarin_alt_lemmas.txt" \
    && echo "Both Maude versions: identical verdicts and step counts" \
    || echo "DIFFERENCE between Maude versions (see diff above)"
fi

banner "Summary"
echo "Evidence folder: $OUT"
echo "verified: $(grep -c ': verified' "$OUT/05_tamarin_main_lemmas.txt")   falsified: $(grep -c ': falsified' "$OUT/05_tamarin_main_lemmas.txt")"
