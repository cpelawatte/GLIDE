#!/usr/bin/env python3
"""
fix2_impl_edit.py -- Fix 2 (epoch beacon), Python implementation edits.

Run from the repo root (~/Desktop/FYP).

    python3 scripts/fix2_impl_edit.py --diff src/edhoc_subset.py   # show one file's diff, write nothing
    python3 scripts/fix2_impl_edit.py --diff                       # show every diff, write nothing
    python3 scripts/fix2_impl_edit.py --apply                      # write all files

Safety rules (same as scripts/fix2_edit.py):
  * Every edit states how many times its target must match. If ANY count is
    off, the script aborts before writing ANY file.
  * Refuses to run twice (detects the already-applied marker).
  * Touches only the files listed in FILES. cooja_serial_bridge.py and the C
    firmware are deliberately NOT touched (firmware step).
"""
import difflib
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
FILES = [
    "src/edhoc_subset.py",
    "src/gateway_verifier.py",
    "src/cbor_codec.py",
    "src/beacon.py",
    "tests/test_edhoc_subset.py",
    "tests/test_beacon.py",
]

EDITS = []   # (file, label, old, new, expected_count, is_regex)


def lit(f, label, old, new, n=1):
    EDITS.append((f, label, old, new, n, False))


def rx(f, label, pattern, repl, n):
    EDITS.append((f, label, pattern, repl, n, True))


# =========================================================================
# src/edhoc_subset.py
# =========================================================================
E = "src/edhoc_subset.py"

lit(E, "docstring: no unqualified 'two-message'",
    "EDHOC subset: two-message mutual authentication and session key establishment.\n",
    "EDHOC subset: mutual authentication and session key establishment using two\n"
    "unicast messages per authentication (MSG_1, MSG_2), with freshness supplied by\n"
    "an amortised epoch-beacon broadcast from the gateway (src/beacon.py, Fix 2).\n")

lit(E, "docstring: messages line",
    "    - Messages: MSG_1 + MSG_2 only (no MSG_3, no explicit key confirmation)\n",
    "    - Unicast messages: MSG_1 + MSG_2 only (no MSG_3, no explicit key\n"
    "      confirmation). Freshness comes from the epoch beacon, not a third flight.\n")

lit(E, "docstring: protocol flow steps 0-4",
    "    1. Device generates ephemeral keypair (e_d, E_d)\n"
    "    2. Device signs (E_d || R || cert_info || nonce_d || Q_gw) with its\n"
    "       long-term key d, where Q_gw is the pre-provisioned gateway public key\n"
    "    3. Device sends MSG_1 = {E_d, R, cert_info, nonce_d, signature_d}\n"
    "    4. Gateway verifies device via ECQV reconstruction + signature check (reuses\n"
    "       gateway_verifier.verify_signature_under_reconstructed_key).\n",
    "    0. Gateway broadcasts a beacon B = epoch (4 B) || value (16 B) once per\n"
    "       epoch. B is public and unsigned; the device keeps the latest one heard.\n"
    "    1. Device generates ephemeral keypair (e_d, E_d)\n"
    "    2. Device signs (E_d || R || cert_info || nonce_d || Q_gw || B) with its\n"
    "       long-term key d, where Q_gw is the pre-provisioned gateway public key.\n"
    "       Neither Q_gw nor B is transmitted in MSG_1 (zero wire bytes).\n"
    "    3. Device sends MSG_1 = {E_d, R, cert_info, nonce_d, signature_d}\n"
    "    4. Gateway rejects (R, nonce_d) if already accepted this epoch, verifies\n"
    "       the device via ECQV reconstruction + signature check against ITS OWN\n"
    "       current beacon (reuses\n"
    "       gateway_verifier.verify_signature_under_reconstructed_key), checks\n"
    "       revocation, and only then records (R, nonce_d) on the epoch's nonce\n"
    "       sheet (at most 2 accepted per device per epoch).\n")

lit(E, "import beacon module",
    "from src.cert_info import decode_cert_info, issuer_id_for\n",
    "from src.beacon import Beacon, EpochState, RecordResult\n"
    "from src.cert_info import decode_cert_info, issuer_id_for\n")

lit(E, "record-failure mapping",
    'HKDF_INFO = b"edhoc-subset-v1-session-key"\n',
    'HKDF_INFO = b"edhoc-subset-v1-session-key"\n'
    "\n"
    "# Fix 2: how a refused nonce-sheet write is reported. EPOCH_ENDED surfaces as\n"
    "# SIGNATURE_INVALID: the device signed over a beacon that is no longer ours,\n"
    "# which the gateway cannot tell apart from any other bad signature.\n"
    "_RECORD_FAILURES = {\n"
    "    RecordResult.REPLAY: (\n"
    "        AuthFailureReason.REPLAY_DETECTED,\n"
    '        "nonce_d already accepted this epoch (concurrent duplicate)"),\n'
    "    RecordResult.DEVICE_CAP_REACHED: (\n"
    "        AuthFailureReason.DEVICE_RATE_LIMITED,\n"
    '        "per-device cap reached for this epoch"),\n'
    "    RecordResult.SHEET_FULL: (\n"
    "        AuthFailureReason.NONCE_SHEET_FULL,\n"
    '        "nonce sheet full; failing closed until the next epoch"),\n'
    "    RecordResult.EPOCH_ENDED: (\n"
    "        AuthFailureReason.SIGNATURE_INVALID,\n"
    '        "epoch ended during verification (stale beacon)"),\n'
    "}\n"
    "if set(_RECORD_FAILURES) != set(RecordResult) - {RecordResult.RECORDED}:\n"
    '    raise RuntimeError("_RECORD_FAILURES must cover every refused RecordResult")\n')

lit(E, "remove dead 4-argument _msg1_signing_bytes",
    "#def _msg1_signing_bytes(\n"
    "#    E_d: PointJacobi,\n"
    "#    R: PointJacobi,\n"
    "#    cert_info: bytes,\n"
    "#    nonce_d: bytes,\n"
    "#) -> bytes:\n"
    '#    """Bytes the device signs in MSG_1."""\n'
    "#    return point_to_compressed(E_d) + point_to_compressed(R) + cert_info + nonce_d\n"
    "\n",
    "")

lit(E, "_msg1_signing_bytes: add beacon",
    "    nonce_d: bytes,\n"
    "    Q_gw: PointJacobi,\n"
    ") -> bytes:\n"
    '    """Bytes the device signs in MSG_1.\n'
    "\n"
    "    Q_gw is the pre-provisioned gateway long-term public key. Binding it\n"
    "    into the signature ties the message to the intended gateway, so a\n"
    "    captured MSG_1 is rejected by any other gateway pinning the same\n"
    "    issuer. Q_gw is held by both parties from provisioning and is NOT\n"
    '    transmitted, so this costs zero wire bytes.\n'
    '    """\n'
    "    return (point_to_compressed(E_d) + point_to_compressed(R)\n"
    "            + cert_info + nonce_d + point_to_compressed(Q_gw))\n",
    "    nonce_d: bytes,\n"
    "    Q_gw: PointJacobi,\n"
    "    beacon: Beacon,\n"
    ") -> bytes:\n"
    '    """Bytes the device signs in MSG_1:\n'
    "\n"
    "        E_d || R || cert_info || nonce_d || Q_gw || beacon\n"
    "\n"
    "    Q_gw is the pre-provisioned gateway long-term public key. Binding it\n"
    "    into the signature ties the message to the intended gateway, so a\n"
    "    captured MSG_1 is rejected by any other gateway pinning the same\n"
    "    issuer (relay fix).\n"
    "\n"
    "    beacon is the gateway's epoch beacon (Fix 2): 4-byte epoch counter +\n"
    "    16-byte random value. Binding it ties the message to one epoch, so a\n"
    "    recorded MSG_1 stops verifying once the epoch rolls (replay) and cannot\n"
    "    be prepared before the epoch starts (pre-play). On the gateway side the\n"
    "    caller MUST pass ITS OWN current beacon, never a value from the message.\n"
    "\n"
    "    Neither Q_gw nor beacon is transmitted in MSG_1: zero wire bytes.\n"
    "    The beacon is last, as `br` is last in the Tamarin signed payload\n"
    "    (paper/sections/tamarin_model_fix2_beacon.spthy).\n"
    '    """\n'
    "    if not isinstance(beacon, Beacon):\n"
    '        raise TypeError(f"beacon must be a Beacon, got {type(beacon).__name__}")\n'
    "    return (point_to_compressed(E_d) + point_to_compressed(R)\n"
    "            + cert_info + nonce_d + point_to_compressed(Q_gw)\n"
    "            + beacon.to_bytes())\n")

lit(E, "device_build_msg1: beacon parameter",
    "    gateway_public_key: PointJacobi,\n"
    ") -> tuple[bytes, EdhocInitiatorState]:\n"
    '    """Device builds MSG_1. Returns (msg1_bytes, state_to_retain).\n',
    "    gateway_public_key: PointJacobi,\n"
    "    beacon: Beacon,\n"
    ") -> tuple[bytes, EdhocInitiatorState]:\n"
    '    """Device builds MSG_1. Returns (msg1_bytes, state_to_retain).\n'
    "\n"
    "    `beacon` is the latest beacon the device heard. The device cannot check\n"
    "    it (beacons are unsigned); a stale or fake beacon only makes the gateway\n"
    "    reject this attempt, it can never make the gateway accept.\n")

lit(E, "device_build_msg1: stale comment + call",
    "    # Sign (E_d || R || cert_info || nonce_d) with long-term key d\n"
    "    signing_bytes = _msg1_signing_bytes(E_d, R, cert_info, nonce_d, gateway_public_key)\n",
    "    # Sign (E_d || R || cert_info || nonce_d || Q_gw || beacon) with long-term key d\n"
    "    signing_bytes = _msg1_signing_bytes(E_d, R, cert_info, nonce_d,\n"
    "                                        gateway_public_key, beacon)\n")

lit(E, "gateway: required keyword-only epoch_state",
    "    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),\n"
    ") -> EdhocResult:\n",
    "    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),\n"
    "    *,\n"
    "    epoch_state: EpochState,\n"
    ") -> EdhocResult:\n")

lit(E, "gateway: docstring on epoch_state + check order",
    "    DEVICE_REVOKED per threat model G5).\n"
    "\n"
    "    Returns EdhocResult with session_key, device_did, msg2_bytes on success.\n"
    '    """\n',
    "    DEVICE_REVOKED per threat model G5).\n"
    "\n"
    "    epoch_state (required, keyword-only; Fix 2) is the gateway's long-lived\n"
    "    EpochState. Create ONE per gateway and pass the same object to every\n"
    "    call: a fresh EpochState per call throws the nonce sheet away and\n"
    "    silently disables replay detection within an epoch. There is no default\n"
    "    on purpose: forgetting it must fail loudly, not run without replay\n"
    "    protection.\n"
    "\n"
    "    Check order (cheap before expensive; nothing written until all pass):\n"
    "        snapshot beacon -> decode -> cert_info / validity / issuer_id\n"
    "        -> nonce-sheet lookup (read-only) -> signature against OUR beacon\n"
    "        -> revocation -> record (cap 2 per device per epoch, fail closed)\n"
    "        -> ephemeral key, MSG_2, session key.\n"
    "\n"
    "    Returns EdhocResult with session_key, device_did, msg2_bytes on success.\n"
    '    """\n'
    "    if not isinstance(epoch_state, EpochState):\n"
    '        raise TypeError("epoch_state must be the gateway\'s EpochState (Fix 2)")\n'
    "    # Snapshot ONE beacon for the whole call. If the epoch rolls before we\n"
    "    # record, record() returns EPOCH_ENDED and nothing is accepted.\n"
    "    beacon = epoch_state.current_beacon()\n"
    "\n")

lit(E, "gateway: replay lookup + signature over our beacon",
    "    # --- Verify device signature via reconstruction (reused from verifier) ---\n"
    "    signing_bytes = _msg1_signing_bytes(msg1.E_d, msg1.R, msg1.cert_info, msg1.nonce_d, keystore.gateway_identity.public_key,)\n",
    "    # --- Replay lookup (Fix 2): READ-ONLY, safe on unauthenticated input ---\n"
    "    # A cheap dictionary lookup before the expensive signature check. The\n"
    "    # only write is record() below, after every check has passed.\n"
    "    device_key = point_to_compressed(msg1.R)\n"
    "    if epoch_state.is_replay(device_key, msg1.nonce_d):\n"
    "        return EdhocResult.fail(\n"
    "            AuthFailureReason.REPLAY_DETECTED,\n"
    '            f"nonce_d already accepted for this device in epoch {beacon.epoch}",\n'
    "        )\n"
    "\n"
    "    # --- Verify device signature via reconstruction (reused from verifier) ---\n"
    "    # Verified against OUR snapshot beacon, never anything in the message:\n"
    "    # a stale or fake beacon on the device side fails here.\n"
    "    signing_bytes = _msg1_signing_bytes(\n"
    "        msg1.E_d, msg1.R, msg1.cert_info, msg1.nonce_d,\n"
    "        keystore.gateway_identity.public_key, beacon,\n"
    "    )\n")

lit(E, "gateway: record after revocation, before MSG_2",
    "    # --- Generate gateway ephemeral keypair, sign MSG_2, derive session key ---\n",
    "    # --- Record (Fix 2): the ONLY write. Cap and fail-closed live here. ---\n"
    "    # After revocation, so a revoked device never uses up its cap; before\n"
    "    # MSG_2, so a refused device never costs a gateway signature.\n"
    "    recorded = epoch_state.record(beacon, device_key, msg1.nonce_d)\n"
    "    if recorded is not RecordResult.RECORDED:\n"
    "        reason, detail = _RECORD_FAILURES[recorded]\n"
    "        return EdhocResult.fail(reason, detail)\n"
    "\n"
    "    # --- Generate gateway ephemeral keypair, sign MSG_2, derive session key ---\n")

# =========================================================================
# src/gateway_verifier.py
# =========================================================================
lit("src/gateway_verifier.py", "AuthFailureReason: 3 Fix 2 members",
    '    REVOCATION_UNAVAILABLE   = "revocation_unavailable"   # Day 11\n',
    '    REVOCATION_UNAVAILABLE   = "revocation_unavailable"   # Day 11\n'
    '    REPLAY_DETECTED          = "replay_detected"          # Fix 2\n'
    '    DEVICE_RATE_LIMITED      = "device_rate_limited"      # Fix 2: cap per device per epoch\n'
    '    NONCE_SHEET_FULL         = "nonce_sheet_full"         # Fix 2: fail closed\n')

# =========================================================================
# src/cbor_codec.py
# =========================================================================
C = "src/cbor_codec.py"
lit(C, "PROTOCOL_VERSION 1 -> 2 (global)",
    "PROTOCOL_VERSION = 1   # Bumped when wire format changes incompatibly\n",
    "PROTOCOL_VERSION = 2   # Bumped when wire format or signed content changes incompatibly.\n"
    "                       # v2 (Fix 2): the MSG_1 signature also covers the epoch beacon.\n")
rx(C, "KEY_SIGNATURE: restore its comment",
   r"^KEY_SIGNATURE  = 7[ \t]*$",
   "KEY_SIGNATURE  = 7     # ECDSA signature (64 bytes: r || s concatenated)", 1)
rx(C, "KEY_NONCE_D: remove misplaced signature comment",
   r"^(KEY_NONCE_D    = 9     # Device nonce in EDHOC MSG_1 \(distinct from gateway nonce\))"
   r"[ \t]+# ECDSA signature \(64 bytes: r \|\| s concatenated\)[ \t]*$",
   r"\1", 1)

# =========================================================================
# src/beacon.py  -- occupancy must roll first (measurement accuracy)
# =========================================================================
lit("src/beacon.py", "occupancy rolls the epoch before reading",
    '        """Entries on the sheet right now (for the Cooja occupancy measurement)."""\n'
    "        with self._lock:\n"
    "            return self._entries\n",
    '        """Entries on the sheet right now (for the Cooja occupancy measurement).\n'
    "\n"
    "        Rolls first, so a reading taken after an epoch ended reports the new,\n"
    "        empty sheet instead of the previous epoch's count.\n"
    '        """\n'
    "        with self._lock:\n"
    "            self._roll_if_due()\n"
    "            return self._entries\n")

lit("tests/test_beacon.py", "test: occupancy reflects rollover",
    "# ---------------------------------------------------------------- the cap\n",
    "def test_occupancy_reflects_rollover_without_other_calls():\n"
    "    s, clock = make(); b = s.current_beacon()\n"
    "    s.record(b, b\"dev\", b\"n1\"); clock.advance(300)\n"
    "    assert s.occupancy == 0                       # no other call needed to roll\n"
    "\n"
    "# ---------------------------------------------------------------- the cap\n")

# =========================================================================
# tests/test_edhoc_subset.py
# =========================================================================
T = "tests/test_edhoc_subset.py"

lit(T, "docstring: Fix 2 coverage",
    "      offline fails closed)\n"
    '"""\n',
    "      offline fails closed)\n"
    "    - Fix 2 epoch-beacon freshness: replay, rollover, stale and fake beacon,\n"
    "      per-device cap, fail-closed sheet, nothing written on failure\n"
    '"""\n')

lit(T, "import beacon",
    "from src.gateway_verifier import AuthFailureReason\n",
    "from src.beacon import Beacon, EpochState\n"
    "from src.gateway_verifier import AuthFailureReason\n")

lit(T, "fixtures: fake monotonic clock + one EpochState per gateway",
    '    return {"d": d, "cert": cert, "contribution": contribution}\n',
    '    return {"d": d, "cert": cert, "contribution": contribution}\n'
    "\n"
    "\n"
    "class _FakeMonotonic:\n"
    '    """Stand-in for time.monotonic so epoch tests never sleep."""\n'
    "    def __init__(self): self.t = 1000.0\n"
    "    def __call__(self): return self.t\n"
    "    def advance(self, s): self.t += s\n"
    "\n"
    "\n"
    "EPOCH_LENGTH_S = 60\n"
    "\n"
    "\n"
    "@pytest.fixture\n"
    "def epoch_clock():\n"
    "    return _FakeMonotonic()\n"
    "\n"
    "\n"
    "@pytest.fixture\n"
    "def epoch_state(epoch_clock):\n"
    '    """ONE EpochState per gateway, shared across calls (as in production)."""\n'
    "    return EpochState(EPOCH_LENGTH_S, max_devices=8, clock=epoch_clock)\n")

# existing tests take the epoch_state fixture
_EXISTING = [
    "test_e2e_handshake_happy_path", "test_tampered_msg1_signature_rejected",
    "test_msg1_decode_failure_rejected", "test_expired_cert_rejected_in_msg1",
    "test_issuer_mismatch_rejected_in_msg1", "test_wrong_gateway_public_key_rejected",
    "test_tampered_msg2_rejected", "test_not_revoked_device_passes_handshake",
    "test_revoked_device_rejected_in_handshake",
    "test_offline_revocation_rejected_in_handshake",
    "test_msg1_signed_for_other_gateway_rejected",
]
rx(T, "existing tests: add epoch_state fixture",
   r"^def (" + "|".join(_EXISTING) + r")\(([^)]*)\):$",
   r"def \1(\2, epoch_state):", len(_EXISTING))

rx(T, "device_build_msg1 multi-line calls: add beacon",
   r"(    msg1_bytes, (?:state|_) = device_build_msg1\(\n"
   r"(?:        [^\n]*\n){3}"
   r"        (?:keystore\.gateway_identity|other_gateway)\.public_key,[^\n]*\n)"
   r"(    \)\n)",
   r"\1        epoch_state.current_beacon(),\n\2", 8)
rx(T, "device_build_msg1 one-line calls: add beacon",
   r"device_build_msg1\(d, cert\.R, cert\.cert_info, keystore\.gateway_identity\.public_key\)",
   "device_build_msg1(d, cert.R, cert.cert_info, keystore.gateway_identity.public_key,\n"
   "                                 epoch_state.current_beacon())", 2)

rx(T, "gateway one-line calls: add epoch_state",
   r"gateway_process_msg1_build_msg2\(keystore, (msg1_bytes|bytes\(tampered\)|b\"not-cbor-garbage\")\)",
   r"gateway_process_msg1_build_msg2(keystore, \1, epoch_state=epoch_state)", 8)
rx(T, "gateway multi-line calls: add epoch_state",
   r"keystore, msg1_bytes, revocation_manager=mgr,\n",
   "keystore, msg1_bytes, revocation_manager=mgr, epoch_state=epoch_state,\n", 3)

NEW_TESTS = '''


# ---------------------------------------------------------------------------
# Fix 2: epoch-beacon freshness
# Python counterparts of the Tamarin lemmas No_Replay, Gateway_Recentness and
# Fake_Beacon_Never_Accepted. Tamarin ASSUMES the gateway checks
# Epoch_Is_Current and Nonce_Sheet_Once_Per_Epoch (restrictions); these tests
# are the evidence that the implementation actually performs them.
# ---------------------------------------------------------------------------
def _msg1(device, keystore, beacon):
    msg1_bytes, _ = device_build_msg1(
        device["d"], device["cert"].R, device["cert"].cert_info,
        keystore.gateway_identity.public_key, beacon,
    )
    return msg1_bytes


def _gw(keystore, msg1_bytes, epoch_state):
    return gateway_process_msg1_build_msg2(keystore, msg1_bytes, epoch_state=epoch_state)


def _new_device(issuer):
    contribution = device_generate_contribution()
    cert = issuer_generate_cert(contribution.U, _make_cert_info(), issuer)
    return {"d": device_derive_private_key(contribution, cert), "cert": cert}


def test_signing_bytes_end_with_beacon(keystore, provisioned_device, epoch_state):
    beacon = epoch_state.current_beacon()
    cert = provisioned_device["cert"]
    sb = _msg1_signing_bytes(7 * G, cert.R, cert.cert_info, bytes(NONCE_SIZE),
                             keystore.gateway_identity.public_key, beacon)
    assert sb.endswith(beacon.to_bytes())
    print(f"\\n[SIZES] MSG_1 signing input={len(sb)} B (cert_info={len(cert.cert_info)} B)")
    assert len(sb) == 33 + 33 + len(cert.cert_info) + NONCE_SIZE + 33 + 20


def test_same_epoch_replay_rejected(keystore, provisioned_device, epoch_state):
    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())
    assert _gw(keystore, m, epoch_state).success
    again = _gw(keystore, m, epoch_state)
    assert again.success is False
    assert again.reason == AuthFailureReason.REPLAY_DETECTED


def test_replay_after_rollover_rejected_by_beacon(keystore, provisioned_device,
                                                  epoch_state, epoch_clock):
    """Rollover empties the sheet; the beacon is what stops the old MSG_1."""
    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())
    assert _gw(keystore, m, epoch_state).success
    epoch_clock.advance(EPOCH_LENGTH_S)
    assert epoch_state.occupancy == 0              # sheet really is empty
    again = _gw(keystore, m, epoch_state)
    assert again.success is False
    assert again.reason == AuthFailureReason.SIGNATURE_INVALID


def test_stale_beacon_rejected(keystore, provisioned_device, epoch_state, epoch_clock):
    old = epoch_state.current_beacon()
    epoch_clock.advance(EPOCH_LENGTH_S)
    r = _gw(keystore, _msg1(provisioned_device, keystore, old), epoch_state)
    assert r.success is False
    assert r.reason == AuthFailureReason.SIGNATURE_INVALID
    assert epoch_state.occupancy == 0


@pytest.mark.parametrize("epoch_offset", [0, 1])   # forged value; same or next epoch label
def test_fake_beacon_rejected_and_writes_nothing(keystore, provisioned_device,
                                                epoch_state, epoch_offset):
    real = epoch_state.current_beacon()
    fake_value = bytes(16) if real.value != bytes(16) else b"\\x01" * 16
    fake = Beacon((real.epoch + epoch_offset) % 2**32, fake_value)
    r = _gw(keystore, _msg1(provisioned_device, keystore, fake), epoch_state)
    assert r.success is False
    assert r.reason == AuthFailureReason.SIGNATURE_INVALID
    assert epoch_state.occupancy == 0
    # the honest device is unaffected afterwards
    assert _gw(keystore, _msg1(provisioned_device, keystore, real), epoch_state).success


def test_device_cap_two_per_epoch(keystore, provisioned_device, epoch_state, epoch_clock):
    b = epoch_state.current_beacon()
    assert _gw(keystore, _msg1(provisioned_device, keystore, b), epoch_state).success
    assert _gw(keystore, _msg1(provisioned_device, keystore, b), epoch_state).success
    third = _gw(keystore, _msg1(provisioned_device, keystore, b), epoch_state)
    assert third.success is False
    assert third.reason == AuthFailureReason.DEVICE_RATE_LIMITED
    epoch_clock.advance(EPOCH_LENGTH_S)          # cap resets with the epoch
    nxt = epoch_state.current_beacon()
    assert _gw(keystore, _msg1(provisioned_device, keystore, nxt), epoch_state).success


def test_sheet_full_fails_closed(keystore, issuer, epoch_clock):
    small = EpochState(EPOCH_LENGTH_S, max_devices=1, clock=epoch_clock)   # capacity 2
    a, b = _new_device(issuer), _new_device(issuer)
    beacon = small.current_beacon()
    assert _gw(keystore, _msg1(a, keystore, beacon), small).success
    assert _gw(keystore, _msg1(a, keystore, beacon), small).success
    r = _gw(keystore, _msg1(b, keystore, beacon), small)
    assert r.success is False
    assert r.reason == AuthFailureReason.NONCE_SHEET_FULL
    epoch_clock.advance(EPOCH_LENGTH_S)          # recovers at the next epoch
    assert _gw(keystore, _msg1(b, keystore, small.current_beacon()), small).success


def test_failed_signature_writes_nothing(keystore, provisioned_device, epoch_state):
    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())
    tampered = bytearray(m)
    tampered[-1] ^= 0x01
    assert _gw(keystore, bytes(tampered), epoch_state).success is False
    assert epoch_state.occupancy == 0
    assert _gw(keystore, m, epoch_state).success   # the genuine one still goes through


def test_revoked_device_writes_nothing(keystore, provisioned_device, epoch_state):
    from src.did_utils import encode_did_key
    fetcher = MockFetcher()
    fetcher.entries = {encode_did_key(provisioned_device["d"] * G): "2026-04-19T11:00:00Z"}
    mgr = RevocationSyncManager("http://x", fetch_fn=fetcher)
    mgr.sync_now()
    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())
    r = gateway_process_msg1_build_msg2(keystore, m, revocation_manager=mgr,
                                        epoch_state=epoch_state)
    assert r.reason == AuthFailureReason.DEVICE_REVOKED
    assert epoch_state.occupancy == 0


def test_epoch_ending_mid_call_is_signature_invalid(keystore, provisioned_device,
                                                    epoch_state, epoch_clock, monkeypatch):
    """The epoch rolls between the read-only lookup and record(): nothing is accepted."""
    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())
    real_is_replay = epoch_state.is_replay

    def lookup_then_roll(device_key, nonce):
        seen = real_is_replay(device_key, nonce)
        epoch_clock.advance(EPOCH_LENGTH_S)      # epoch ends during signature verification
        return seen

    monkeypatch.setattr(epoch_state, "is_replay", lookup_then_roll)
    r = _gw(keystore, m, epoch_state)
    assert r.success is False
    assert r.reason == AuthFailureReason.SIGNATURE_INVALID
    assert "epoch ended" in r.detail
    assert epoch_state.occupancy == 0


def test_epoch_state_is_required(keystore, provisioned_device, epoch_state):
    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())
    with pytest.raises(TypeError):
        gateway_process_msg1_build_msg2(keystore, m)                     # forgotten
    with pytest.raises(TypeError):
        gateway_process_msg1_build_msg2(keystore, m, epoch_state=None)   # explicit None


def test_device_requires_a_beacon_object(keystore, provisioned_device):
    with pytest.raises(TypeError):
        device_build_msg1(provisioned_device["d"], provisioned_device["cert"].R,
                          provisioned_device["cert"].cert_info,
                          keystore.gateway_identity.public_key, bytes(20))
'''

# Anchor = the last assertion of the file (count 1), so the block is appended at the end.
rx(T, "append Fix 2 tests at end of file",
   r"(    assert result\.reason == AuthFailureReason\.SIGNATURE_INVALID)\s*\Z",
   lambda mm: mm.group(1) + NEW_TESTS, 1)


# =========================================================================
def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("--diff", "--apply"):
        print(__doc__)
        return 2
    mode, only = sys.argv[1], sys.argv[2:]

    original, edited = {}, {}
    for f in FILES:
        p = ROOT / f
        if not p.exists():
            print(f"ABORT: {f} not found (run from the repo root)")
            return 1
        original[f] = edited[f] = p.read_text()

    if "from src.beacon import" in original["src/edhoc_subset.py"]:
        print("ABORT: edits already applied (src/edhoc_subset.py imports src.beacon).")
        return 1

    bad = []
    for f, label, old, new, n, is_rx in EDITS:
        text = edited[f]
        if is_rx:
            got = len(re.findall(old, text, flags=re.M))
            if got == n:
                text = re.sub(old, new, text, flags=re.M)
        else:
            got = text.count(old)
            if got == n:
                text = text.replace(old, new)
        status = "ok " if got == n else "BAD"
        print(f"  [{status}] {f}: {label}  (expected {n}, found {got})")
        if got != n:
            bad.append(label)
        edited[f] = text

    if bad:
        print(f"\nABORT: {len(bad)} edit(s) did not match exactly; NOTHING was written.")
        return 1

    if mode == "--diff":
        for f in FILES:
            if only and f not in only:
                continue
            sys.stdout.writelines(difflib.unified_diff(
                original[f].splitlines(True), edited[f].splitlines(True),
                fromfile=f"a/{f}", tofile=f"b/{f}"))
        print("\n(diff only: nothing written)")
        return 0

    for f in FILES:
        if edited[f] != original[f]:
            (ROOT / f).write_text(edited[f])
            print(f"  wrote {f}")
    print("\nApplied. Next: python -m pytest -q")
    return 0


if __name__ == "__main__":
    sys.exit(main())
