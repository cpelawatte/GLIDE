#!/usr/bin/env python3
"""
d0_resend_edit.py -- Fix 2, decision 6 / T2: resend, don't re-sign.

A lost MSG_2 must not cost the device a new authentication. The gateway keeps,
per accepted authentication, the SHA-256 of the MSG_1 it accepted and the MSG_2
it sent. A byte-identical MSG_1 in the same epoch gets that stored MSG_2 again
(at most MAX_RESENDS = 4 times, RFC 7252 section 4.8 MAX_RETRANSMIT). A resend
is never an acceptance: no new sheet entry, no signature check, no gateway
signature, no session key. Stored replies die with the epoch.

Run from the repo root (~/Desktop/FYP).

    python3 scripts/d0_resend_edit.py --diff src/beacon.py   # one file's diff, write nothing
    python3 scripts/d0_resend_edit.py --diff                 # every diff, write nothing
    python3 scripts/d0_resend_edit.py --apply                # write all files

Safety rules (same as fix2_impl_edit.py):
  * Every edit states how many times its target must match. If ANY count is
    off, the script aborts before writing ANY file.
  * Refuses to run twice (detects MAX_RESENDS in src/beacon.py).
  * Touches only the files listed in FILES. The bridge and the firmware are
    NOT touched (Phase D).
"""
import difflib
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
FILES = [
    "src/beacon.py",
    "src/edhoc_subset.py",
    "src/gateway_verifier.py",
    "tests/test_beacon.py",
    "tests/test_edhoc_subset.py",
]

EDITS = []   # (file, label, old, new, expected_count, is_regex)


def lit(f, label, old, new, n=1):
    EDITS.append((f, label, old, new, n, False))


# =========================================================================
# src/beacon.py
# =========================================================================
B = "src/beacon.py"

lit(B, "docstring: T2 bullet",
    "  * Overflow FAILS CLOSED (and is logged): never accept without recording.\n",
    "  * Overflow FAILS CLOSED (and is logged): never accept without recording.\n"
    "  * Lost MSG_2 (decision 6, T2: resend, don't re-sign). Each entry also keeps\n"
    "    the SHA-256 of the MSG_1 that was accepted and the MSG_2 sent for it. A\n"
    "    byte-identical MSG_1 in the same epoch gets that stored MSG_2 again, at\n"
    "    most `max_resends` times (default 4, RFC 7252 MAX_RETRANSMIT). A resend\n"
    "    is never an acceptance: no new entry, no new gateway signature, no new\n"
    "    session key. Any other MSG_1 reusing the nonce is a replay. Stored\n"
    "    replies die with the epoch.\n")

lit(B, "imports: Optional",
    "from typing import Callable\n",
    "from typing import Callable, Optional\n")

lit(B, "constants: digest size and resend limit",
    "DEFAULT_PER_DEVICE_CAP = 2              # decision 6: max 2 accepted per device per epoch\n",
    "DEFAULT_PER_DEVICE_CAP = 2              # decision 6: max 2 accepted per device per epoch\n"
    "MSG1_DIGEST_SIZE = 32                   # SHA-256 of the whole MSG_1\n"
    "MAX_RESENDS = 4                         # T2: RFC 7252 section 4.8 MAX_RETRANSMIT\n")

lit(B, "entry and stored-reply types",
    '    EPOCH_ENDED = "epoch_ended"              # the epoch rolled while the message was being verified\n'
    "\n"
    "\n"
    "class EpochState:\n",
    '    EPOCH_ENDED = "epoch_ended"              # the epoch rolled while the message was being verified\n'
    "\n"
    "\n"
    "@dataclass\n"
    "class _Entry:\n"
    '    """One accepted authentication on the sheet (keyed by device, then nonce)."""\n'
    "    msg1_digest: Optional[bytes]       # None: this entry can never be resent\n"
    "    reply: Optional[bytes] = None      # the MSG_2 sent for it, once stored\n"
    "    device_did: Optional[str] = None   # for the revocation re-check on resend\n"
    "    resends: int = 0\n"
    "\n"
    "\n"
    "@dataclass(frozen=True)\n"
    "class StoredReply:\n"
    '    """What resend() hands back: the stored MSG_2 and whose it is."""\n'
    "    reply: bytes\n"
    "    device_did: Optional[str]\n"
    "\n"
    "\n"
    "class EpochState:\n")

lit(B, "constructor: max_resends parameter",
    "        per_device_cap: int = DEFAULT_PER_DEVICE_CAP,\n"
    "        clock: Callable[[], float] = time.monotonic,\n",
    "        per_device_cap: int = DEFAULT_PER_DEVICE_CAP,\n"
    "        max_resends: int = MAX_RESENDS,\n"
    "        clock: Callable[[], float] = time.monotonic,\n")

lit(B, "constructor: validate max_resends",
    "        if per_device_cap < 1:\n"
    '            raise ValueError("per_device_cap must be at least 1")\n'
    "        self._epoch_length_s = float(epoch_length_s)\n"
    "        self._per_device_cap = per_device_cap\n",
    "        if per_device_cap < 1:\n"
    '            raise ValueError("per_device_cap must be at least 1")\n'
    "        if max_resends < 0:\n"
    '            raise ValueError("max_resends must be 0 (resend off) or more")\n'
    "        self._epoch_length_s = float(epoch_length_s)\n"
    "        self._per_device_cap = per_device_cap\n"
    "        self._max_resends = max_resends\n")

lit(B, "sheet type: nonce -> entry",
    "        self._sheet: dict[bytes, list[bytes]] = {}\n",
    "        # device_key -> {nonce -> _Entry}. Bounded: at most per_device_cap\n"
    "        # nonces per device and `capacity` entries in all.\n"
    "        self._sheet: dict[bytes, dict[bytes, _Entry]] = {}\n")

lit(B, "record(): optional MSG_1 digest, store an entry",
    "    def record(self, beacon: Beacon, device_key: bytes, nonce: bytes) -> RecordResult:\n"
    '        """Write a nonce on the sheet. Call ONLY after the whole authentication succeeded.\n'
    "\n"
    "        `beacon` is the beacon the signature was verified against. If that epoch\n"
    "        has ended meanwhile the result is EPOCH_ENDED and nothing is written:\n"
    "        an ended epoch is never accepted (strict rule; Tamarin: Epoch_Is_Current).\n"
    '        """\n'
    "        with self._lock:\n"
    "            self._roll_if_due()\n"
    "            if beacon != self._beacon:\n"
    "                return RecordResult.EPOCH_ENDED\n"
    "            nonces = self._sheet.get(device_key)\n"
    "            if nonces is not None and nonce in nonces:\n"
    "                return RecordResult.REPLAY\n"
    "            if nonces is not None and len(nonces) >= self._per_device_cap:\n"
    "                return RecordResult.DEVICE_CAP_REACHED\n",
    "    def record(self, beacon: Beacon, device_key: bytes, nonce: bytes,\n"
    "               msg1_digest: Optional[bytes] = None) -> RecordResult:\n"
    '        """Write a nonce on the sheet. Call ONLY after the whole authentication succeeded.\n'
    "\n"
    "        `beacon` is the beacon the signature was verified against. If that epoch\n"
    "        has ended meanwhile the result is EPOCH_ENDED and nothing is written:\n"
    "        an ended epoch is never accepted (strict rule; Tamarin: Epoch_Is_Current).\n"
    "\n"
    "        `msg1_digest` is the SHA-256 of the whole accepted MSG_1. Without it the\n"
    "        entry can never be resent (the safe default).\n"
    '        """\n'
    "        if msg1_digest is not None and len(msg1_digest) != MSG1_DIGEST_SIZE:\n"
    '            raise ValueError(f"msg1_digest must be {MSG1_DIGEST_SIZE} bytes")\n'
    "        with self._lock:\n"
    "            self._roll_if_due()\n"
    "            if beacon != self._beacon:\n"
    "                return RecordResult.EPOCH_ENDED\n"
    "            nonces = self._sheet.get(device_key)\n"
    "            if nonces is not None and nonce in nonces:\n"
    "                return RecordResult.REPLAY\n"
    "            if nonces is not None and len(nonces) >= self._per_device_cap:\n"
    "                return RecordResult.DEVICE_CAP_REACHED\n")

lit(B, "record(): write an entry instead of appending a nonce",
    "            if nonces is None:\n"
    "                nonces = self._sheet[device_key] = []\n"
    "            nonces.append(nonce)\n"
    "            self._entries += 1\n"
    "            return RecordResult.RECORDED\n",
    "            if nonces is None:\n"
    "                nonces = self._sheet[device_key] = {}\n"
    "            nonces[nonce] = _Entry(msg1_digest)\n"
    "            self._entries += 1\n"
    "            return RecordResult.RECORDED\n"
    "\n"
    "    def store_reply(self, beacon: Beacon, device_key: bytes, nonce: bytes,\n"
    "                    reply: bytes, device_did: Optional[str] = None) -> bool:\n"
    '        """Keep the MSG_2 just sent for an entry, so it can be resent (T2).\n'
    "\n"
    "        Stored at most once per entry, and only in the epoch the entry was\n"
    "        recorded in. Returns False and stores nothing if that epoch has ended,\n"
    "        the entry does not exist, or a reply is already stored.\n"
    '        """\n'
    "        with self._lock:\n"
    "            self._roll_if_due()\n"
    "            if beacon != self._beacon:\n"
    "                return False\n"
    "            entry = self._sheet.get(device_key, {}).get(nonce)\n"
    "            if entry is None or entry.reply is not None:\n"
    "                return False\n"
    "            entry.reply = bytes(reply)\n"
    "            entry.device_did = device_did\n"
    "            return True\n"
    "\n"
    "    def resend(self, beacon: Beacon, device_key: bytes, nonce: bytes,\n"
    "               msg1_digest: bytes) -> Optional[StoredReply]:\n"
    '        """The stored MSG_2 for a byte-identical MSG_1, or None (T2).\n'
    "\n"
    "        Returns None unless ALL of these hold: the epoch of `beacon` is still\n"
    "        current, the entry exists, its MSG_1 digest equals `msg1_digest`, a\n"
    "        reply is stored, and fewer than max_resends resends have been made.\n"
    "        Adds nothing to the sheet; only the entry's resend counter goes up.\n"
    "        A resend is never an acceptance.\n"
    '        """\n'
    "        with self._lock:\n"
    "            self._roll_if_due()\n"
    "            if beacon != self._beacon:\n"
    "                return None\n"
    "            entry = self._sheet.get(device_key, {}).get(nonce)\n"
    "            if (entry is None or entry.msg1_digest is None or entry.reply is None\n"
    "                    or entry.msg1_digest != msg1_digest\n"
    "                    or entry.resends >= self._max_resends):\n"
    "                return None\n"
    "            entry.resends += 1\n"
    "            return StoredReply(entry.reply, entry.device_did)\n")


# =========================================================================
# src/edhoc_subset.py
# =========================================================================
E = "src/edhoc_subset.py"

lit(E, "docstring: protocol flow step 4 (resend)",
    "       sheet (at most 2 accepted per device per epoch).\n",
    "       sheet (at most 2 accepted per device per epoch).\n"
    "       A byte-identical MSG_1 later in the same epoch (the device lost\n"
    "       MSG_2) gets the stored MSG_2 again, at most 4 times; it causes no\n"
    "       new acceptance, signature or session key (decision 6, T2).\n")

lit(E, "EdhocResult: retransmission constructor",
    "    @classmethod\n"
    '    def fail(cls, reason: AuthFailureReason, detail: str = "") -> "EdhocResult":\n'
    "        return cls(success=False, reason=reason, detail=detail)\n",
    "    @classmethod\n"
    '    def fail(cls, reason: AuthFailureReason, detail: str = "") -> "EdhocResult":\n'
    "        return cls(success=False, reason=reason, detail=detail)\n"
    "\n"
    "    @classmethod\n"
    "    def retransmission(cls, msg2_bytes: bytes,\n"
    '                       device_did: Optional[str] = None) -> "EdhocResult":\n'
    '        """T2: send `msg2_bytes` again. NOT an acceptance (success is False),\n'
    "        so a caller that counts or logs successes never counts it twice.\n"
    '        The caller must still transmit msg2_bytes."""\n'
    "        return cls(success=False, device_did=device_did, msg2_bytes=msg2_bytes,\n"
    "                   reason=AuthFailureReason.RETRANSMISSION,\n"
    '                   detail="byte-identical MSG_1: stored MSG_2 resent, no new acceptance")\n')

lit(E, "revocation helper (shared by first pass and resend)",
    "# ---------------------------------------------------------------------------\n"
    "# Gateway side\n"
    "# ---------------------------------------------------------------------------\n",
    "# ---------------------------------------------------------------------------\n"
    "# Gateway side\n"
    "# ---------------------------------------------------------------------------\n"
    "\n"
    "def _revocation_refusal(revocation_manager, device_did) -> Optional[EdhocResult]:\n"
    '    """The failure to return if the device is revoked or revocation is\n'
    '    unavailable (fail closed), else None."""\n'
    "    from src.revocation_sync import RevocationCheck\n"
    "    check = revocation_manager.check_revocation(device_did)\n"
    "    if check is RevocationCheck.REVOKED:\n"
    "        return EdhocResult.fail(\n"
    "            AuthFailureReason.DEVICE_REVOKED,\n"
    '            f"device_did={device_did} is revoked",\n'
    "        )\n"
    "    if check is RevocationCheck.UNAVAILABLE:\n"
    "        return EdhocResult.fail(\n"
    "            AuthFailureReason.REVOCATION_UNAVAILABLE,\n"
    '            "gateway is OFFLINE",\n'
    "        )\n"
    "    return None\n"
    "\n")

lit(E, "docstring: check order with resend branch",
    "    Check order (cheap before expensive; nothing written until all pass):\n"
    "        snapshot beacon -> decode -> cert_info / validity / issuer_id\n"
    "        -> nonce-sheet lookup (read-only) -> signature against OUR beacon\n"
    "        -> revocation -> record (cap 2 per device per epoch, fail closed)\n"
    "        -> ephemeral key, MSG_2, session key.\n"
    "\n"
    "    Returns EdhocResult with session_key, device_did, msg2_bytes on success.\n",
    "    Check order (cheap before expensive; nothing written until all pass):\n"
    "        snapshot beacon -> decode -> cert_info / validity / issuer_id\n"
    "        -> nonce-sheet lookup (read-only) -> signature against OUR beacon\n"
    "        -> revocation -> record (cap 2 per device per epoch, fail closed)\n"
    "        -> ephemeral key, MSG_2, session key -> store MSG_2 for resends.\n"
    "\n"
    "    If the lookup finds the nonce already accepted: a byte-identical MSG_1\n"
    "    (same SHA-256) whose stored MSG_2 has been resent fewer than 4 times\n"
    "    gets EdhocResult.retransmission(stored MSG_2), after a revocation\n"
    "    re-check; anything else is REPLAY_DETECTED. Neither path verifies a\n"
    "    signature, writes a sheet entry, signs, or derives a key.\n"
    "\n"
    "    Returns EdhocResult with session_key, device_did, msg2_bytes on success.\n"
    "    On a retransmission, success is False and msg2_bytes must still be sent.\n")

lit(E, "replay lookup: resend branch",
    "    device_key = point_to_compressed(msg1.R)\n"
    "    if epoch_state.is_replay(device_key, msg1.nonce_d):\n"
    "        return EdhocResult.fail(\n"
    "            AuthFailureReason.REPLAY_DETECTED,\n"
    '            f"nonce_d already accepted for this device in epoch {beacon.epoch}",\n'
    "        )\n",
    "    device_key = point_to_compressed(msg1.R)\n"
    "    msg1_digest = hashlib.sha256(msg1_bytes).digest()\n"
    "    if epoch_state.is_replay(device_key, msg1.nonce_d):\n"
    "        # T2: only a byte-identical MSG_1 gets the stored MSG_2 again, and\n"
    "        # only up to 4 times. Any other reuse of the nonce is a replay.\n"
    "        stored = epoch_state.resend(beacon, device_key, msg1.nonce_d, msg1_digest)\n"
    "        if stored is None:\n"
    "            return EdhocResult.fail(\n"
    "                AuthFailureReason.REPLAY_DETECTED,\n"
    '                f"nonce_d already accepted for this device in epoch {beacon.epoch}",\n'
    "            )\n"
    "        if revocation_manager is not None:\n"
    "            refusal = _revocation_refusal(revocation_manager, stored.device_did)\n"
    "            if refusal is not None:\n"
    "                return refusal\n"
    "        return EdhocResult.retransmission(stored.reply, stored.device_did)\n")

lit(E, "revocation block -> helper",
    "    if revocation_manager is not None:\n"
    "        from src.revocation_sync import RevocationCheck\n"
    "        check = revocation_manager.check_revocation(device_did)\n"
    "        if check is RevocationCheck.REVOKED:\n"
    "            return EdhocResult.fail(\n"
    "                AuthFailureReason.DEVICE_REVOKED,\n"
    '                f"device_did={device_did} is revoked",\n'
    "            )\n"
    "        if check is RevocationCheck.UNAVAILABLE:\n"
    "            return EdhocResult.fail(\n"
    "                AuthFailureReason.REVOCATION_UNAVAILABLE,\n"
    '                "gateway is OFFLINE",\n'
    "            )\n",
    "    if revocation_manager is not None:\n"
    "        refusal = _revocation_refusal(revocation_manager, device_did)\n"
    "        if refusal is not None:\n"
    "            return refusal\n")

lit(E, "record(): pass the MSG_1 digest",
    "    recorded = epoch_state.record(beacon, device_key, msg1.nonce_d)\n",
    "    recorded = epoch_state.record(beacon, device_key, msg1.nonce_d, msg1_digest)\n")

lit(E, "store MSG_2 for resends",
    "    msg2_bytes = encode_edhoc_msg2(E_g, nonce_g, signature_g)\n",
    "    msg2_bytes = encode_edhoc_msg2(E_g, nonce_g, signature_g)\n"
    "    # T2: keep it for byte-identical MSG_1 resends. If the epoch ended in the\n"
    "    # meantime nothing is stored and this MSG_2 simply cannot be resent.\n"
    "    epoch_state.store_reply(beacon, device_key, msg1.nonce_d, msg2_bytes, device_did)\n")


# =========================================================================
# src/gateway_verifier.py
# =========================================================================
V = "src/gateway_verifier.py"

lit(V, "AuthFailureReason.RETRANSMISSION",
    '    NONCE_SHEET_FULL         = "nonce_sheet_full"         # Fix 2: fail closed\n',
    '    NONCE_SHEET_FULL         = "nonce_sheet_full"         # Fix 2: fail closed\n'
    '    RETRANSMISSION           = "retransmission"           # Fix 2 / T2: stored MSG_2 resent, no new acceptance\n')


# =========================================================================
# tests/test_beacon.py
# =========================================================================
TB = "tests/test_beacon.py"

lit(TB, "imports",
    "from src.beacon import (\n"
    "    BEACON_SIZE, BEACON_VALUE_SIZE, Beacon, EpochState, RecordResult,\n"
    ")\n",
    "from src.beacon import (\n"
    "    BEACON_SIZE, BEACON_VALUE_SIZE, MAX_RESENDS, Beacon, EpochState, RecordResult,\n"
    ")\n")

lit(TB, "constructor validation: max_resends",
    "    with pytest.raises(ValueError): EpochState(10, 1, per_device_cap=0)\n",
    "    with pytest.raises(ValueError): EpochState(10, 1, per_device_cap=0)\n"
    "    with pytest.raises(ValueError): EpochState(10, 1, max_resends=-1)\n")

lit(TB, "resend tests (appended after the atomicity test)",
    "    assert results.count(RecordResult.RECORDED) == 1\n"
    "    assert results.count(RecordResult.REPLAY) == 15\n"
    "    assert s.occupancy == 1\n",
    "    assert results.count(RecordResult.RECORDED) == 1\n"
    "    assert results.count(RecordResult.REPLAY) == 15\n"
    "    assert s.occupancy == 1\n"
    "\n"
    "# ---------------------------------------------------------------- T2 resend\n"
    "\n"
    "D1, D2 = b\"\\x11\" * 32, b\"\\x22\" * 32       # two different MSG_1 digests\n"
    "\n"
    "def _accepted(s, digest=D1, reply=b\"MSG2\"):\n"
    "    b = s.current_beacon()\n"
    "    assert s.record(b, b\"dev\", b\"n1\", digest) is RecordResult.RECORDED\n"
    "    assert s.store_reply(b, b\"dev\", b\"n1\", reply, \"did:key:z1\")\n"
    "    return b\n"
    "\n"
    "def test_max_resends_matches_coap_max_retransmit():\n"
    "    assert MAX_RESENDS == 4                       # RFC 7252 section 4.8\n"
    "\n"
    "def test_resend_returns_the_stored_reply_and_adds_nothing():\n"
    "    s, _ = make(); b = _accepted(s)\n"
    "    got = s.resend(b, b\"dev\", b\"n1\", D1)\n"
    "    assert got.reply == b\"MSG2\" and got.device_did == \"did:key:z1\"\n"
    "    assert s.occupancy == 1                       # no new entry\n"
    "\n"
    "def test_resend_needs_the_same_msg1_digest():\n"
    "    s, _ = make(); b = _accepted(s)\n"
    "    assert s.resend(b, b\"dev\", b\"n1\", D2) is None\n"
    "\n"
    "def test_resend_needs_the_same_device_and_nonce():\n"
    "    s, _ = make(); b = _accepted(s)\n"
    "    assert s.resend(b, b\"other\", b\"n1\", D1) is None\n"
    "    assert s.resend(b, b\"dev\", b\"n2\", D1) is None\n"
    "\n"
    "def test_resend_stops_after_max_resends():\n"
    "    s, _ = make(); b = _accepted(s)\n"
    "    for _ in range(MAX_RESENDS):\n"
    "        assert s.resend(b, b\"dev\", b\"n1\", D1) is not None\n"
    "    assert s.resend(b, b\"dev\", b\"n1\", D1) is None\n"
    "\n"
    "def test_max_resends_zero_turns_resend_off():\n"
    "    clock = FakeClock()\n"
    "    s = EpochState(300, 4, max_resends=0, clock=clock, value_source=counting_values())\n"
    "    b = _accepted(s)\n"
    "    assert s.resend(b, b\"dev\", b\"n1\", D1) is None\n"
    "\n"
    "def test_no_resend_before_the_reply_is_stored_and_it_does_not_count():\n"
    "    s, _ = make(); b = s.current_beacon()\n"
    "    s.record(b, b\"dev\", b\"n1\", D1)\n"
    "    assert s.resend(b, b\"dev\", b\"n1\", D1) is None\n"
    "    s.store_reply(b, b\"dev\", b\"n1\", b\"MSG2\")\n"
    "    for _ in range(MAX_RESENDS):\n"
    "        assert s.resend(b, b\"dev\", b\"n1\", D1) is not None\n"
    "\n"
    "def test_record_without_a_digest_is_never_resent():\n"
    "    s, _ = make(); b = s.current_beacon()\n"
    "    s.record(b, b\"dev\", b\"n1\")\n"
    "    s.store_reply(b, b\"dev\", b\"n1\", b\"MSG2\")\n"
    "    assert s.resend(b, b\"dev\", b\"n1\", D1) is None\n"
    "\n"
    "def test_stored_replies_die_with_the_epoch():\n"
    "    s, clock = make(); old = _accepted(s)\n"
    "    clock.advance(300); new = s.current_beacon()\n"
    "    assert s.resend(old, b\"dev\", b\"n1\", D1) is None\n"
    "    assert s.resend(new, b\"dev\", b\"n1\", D1) is None\n"
    "\n"
    "def test_resend_with_a_made_up_beacon_is_refused():\n"
    "    s, _ = make(); real = _accepted(s)\n"
    "    assert s.resend(Beacon(real.epoch, bytes(16)), b\"dev\", b\"n1\", D1) is None\n"
    "    assert s.resend(real, b\"dev\", b\"n1\", D1) is not None   # the real one still works\n"
    "\n"
    "def test_store_reply_rules():\n"
    "    s, clock = make(); b = s.current_beacon()\n"
    "    assert not s.store_reply(b, b\"dev\", b\"n1\", b\"X\")      # no such entry\n"
    "    s.record(b, b\"dev\", b\"n1\", D1)\n"
    "    assert s.store_reply(b, b\"dev\", b\"n1\", b\"FIRST\")\n"
    "    assert not s.store_reply(b, b\"dev\", b\"n1\", b\"SECOND\")  # never overwritten\n"
    "    assert s.resend(b, b\"dev\", b\"n1\", D1).reply == b\"FIRST\"\n"
    "    s.record(b, b\"dev\", b\"n2\", D2); clock.advance(300)\n"
    "    assert not s.store_reply(b, b\"dev\", b\"n2\", b\"LATE\")    # epoch ended\n"
    "\n"
    "@pytest.mark.parametrize(\"bad\", [b\"\", bytes(31), bytes(33)])\n"
    "def test_record_rejects_a_wrong_size_digest(bad):\n"
    "    s, _ = make(); b = s.current_beacon()\n"
    "    with pytest.raises(ValueError):\n"
    "        s.record(b, b\"dev\", b\"n1\", bad)\n"
    "    assert s.occupancy == 0\n"
    "\n"
    "def test_concurrent_resends_never_exceed_the_limit():\n"
    "    s, _ = make(); b = _accepted(s); results = []\n"
    "    def worker(): results.append(s.resend(b, b\"dev\", b\"n1\", D1))\n"
    "    threads = [threading.Thread(target=worker) for _ in range(16)]\n"
    "    for t in threads: t.start()\n"
    "    for t in threads: t.join()\n"
    "    assert sum(r is not None for r in results) == MAX_RESENDS\n")


# =========================================================================
# tests/test_edhoc_subset.py
# =========================================================================
TE = "tests/test_edhoc_subset.py"

lit(TE, "module docstring",
    "    - Fix 2 epoch-beacon freshness: replay, rollover, stale and fake beacon,\n"
    "      per-device cap, fail-closed sheet, nothing written on failure\n",
    "    - Fix 2 epoch-beacon freshness: replay, rollover, stale and fake beacon,\n"
    "      per-device cap, fail-closed sheet, nothing written on failure\n"
    "    - Fix 2 / T2 resend: byte-identical MSG_1 gets the stored MSG_2 (no new\n"
    "      acceptance), any other nonce reuse is a replay, at most 4 resends\n")

lit(TE, "imports: N for the malleability test",
    "from src.ecqv_core import (\n"
    "    G,\n",
    "from src.ecqv_core import (\n"
    "    G,\n"
    "    N,\n")

lit(TE, "replace the same-epoch replay test with the T2 tests",
    "def test_same_epoch_replay_rejected(keystore, provisioned_device, epoch_state):\n"
    "    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())\n"
    "    assert _gw(keystore, m, epoch_state).success\n"
    "    again = _gw(keystore, m, epoch_state)\n"
    "    assert again.success is False\n"
    "    assert again.reason == AuthFailureReason.REPLAY_DETECTED\n",
    "def test_identical_msg1_gets_the_stored_msg2_and_no_new_acceptance(\n"
    "        keystore, provisioned_device, epoch_state):\n"
    "    \"\"\"T2: the device lost MSG_2 and sends the same MSG_1 bytes again.\"\"\"\n"
    "    d = provisioned_device\n"
    "    m, dev_state = device_build_msg1(d[\"d\"], d[\"cert\"].R, d[\"cert\"].cert_info,\n"
    "                                     keystore.gateway_identity.public_key,\n"
    "                                     epoch_state.current_beacon())\n"
    "    first = _gw(keystore, m, epoch_state)\n"
    "    assert first.success\n"
    "    again = _gw(keystore, m, epoch_state)\n"
    "    assert again.success is False                     # never a second acceptance\n"
    "    assert again.reason == AuthFailureReason.RETRANSMISSION\n"
    "    assert again.msg2_bytes == first.msg2_bytes       # same bytes, not re-signed\n"
    "    assert again.session_key is None\n"
    "    assert epoch_state.occupancy == 1                 # no new sheet entry\n"
    "    # the device gets the SAME session key the gateway derived the first time\n"
    "    dev = device_process_msg2(dev_state, keystore.gateway_identity.public_key,\n"
    "                              again.msg2_bytes)\n"
    "    assert dev.success and dev.session_key == first.session_key\n"
    "    print(f\"\\n[SIZES] MSG_1={len(m)} B, stored MSG_2={len(first.msg2_bytes)} B\")\n"
    "\n"
    "\n"
    "def test_fifth_identical_msg1_is_a_replay(keystore, provisioned_device, epoch_state):\n"
    "    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())\n"
    "    assert _gw(keystore, m, epoch_state).success\n"
    "    for _ in range(4):\n"
    "        assert _gw(keystore, m, epoch_state).reason == AuthFailureReason.RETRANSMISSION\n"
    "    fifth = _gw(keystore, m, epoch_state)\n"
    "    assert fifth.reason == AuthFailureReason.REPLAY_DETECTED\n"
    "    assert fifth.msg2_bytes is None\n"
    "\n"
    "\n"
    "def test_valid_but_different_msg1_with_same_nonce_is_a_replay(\n"
    "        keystore, provisioned_device, epoch_state):\n"
    "    \"\"\"ECDSA malleability: (r, n - s) is a second VALID signature over the same\n"
    "    bytes. Its MSG_1 differs, so it gets no resend; the nonce makes it a replay.\"\"\"\n"
    "    beacon = epoch_state.current_beacon()\n"
    "    m = _msg1(provisioned_device, keystore, beacon)\n"
    "    msg1 = decode_edhoc_msg1(m)\n"
    "    r, s = msg1.signature[:32], int.from_bytes(msg1.signature[32:], \"big\")\n"
    "    twin = encode_edhoc_msg1(msg1.E_d, msg1.R, msg1.cert_info, msg1.nonce_d,\n"
    "                             r + (N - s).to_bytes(32, \"big\"))\n"
    "    assert twin != m\n"
    "    # proof the twin is genuinely valid: a gateway that never saw m accepts it\n"
    "    same_beacon = EpochState(EPOCH_LENGTH_S, max_devices=8, clock=_FakeMonotonic(),\n"
    "                             value_source=lambda n: beacon.value,\n"
    "                             first_epoch=beacon.epoch)\n"
    "    assert _gw(keystore, twin, same_beacon).success\n"
    "    # on the real gateway m was accepted first, so the twin is a replay\n"
    "    assert _gw(keystore, m, epoch_state).success\n"
    "    r2 = _gw(keystore, twin, epoch_state)\n"
    "    assert r2.reason == AuthFailureReason.REPLAY_DETECTED\n"
    "    assert r2.msg2_bytes is None\n"
    "    assert epoch_state.occupancy == 1\n"
    "\n"
    "\n"
    "def test_resend_does_not_verify_sign_or_derive(keystore, provisioned_device,\n"
    "                                               epoch_state, monkeypatch):\n"
    "    import src.edhoc_subset as es\n"
    "    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())\n"
    "    assert _gw(keystore, m, epoch_state).success\n"
    "    def must_not_run(*a, **k):\n"
    "        raise AssertionError(\"expensive step ran on a resend\")\n"
    "    monkeypatch.setattr(es, \"verify_signature_under_reconstructed_key\", must_not_run)\n"
    "    monkeypatch.setattr(es, \"derive_session_key\", must_not_run)\n"
    "    monkeypatch.setattr(es, \"encode_edhoc_msg2\", must_not_run)\n"
    "    assert _gw(keystore, m, epoch_state).reason == AuthFailureReason.RETRANSMISSION\n"
    "\n"
    "\n"
    "def test_no_resend_after_rollover(keystore, provisioned_device, epoch_state, epoch_clock):\n"
    "    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())\n"
    "    assert _gw(keystore, m, epoch_state).success\n"
    "    epoch_clock.advance(EPOCH_LENGTH_S)\n"
    "    r = _gw(keystore, m, epoch_state)\n"
    "    assert r.reason == AuthFailureReason.SIGNATURE_INVALID\n"
    "    assert r.msg2_bytes is None\n"
    "\n"
    "\n"
    "def test_device_revoked_after_acceptance_gets_no_resend(keystore, provisioned_device,\n"
    "                                                       epoch_state):\n"
    "    from src.did_utils import encode_did_key\n"
    "    fetcher = MockFetcher()\n"
    "    mgr = RevocationSyncManager(\"http://x\", fetch_fn=fetcher)\n"
    "    mgr.sync_now()\n"
    "    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())\n"
    "    assert gateway_process_msg1_build_msg2(keystore, m, revocation_manager=mgr,\n"
    "                                           epoch_state=epoch_state).success\n"
    "    fetcher.entries = {encode_did_key(provisioned_device[\"d\"] * G): \"2026-04-19T11:00:00Z\"}\n"
    "    mgr.sync_now()\n"
    "    r = gateway_process_msg1_build_msg2(keystore, m, revocation_manager=mgr,\n"
    "                                        epoch_state=epoch_state)\n"
    "    assert r.reason == AuthFailureReason.DEVICE_REVOKED\n"
    "    assert r.msg2_bytes is None\n")


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

    if "MAX_RESENDS" in original["src/beacon.py"]:
        print("ABORT: edits already applied (src/beacon.py defines MAX_RESENDS).")
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
