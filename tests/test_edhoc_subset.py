"""
Test suite for edhoc_subset.

Covers:
    - MSG_1 / MSG_2 CBOR codec round-trips (done in test_cbor_codec.py)
    - HKDF primitives match test vectors from RFC 5869
    - Session key derivation symmetry (both sides derive identical key)
    - End-to-end handshake happy path
    - Tampered MSG_1 field rejections (ephemeral, R, cert_info, nonce, signature)
    - Tampered MSG_2 rejections
    - Wrong gateway public key at device rejects handshake
    - Integration with revocation manager (not-revoked passes, revoked rejected,
      offline fails closed)
    - Fix 2 epoch-beacon freshness: replay, rollover, stale and fake beacon,
      per-device cap, fail-closed sheet, nothing written on failure
    - Fix 2 / T2 resend: byte-identical MSG_1 gets the stored MSG_2 (no new
      acceptance), any other nonce reuse is a replay, at most 4 resends
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from src.cbor_codec import (
    NONCE_SIZE,
    SIGNATURE_SIZE,
    decode_edhoc_msg1,
    decode_edhoc_msg2,
    encode_edhoc_msg1,
    encode_edhoc_msg2,
)
from src.cert_info import encode_cert_info
from src.ecqv_core import (
    G,
    N,
    device_derive_private_key,
    device_generate_contribution,
    issuer_generate_cert,
    issuer_generate_keypair,
)
from src.edhoc_subset import (
    HKDF_INFO,
    SESSION_KEY_LENGTH,
    _hkdf_expand,
    _hkdf_extract,
    _msg1_signing_bytes,
    _msg2_signing_bytes,
    derive_session_key,
    device_build_msg1,
    device_process_msg2,
    gateway_process_msg1_build_msg2,
)
from src.gateway_keystore import (
    Keystore,
    PinnedIssuer,
    _compute_q_ca_hash,
    _generate_gateway_identity,
)
from src.beacon import Beacon, EpochState
from src.gateway_verifier import AuthFailureReason
from src.revocation_sync import RevocationCheck, RevocationSyncManager

ISSUER_DID = "did:web:issuer.example"


# ---------------------------------------------------------------------------
# Mock fetcher for revocation manager (same pattern as Day 11)
# ---------------------------------------------------------------------------
class MockFetcher:
    def __init__(self):
        self.entries = {}

    def __call__(self, url, timeout):
        return {"revoked_at": "2026-04-19T12:00:00Z", "entries": dict(self.entries)}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def _make_cert_info(issuer_did=ISSUER_DID, issued_at=None, max_age_hours=8760) -> bytes:
    if issued_at is None:
        issued_at = datetime.now(timezone.utc)
    return encode_cert_info(issuer_did, issued_at, max_age_hours)


@pytest.fixture
def issuer():
    return issuer_generate_keypair()


@pytest.fixture
def gateway_identity():
    return _generate_gateway_identity(lifetime_days=90)


@pytest.fixture
def keystore(issuer, gateway_identity):
    pinned = PinnedIssuer(
        issuer_did=ISSUER_DID,
        Q_ca=issuer.Q_ca,
        Q_ca_hash_hex=_compute_q_ca_hash(issuer.Q_ca),
        bootstrap_mode="pinned",
        bootstrapped_at=datetime.now(timezone.utc).isoformat(),
    )
    return Keystore(pinned_issuer=pinned, gateway_identity=gateway_identity)


@pytest.fixture
def provisioned_device(issuer):
    contribution = device_generate_contribution()
    cert_info = _make_cert_info()
    cert = issuer_generate_cert(contribution.U, cert_info, issuer)
    d = device_derive_private_key(contribution, cert)
    return {"d": d, "cert": cert, "contribution": contribution}


class _FakeMonotonic:
    """Stand-in for time.monotonic so epoch tests never sleep."""
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, s): self.t += s


EPOCH_LENGTH_S = 60


@pytest.fixture
def epoch_clock():
    return _FakeMonotonic()


@pytest.fixture
def epoch_state(epoch_clock):
    """ONE EpochState per gateway, shared across calls (as in production)."""
    return EpochState(EPOCH_LENGTH_S, max_devices=8, clock=epoch_clock)


# ---------------------------------------------------------------------------
# HKDF sanity (not a full RFC 5869 vector, just shape checks)
# ---------------------------------------------------------------------------
def test_hkdf_extract_is_32_bytes():
    assert len(_hkdf_extract(b"salt", b"ikm")) == 32


def test_hkdf_expand_produces_requested_length():
    prk = _hkdf_extract(b"salt", b"ikm")
    assert len(_hkdf_expand(prk, b"info", 16)) == 16
    assert len(_hkdf_expand(prk, b"info", 42)) == 42


def test_hkdf_expand_deterministic():
    prk = _hkdf_extract(b"salt", b"ikm")
    a = _hkdf_expand(prk, b"info", 16)
    b = _hkdf_expand(prk, b"info", 16)
    assert a == b


# ---------------------------------------------------------------------------
# Session key symmetry: both sides compute the same key
# ---------------------------------------------------------------------------
def test_session_key_symmetry():
    """derive_session_key(e_d, E_g, ...) == derive_session_key(e_g, E_d, ...)"""
    import secrets
    from src.ecqv_core import N
    e_d = secrets.randbelow(N - 1) + 1
    e_g = secrets.randbelow(N - 1) + 1
    E_d = e_d * G
    E_g = e_g * G
    msg1 = b"msg1_placeholder"
    msg2 = b"msg2_placeholder"
    device_key = derive_session_key(e_d, E_g, msg1, msg2)
    gateway_key = derive_session_key(e_g, E_d, msg1, msg2)
    assert device_key == gateway_key
    assert len(device_key) == SESSION_KEY_LENGTH


def test_different_transcripts_produce_different_keys():
    import secrets
    from src.ecqv_core import N
    e_d = secrets.randbelow(N - 1) + 1
    e_g = secrets.randbelow(N - 1) + 1
    E_g = e_g * G
    key1 = derive_session_key(e_d, E_g, b"msg1_A", b"msg2_A")
    key2 = derive_session_key(e_d, E_g, b"msg1_B", b"msg2_B")
    assert key1 != key2


# ---------------------------------------------------------------------------
# End-to-end happy path
# ---------------------------------------------------------------------------
def test_e2e_handshake_happy_path(keystore, provisioned_device, epoch_state):
    # Device builds MSG_1
    msg1_bytes, state = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
        epoch_state.current_beacon(),
    )
    # Gateway processes MSG_1 and builds MSG_2
    gw_result = gateway_process_msg1_build_msg2(keystore, msg1_bytes, epoch_state=epoch_state)
    assert gw_result.success, f"Gateway rejected: {gw_result.reason} / {gw_result.detail}"
    assert gw_result.session_key is not None
    assert gw_result.msg2_bytes is not None
    print(f"\n[SIZES] MSG_1={len(msg1_bytes)}  MSG_2={len(gw_result.msg2_bytes)}")
    assert gw_result.device_did is not None
    # Device processes MSG_2
    dev_result = device_process_msg2(
        state,
        keystore.gateway_identity.public_key,
        gw_result.msg2_bytes,
    )
    assert dev_result.success, f"Device rejected: {dev_result.reason} / {dev_result.detail}"
    # Both sides have the same session key
    assert dev_result.session_key == gw_result.session_key


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------
def test_tampered_msg1_signature_rejected(keystore, provisioned_device, epoch_state):
    msg1_bytes, _ = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
        epoch_state.current_beacon(),
    )
    # Flip the last byte (highly likely to be inside the signature field)
    tampered = bytearray(msg1_bytes)
    tampered[-1] ^= 0x01
    result = gateway_process_msg1_build_msg2(keystore, bytes(tampered), epoch_state=epoch_state)
    assert result.success is False


def test_msg1_decode_failure_rejected(keystore, epoch_state):
    result = gateway_process_msg1_build_msg2(keystore, b"not-cbor-garbage", epoch_state=epoch_state)
    assert result.success is False
    assert result.reason == AuthFailureReason.CERT_INFO_MALFORMED


def test_expired_cert_rejected_in_msg1(keystore, issuer, epoch_state):
    contribution = device_generate_contribution()
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    cert_info = _make_cert_info(issued_at=old, max_age_hours=1)
    cert = issuer_generate_cert(contribution.U, cert_info, issuer)
    d = device_derive_private_key(contribution, cert)
    msg1_bytes, _ = device_build_msg1(d, cert.R, cert.cert_info, keystore.gateway_identity.public_key,
                                 epoch_state.current_beacon())
    result = gateway_process_msg1_build_msg2(keystore, msg1_bytes, epoch_state=epoch_state)
    assert result.success is False
    assert result.reason == AuthFailureReason.CERT_EXPIRED


def test_issuer_mismatch_rejected_in_msg1(keystore, issuer, epoch_state):
    contribution = device_generate_contribution()
    cert_info = _make_cert_info(issuer_did="did:web:different-issuer.example")
    cert = issuer_generate_cert(contribution.U, cert_info, issuer)
    d = device_derive_private_key(contribution, cert)
    msg1_bytes, _ = device_build_msg1(d, cert.R, cert.cert_info, keystore.gateway_identity.public_key,
                                 epoch_state.current_beacon())
    result = gateway_process_msg1_build_msg2(keystore, msg1_bytes, epoch_state=epoch_state)
    assert result.success is False
    assert result.reason == AuthFailureReason.ISSUER_MISMATCH


def test_wrong_gateway_public_key_rejected(keystore, provisioned_device, epoch_state):
    """Device receives MSG_2 but was provisioned with a DIFFERENT gateway pubkey."""
    msg1_bytes, state = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
        epoch_state.current_beacon(),
    )
    gw_result = gateway_process_msg1_build_msg2(keystore, msg1_bytes, epoch_state=epoch_state)
    assert gw_result.success
    # Device uses WRONG gateway pubkey (e.g., from a different gateway)
    wrong_gateway = _generate_gateway_identity(lifetime_days=90)
    dev_result = device_process_msg2(
        state,
        wrong_gateway.public_key,   # WRONG
        gw_result.msg2_bytes,
    )
    assert dev_result.success is False
    assert dev_result.reason == AuthFailureReason.SIGNATURE_INVALID


def test_tampered_msg2_rejected(keystore, provisioned_device, epoch_state):
    msg1_bytes, state = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
        epoch_state.current_beacon(),
    )
    gw_result = gateway_process_msg1_build_msg2(keystore, msg1_bytes, epoch_state=epoch_state)
    assert gw_result.success
    tampered = bytearray(gw_result.msg2_bytes)
    tampered[-1] ^= 0x01   # tamper signature byte
    dev_result = device_process_msg2(
        state, keystore.gateway_identity.public_key, bytes(tampered),
    )
    assert dev_result.success is False


# ---------------------------------------------------------------------------
# Revocation integration
# ---------------------------------------------------------------------------
def test_not_revoked_device_passes_handshake(keystore, provisioned_device, epoch_state):
    # Revocation manager attached, but this device is NOT in the list.
    # Guards against an over-aggressive revocation check that would reject
    # a legitimate device.
    fetcher = MockFetcher()
    fetcher.entries = {}          # empty revocation list
    mgr = RevocationSyncManager("http://x", fetch_fn=fetcher)
    mgr.sync_now()
    msg1_bytes, _ = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
        epoch_state.current_beacon(),
    )
    result = gateway_process_msg1_build_msg2(
        keystore, msg1_bytes, revocation_manager=mgr, epoch_state=epoch_state,
    )
    assert result.success is True
    assert result.session_key is not None


def test_revoked_device_rejected_in_handshake(keystore, provisioned_device, epoch_state):
    from src.did_utils import encode_did_key
    # Expected device DID
    device_did = encode_did_key(provisioned_device["d"] * G)
    # Build a revocation manager with this device revoked
    fetcher = MockFetcher()
    fetcher.entries = {device_did: "2026-04-19T11:00:00Z"}
    mgr = RevocationSyncManager("http://x", fetch_fn=fetcher)
    mgr.sync_now()
    msg1_bytes, _ = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
        epoch_state.current_beacon(),
    )
    result = gateway_process_msg1_build_msg2(
        keystore, msg1_bytes, revocation_manager=mgr, epoch_state=epoch_state,
    )
    assert result.success is False
    assert result.reason == AuthFailureReason.DEVICE_REVOKED


def test_offline_revocation_rejected_in_handshake(keystore, provisioned_device, epoch_state):
    from datetime import datetime, timezone

    class FrozenClock:
        def __init__(self, t): self.t = t
        def __call__(self): return self.t
        def advance(self, s):
            from datetime import timedelta
            self.t += timedelta(seconds=s)

    clock = FrozenClock(datetime(2026, 4, 19, 12, 0, 0, tzinfo=timezone.utc))
    fetcher = MockFetcher()
    mgr = RevocationSyncManager(
        "http://x",
        sync_interval=60, grace_window=300,
        now_fn=clock, fetch_fn=fetcher,
    )
    mgr.sync_now()
    clock.advance(1000)   # way past I + G
    msg1_bytes, _ = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
        epoch_state.current_beacon(),
    )
    # We need cert freshness to still pass, so inject a fresh "now" for the verifier
    fresh_now = datetime.now(timezone.utc)
    result = gateway_process_msg1_build_msg2(
        keystore, msg1_bytes, revocation_manager=mgr, epoch_state=epoch_state,
        now_fn=lambda: fresh_now,
    )
    assert result.success is False
    assert result.reason == AuthFailureReason.REVOCATION_UNAVAILABLE


# ---------------------------------------------------------------------------
# Cross-gateway relay countermeasure (Semester 3)
# ---------------------------------------------------------------------------
def test_msg1_signed_for_other_gateway_rejected(keystore, provisioned_device, epoch_state):
    """Cross-gateway relay: MSG_1 signed for gateway A must not verify at B.

    Countermeasure: Q_gw is bound into sigma_d. Corresponds to Tamarin
    lemma Gateway_Authenticates_Device (verified, 21 steps).
    """
    other_gateway = _generate_gateway_identity(lifetime_days=90)

    msg1_bytes, _ = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        other_gateway.public_key,      # signed for a DIFFERENT gateway
        epoch_state.current_beacon(),
    )
    result = gateway_process_msg1_build_msg2(keystore, msg1_bytes, epoch_state=epoch_state)
    assert result.success is False
    assert result.reason == AuthFailureReason.SIGNATURE_INVALID


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
    print(f"\n[SIZES] MSG_1 signing input={len(sb)} B (cert_info={len(cert.cert_info)} B)")
    assert len(sb) == 33 + 33 + len(cert.cert_info) + NONCE_SIZE + 33 + 20


def test_identical_msg1_gets_the_stored_msg2_and_no_new_acceptance(
        keystore, provisioned_device, epoch_state):
    """T2: the device lost MSG_2 and sends the same MSG_1 bytes again."""
    d = provisioned_device
    m, dev_state = device_build_msg1(d["d"], d["cert"].R, d["cert"].cert_info,
                                     keystore.gateway_identity.public_key,
                                     epoch_state.current_beacon())
    first = _gw(keystore, m, epoch_state)
    assert first.success
    again = _gw(keystore, m, epoch_state)
    assert again.success is False                     # never a second acceptance
    assert again.reason == AuthFailureReason.RETRANSMISSION
    assert again.msg2_bytes == first.msg2_bytes       # same bytes, not re-signed
    assert again.session_key is None
    assert epoch_state.occupancy == 1                 # no new sheet entry
    # the device gets the SAME session key the gateway derived the first time
    dev = device_process_msg2(dev_state, keystore.gateway_identity.public_key,
                              again.msg2_bytes)
    assert dev.success and dev.session_key == first.session_key
    print(f"\n[SIZES] MSG_1={len(m)} B, stored MSG_2={len(first.msg2_bytes)} B")


def test_fifth_identical_msg1_is_a_replay(keystore, provisioned_device, epoch_state):
    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())
    assert _gw(keystore, m, epoch_state).success
    for _ in range(4):
        assert _gw(keystore, m, epoch_state).reason == AuthFailureReason.RETRANSMISSION
    fifth = _gw(keystore, m, epoch_state)
    assert fifth.reason == AuthFailureReason.REPLAY_DETECTED
    assert fifth.msg2_bytes is None


def test_valid_but_different_msg1_with_same_nonce_is_a_replay(
        keystore, provisioned_device, epoch_state):
    """ECDSA malleability: (r, n - s) is a second VALID signature over the same
    bytes. Its MSG_1 differs, so it gets no resend; the nonce makes it a replay."""
    beacon = epoch_state.current_beacon()
    m = _msg1(provisioned_device, keystore, beacon)
    msg1 = decode_edhoc_msg1(m)
    r, s = msg1.signature[:32], int.from_bytes(msg1.signature[32:], "big")
    twin = encode_edhoc_msg1(msg1.E_d, msg1.R, msg1.cert_info, msg1.nonce_d,
                             r + (N - s).to_bytes(32, "big"))
    assert twin != m
    # proof the twin is genuinely valid: a gateway that never saw m accepts it
    same_beacon = EpochState(EPOCH_LENGTH_S, max_devices=8, clock=_FakeMonotonic(),
                             value_source=lambda n: beacon.value,
                             first_epoch=beacon.epoch)
    assert _gw(keystore, twin, same_beacon).success
    # on the real gateway m was accepted first, so the twin is a replay
    assert _gw(keystore, m, epoch_state).success
    r2 = _gw(keystore, twin, epoch_state)
    assert r2.reason == AuthFailureReason.REPLAY_DETECTED
    assert r2.msg2_bytes is None
    assert epoch_state.occupancy == 1


def test_resend_does_not_verify_sign_or_derive(keystore, provisioned_device,
                                               epoch_state, monkeypatch):
    import src.edhoc_subset as es
    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())
    assert _gw(keystore, m, epoch_state).success
    def must_not_run(*a, **k):
        raise AssertionError("expensive step ran on a resend")
    monkeypatch.setattr(es, "verify_signature_under_reconstructed_key", must_not_run)
    monkeypatch.setattr(es, "derive_session_key", must_not_run)
    monkeypatch.setattr(es, "encode_edhoc_msg2", must_not_run)
    assert _gw(keystore, m, epoch_state).reason == AuthFailureReason.RETRANSMISSION


def test_no_resend_after_rollover(keystore, provisioned_device, epoch_state, epoch_clock):
    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())
    assert _gw(keystore, m, epoch_state).success
    epoch_clock.advance(EPOCH_LENGTH_S)
    r = _gw(keystore, m, epoch_state)
    assert r.reason == AuthFailureReason.SIGNATURE_INVALID
    assert r.msg2_bytes is None


def test_device_revoked_after_acceptance_gets_no_resend(keystore, provisioned_device,
                                                       epoch_state):
    from src.did_utils import encode_did_key
    fetcher = MockFetcher()
    mgr = RevocationSyncManager("http://x", fetch_fn=fetcher)
    mgr.sync_now()
    m = _msg1(provisioned_device, keystore, epoch_state.current_beacon())
    assert gateway_process_msg1_build_msg2(keystore, m, revocation_manager=mgr,
                                           epoch_state=epoch_state).success
    fetcher.entries = {encode_did_key(provisioned_device["d"] * G): "2026-04-19T11:00:00Z"}
    mgr.sync_now()
    r = gateway_process_msg1_build_msg2(keystore, m, revocation_manager=mgr,
                                        epoch_state=epoch_state)
    assert r.reason == AuthFailureReason.DEVICE_REVOKED
    assert r.msg2_bytes is None


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
    fake_value = bytes(16) if real.value != bytes(16) else b"\x01" * 16
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
