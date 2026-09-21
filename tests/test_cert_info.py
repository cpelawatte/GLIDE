"""
Test suite for src/cert_info.py — the 10-byte binary cert_info (Fix 7).

cert_info is an input to hash_to_scalar(R, cert_info) in ECQV key derivation,
so issuer and gateway must agree byte-for-byte. The known-vector test pins the
exact bytes: a layout change that moved encode and decode together would pass
every round-trip test but fail this one.

Replaces the conference-era tests for the pipe-delimited text format.
"""
from datetime import datetime, timezone

import pytest

from src.cert_info import (
    CERT_INFO_LEN,
    decode_cert_info,
    encode_cert_info,
    issuer_id_for,
)

BENCH_ISSUER = "did:web:issuer.example"
BENCH_TIME = datetime(2026, 5, 26, 10, 35, 48, 761047, tzinfo=timezone.utc)
ONE_YEAR_HOURS = 8760


def test_known_vector_benchmark_issuer():
    ci = encode_cert_info(BENCH_ISSUER, BENCH_TIME, ONE_YEAR_HOURS)
    assert ci.hex() == "3b3ae0aa6a1577842238"


def test_length_is_exactly_ten_bytes():
    ci = encode_cert_info(BENCH_ISSUER, BENCH_TIME, ONE_YEAR_HOURS)
    assert len(ci) == CERT_INFO_LEN == 10


def test_encode_decode_roundtrip():
    ci = encode_cert_info(BENCH_ISSUER, BENCH_TIME, ONE_YEAR_HOURS)
    parsed = decode_cert_info(ci)
    assert parsed.issuer_id == issuer_id_for(BENCH_ISSUER)
    assert parsed.issued_at == BENCH_TIME.replace(microsecond=0)
    assert parsed.max_age_seconds == ONE_YEAR_HOURS * 3600


def test_microseconds_are_dropped():
    parsed = decode_cert_info(encode_cert_info(BENCH_ISSUER, BENCH_TIME, 1))
    assert parsed.issued_at.microsecond == 0


def test_decode_returns_utc():
    parsed = decode_cert_info(encode_cert_info(BENCH_ISSUER, BENCH_TIME, 1))
    assert parsed.issued_at.tzinfo is timezone.utc


def test_expires_at_is_issued_at_plus_max_age():
    parsed = decode_cert_info(encode_cert_info(BENCH_ISSUER, BENCH_TIME, 1))
    assert (parsed.expires_at - parsed.issued_at).total_seconds() == 3600


def test_issuer_id_distinguishes_issuers():
    assert issuer_id_for("did:web:issuer.example") != issuer_id_for("did:web:127.0.0.1%3A5000")
    assert issuer_id_for(BENCH_ISSUER) == issuer_id_for(BENCH_ISSUER)


def test_encode_accepts_max_age_upper_bound():
    parsed = decode_cert_info(encode_cert_info(BENCH_ISSUER, BENCH_TIME, 65535))
    assert parsed.max_age_seconds == 65535 * 3600


def test_encode_rejects_naive_datetime():
    with pytest.raises(ValueError, match="timezone-aware"):
        encode_cert_info(BENCH_ISSUER, BENCH_TIME.replace(tzinfo=None), 1)


def test_encode_rejects_non_did_issuer():
    with pytest.raises(ValueError, match="not a DID"):
        encode_cert_info("not-a-did", BENCH_TIME, 1)


@pytest.mark.parametrize("bad_time", [
    datetime(1969, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
    datetime(2106, 12, 31, 0, 0, 0, tzinfo=timezone.utc),
])
def test_encode_rejects_out_of_range_timestamp(bad_time):
    with pytest.raises(ValueError, match="uint32 range"):
        encode_cert_info(BENCH_ISSUER, bad_time, 1)


@pytest.mark.parametrize("bad_hours", [0, 65536, True, 1.5])
def test_encode_rejects_bad_max_age(bad_hours):
    with pytest.raises(ValueError, match="max_age"):
        encode_cert_info(BENCH_ISSUER, BENCH_TIME, bad_hours)


@pytest.mark.parametrize("length", [0, 9, 11])
def test_decode_rejects_wrong_length(length):
    with pytest.raises(ValueError, match="exactly 10 bytes"):
        decode_cert_info(b"\x00" * length)


def test_decode_rejects_legacy_text_format():
    legacy = b"did:web:issuer.example||2026-05-26T10:35:48.761047+00:00||31536000"
    with pytest.raises(ValueError, match="exactly 10 bytes"):
        decode_cert_info(legacy)


def test_decode_rejects_non_bytes():
    with pytest.raises(ValueError, match="must be bytes"):
        decode_cert_info("3b3ae0aa6a1577842238")


def test_decode_rejects_zero_max_age():
    ci = encode_cert_info(BENCH_ISSUER, BENCH_TIME, 1)
    zeroed = ci[:8] + b"\x00\x00"
    with pytest.raises(ValueError, match="positive"):
        decode_cert_info(zeroed)
