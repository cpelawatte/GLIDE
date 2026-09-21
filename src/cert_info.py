"""
cert_info binary encoding (Fix 7, IEEE Access phase).

Single source of truth for the cert_info layout. The issuer builds it with
encode_cert_info(); the gateway reads it with decode_cert_info(). Both ends call
this one module, so they cannot drift. That matters because cert_info is an
input to hash_to_scalar(R, cert_info) in ECQV key derivation: a one-byte
disagreement between issuer and gateway breaks every handshake.

Layout (10 bytes, fixed width, big-endian, no delimiters):

    offset  size  field
    0       4     issuer_id   first 4 bytes of SHA-256(issuer DID as UTF-8)
    4       4     issued_at   uint32, Unix seconds, UTC (valid until 2106)
    8       2     max_age     uint16, whole hours (max 65535 h, about 7.5 years)

Replaces the conference-era pipe-delimited UTF-8 text
"issuer_did||issued_at_iso||max_age_seconds" (66 B for the benchmark issuer).

issuer_id is an identifier, not an authenticator. Issuer authenticity comes
from the gateway reconstructing Q_dev with its pinned Q_ca: a certificate from
any other issuer reconstructs to the wrong public key and fails signature
verification whatever its issuer_id says. The 4-byte hash exists for early,
clearly reported rejection, and so a future pinned *set* of issuers can pick
the right Q_ca without a wire-format change.
"""

import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

CERT_INFO_LEN = 10
ISSUER_ID_LEN = 4
SECONDS_PER_HOUR = 3600
MAX_AGE_HOURS_MAX = 0xFFFF          # uint16
ISSUED_AT_MAX = 0xFFFFFFFF          # uint32

# ">" big-endian, "4s" 4 raw bytes, "I" uint32, "H" uint16
_LAYOUT = struct.Struct(">4sIH")
assert _LAYOUT.size == CERT_INFO_LEN


@dataclass(frozen=True)
class ParsedCertInfo:
    issuer_id: bytes
    issued_at: datetime
    max_age_seconds: int

    @property
    def expires_at(self) -> datetime:
        return self.issued_at + timedelta(seconds=self.max_age_seconds)


def issuer_id_for(issuer_did: str) -> bytes:
    """Return the 4-byte issuer identifier for a DID string."""
    if not isinstance(issuer_did, str) or not issuer_did.startswith("did:"):
        raise ValueError(f"issuer_did is not a DID: {issuer_did!r}")
    return hashlib.sha256(issuer_did.encode("utf-8")).digest()[:ISSUER_ID_LEN]


def encode_cert_info(issuer_did: str, issued_at: datetime, max_age_hours: int) -> bytes:
    """Build the 10-byte cert_info.

    Sub-second precision in issued_at is dropped here. The returned bytes are
    authoritative: anything logged or exported afterwards must be derived from
    them (decode_cert_info), not from the original clock reading.
    """
    if issued_at.tzinfo is None:
        raise ValueError("issued_at must be timezone-aware")
    ts = int(issued_at.timestamp())
    if not 0 <= ts <= ISSUED_AT_MAX:
        raise ValueError(f"issued_at out of uint32 range: {ts}")
    if isinstance(max_age_hours, bool) or not isinstance(max_age_hours, int):
        raise ValueError(f"max_age must be an integer number of hours, got {max_age_hours!r}")
    if not 1 <= max_age_hours <= MAX_AGE_HOURS_MAX:
        raise ValueError(f"max_age must be 1..{MAX_AGE_HOURS_MAX} hours, got {max_age_hours}")
    return _LAYOUT.pack(issuer_id_for(issuer_did), ts, max_age_hours)


def decode_cert_info(cert_info_bytes: bytes) -> ParsedCertInfo:
    """Parse the 10-byte cert_info. Raises ValueError on any malformed input."""
    if not isinstance(cert_info_bytes, (bytes, bytearray)):
        raise ValueError(f"cert_info must be bytes, got {type(cert_info_bytes).__name__}")
    if len(cert_info_bytes) != CERT_INFO_LEN:
        raise ValueError(
            f"cert_info must be exactly {CERT_INFO_LEN} bytes, got {len(cert_info_bytes)}"
        )
    issuer_id, ts, hours = _LAYOUT.unpack(bytes(cert_info_bytes))
    if hours == 0:
        raise ValueError("max_age must be positive, got 0 hours")
    return ParsedCertInfo(
        issuer_id=issuer_id,
        issued_at=datetime.fromtimestamp(ts, tz=timezone.utc),
        max_age_seconds=hours * SECONDS_PER_HOUR,
    )
