"""
beacon.py -- Fix 2: freshness via a gateway-broadcast epoch beacon.

Single source of truth for three things, so the pieces cannot drift apart:
  1. the beacon layout: 4-byte epoch counter + 16-byte random value,
  2. the gateway's epoch state: which beacon is current, and when it rolls,
  3. the per-epoch nonce sheet: replay detection and the per-device cap.

Locked design decisions (project context, section 4.2):
  * The beacon is PUBLIC. Freshness comes from the random value being
    unpredictable until its epoch starts, not from secrecy.
  * The beacon is NOT signed at the GLIDE layer. The device signs over it; the
    gateway checks the signature against ITS OWN copy, never a value taken from
    the message. A fake beacon therefore cannot cause a false authentication.
  * STRICT: only the current epoch is accepted. There is no epoch index on the
    wire (decision 1, revised): a stale message simply fails signature
    verification. A grace period is a fallback only if measurement shows the
    boundary race is frequent.
  * A nonce is written to the sheet only after the WHOLE authentication has
    succeeded. Lookup is read-only, so outsiders cannot add entries.
  * The sheet is per device (keyed by the reconstruction point R), with at most
    `per_device_cap` accepted authentications per device per epoch, so its size
    is bounded by per_device_cap x max_devices.
  * Overflow FAILS CLOSED (and is logged): never accept without recording.
  * Lost MSG_2 (decision 6, T2: resend, don't re-sign). Each entry also keeps
    the SHA-256 of the MSG_1 that was accepted and the MSG_2 sent for it. A
    byte-identical MSG_1 in the same epoch gets that stored MSG_2 again, at
    most `max_resends` times (default 4, RFC 7252 MAX_RETRANSMIT). A resend
    is never an acceptance: no new entry, no new gateway signature, no new
    session key. Any other MSG_1 reusing the nonce is a replay. Stored
    replies die with the epoch.

Epoch rolling is lazy: the epoch advances when a method is called and its
stopwatch has run out. The component that broadcasts the beacon must call
current_beacon() at least once per repeat interval, so the epoch rolls on time.
The epoch counter is a label for logs and for the broadcaster; the security
comes from the random value.

This module is the Python counterpart of the Tamarin rules Gateway_Bootstrap /
Gateway_New_Epoch and of the restrictions Epoch_Is_Current and
Nonce_Sheet_Once_Per_Epoch (paper/sections/tamarin_model_fix2_beacon.spthy).
Those two restrictions are modelled gateway checks; THIS module is where the
implementation performs them. AI-assisted: see the paper's acknowledgements.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

log = logging.getLogger(__name__)

EPOCH_COUNTER_SIZE = 4                  # uint32, big-endian
BEACON_VALUE_SIZE = 16                  # 128-bit, matches P-256 / AES-128
BEACON_SIZE = EPOCH_COUNTER_SIZE + BEACON_VALUE_SIZE   # 20 bytes
DEFAULT_PER_DEVICE_CAP = 2              # decision 6: max 2 accepted per device per epoch
MSG1_DIGEST_SIZE = 32                   # SHA-256 of the whole MSG_1
MAX_RESENDS = 4                         # T2: RFC 7252 section 4.8 MAX_RETRANSMIT
_EPOCH_MODULUS = 2 ** (8 * EPOCH_COUNTER_SIZE)


@dataclass(frozen=True)
class Beacon:
    """What the gateway broadcasts at the start of an epoch."""
    epoch: int
    value: bytes

    def __post_init__(self) -> None:
        if not (0 <= self.epoch < _EPOCH_MODULUS):
            raise ValueError(f"epoch must fit in {EPOCH_COUNTER_SIZE} bytes, got {self.epoch}")
        if len(self.value) != BEACON_VALUE_SIZE:
            raise ValueError(f"beacon value must be {BEACON_VALUE_SIZE} bytes, got {len(self.value)}")

    def to_bytes(self) -> bytes:
        """The 20 bytes that are broadcast, and that the device signs over."""
        return self.epoch.to_bytes(EPOCH_COUNTER_SIZE, "big") + self.value

    @classmethod
    def from_bytes(cls, data: bytes) -> "Beacon":
        if len(data) != BEACON_SIZE:
            raise ValueError(f"beacon must be {BEACON_SIZE} bytes, got {len(data)}")
        return cls(int.from_bytes(data[:EPOCH_COUNTER_SIZE], "big"), data[EPOCH_COUNTER_SIZE:])


class RecordResult(Enum):
    """Outcome of trying to write a nonce on the sheet."""
    RECORDED = "recorded"
    REPLAY = "replay"                        # this nonce is already on this device's sheet
    DEVICE_CAP_REACHED = "device_cap_reached"
    SHEET_FULL = "sheet_full"                # fail closed
    EPOCH_ENDED = "epoch_ended"              # the epoch rolled while the message was being verified


@dataclass
class _Entry:
    """One accepted authentication on the sheet (keyed by device, then nonce)."""
    msg1_digest: Optional[bytes]       # None: this entry can never be resent
    reply: Optional[bytes] = None      # the MSG_2 sent for it, once stored
    device_did: Optional[str] = None   # for the revocation re-check on resend
    resends: int = 0


@dataclass(frozen=True)
class StoredReply:
    """What resend() hands back: the stored MSG_2 and whose it is."""
    reply: bytes
    device_did: Optional[str]


class EpochState:
    """The gateway's current epoch and its nonce sheet."""

    def __init__(
        self,
        epoch_length_s: float,
        max_devices: int,
        *,
        per_device_cap: int = DEFAULT_PER_DEVICE_CAP,
        max_resends: int = MAX_RESENDS,
        clock: Callable[[], float] = time.monotonic,
        value_source: Callable[[int], bytes] = secrets.token_bytes,
        first_epoch: int = 0,
    ) -> None:
        if epoch_length_s <= 0:
            raise ValueError("epoch_length_s must be positive")
        if max_devices < 1:
            raise ValueError("max_devices must be at least 1")
        if per_device_cap < 1:
            raise ValueError("per_device_cap must be at least 1")
        if max_resends < 0:
            raise ValueError("max_resends must be 0 (resend off) or more")
        self._epoch_length_s = float(epoch_length_s)
        self._per_device_cap = per_device_cap
        self._max_resends = max_resends
        # Stopwatch (monotonic) time, NOT wall-clock time: a wall clock can jump
        # when the system time is corrected, which would stretch or shrink an epoch.
        self._clock = clock
        self._value_source = value_source
        self._lock = threading.Lock()
        self.capacity = per_device_cap * max_devices   # the bound on the sheet
        self._beacon = Beacon(first_epoch % _EPOCH_MODULUS, value_source(BEACON_VALUE_SIZE))
        self._started = clock()
        # device_key -> {nonce -> _Entry}. Bounded: at most per_device_cap
        # nonces per device and `capacity` entries in all.
        self._sheet: dict[bytes, dict[bytes, _Entry]] = {}
        self._entries = 0

    # -- internal (caller holds the lock) --------------------------------

    def _roll_if_due(self) -> None:
        now = self._clock()
        if now - self._started >= self._epoch_length_s:
            self._beacon = Beacon(
                (self._beacon.epoch + 1) % _EPOCH_MODULUS,
                self._value_source(BEACON_VALUE_SIZE),
            )
            self._started = now
            self._sheet.clear()      # a new epoch starts with an empty sheet
            self._entries = 0

    # -- public -----------------------------------------------------------

    def current_beacon(self) -> Beacon:
        """The beacon for the current epoch (rolls the epoch first if it is due)."""
        with self._lock:
            self._roll_if_due()
            return self._beacon

    def is_replay(self, device_key: bytes, nonce: bytes) -> bool:
        """READ-ONLY: is this nonce already on this device's sheet for the current epoch?

        Safe to call on unauthenticated input: it never adds an entry.
        """
        with self._lock:
            self._roll_if_due()
            return nonce in self._sheet.get(device_key, ())

    def record(self, beacon: Beacon, device_key: bytes, nonce: bytes,
               msg1_digest: Optional[bytes] = None) -> RecordResult:
        """Write a nonce on the sheet. Call ONLY after the whole authentication succeeded.

        `beacon` is the beacon the signature was verified against. If that epoch
        has ended meanwhile the result is EPOCH_ENDED and nothing is written:
        an ended epoch is never accepted (strict rule; Tamarin: Epoch_Is_Current).

        `msg1_digest` is the SHA-256 of the whole accepted MSG_1. Without it the
        entry can never be resent (the safe default).
        """
        if msg1_digest is not None and len(msg1_digest) != MSG1_DIGEST_SIZE:
            raise ValueError(f"msg1_digest must be {MSG1_DIGEST_SIZE} bytes")
        with self._lock:
            self._roll_if_due()
            if beacon != self._beacon:
                return RecordResult.EPOCH_ENDED
            nonces = self._sheet.get(device_key)
            if nonces is not None and nonce in nonces:
                return RecordResult.REPLAY
            if nonces is not None and len(nonces) >= self._per_device_cap:
                return RecordResult.DEVICE_CAP_REACHED
            if self._entries >= self.capacity:
                log.warning("nonce sheet full (%d entries): failing closed until the next epoch",
                            self._entries)
                return RecordResult.SHEET_FULL
            if nonces is None:
                nonces = self._sheet[device_key] = {}
            nonces[nonce] = _Entry(msg1_digest)
            self._entries += 1
            return RecordResult.RECORDED

    def store_reply(self, beacon: Beacon, device_key: bytes, nonce: bytes,
                    reply: bytes, device_did: Optional[str] = None) -> bool:
        """Keep the MSG_2 just sent for an entry, so it can be resent (T2).

        Stored at most once per entry, and only in the epoch the entry was
        recorded in. Returns False and stores nothing if that epoch has ended,
        the entry does not exist, or a reply is already stored.
        """
        with self._lock:
            self._roll_if_due()
            if beacon != self._beacon:
                return False
            entry = self._sheet.get(device_key, {}).get(nonce)
            if entry is None or entry.reply is not None:
                return False
            entry.reply = bytes(reply)
            entry.device_did = device_did
            return True

    def resend(self, beacon: Beacon, device_key: bytes, nonce: bytes,
               msg1_digest: bytes) -> Optional[StoredReply]:
        """The stored MSG_2 for a byte-identical MSG_1, or None (T2).

        Returns None unless ALL of these hold: the epoch of `beacon` is still
        current, the entry exists, its MSG_1 digest equals `msg1_digest`, a
        reply is stored, and fewer than max_resends resends have been made.
        Adds nothing to the sheet; only the entry's resend counter goes up.
        A resend is never an acceptance.
        """
        with self._lock:
            self._roll_if_due()
            if beacon != self._beacon:
                return None
            entry = self._sheet.get(device_key, {}).get(nonce)
            if (entry is None or entry.msg1_digest is None or entry.reply is None
                    or entry.msg1_digest != msg1_digest
                    or entry.resends >= self._max_resends):
                return None
            entry.resends += 1
            return StoredReply(entry.reply, entry.device_did)

    @property
    def occupancy(self) -> int:
        """Entries on the sheet right now (for the Cooja occupancy measurement).

        Rolls first, so a reading taken after an epoch ended reports the new,
        empty sheet instead of the previous epoch's count.
        """
        with self._lock:
            self._roll_if_due()
            return self._entries
