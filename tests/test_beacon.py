"""Tests for src/beacon.py (Fix 2): layout, epoch rolling, nonce sheet, cap, fail-closed."""
import itertools
import random
import threading

import pytest

from src.beacon import (
    BEACON_SIZE, BEACON_VALUE_SIZE, MAX_RESENDS, Beacon, EpochState, RecordResult,
)


class FakeClock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, s): self.t += s


def counting_values():
    """Deterministic, distinct 16-byte values: 0001..., 0002..., ..."""
    c = itertools.count(1)
    return lambda n: next(c).to_bytes(n, "big")


def make(epoch_len=300, devices=4, cap=2, clock=None):
    clock = clock or FakeClock()
    return EpochState(epoch_len, devices, per_device_cap=cap,
                      clock=clock, value_source=counting_values()), clock


# ---------------------------------------------------------------- layout

def test_beacon_is_20_bytes_and_round_trips():
    b = Beacon(7, bytes(range(16)))
    raw = b.to_bytes()
    assert len(raw) == BEACON_SIZE == 20
    assert raw[:4] == (7).to_bytes(4, "big")
    assert Beacon.from_bytes(raw) == b

@pytest.mark.parametrize("bad", [b"", bytes(19), bytes(21)])
def test_beacon_from_bytes_rejects_wrong_length(bad):
    with pytest.raises(ValueError):
        Beacon.from_bytes(bad)

def test_beacon_rejects_bad_fields():
    with pytest.raises(ValueError):
        Beacon(-1, bytes(16))
    with pytest.raises(ValueError):
        Beacon(2 ** 32, bytes(16))
    with pytest.raises(ValueError):
        Beacon(0, bytes(15))

def test_constructor_validation():
    with pytest.raises(ValueError): EpochState(0, 1)
    with pytest.raises(ValueError): EpochState(10, 0)
    with pytest.raises(ValueError): EpochState(10, 1, per_device_cap=0)
    with pytest.raises(ValueError): EpochState(10, 1, max_resends=-1)

# ---------------------------------------------------------------- epochs

def test_beacon_is_stable_within_an_epoch():
    s, clock = make()
    b1 = s.current_beacon(); clock.advance(299); b2 = s.current_beacon()
    assert b1 == b2

def test_epoch_rolls_with_new_value_and_counter():
    s, clock = make()
    b1 = s.current_beacon(); clock.advance(300); b2 = s.current_beacon()
    assert b2.epoch == b1.epoch + 1
    assert b2.value != b1.value

def test_real_random_values_differ_between_epochs():
    clock = FakeClock()
    s = EpochState(10, 1, clock=clock)            # real secrets.token_bytes
    v1 = s.current_beacon().value; clock.advance(10)
    assert s.current_beacon().value != v1

def test_epoch_counter_wraps_at_32_bits():
    clock = FakeClock()
    s = EpochState(10, 1, clock=clock, value_source=counting_values(), first_epoch=2 ** 32 - 1)
    assert s.current_beacon().epoch == 2 ** 32 - 1
    clock.advance(10)
    assert s.current_beacon().epoch == 0

def test_a_long_idle_gap_rolls_exactly_one_epoch():
    s, clock = make()
    e0 = s.current_beacon().epoch; clock.advance(10_000)
    assert s.current_beacon().epoch == e0 + 1

# ---------------------------------------------------------------- the sheet

def test_is_replay_is_false_then_true_and_is_read_only():
    s, _ = make(); b = s.current_beacon()
    assert not s.is_replay(b"dev", b"n1")
    assert s.occupancy == 0                       # lookup added nothing
    assert s.record(b, b"dev", b"n1") is RecordResult.RECORDED
    assert s.is_replay(b"dev", b"n1")
    assert s.occupancy == 1

def test_same_nonce_twice_is_a_replay_and_writes_nothing():
    s, _ = make(); b = s.current_beacon()
    s.record(b, b"dev", b"n1")
    assert s.record(b, b"dev", b"n1") is RecordResult.REPLAY
    assert s.occupancy == 1

def test_sheet_is_per_device():
    s, _ = make(); b = s.current_beacon()
    assert s.record(b, b"devA", b"n1") is RecordResult.RECORDED
    assert s.record(b, b"devB", b"n1") is RecordResult.RECORDED
    assert not s.is_replay(b"devC", b"n1")

def test_rollover_empties_the_sheet():
    s, clock = make(); b = s.current_beacon()
    s.record(b, b"dev", b"n1"); clock.advance(300)
    assert not s.is_replay(b"dev", b"n1")
    assert s.occupancy == 0

def test_occupancy_reflects_rollover_without_other_calls():
    s, clock = make(); b = s.current_beacon()
    s.record(b, b"dev", b"n1"); clock.advance(300)
    assert s.occupancy == 0                       # no other call needed to roll

# ---------------------------------------------------------------- the cap

def test_third_acceptance_for_one_device_hits_the_cap():
    s, _ = make(); b = s.current_beacon()
    assert s.record(b, b"dev", b"n1") is RecordResult.RECORDED
    assert s.record(b, b"dev", b"n2") is RecordResult.RECORDED
    assert s.record(b, b"dev", b"n3") is RecordResult.DEVICE_CAP_REACHED
    assert s.record(b, b"other", b"n3") is RecordResult.RECORDED   # others unaffected
    assert s.occupancy == 3

def test_cap_resets_each_epoch():
    s, clock = make(); b = s.current_beacon()
    s.record(b, b"dev", b"n1"); s.record(b, b"dev", b"n2"); clock.advance(300)
    b2 = s.current_beacon()
    assert s.record(b2, b"dev", b"n3") is RecordResult.RECORDED

# ---------------------------------------------------------------- fail closed

def test_overflow_fails_closed_and_writes_nothing():
    s, _ = make(devices=2, cap=2); b = s.current_beacon()      # capacity 4
    for dev, n in [(b"A", b"1"), (b"A", b"2"), (b"B", b"1"), (b"B", b"2")]:
        assert s.record(b, dev, n) is RecordResult.RECORDED
    assert s.record(b, b"C", b"1") is RecordResult.SHEET_FULL
    assert s.occupancy == 4
    assert not s.is_replay(b"C", b"1")            # the refused nonce was NOT recorded

def test_overflow_clears_at_the_next_epoch():
    s, clock = make(devices=1, cap=1); b = s.current_beacon()
    s.record(b, b"A", b"1")
    assert s.record(b, b"B", b"1") is RecordResult.SHEET_FULL
    clock.advance(300); b2 = s.current_beacon()
    assert s.record(b2, b"B", b"1") is RecordResult.RECORDED

def test_sheet_never_exceeds_its_bound_under_hammering():
    s, clock = make(devices=5, cap=2); rng = random.Random(1234)
    for _ in range(5000):
        if rng.random() < 0.01: clock.advance(300)
        b = s.current_beacon()
        s.record(b, bytes([rng.randrange(40)]), bytes([rng.randrange(256)]))
        assert s.occupancy <= s.capacity == 10

# ---------------------------------------------------------------- strict epoch

def test_record_under_an_ended_epoch_is_refused():
    s, clock = make(); old = s.current_beacon()
    clock.advance(300)                            # the epoch ends while verification is running
    assert s.record(old, b"dev", b"n1") is RecordResult.EPOCH_ENDED
    assert s.occupancy == 0

def test_record_with_a_made_up_beacon_is_refused():
    s, _ = make(); real = s.current_beacon()
    fake = Beacon(real.epoch, bytes(16))
    assert s.record(fake, b"dev", b"n1") is RecordResult.EPOCH_ENDED

# ---------------------------------------------------------------- atomicity

def test_concurrent_records_of_the_same_nonce_accept_exactly_one():
    s, _ = make(); b = s.current_beacon(); results = []
    def worker(): results.append(s.record(b, b"dev", b"same"))
    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert results.count(RecordResult.RECORDED) == 1
    assert results.count(RecordResult.REPLAY) == 15
    assert s.occupancy == 1

# ---------------------------------------------------------------- T2 resend

D1, D2 = b"\x11" * 32, b"\x22" * 32       # two different MSG_1 digests

def _accepted(s, digest=D1, reply=b"MSG2"):
    b = s.current_beacon()
    assert s.record(b, b"dev", b"n1", digest) is RecordResult.RECORDED
    assert s.store_reply(b, b"dev", b"n1", reply, "did:key:z1")
    return b

def test_max_resends_matches_coap_max_retransmit():
    assert MAX_RESENDS == 4                       # RFC 7252 section 4.8

def test_resend_returns_the_stored_reply_and_adds_nothing():
    s, _ = make(); b = _accepted(s)
    got = s.resend(b, b"dev", b"n1", D1)
    assert got.reply == b"MSG2" and got.device_did == "did:key:z1"
    assert s.occupancy == 1                       # no new entry

def test_resend_needs_the_same_msg1_digest():
    s, _ = make(); b = _accepted(s)
    assert s.resend(b, b"dev", b"n1", D2) is None

def test_resend_needs_the_same_device_and_nonce():
    s, _ = make(); b = _accepted(s)
    assert s.resend(b, b"other", b"n1", D1) is None
    assert s.resend(b, b"dev", b"n2", D1) is None

def test_resend_stops_after_max_resends():
    s, _ = make(); b = _accepted(s)
    for _ in range(MAX_RESENDS):
        assert s.resend(b, b"dev", b"n1", D1) is not None
    assert s.resend(b, b"dev", b"n1", D1) is None

def test_max_resends_zero_turns_resend_off():
    clock = FakeClock()
    s = EpochState(300, 4, max_resends=0, clock=clock, value_source=counting_values())
    b = _accepted(s)
    assert s.resend(b, b"dev", b"n1", D1) is None

def test_no_resend_before_the_reply_is_stored_and_it_does_not_count():
    s, _ = make(); b = s.current_beacon()
    s.record(b, b"dev", b"n1", D1)
    assert s.resend(b, b"dev", b"n1", D1) is None
    s.store_reply(b, b"dev", b"n1", b"MSG2")
    for _ in range(MAX_RESENDS):
        assert s.resend(b, b"dev", b"n1", D1) is not None

def test_record_without_a_digest_is_never_resent():
    s, _ = make(); b = s.current_beacon()
    s.record(b, b"dev", b"n1")
    s.store_reply(b, b"dev", b"n1", b"MSG2")
    assert s.resend(b, b"dev", b"n1", D1) is None

def test_stored_replies_die_with_the_epoch():
    s, clock = make(); old = _accepted(s)
    clock.advance(300); new = s.current_beacon()
    assert s.resend(old, b"dev", b"n1", D1) is None
    assert s.resend(new, b"dev", b"n1", D1) is None

def test_resend_with_a_made_up_beacon_is_refused():
    s, _ = make(); real = _accepted(s)
    assert s.resend(Beacon(real.epoch, bytes(16)), b"dev", b"n1", D1) is None
    assert s.resend(real, b"dev", b"n1", D1) is not None   # the real one still works

def test_store_reply_rules():
    s, clock = make(); b = s.current_beacon()
    assert not s.store_reply(b, b"dev", b"n1", b"X")      # no such entry
    s.record(b, b"dev", b"n1", D1)
    assert s.store_reply(b, b"dev", b"n1", b"FIRST")
    assert not s.store_reply(b, b"dev", b"n1", b"SECOND")  # never overwritten
    assert s.resend(b, b"dev", b"n1", D1).reply == b"FIRST"
    s.record(b, b"dev", b"n2", D2); clock.advance(300)
    assert not s.store_reply(b, b"dev", b"n2", b"LATE")    # epoch ended

@pytest.mark.parametrize("bad", [b"", bytes(31), bytes(33)])
def test_record_rejects_a_wrong_size_digest(bad):
    s, _ = make(); b = s.current_beacon()
    with pytest.raises(ValueError):
        s.record(b, b"dev", b"n1", bad)
    assert s.occupancy == 0

def test_concurrent_resends_never_exceed_the_limit():
    s, _ = make(); b = _accepted(s); results = []
    def worker(): results.append(s.resend(b, b"dev", b"n1", D1))
    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert sum(r is not None for r in results) == MAX_RESENDS
