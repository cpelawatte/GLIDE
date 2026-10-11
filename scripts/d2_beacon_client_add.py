#!/usr/bin/env python3
"""
d2_beacon_client_add.py -- Fix 2, Phase D2: device-side beacon rules (new files only).

Adds:
  contiki/beacon_client.h / .c          decision 3 (hold latest beacon, never sign on
                                        hearing, rule C, no older-epoch rule, attempt
                                        cap 2 in any epoch length on the device timer,
                                        sliding window), decision 4 (stale wait), T2
                                        (resend same MSG_1: 2 s x U[1,1.5], doubling,
                                        4 resends; stop when the held beacon changes)
  contiki/test/host/beacon_client_test.c / .py   host unit tests, ASan + UBSan

Changes NO existing file. Wiring into the Cooja / footprint mains and the
Makefile is Phase D3.

Run from the repo root (~/Desktop/FYP).

    python3 scripts/d2_beacon_client_add.py --diff     # show the new files, write nothing
    python3 scripts/d2_beacon_client_add.py --apply    # write them

Refuses to overwrite: if any of the four files already exists, nothing is written.
"""
import difflib
import sys
from pathlib import Path

ROOT = Path.cwd()
NEW = {}

NEW["contiki/beacon_client.h"] = r'''/*
 * beacon_client.h -- device-side epoch-beacon rules for GLIDE (Fix 2).
 *
 * Pure logic: no Contiki calls, no radio, no clock. The caller passes the time
 * (milliseconds from its own stopwatch; wrap-safe) and one random byte for
 * the resend jitter, so every rule can be tested on the host.
 *
 * Rules (project context, Fix 2 decisions 3 and 4, and T2):
 *   - Hold only the latest beacon. Hearing a beacon never triggers signing.
 *   - Same bytes as held: a repeat; it refreshes the beacon's age.
 *   - Same epoch number, different value: CONFLICT (rule C). Log it, discard
 *     both, sign nothing until the next beacon, then adopt that one without
 *     comparing it to anything.
 *   - Any other epoch number, higher or lower: adopted. There is deliberately
 *     no "ignore older numbers" rule (a fake 0xFFFFFFFF would lock us out).
 *   - Sign only over a beacon heard within the last repeat interval;
 *     otherwise wait for the next repeat (decision 4).
 *   - At most BC_MAX_ATTEMPTS signing attempts in ANY window of one epoch
 *     length, timed on the device's own stopwatch, never by epoch numbers
 *     (sliding window; fake beacons with rising numbers cannot reset it).
 *   - Lost MSG_2 (T2): resend the SAME MSG_1 bytes, never re-sign. First wait
 *     2 s x U[1, 1.5], doubling, at most 4 resends (RFC 7252 section 4.8).
 *     Resends stop as soon as the held beacon changes, because the gateway
 *     only keeps the stored MSG_2 for the epoch it was signed in.
 *
 * Epoch length and repeat interval are per-deployment settings fixed at
 * build time (provisioning), never taken from a beacon: an unsigned message
 * must never carry a setting.
 */
#ifndef BEACON_CLIENT_H_
#define BEACON_CLIENT_H_

#include <stdint.h>
#include "device_auth.h"            /* AUTH_BEACON_LEN */

#ifndef GLIDE_EPOCH_S
#define GLIDE_EPOCH_S             300   /* must match the gateway's epoch length */
#endif
#ifndef GLIDE_BEACON_REPEAT_S
#define GLIDE_BEACON_REPEAT_S     30    /* must match the gateway's repeat interval */
#endif

#define BC_EPOCH_MS               ((uint32_t)GLIDE_EPOCH_S * 1000u)
#define BC_REPEAT_MS              ((uint32_t)GLIDE_BEACON_REPEAT_S * 1000u)
#define BC_EPOCH_NUMBER_LEN       4     /* leading bytes of the beacon */
#define BC_MAX_ATTEMPTS           2     /* decision 3 */
#define BC_MAX_RESENDS            4     /* T2: RFC 7252 MAX_RETRANSMIT */
#define BC_ACK_TIMEOUT_MS         2000u /* RFC 7252 ACK_TIMEOUT */
#define BC_ACK_JITTER_MS          1000u /* ACK_RANDOM_FACTOR 1.5 -> up to +1 s */

typedef struct {
    uint32_t heard_ms;                      /* when the held beacon was last heard */
    uint32_t attempt_ms[BC_MAX_ATTEMPTS];   /* starts of the last attempts, oldest first */
    uint32_t deadline_ms;                   /* next resend or give-up time */
    uint8_t  beacon[AUTH_BEACON_LEN];       /* the held beacon (valid if held) */
    uint16_t first_wait_ms;                 /* 2000..3000, set when MSG_1 is sent */
    uint16_t conflicts;                     /* rule C discards, for measurement */
    uint8_t  held;                          /* beacon[] valid */
    uint8_t  fresh;                         /* heard within the last repeat interval */
    uint8_t  attempts;                      /* valid entries in attempt_ms */
    uint8_t  generation;                    /* +1 whenever the held beacon changes */
    uint8_t  signed_generation;             /* generation the outstanding MSG_1 used */
    uint8_t  outstanding;                   /* waiting for MSG_2 */
    uint8_t  resends;                       /* resends of the outstanding MSG_1 */
} beacon_client_t;

typedef enum {
    BC_BEACON_ADOPTED,    /* now held: first one, after a discard, or a new epoch number */
    BC_BEACON_REPEAT,     /* same bytes as held: age refreshed */
    BC_BEACON_CONFLICT    /* same epoch number, different value: both discarded (rule C) */
} bc_beacon_result_t;

typedef enum {
    BC_START_OK,          /* sign over *beacon_out now; one attempt has been charged */
    BC_START_NO_BEACON,   /* nothing held (never heard, or discarded by rule C) */
    BC_START_STALE,       /* held beacon older than one repeat interval: wait */
    BC_START_CAPPED,      /* BC_MAX_ATTEMPTS attempts within the last epoch length */
    BC_START_BUSY         /* an attempt is still waiting for MSG_2 */
} bc_start_result_t;

typedef enum {
    BC_POLL_IDLE,           /* nothing outstanding */
    BC_POLL_WAIT,           /* keep waiting for MSG_2 */
    BC_POLL_RESEND,         /* send the same MSG_1 bytes again now */
    BC_POLL_GAVE_UP,        /* resends used up and the last wait passed */
    BC_POLL_BEACON_CHANGED  /* the held beacon changed since signing: attempt over */
} bc_poll_result_t;

void bc_init(beacon_client_t *bc);

/* A beacon was heard (exactly AUTH_BEACON_LEN bytes). */
bc_beacon_result_t bc_on_beacon(beacon_client_t *bc, const uint8_t *beacon,
                                uint32_t now_ms);

/* The device wants to authenticate. On BC_START_OK, *beacon_out points at the
 * held beacon to pass to device_auth_build_msg1(), and one attempt is charged
 * (even if building then fails: the cap counts attempts, not successes). */
bc_start_result_t bc_start_attempt(beacon_client_t *bc, uint32_t now_ms,
                                   const uint8_t **beacon_out);

/* MSG_1 has just been transmitted. `jitter` is a random byte (0..255). */
void bc_msg1_sent(beacon_client_t *bc, uint32_t now_ms, uint8_t jitter);

/* Call when a timer fires (and at least every few seconds while waiting). */
bc_poll_result_t bc_poll(beacon_client_t *bc, uint32_t now_ms);

/* Milliseconds until bc_poll() has something to do (0 = now);
 * UINT32_MAX if nothing is outstanding. For scheduling an etimer. */
uint32_t bc_ms_until_deadline(const beacon_client_t *bc, uint32_t now_ms);

/* MSG_2 verified (session key derived), or the attempt was abandoned (e.g.
 * building MSG_1 failed): stop waiting. A MSG_2 that fails verification must
 * NOT call this -- a forged MSG_2 must not cancel a genuine attempt. */
void bc_attempt_done(beacon_client_t *bc);

#endif /* BEACON_CLIENT_H_ */
'''

NEW["contiki/beacon_client.c"] = r'''/*
 * beacon_client.c -- device-side epoch-beacon rules for GLIDE (Fix 2).
 * See beacon_client.h for the rules and where each comes from.
 *
 * Time: all times are milliseconds from the caller's stopwatch, compared with
 * wrap-safe unsigned/signed differences. Every entry point first drops
 * attempts older than one epoch length and marks the beacon stale once it is
 * older than one repeat interval, so a 32-bit wrap (49.7 days) cannot make an
 * old event look recent as long as some entry point runs at least every few
 * weeks (beacons arrive every repeat interval, so in practice constantly).
 */
#include "beacon_client.h"
#include <string.h>

static int before(uint32_t a, uint32_t b)       /* a earlier than b (wrap-safe) */
{
    return (int32_t)(a - b) < 0;
}

static void refresh(beacon_client_t *bc, uint32_t now_ms)
{
    /* Sliding window: forget attempts that left the last epoch length. */
    while(bc->attempts > 0 && now_ms - bc->attempt_ms[0] >= BC_EPOCH_MS) {
        bc->attempt_ms[0] = bc->attempt_ms[1];
        bc->attempts--;
    }
    /* Decision 4: a beacon not heard within one repeat interval is stale. */
    if(bc->fresh && now_ms - bc->heard_ms >= BC_REPEAT_MS) {
        bc->fresh = 0;
    }
}

void bc_init(beacon_client_t *bc)
{
    memset(bc, 0, sizeof(*bc));
}

bc_beacon_result_t bc_on_beacon(beacon_client_t *bc, const uint8_t *beacon,
                                uint32_t now_ms)
{
    refresh(bc, now_ms);

    if(bc->held && memcmp(beacon, bc->beacon, AUTH_BEACON_LEN) == 0) {
        bc->heard_ms = now_ms;                  /* a repeat */
        bc->fresh = 1;
        return BC_BEACON_REPEAT;
    }
    /* Any change of the held beacon ends resends of an outstanding MSG_1.
     * (generation is 8-bit: 256 changes inside one wait would wrap it; the
     * only effect would be extra resends, which the gateway refuses.) */
    bc->generation++;

    if(bc->held && memcmp(beacon, bc->beacon, BC_EPOCH_NUMBER_LEN) == 0) {
        bc->held = 0;                           /* rule C: discard both */
        bc->fresh = 0;
        if(bc->conflicts < UINT16_MAX) {
            bc->conflicts++;
        }
        return BC_BEACON_CONFLICT;
    }
    memcpy(bc->beacon, beacon, AUTH_BEACON_LEN);  /* first, after a discard, */
    bc->held = 1;                                 /* or any other epoch number */
    bc->fresh = 1;
    bc->heard_ms = now_ms;
    return BC_BEACON_ADOPTED;
}

bc_start_result_t bc_start_attempt(beacon_client_t *bc, uint32_t now_ms,
                                   const uint8_t **beacon_out)
{
    refresh(bc, now_ms);

    if(bc->outstanding) {
        return BC_START_BUSY;
    }
    if(!bc->held) {
        return BC_START_NO_BEACON;
    }
    if(!bc->fresh) {
        return BC_START_STALE;
    }
    if(bc->attempts >= BC_MAX_ATTEMPTS) {
        return BC_START_CAPPED;
    }
    bc->attempt_ms[bc->attempts++] = now_ms;
    bc->signed_generation = bc->generation;
    *beacon_out = bc->beacon;
    return BC_START_OK;
}

void bc_msg1_sent(beacon_client_t *bc, uint32_t now_ms, uint8_t jitter)
{
    bc->first_wait_ms = (uint16_t)(BC_ACK_TIMEOUT_MS
                                   + (BC_ACK_JITTER_MS * jitter) / 255u);
    bc->resends = 0;
    bc->outstanding = 1;
    bc->deadline_ms = now_ms + bc->first_wait_ms;
}

bc_poll_result_t bc_poll(beacon_client_t *bc, uint32_t now_ms)
{
    refresh(bc, now_ms);

    if(!bc->outstanding) {
        return BC_POLL_IDLE;
    }
    if(bc->signed_generation != bc->generation) {
        bc->outstanding = 0;
        return BC_POLL_BEACON_CHANGED;
    }
    if(before(now_ms, bc->deadline_ms)) {
        return BC_POLL_WAIT;
    }
    if(bc->resends < BC_MAX_RESENDS) {
        bc->resends++;
        bc->deadline_ms = now_ms + ((uint32_t)bc->first_wait_ms << bc->resends);
        return BC_POLL_RESEND;
    }
    bc->outstanding = 0;
    return BC_POLL_GAVE_UP;
}

uint32_t bc_ms_until_deadline(const beacon_client_t *bc, uint32_t now_ms)
{
    if(!bc->outstanding) {
        return UINT32_MAX;
    }
    if(bc->signed_generation != bc->generation || !before(now_ms, bc->deadline_ms)) {
        return 0;
    }
    return bc->deadline_ms - now_ms;
}

void bc_attempt_done(beacon_client_t *bc)
{
    bc->outstanding = 0;
}
'''

NEW["contiki/test/host/beacon_client_test.c"] = r'''/* Host unit tests for beacon_client.c (Fix 2 device rules). Prints one line
 * per failed check and a final "BC_RESULT <checks> <failures>" line. */
#include "beacon_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int checks, failures;
#define CHECK(cond) do { checks++; if(!(cond)) { failures++; \
    printf("FAIL %s:%d %s\n", __func__, __LINE__, #cond); } } while(0)

static void mk(uint8_t *b, uint32_t epoch, uint8_t fill)
{
    b[0] = (uint8_t)(epoch >> 24); b[1] = (uint8_t)(epoch >> 16);
    b[2] = (uint8_t)(epoch >> 8);  b[3] = (uint8_t)epoch;
    memset(b + 4, fill, AUTH_BEACON_LEN - 4);
}

static void t_no_beacon_until_heard(uint32_t t)
{
    beacon_client_t bc; const uint8_t *p = NULL; uint8_t b[20];
    bc_init(&bc);
    CHECK(bc_start_attempt(&bc, t, &p) == BC_START_NO_BEACON);
    CHECK(bc.attempts == 0);                                /* not charged */
    mk(b, 7, 0xAA);
    CHECK(bc_on_beacon(&bc, b, t) == BC_BEACON_ADOPTED);
    CHECK(bc_start_attempt(&bc, t + 1, &p) == BC_START_OK);
    CHECK(p == bc.beacon && memcmp(p, b, 20) == 0);
}

static void t_hearing_never_signs(uint32_t t)
{
    beacon_client_t bc; uint8_t b[20]; int i;
    bc_init(&bc);
    for(i = 0; i < 50; i++) { mk(b, (uint32_t)i, (uint8_t)i); bc_on_beacon(&bc, b, t + (uint32_t)i); }
    CHECK(bc.attempts == 0 && !bc.outstanding);
}

static void t_repeat_refreshes_age(uint32_t t)
{
    beacon_client_t bc; const uint8_t *p; uint8_t b[20];
    bc_init(&bc); mk(b, 7, 0xAA);
    bc_on_beacon(&bc, b, t);
    uint8_t g = bc.generation;
    CHECK(bc_start_attempt(&bc, t + BC_REPEAT_MS - 1, &p) == BC_START_OK);
    bc_attempt_done(&bc);
    CHECK(bc_start_attempt(&bc, t + BC_REPEAT_MS, &p) == BC_START_STALE);   /* decision 4 */
    CHECK(bc_on_beacon(&bc, b, t + BC_REPEAT_MS + 5) == BC_BEACON_REPEAT);
    CHECK(bc.generation == g);                              /* a repeat is not a change */
    CHECK(bc_start_attempt(&bc, t + BC_REPEAT_MS + 6, &p) == BC_START_OK);
}

static void t_conflict_rule_c(uint32_t t)
{
    beacon_client_t bc; const uint8_t *p; uint8_t real[20], fake[20], next[20];
    bc_init(&bc); mk(real, 7, 0xAA); mk(fake, 7, 0xBB); mk(next, 7, 0xBB);
    bc_on_beacon(&bc, real, t);
    CHECK(bc_on_beacon(&bc, fake, t + 1) == BC_BEACON_CONFLICT);   /* same number, other value */
    CHECK(!bc.held && bc.conflicts == 1);
    CHECK(bc_start_attempt(&bc, t + 2, &p) == BC_START_NO_BEACON); /* signs nothing: 0 attempts */
    CHECK(bc.attempts == 0);
    /* the next beacon is adopted without comparison -- whichever it is */
    CHECK(bc_on_beacon(&bc, real, t + 3) == BC_BEACON_ADOPTED);
    CHECK(bc_start_attempt(&bc, t + 4, &p) == BC_START_OK && memcmp(p, real, 20) == 0);
    bc_attempt_done(&bc);
    bc_init(&bc); bc_on_beacon(&bc, real, t); bc_on_beacon(&bc, fake, t + 1);
    CHECK(bc_on_beacon(&bc, next, t + 2) == BC_BEACON_ADOPTED);    /* even the fake value */
}

static void t_no_older_epoch_rule(uint32_t t)
{
    beacon_client_t bc; const uint8_t *p; uint8_t hi[20], lo[20];
    bc_init(&bc); mk(hi, 0xFFFFFFFFu, 0x11); mk(lo, 3, 0x22);
    bc_on_beacon(&bc, hi, t);                               /* a fake huge epoch number */
    CHECK(bc_on_beacon(&bc, lo, t + 1) == BC_BEACON_ADOPTED);   /* does not lock us out */
    CHECK(bc_start_attempt(&bc, t + 2, &p) == BC_START_OK && memcmp(p, lo, 20) == 0);
}

static void t_cap_sliding_window(uint32_t t)
{
    beacon_client_t bc; const uint8_t *p; uint8_t b[20];
    bc_init(&bc); mk(b, 1, 0x01);
    #define FRESH(at) bc_on_beacon(&bc, b, (at))
    FRESH(t);         CHECK(bc_start_attempt(&bc, t, &p) == BC_START_OK);       bc_attempt_done(&bc);
    FRESH(t + 10);    CHECK(bc_start_attempt(&bc, t + 10, &p) == BC_START_OK);  bc_attempt_done(&bc);
    FRESH(t + 20);    CHECK(bc_start_attempt(&bc, t + 20, &p) == BC_START_CAPPED);
    FRESH(t + BC_EPOCH_MS - 1); CHECK(bc_start_attempt(&bc, t + BC_EPOCH_MS - 1, &p) == BC_START_CAPPED);
    FRESH(t + BC_EPOCH_MS);     CHECK(bc_start_attempt(&bc, t + BC_EPOCH_MS, &p) == BC_START_OK); bc_attempt_done(&bc);
    /* a fixed window would allow a 4th here; the sliding window does not */
    FRESH(t + BC_EPOCH_MS + 5); CHECK(bc_start_attempt(&bc, t + BC_EPOCH_MS + 5, &p) == BC_START_CAPPED);
    FRESH(t + BC_EPOCH_MS + 10); CHECK(bc_start_attempt(&bc, t + BC_EPOCH_MS + 10, &p) == BC_START_OK);
    #undef FRESH
}

static void t_cap_ignores_epoch_numbers(uint32_t t)
{
    beacon_client_t bc; const uint8_t *p; uint8_t b[20]; uint32_t e;
    bc_init(&bc); mk(b, 1, 0x01); bc_on_beacon(&bc, b, t);
    bc_start_attempt(&bc, t, &p); bc_attempt_done(&bc);
    bc_start_attempt(&bc, t + 1, &p); bc_attempt_done(&bc);
    for(e = 2; e < 12; e++) {                               /* fake rising numbers 2..11 */
        mk(b, e, (uint8_t)e); bc_on_beacon(&bc, b, t + e);
        CHECK(bc_start_attempt(&bc, t + e, &p) == BC_START_CAPPED);
    }
}

static void t_cap_property_random(uint32_t t)
{
    /* Under any call pattern: no BC_MAX_ATTEMPTS + 1 granted attempts inside one epoch length. */
    beacon_client_t bc; const uint8_t *p; uint8_t b[20];
    uint32_t granted[4096]; int n = 0, i; uint32_t now = t;
    srand(1234); bc_init(&bc);
    for(i = 0; i < 20000 && n < 4096; i++) {
        now += (uint32_t)(rand() % 20000);
        if(rand() % 3 == 0) { mk(b, (uint32_t)(rand() % 5), (uint8_t)(rand() % 3)); bc_on_beacon(&bc, b, now); }
        if(bc_start_attempt(&bc, now, &p) == BC_START_OK) { granted[n++] = now; bc_attempt_done(&bc); }
    }
    for(i = BC_MAX_ATTEMPTS; i < n; i++) {
        CHECK(granted[i] - granted[i - BC_MAX_ATTEMPTS] >= BC_EPOCH_MS);
    }
    CHECK(n > 10);                                          /* the walk actually granted some */
}

static void t_busy_does_not_charge(uint32_t t)
{
    beacon_client_t bc; const uint8_t *p; uint8_t b[20];
    bc_init(&bc); mk(b, 1, 1); bc_on_beacon(&bc, b, t);
    bc_start_attempt(&bc, t, &p); bc_msg1_sent(&bc, t, 0);
    CHECK(bc_start_attempt(&bc, t + 1, &p) == BC_START_BUSY);
    CHECK(bc.attempts == 1);
}

static void t_backoff_schedule(uint32_t t, uint8_t jitter, uint32_t first)
{
    beacon_client_t bc; const uint8_t *p; uint8_t b[20]; uint32_t at = t, w = first; int k;
    bc_init(&bc); mk(b, 1, 1);
    bc_on_beacon(&bc, b, t);       /* never repeated: going stale must NOT stop resends */
    bc_start_attempt(&bc, t, &p); bc_msg1_sent(&bc, t, jitter);
    CHECK(bc.first_wait_ms == first);
    for(k = 1; k <= BC_MAX_RESENDS; k++) {
        CHECK(bc_poll(&bc, at + w - 1) == BC_POLL_WAIT);
        CHECK(bc_ms_until_deadline(&bc, at + w - 1) == 1);
        CHECK(bc_poll(&bc, at + w) == BC_POLL_RESEND);
        at += w; w *= 2;
        CHECK(bc_poll(&bc, at + 1) == BC_POLL_WAIT);        /* right after a resend */
    }
    CHECK(at - t <= 45000u);                                /* RFC 7252 MAX_TRANSMIT_SPAN */
    CHECK(bc_poll(&bc, at + w - 1) == BC_POLL_WAIT);
    CHECK(bc_poll(&bc, at + w) == BC_POLL_GAVE_UP);         /* after 31 x first wait */
    CHECK((at + w) - t == 31u * first);
    CHECK(bc_poll(&bc, at + w + 1) == BC_POLL_IDLE);
    CHECK(bc_ms_until_deadline(&bc, at + w + 1) == UINT32_MAX);
}

static void t_beacon_change_stops_resends(uint32_t t)
{
    beacon_client_t bc; const uint8_t *p; uint8_t b[20], other[20], conf[20];
    bc_init(&bc); mk(b, 1, 1); mk(other, 2, 2); mk(conf, 1, 9);
    bc_on_beacon(&bc, b, t); bc_start_attempt(&bc, t, &p); bc_msg1_sent(&bc, t, 0);
    bc_on_beacon(&bc, b, t + 100);                          /* a repeat: keeps going */
    CHECK(bc_poll(&bc, t + 2000) == BC_POLL_RESEND);
    bc_on_beacon(&bc, other, t + 2100);                     /* new epoch number */
    CHECK(bc_ms_until_deadline(&bc, t + 2101) == 0);
    CHECK(bc_poll(&bc, t + 2101) == BC_POLL_BEACON_CHANGED);
    CHECK(bc_poll(&bc, t + 9000) == BC_POLL_IDLE);          /* no further resends */
    /* a rule-C conflict also stops them */
    bc_init(&bc); bc_on_beacon(&bc, b, t); bc_start_attempt(&bc, t, &p); bc_msg1_sent(&bc, t, 0);
    bc_on_beacon(&bc, conf, t + 10);
    CHECK(bc_poll(&bc, t + 11) == BC_POLL_BEACON_CHANGED);
}

static void t_done_ends_wait(uint32_t t)
{
    beacon_client_t bc; const uint8_t *p; uint8_t b[20];
    bc_init(&bc); mk(b, 1, 1); bc_on_beacon(&bc, b, t);
    bc_start_attempt(&bc, t, &p); bc_msg1_sent(&bc, t, 0);
    bc_attempt_done(&bc);
    CHECK(bc_poll(&bc, t + 5000) == BC_POLL_IDLE);
    CHECK(bc_start_attempt(&bc, t + 5001, &p) == BC_START_OK);   /* 2nd of 2 */
    bc_attempt_done(&bc);
    CHECK(bc_start_attempt(&bc, t + 5002, &p) == BC_START_CAPPED);
}

static void run_all(uint32_t t)
{
    t_no_beacon_until_heard(t);
    t_hearing_never_signs(t);
    t_repeat_refreshes_age(t);
    t_conflict_rule_c(t);
    t_no_older_epoch_rule(t);
    t_cap_sliding_window(t);
    t_cap_ignores_epoch_numbers(t);
    t_cap_property_random(t);
    t_busy_does_not_charge(t);
    t_backoff_schedule(t, 0, 2000);
    t_backoff_schedule(t, 255, 3000);
    t_backoff_schedule(t, 128, 2501);
    t_beacon_change_stops_resends(t);
    t_done_ends_wait(t);
}

int main(void)
{
    run_all(1000u);
    run_all(0xFFFFFFFFu - 20000u);      /* the same rules across the 32-bit wrap */
    printf("BC_RESULT %d %d\n", checks, failures);
    return failures != 0;
}
'''

NEW["contiki/test/host/beacon_client_test.py"] = r'''#!/usr/bin/env python3
"""
beacon_client_test.py -- unit tests for contiki/beacon_client.c on the host.

Usage (repo root):  python3 contiki/test/host/beacon_client_test.py

Compiles contiki/beacon_client.c with beacon_client_test.c under
AddressSanitizer + UBSan, at the default settings and at a short-epoch
setting, and runs it. Pure logic: no Contiki tree, no keys. Covers decision 3
(hold latest, never sign on hearing, rule C, no older-epoch rule, sliding
attempt cap on the device timer), decision 4 (stale wait) and T2 (resend
schedule, stop on beacon change), also across the 32-bit millisecond wrap.
"""
import subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTIKI = HERE.parent.parent

def main() -> int:
    flags = "-std=gnu11 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer".split()
    ok = True
    with tempfile.TemporaryDirectory(prefix="glide_bc_") as work:
        for label, defs in (("defaults (300 s epoch, 30 s repeat)", []),
                            ("short (60 s epoch, 10 s repeat)", ["-DGLIDE_EPOCH_S=60", "-DGLIDE_BEACON_REPEAT_S=10"])):
            exe = Path(work) / "bc"
            r = subprocess.run(["gcc", *flags, *defs, "-I", str(CONTIKI), "-o", str(exe),
                                str(HERE / "beacon_client_test.c"), str(CONTIKI / "beacon_client.c")],
                               capture_output=True, text=True)
            warn = [l for l in r.stderr.splitlines() if "beacon_client.c" in l and "warning" in l]
            if r.returncode:
                print(f"compile ({label}): FAILED"); print(r.stderr[-2000:]); return 1
            p = subprocess.run([str(exe)], capture_output=True, text=True, timeout=120)
            san = "AddressSanitizer" in p.stderr or "runtime error" in p.stderr
            res = [l for l in p.stdout.splitlines() if l.startswith("BC_RESULT")]
            fails = [l for l in p.stdout.splitlines() if l.startswith("FAIL")]
            n, f = (int(x) for x in res[0].split()[1:]) if res else (0, -1)
            good = bool(res) and f == 0 and not san and p.returncode == 0 and not warn
            ok &= good
            print(f"  [{'ok ' if good else 'BAD'}] {label}: {n} checks, {f} failed, "
                  f"beacon_client.c warnings {len(warn)}, sanitizer {'ERROR' if san else 'clean'}")
            for line in fails[:10]:
                print("     ", line)
    print("beacon_client:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
'''


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("--diff", "--apply"):
        print(__doc__)
        return 2
    if not (ROOT / "contiki" / "device_auth.h").exists():
        print("ABORT: contiki/device_auth.h not found (run from the repo root)")
        return 1
    if "AUTH_BEACON_LEN" not in (ROOT / "contiki" / "device_auth.h").read_text():
        print("ABORT: D1 not applied (device_auth.h has no AUTH_BEACON_LEN)")
        return 1
    present = [f for f in NEW if (ROOT / f).exists()]
    if present:
        print("ABORT: already exists, nothing written:", ", ".join(present))
        return 1
    for f, text in NEW.items():
        print(f"  [new] {f}  ({len(text.splitlines())} lines)")
    if sys.argv[1] == "--diff":
        for f, text in NEW.items():
            sys.stdout.writelines(difflib.unified_diff(
                [], text.splitlines(True), fromfile="/dev/null", tofile=f"b/{f}"))
        print("\n(diff only: nothing written)")
        return 0
    for f, text in NEW.items():
        (ROOT / f).write_text(text)
        print(f"  wrote {f}")
    print("\nApplied. Next: python3 contiki/test/host/beacon_client_test.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
