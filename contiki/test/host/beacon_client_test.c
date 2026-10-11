/* Host unit tests for beacon_client.c (Fix 2 device rules). Prints one line
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
