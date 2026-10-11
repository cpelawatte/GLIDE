/*
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
