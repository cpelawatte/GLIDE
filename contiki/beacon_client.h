/*
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
