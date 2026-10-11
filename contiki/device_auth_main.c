/*
 * device_auth_main.c -- GLIDE device: epoch beacon (Fix 2) + EDHOC-subset
 * handshake with the gateway over a serial line.
 *
 * ONE source for both builds, so the measured image is the code that runs:
 *   TARGET=cooja     Cooja native mote; serial = Cooja RS232 (Serial Socket)
 *   TARGET=cc2538dk  footprint build (scripts/cap_evidence.sh); serial = UART
 *   TARGET=native    host end-to-end test only (contiki/test/host/e2e_test.py);
 *                    serial = stdin/stdout
 *
 * Serial lines (hex payloads, one per line):
 *   gateway -> device   BEACON:<40 hex>   the epoch beacon, every repeat interval
 *   gateway -> device   MSG2:<hex>        the reply to our MSG_1
 *   device  -> gateway  MSG1:<hex>        on each attempt and each T2 resend
 *   device  -> gateway  KCV:<8 hex>       key check value: the first 4 bytes of
 *                                         SHA-256("GLIDE-KCV" || session key).
 *                                         Proves both sides hold the same key
 *                                         without ever printing the key.
 *
 * Flow: wait for a beacon -> authenticate once (beacon_client decides when
 * signing is allowed and when to resend) -> print the KCV -> stay idle,
 * still tracking beacons.
 *
 * Input is decoded from hex straight into binary as bytes arrive, and the
 * process is woken only when a whole line is in: no text line buffer and no
 * periodic polling. While one line waits to be handled, further input is
 * dropped until the next newline (a dropped beacon is repeated anyway).
 */

#include "contiki.h"
#include "device_auth.h"
#include "beacon_client.h"
#include "sha256_impl.h"
#include "lib/random.h"
#include "sys/energest.h"
#include "sys/log.h"

#if CONTIKI_TARGET_COOJA
#include "dev/rs232.h"
#elif CONTIKI_TARGET_CC2538DK
#include "dev/uart.h"
#elif CONTIKI_TARGET_NATIVE
/* Host end-to-end test build only (contiki/test/host/e2e_test.py): the native
 * platform feeds stdin to this handler. Defined in arch/platform/native. */
void native_uart_set_input(int (*input)(unsigned char c));
#endif

#include <stdio.h>
#include <string.h>

#define LOG_MODULE "DeviceAuth"
#define LOG_LEVEL  LOG_LEVEL_INFO

PROCESS(device_auth_process, "Device Auth Process");
AUTOSTART_PROCESSES(&device_auth_process);

/* ---------------------------------------------------------------------------
 * Serial input: "BEACON:<hex>" / "MSG2:<hex>", decoded as it arrives.
 * Runs in interrupt context on the CC2538 (UART) and in the pre-tick hook in
 * Cooja; it only touches the in_* variables and calls process_poll().
 * --------------------------------------------------------------------------- */
enum { IN_NONE = 0, IN_BEACON = 1, IN_MSG2 = 2 };
enum { ST_PREFIX, ST_HEX, ST_SKIP };

static uint8_t           in_buf[AUTH_MSG2_MAX_LEN];  /* decoded payload */
static volatile uint16_t in_len;
static volatile uint8_t  in_kind;
static volatile uint8_t  in_ready;                   /* a whole line waits */
static uint8_t           in_state = ST_PREFIX;
static uint8_t           in_prefix_len;
static uint8_t           in_hi, in_have_hi;
static char              in_prefix[7];               /* longest prefix: BEACON */

static int hexval(unsigned char c)
{
    if(c >= '0' && c <= '9') { return c - '0'; }
    if(c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if(c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

static int serial_input_byte(unsigned char c)
{
    if(c == '\n' || c == '\r') {
        if(!in_ready && in_state == ST_HEX && !in_have_hi && in_len > 0) {
            in_ready = 1;
            process_poll(&device_auth_process);
        }
        in_state = ST_PREFIX;
        in_prefix_len = 0;
        in_have_hi = 0;
        return 1;
    }
    if(in_ready) {                      /* previous line not handled yet */
        in_state = ST_SKIP;             /* drop this one up to its newline */
        return 0;
    }
    switch(in_state) {
    case ST_PREFIX:
        if(c == ':') {
            if(in_prefix_len == 6 && memcmp(in_prefix, "BEACON", 6) == 0) {
                in_kind = IN_BEACON;
            } else if(in_prefix_len == 4 && memcmp(in_prefix, "MSG2", 4) == 0) {
                in_kind = IN_MSG2;
            } else {
                in_state = ST_SKIP;
                break;
            }
            in_len = 0;
            in_state = ST_HEX;
        } else if(in_prefix_len < sizeof(in_prefix)) {
            in_prefix[in_prefix_len++] = (char)c;
        } else {
            in_state = ST_SKIP;
        }
        break;
    case ST_HEX: {
        int v = hexval(c);
        if(v < 0 || in_len >= sizeof(in_buf)) {
            in_state = ST_SKIP;         /* bad character or too long: drop line */
            break;
        }
        if(!in_have_hi) {
            in_hi = (uint8_t)v;
            in_have_hi = 1;
        } else {
            in_buf[in_len++] = (uint8_t)((in_hi << 4) | v);
            in_have_hi = 0;
        }
        break;
    }
    default:                            /* ST_SKIP */
        break;
    }
    return 0;
}

static void serial_input_init(void)
{
#if CONTIKI_TARGET_COOJA
    rs232_set_input(serial_input_byte);
#elif CONTIKI_TARGET_CC2538DK
    uart_set_input(SERIAL_LINE_CONF_UART, serial_input_byte);
#elif CONTIKI_TARGET_NATIVE
    setvbuf(stdout, NULL, _IOLBF, 0);   /* line-buffered when stdout is a pipe */
    native_uart_set_input(serial_input_byte);
#endif
}

/* Hex out, streamed: no line buffer. */
static void put_hex_line(const char *label, const uint8_t *data, size_t len)
{
    size_t i;
    printf("%s:", label);
    for(i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* ---------------------------------------------------------------------------
 * Time: milliseconds from the Contiki clock (beacon_client is wrap-safe).
 * CLOCK_SECOND is a constant (1000 in Cooja, a power of two on the CC2538),
 * so the division compiles to nothing or a shift.
 * --------------------------------------------------------------------------- */
static uint32_t now_ms(void)
{
    return (uint32_t)(((uint64_t)clock_time() * 1000u) / (uint64_t)CLOCK_SECOND);
}

static clock_time_t ms_to_ticks(uint32_t ms)
{
    uint32_t t;
    if(ms > 3600000u) {
        ms = 3600000u;                  /* at most an hour per timer */
    }
    t = (ms * (uint32_t)CLOCK_SECOND + 999u) / 1000u;
    return (clock_time_t)(t ? t : 1);
}

/* ---------------------------------------------------------------------------
 * Key check value: proves key agreement without printing the key.
 * --------------------------------------------------------------------------- */
/* noinline: keeps the 104 B hash state out of the process frame, so it is
 * only on the stack while the KCV is computed, never under the MSG_2 chain. */
static void __attribute__((noinline)) put_kcv(const uint8_t *key)
{
    static const uint8_t label[] = "GLIDE-KCV";
    sha256_impl_ctx_t ctx;
    uint8_t digest[32];

    sha256_impl_init(&ctx);
    sha256_impl_update(&ctx, label, sizeof(label) - 1);
    sha256_impl_update(&ctx, key, AUTH_SESSION_KEY_LEN);
    sha256_impl_final(&ctx, digest);
    put_hex_line("KCV", digest, 4);
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(device_auth_process, ev, data)
{
    static beacon_client_t bc;
    static device_auth_state_t auth_state;
    static uint8_t msg1_buf[AUTH_MSG1_MAX_LEN];
    static uint8_t session_key[AUTH_SESSION_KEY_LEN];
    static struct etimer et;
    static int msg1_len;            /* > 0 while auth_state matches msg1_buf */
    static uint8_t authenticated;
    const uint8_t *beacon;
    uint32_t now, wait;
    int ret;

    PROCESS_BEGIN();

    bc_init(&bc);
    msg1_len = 0;
    authenticated = 0;
    serial_input_init();
    energest_init();
    LOG_INFO("GLIDE device up: epoch %u s, beacon repeat %u s; waiting for a beacon\n",
             (unsigned)GLIDE_EPOCH_S, (unsigned)GLIDE_BEACON_REPEAT_S);

    while(1) {
        PROCESS_WAIT_EVENT();
        now = now_ms();

        /* 1. A complete input line. */
        if(in_ready) {
            if(in_kind == IN_BEACON && in_len == AUTH_BEACON_LEN) {
                switch(bc_on_beacon(&bc, in_buf, now)) {
                case BC_BEACON_ADOPTED:
                    LOG_INFO("beacon adopted (epoch %lu)\n",
                             (unsigned long)(((uint32_t)in_buf[0] << 24) | ((uint32_t)in_buf[1] << 16)
                                             | ((uint32_t)in_buf[2] << 8) | in_buf[3]));
                    break;
                case BC_BEACON_CONFLICT:
                    LOG_WARN("beacon conflict: both discarded, waiting for the next (%u so far)\n",
                             (unsigned)bc.conflicts);
                    break;
                default:                /* a repeat */
                    break;
                }
            } else if(in_kind == IN_MSG2 && msg1_len > 0 && !authenticated) {
                ret = device_auth_process_msg2(&auth_state, in_buf, in_len, session_key);
                if(ret == AUTH_OK) {
                    bc_attempt_done(&bc);
                    authenticated = 1;
                    LOG_INFO("=== Authentication Successful ===\n");
                    put_kcv(session_key);
                    energest_flush();
                    LOG_INFO("CPU ticks: %llu\n",
                             (unsigned long long)energest_type_time(ENERGEST_TYPE_CPU));
                    LOG_INFO("=== Done ===\n");
                } else {
                    /* Not ours or forged: keep waiting for the real one. */
                    LOG_WARN("MSG_2 rejected (%d); still waiting\n", ret);
                }
            }
            in_ready = 0;               /* hand the buffer back to the input */
        }

        /* 2. Resend / give-up schedule of the outstanding attempt (T2). */
        switch(bc_poll(&bc, now)) {
        case BC_POLL_RESEND:
            LOG_INFO("no MSG_2 yet: resending the same MSG_1 (%u/%u)\n",
                     (unsigned)bc.resends, (unsigned)BC_MAX_RESENDS);
            put_hex_line("MSG1", msg1_buf, (size_t)msg1_len);
            break;
        case BC_POLL_GAVE_UP:
            LOG_WARN("attempt gave up after %u resends\n", (unsigned)BC_MAX_RESENDS);
            break;
        case BC_POLL_BEACON_CHANGED:
            LOG_INFO("beacon changed: stopped resending this MSG_1\n");
            break;
        default:
            break;
        }

        /* 3. Start an attempt if we still need one and the rules allow it. */
        if(!authenticated
           && bc_start_attempt(&bc, now, &beacon) == BC_START_OK) {
            ret = device_auth_build_msg1(&auth_state, beacon, msg1_buf, sizeof(msg1_buf));
            if(ret < 0) {
                msg1_len = 0;
                bc_attempt_done(&bc);   /* the attempt still counts */
                LOG_ERR("MSG_1 build failed: %d\n", ret);
            } else {
                msg1_len = ret;
                put_hex_line("MSG1", msg1_buf, (size_t)msg1_len);
                bc_msg1_sent(&bc, now_ms(), (uint8_t)random_rand());
            }
        }

        /* 4. Sleep until the next resend deadline (or the next input line). */
        wait = bc_ms_until_deadline(&bc, now_ms());
        if(wait == UINT32_MAX) {
            etimer_stop(&et);
        } else {
            etimer_set(&et, ms_to_ticks(wait));
        }
    }

    PROCESS_END();
}
