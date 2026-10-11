#!/usr/bin/env python3
"""
d3a_firmware_main_edit.py -- Fix 2, Phase D3a: one device main, wired to beacon_client.

  * contiki/device_auth_main.c: REPLACED. Beacon + MSG_2 input decoded from hex
    as it arrives (no 600 B line buffer, no sscanf, no 10 Hz polling); MSG_1 hex
    streamed out (no 600 B buffer); beacon_client decides when to sign and when
    to resend; prints a key check value (KCV), never the session key. One
    source for TARGET=cooja (rs232), cc2538dk (UART) and native (host test).
  * contiki/device_auth_main_footprint.c, contiki/device_auth_main_cc2538.c:
    DELETED (the footprint build now uses device_auth_main.c itself).
  * contiki/device_auth.c: no longer prints the session key.
  * contiki/Makefile: default TARGET cooja (this main cannot build for sky),
    adds beacon_client.c, syscalls_stub.c only for cc2538dk.
  * cap_evidence.sh: footprint builds use device_auth_main; 4a label fixed
    (the Makefile sets NULLROUTING, so there is no RPL in that image).
    Its "Expected" numbers stay stale until Phase E.
  * contiki/test/host/e2e_test.py: NEW. The real firmware (TARGET=native)
    against the real Python gateway, ASan/UBSan.

NOT touched: scripts/cooja_serial_bridge.py and the .csc (Phase D3b).

Run from the repo root (~/Desktop/FYP).

    python3 scripts/d3a_firmware_main_edit.py --diff contiki/device_auth.c
    python3 scripts/d3a_firmware_main_edit.py --diff
    python3 scripts/d3a_firmware_main_edit.py --apply

Safety rules:
  * Every edit states how many times its target must match; replaced and
    deleted files must contain marker lines from their current version. If
    anything is off, the script aborts before writing or deleting ANYTHING.
  * Refuses to run twice (detects beacon_client.c in contiki/Makefile).
"""
import difflib
import sys
from pathlib import Path

ROOT = Path.cwd()


def find_one(name):
    hits = [p for p in ROOT.rglob(name)
            if not any(part in ("venv", ".git", "build") for part in p.relative_to(ROOT).parts)]
    return hits[0].relative_to(ROOT).as_posix() if len(hits) == 1 else None


CAP = find_one("cap_evidence.sh")
FILES = ["contiki/device_auth_main.c", "contiki/device_auth.c", "contiki/Makefile",
         CAP or "cap_evidence.sh"]
EDITS = []      # (file, label, old, new, expected_count)
REPLACE = {}    # file -> (markers, new_text)
DELETE = {}     # file -> markers
NEW = {}        # file -> text


def lit(f, label, old, new, n=1):
    EDITS.append((f, label, old, new, n))


# ---------------------------------------------------------------- device_auth.c
lit("contiki/device_auth.c", "stop printing the session key",
    '    LOG_INFO("[AUTH] MSG_2 OK. Session key derived. %lu ticks\\n",\n'
    "           (unsigned long)(t_end - t_start));\n"
    '    LOG_INFO("[AUTH] Key: ");\n'
    "    for(i = 0; i < AUTH_SESSION_KEY_LEN; i++) {\n"
    '        printf("%02x", session_key[i]);\n'
    "    }\n"
    '    printf("\\n");\n',
    "    /* The session key is never printed; the caller prints a key check\n"
    "     * value instead (device_auth_main.c, put_kcv). */\n"
    '    LOG_INFO("[AUTH] MSG_2 OK. Session key derived. %lu ticks\\n",\n'
    "           (unsigned long)(t_end - t_start));\n")

# ---------------------------------------------------------------- Makefile
lit("contiki/Makefile", "default TARGET cooja",
    "TARGET ?= sky\n",
    "# device_auth_main.c builds for cooja (Cooja native mote), cc2538dk\n"
    "# (footprint, scripts/cap_evidence.sh) and native (host e2e test).\n"
    "TARGET ?= cooja\n")
lit("contiki/Makefile", "add beacon_client.c",
    "PROJECT_SOURCEFILES += device_auth.c\n",
    "PROJECT_SOURCEFILES += device_auth.c\n"
    "PROJECT_SOURCEFILES += beacon_client.c\n")
lit("contiki/Makefile", "syscalls_stub.c only for cc2538dk",
    "PROJECT_SOURCEFILES += syscalls_stub.c\n",
    "ifeq ($(TARGET),cc2538dk)\n"
    "PROJECT_SOURCEFILES += syscalls_stub.c\n"
    "endif\n")

# ---------------------------------------------------------------- cap_evidence.sh
if CAP:
    lit(CAP, "note: one firmware source",
        "# NOTE: target is device_auth_main_footprint, NOT device_auth_main.\n",
        "# NOTE: one firmware source, device_auth_main.c, for Cooja and this build (Fix 2 D3a).\n")
    lit(CAP, "CONTIKI_PROJECT -> device_auth_main",
        "CONTIKI_PROJECT=device_auth_main_footprint", "CONTIKI_PROJECT=device_auth_main", 4)
    lit(CAP, "size target -> device_auth_main",
        "build/cc2538dk/device_auth_main_footprint.cc2538dk",
        "build/cc2538dk/device_auth_main.cc2538dk", 2)
    lit(CAP, "4a label: no RPL",
        'banner "4a. Footprint \u2014 full image (IPv6 + RPL)"',
        'banner "4a. Footprint \u2014 full image (IPv6, no RPL: the Makefile sets NULLROUTING)"')

# ---------------------------------------------------------------- mains
REPLACE["contiki/device_auth_main.c"] = (
    ["rs232_set_input(serial_input_byte);",
     "msg1_len = device_auth_build_msg1(&auth_state, msg1_buf, sizeof(msg1_buf));",
     'print_hex("SESSION_KEY", session_key, AUTH_SESSION_KEY_LEN);'],
    r'''/*
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
''')
DELETE["contiki/device_auth_main_footprint.c"] = [
    "/* rs232 stubbed for cc2538dk footprint build */",
    "msg1_len = device_auth_build_msg1(&auth_state, msg1_buf, sizeof(msg1_buf));"]
DELETE["contiki/device_auth_main_cc2538.c"] = [
    "int msg1_len = device_auth_build_msg1(&auth_state, msg1_buf, sizeof(msg1_buf));"]

NEW["contiki/test/host/e2e_test.py"] = r'''#!/usr/bin/env python3
"""
e2e_test.py -- the REAL device firmware (device_auth_main.c, TARGET=native)
against the REAL Python gateway, over a serial-style pipe.

Usage (repo root):  python3 contiki/test/host/e2e_test.py [path/to/contiki-ng]
                    (default contiki-ng path: ../contiki-ng)

Builds contiki/ for Contiki-NG's native target in a temporary directory, with
a throwaway credential made with src/ (never your credentials.h), short
settings (epoch 10 s, beacon repeat 1 s) and AddressSanitizer + UBSan. Each
scenario starts a fresh device process and plays the gateway with
src/edhoc_subset.py + src/beacon.py:

  S1 happy path: beacon -> MSG_1 (version 2, 174 B) -> MSG_2 -> KCV matches
     the gateway's key; the session key never appears in the device output
  S2 lost MSG_2 (T2): the device resends the identical MSG_1; the gateway
     answers RETRANSMISSION with the stored MSG_2; same key
  S3 forged MSG_2 first: rejected, attempt not cancelled; the real one works
  S4 rule C: a conflicting beacon stops resends and nothing is signed until
     the next beacon; the new epoch's MSG_1 is accepted
  S5 junk input (bad prefix, bad hex, short / odd-length beacon, over-long
     lines) is ignored; no MSG_1 without a beacon; the device still works afterwards
Prints verdicts only.
"""
import hashlib, os, queue, re, secrets, shutil, subprocess, sys, tempfile, threading, time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
CNG = Path(sys.argv[1] if len(sys.argv) > 1 else REPO.parent / "contiki-ng").resolve()
sys.path.insert(0, str(REPO))

import cbor2                                                                   # noqa: E402
from src.beacon import Beacon, EpochState                                      # noqa: E402
from src.cert_info import encode_cert_info                                     # noqa: E402
from src.ecqv_core import (device_derive_private_key, device_generate_contribution,  # noqa: E402
                           issuer_generate_cert, issuer_generate_keypair, point_to_compressed)
from src.edhoc_subset import gateway_process_msg1_build_msg2                  # noqa: E402
from src.gateway_keystore import (Keystore, PinnedIssuer, _compute_q_ca_hash, # noqa: E402
                                  _generate_gateway_identity)
from src.gateway_verifier import AuthFailureReason                            # noqa: E402

ISSUER_DID = "did:web:host-test.invalid"
EPOCH_S, REPEAT_S = 10, 1


def carr(n, b):
    return f"#define {n}_LEN {len(b)}\nstatic const uint8_t {n}[{n}_LEN] = {{{', '.join('0x%02x' % x for x in b)}}};\n"


def kcv(key: bytes) -> str:
    return hashlib.sha256(b"GLIDE-KCV" + key).digest()[:4].hex()


class FakeClock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, s): self.t += s


class Device:
    """One native device process; lines from its stdout arrive on a queue."""
    def __init__(self, exe):
        self.p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, bufsize=1)
        self.q, self.seen = queue.Queue(), []
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.q.put(line.rstrip("\n"))

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def wait_for(self, pattern, timeout):
        """Next line matching `pattern` (regex) within `timeout` s, else None."""
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return None
            try:
                line = self.q.get(timeout=left)
            except queue.Empty:
                return None
            self.seen.append(line)
            if re.search(pattern, line):
                return line

    def quiet(self, pattern, seconds):
        """True if no line matching `pattern` appears for `seconds`."""
        return self.wait_for(pattern, seconds) is None

    def close(self):
        self.p.kill()
        self.p.wait()
        err = self.p.stderr.read()
        return "AddressSanitizer" not in err and "runtime error" not in err


def msg1_of(line):
    return bytes.fromhex(line.split("MSG1:", 1)[1]) if line else None


def main() -> int:
    for need in (CNG / "Makefile.include", CNG / "arch/platform/native"):
        if not need.exists():
            print("ABORT: not found:", need); return 1
    work = Path(tempfile.mkdtemp(prefix="glide_e2e_"))
    try:
        src = work / "contiki"
        src.mkdir()
        for f in (REPO / "contiki").iterdir():
            if f.is_file() and f.suffix in (".c", ".h") and f.name != "credentials.h":
                shutil.copy(f, src / f.name)
        shutil.copy(REPO / "contiki" / "Makefile", src / "Makefile")

        now = datetime.now(timezone.utc)
        issuer = issuer_generate_keypair()
        contribution = device_generate_contribution()
        cert = issuer_generate_cert(contribution.U, encode_cert_info(ISSUER_DID, now, 24), issuer)
        d = device_derive_private_key(contribution, cert)
        keystore = Keystore(
            pinned_issuer=PinnedIssuer(issuer_did=ISSUER_DID, Q_ca=issuer.Q_ca,
                                       Q_ca_hash_hex=_compute_q_ca_hash(issuer.Q_ca),
                                       bootstrap_mode="pinned", bootstrapped_at=now.isoformat()),
            gateway_identity=_generate_gateway_identity(lifetime_days=90))
        (src / "credentials.h").write_text(
            "#pragma once\n#include <stdint.h>\n" + carr("DEVICE_PRIVATE_KEY", d.to_bytes(32, "big"))
            + carr("DEVICE_CERT_R", point_to_compressed(cert.R)) + carr("DEVICE_CERT_INFO", cert.cert_info)
            + carr("GATEWAY_PUBLIC_KEY", point_to_compressed(keystore.gateway_identity.public_key))
            + carr("ISSUER_PUBLIC_KEY", point_to_compressed(issuer.Q_ca)))

        env = dict(os.environ, CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer",
                   LDFLAGS="-fsanitize=address,undefined")
        r = subprocess.run(["make", "-j4", "TARGET=native", "MAKE_NET=MAKE_NET_NULLNET",
                            f"CONTIKI_NG_PATH={CNG}",
                            f"DEFINES=GLIDE_EPOCH_S={EPOCH_S},GLIDE_BEACON_REPEAT_S={REPEAT_S}"],
                           cwd=src, capture_output=True, text=True, env=env)
        warn = [l for l in (r.stdout + r.stderr).splitlines()
                if "warning" in l and ("device_auth" in l or "beacon_client" in l)]
        print(f"build (native, ASan/UBSan): {'ok' if r.returncode == 0 else 'FAILED'}, "
              f"GLIDE source warnings: {len(warn)}")
        if r.returncode:
            print((r.stdout + r.stderr)[-2500:]); return 1
        exe = src / "build/native/device_auth_main.native"

        values = iter(secrets.token_bytes(16) for _ in range(100))
        results = {}

        def gateway():
            clock = FakeClock()
            return EpochState(EPOCH_S, max_devices=8, clock=clock,
                              value_source=lambda n: next(values)), clock

        def beacon_line(b):
            return "BEACON:" + b.to_bytes().hex()

        def finish(dev, label, ok, key=None):
            clean = dev.close()
            if key is not None:
                ok = ok and not any(key.hex() in l for l in dev.seen)
            results[label] = ok and clean

        # ---- S1 happy path ----
        gw, _ = gateway(); dev = Device(exe)
        dev.send(beacon_line(gw.current_beacon()))
        m1 = msg1_of(dev.wait_for(r"^MSG1:", 10))
        ok = m1 is not None and len(m1) == 174 and cbor2.loads(m1)[0] == 2
        res = gateway_process_msg1_build_msg2(keystore, m1, epoch_state=gw) if ok else None
        ok = ok and res.success
        if ok:
            dev.send("MSG2:" + res.msg2_bytes.hex())
            ok = dev.wait_for(r"^KCV:", 10) == f"KCV:{kcv(res.session_key)}" \
                and dev.wait_for(r"=== Done ===", 5) is not None
        finish(dev, "S1 beacon -> MSG_1 (v2, 174 B) -> MSG_2 -> KCV == gateway; key never printed",
               ok, res.session_key if res else None)

        # ---- S2 lost MSG_2: identical resend, stored MSG_2 ----
        gw, _ = gateway(); dev = Device(exe); b = gw.current_beacon()
        dev.send(beacon_line(b))
        m1 = msg1_of(dev.wait_for(r"^MSG1:", 10))
        first = gateway_process_msg1_build_msg2(keystore, m1, epoch_state=gw) if m1 else None
        t0 = time.monotonic(); again = None                 # the first MSG_2 is "lost"
        while time.monotonic() - t0 < 6 and again is None:
            dev.send(beacon_line(b))                         # repeats keep coming
            again = msg1_of(dev.wait_for(r"^MSG1:", REPEAT_S))
        ok = bool(first and first.success and again == m1 and 2.0 <= time.monotonic() - t0 <= 4.5)
        if ok:
            r2 = gateway_process_msg1_build_msg2(keystore, again, epoch_state=gw)
            ok = (r2.reason is AuthFailureReason.RETRANSMISSION and r2.msg2_bytes == first.msg2_bytes
                  and gw.occupancy == 1)
            dev.send("MSG2:" + r2.msg2_bytes.hex())
            ok = ok and dev.wait_for(r"^KCV:", 10) == f"KCV:{kcv(first.session_key)}"
        finish(dev, "S2 lost MSG_2: same MSG_1 resent after 2-3 s, RETRANSMISSION, same key",
               ok, first.session_key if first else None)

        # ---- S3 forged MSG_2 first ----
        gw, _ = gateway(); dev = Device(exe)
        dev.send(beacon_line(gw.current_beacon()))
        m1 = msg1_of(dev.wait_for(r"^MSG1:", 10))
        res = gateway_process_msg1_build_msg2(keystore, m1, epoch_state=gw) if m1 else None
        ok = bool(res and res.success)
        if ok:
            forged = res.msg2_bytes[:-1] + bytes([res.msg2_bytes[-1] ^ 1])
            dev.send("MSG2:" + forged.hex())
            ok = dev.wait_for(r"MSG_2 rejected", 5) is not None and dev.quiet(r"^KCV:", 0.5)
            dev.send("MSG2:" + res.msg2_bytes.hex())
            ok = ok and dev.wait_for(r"^KCV:", 10) == f"KCV:{kcv(res.session_key)}"
        finish(dev, "S3 forged MSG_2 rejected without cancelling; real MSG_2 then works",
               ok, res.session_key if res else None)

        # ---- S4 rule C ----
        gw, clock = gateway(); dev = Device(exe); b1 = gw.current_beacon()
        dev.send(beacon_line(b1))
        m1 = msg1_of(dev.wait_for(r"^MSG1:", 10))
        fake = Beacon(b1.epoch, secrets.token_bytes(16))
        dev.send(beacon_line(fake))
        ok = m1 is not None and dev.wait_for(r"beacon conflict", 5) is not None
        ok = ok and dev.quiet(r"^MSG1:", 4.0)                # no resends, nothing signed
        clock.advance(EPOCH_S); b2 = gw.current_beacon()     # the gateway's next epoch
        dev.send(beacon_line(b2))
        m1b = msg1_of(dev.wait_for(r"^MSG1:", 10))
        res = gateway_process_msg1_build_msg2(keystore, m1b, epoch_state=gw) if m1b else None
        ok = ok and m1b is not None and m1b != m1 and bool(res and res.success)
        if ok:
            dev.send("MSG2:" + res.msg2_bytes.hex())
            ok = dev.wait_for(r"^KCV:", 10) == f"KCV:{kcv(res.session_key)}"
        finish(dev, "S4 rule C: conflict stops resends, nothing signed; next epoch's MSG_1 accepted",
               ok, res.session_key if res else None)

        # ---- S5 junk input ----
        gw, _ = gateway(); dev = Device(exe)
        for junk in ("HELLO:00", "MSG2:zz", "BEACON:00", "BEACON:" + "ab" * 21, "X" * 1000,
                     "MSG2:" + "00" * 400, "BEACON" + "00" * 20, "MSG2:abc",
                     "BEACON:" + "ab" * 20 + "c", "beacon:" + "ab" * 20):
            dev.send(junk)
        ok = dev.quiet(r"^MSG1:", 3.0)                      # no beacon held -> nothing signed
        dev.send(beacon_line(gw.current_beacon()))
        m1 = msg1_of(dev.wait_for(r"^MSG1:", 10))
        res = gateway_process_msg1_build_msg2(keystore, m1, epoch_state=gw) if m1 else None
        ok = ok and bool(res and res.success)
        if ok:
            dev.send("MSG2:" + res.msg2_bytes.hex())
            ok = dev.wait_for(r"^KCV:", 10) == f"KCV:{kcv(res.session_key)}"
        finish(dev, "S5 junk lines ignored, nothing signed without a beacon, then normal",
               ok, res.session_key if res else None)

        for label, ok in results.items():
            print(f"  [{'ok ' if ok else 'BAD'}] {label}")
        good = len(results) == 5 and all(results.values())
        print("device firmware (native) <-> real gateway, ASan/UBSan clean:",
              "ALL PASS" if good else "FAILURES")
        return 0 if good else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
'''


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("--diff", "--apply"):
        print(__doc__)
        return 2
    mode, only = sys.argv[1], sys.argv[2:]
    if CAP is None:
        print("ABORT: expected exactly one cap_evidence.sh in the repo")
        return 1
    mk = ROOT / "contiki" / "Makefile"
    if mk.exists() and "beacon_client.c" in mk.read_text():
        print("ABORT: edits already applied (contiki/Makefile lists beacon_client.c).")
        return 1
    every = FILES + list(DELETE)
    for f in every:
        if not (ROOT / f).exists():
            print(f"ABORT: {f} not found (run from the repo root)")
            return 1
    original = {f: (ROOT / f).read_text() for f in every}
    edited = {f: original[f] for f in FILES}

    bad = []
    for f, label, old, new, n in EDITS:
        got = edited[f].count(old)
        if got == n:
            edited[f] = edited[f].replace(old, new)
        print(f"  [{'ok ' if got == n else 'BAD'}] {f}: {label}  (expected {n}, found {got})")
        if got != n:
            bad.append(label)
    for f, (markers, new) in REPLACE.items():
        ok = all(m in original[f] for m in markers)
        print(f"  [{'ok ' if ok else 'BAD'}] {f}: replace whole file  (old-version markers {'found' if ok else 'MISSING'})")
        if ok:
            edited[f] = new
        else:
            bad.append(f)
    for f, markers in DELETE.items():
        ok = all(m in original[f] for m in markers)
        print(f"  [{'ok ' if ok else 'BAD'}] {f}: delete  (markers {'found' if ok else 'MISSING'})")
        if not ok:
            bad.append(f)
    for f in NEW:
        ok = not (ROOT / f).exists()
        print(f"  [{'ok ' if ok else 'BAD'}] {f}: new file  ({'absent' if ok else 'ALREADY EXISTS'})")
        if not ok:
            bad.append(f)
    if bad:
        print(f"\nABORT: {len(bad)} check(s) failed; NOTHING was written or deleted.")
        return 1

    if mode == "--diff":
        for f in FILES:
            if not only or f in only:
                sys.stdout.writelines(difflib.unified_diff(
                    original[f].splitlines(True), edited[f].splitlines(True),
                    fromfile=f"a/{f}", tofile=f"b/{f}"))
        for f in DELETE:
            if not only or f in only:
                print(f"--- a/{f}\n+++ /dev/null   (deleted, {len(original[f].splitlines())} lines)")
        for f, text in NEW.items():
            if not only or f in only:
                sys.stdout.writelines(difflib.unified_diff(
                    [], text.splitlines(True), fromfile="/dev/null", tofile=f"b/{f}"))
        print("\n(diff only: nothing written)")
        return 0

    for f in FILES:
        if edited[f] != original[f]:
            (ROOT / f).write_text(edited[f])
            print(f"  wrote {f}")
    for f, text in NEW.items():
        (ROOT / f).write_text(text)
        print(f"  wrote {f}")
    for f in DELETE:
        (ROOT / f).unlink()
        print(f"  deleted {f}")
    print("\nApplied. Next: python3 contiki/test/host/e2e_test.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
