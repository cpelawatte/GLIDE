#!/usr/bin/env python3
"""
d3b_bridge_sim_edit.py -- Fix 2, Phase D3b: the gateway side for Cooja.

  * scripts/cooja_serial_bridge.py: REPLACED. One EpochState for the run,
    BEACON every repeat interval, every MSG1 answered (accepted -> MSG2,
    RETRANSMISSION -> stored MSG2, refused -> nothing, reason printed),
    KCV check instead of printing the session key, settings check against
    the mote's boot line, --drop-msg2 N (T2 demo), --replay (replay demo).
  * contiki/sim/glide.csc: NEW. Your simulation, moved into the repo: source
    path relative to the repo, speed limit 100%, Serial Socket client to
    localhost:60001 saved in the file. ~/Downloads/lecqv test.csc is untouched.
  * contiki/test/host/bridge_test.py: NEW. The bridge against the real
    firmware (native build) through a socket pair, no Cooja needed.

Run from the repo root (~/Desktop/FYP).

    python3 scripts/d3b_bridge_sim_edit.py --diff scripts/cooja_serial_bridge.py
    python3 scripts/d3b_bridge_sim_edit.py --apply

Safety rules: the replaced file must contain marker lines from its current
version, new files must not exist; otherwise NOTHING is written. Refuses to
run twice (detects "class Bridge" in the bridge).
"""
import difflib
import sys
from pathlib import Path

ROOT = Path.cwd()
BRIDGE = "scripts/cooja_serial_bridge.py"
MARKERS = ["msg1_hex = line[5:]",
           "result = gateway_process_msg1_build_msg2(keystore, msg1_bytes)",
           'print(f"[BRIDGE] SESSION KEY: {result.session_key.hex()}")']
NEW = {}

BRIDGE_NEW = r'''#!/usr/bin/env python3
"""
cooja_serial_bridge.py -- the GLIDE gateway for a Cooja mote (Fix 2).

Cooja's Serial Socket (CLIENT mode) connects to this script. The script then
acts as the gateway for that mote:
  * keeps ONE EpochState for the whole run (the nonce sheet, the stored MSG_2s);
  * sends BEACON:<hex> every repeat interval (the epoch rolls on time);
  * answers every MSG1:<hex> line with src/edhoc_subset.py:
        accepted        -> MSG2:<hex>
        RETRANSMISSION  -> the stored MSG2:<hex> again (T2: no new acceptance)
        anything else   -> nothing is sent; the reason is printed;
  * checks the mote's KCV:<hex> against the gateway's own key check value
    (first 4 bytes of SHA-256("GLIDE-KCV" || key)). The session key itself is
    never printed.

The epoch length and repeat interval must match the firmware build
(GLIDE_EPOCH_S / GLIDE_BEACON_REPEAT_S). The mote prints its settings at boot;
the bridge stops with an error if they differ. Run Cooja at 100% speed: the
bridge times beacons on the wall clock, the mote on simulated time.

Usage (repo root, start this BEFORE the simulation):
    python -m scripts.cooja_serial_bridge
    python -m scripts.cooja_serial_bridge --epoch-s 60 --repeat-s 10
    python -m scripts.cooja_serial_bridge --drop-msg2 1      # T2 demo: lose the first MSG_2
    python -m scripts.cooja_serial_bridge --replay           # replay demo after success
Options: --port (60001), --max-devices (8), --duration (seconds, 0 = until
the mote disconnects), --keystore (gateway_keystore.json).
"""

import argparse
import hashlib
import re
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.beacon import EpochState                                  # noqa: E402
from src.edhoc_subset import gateway_process_msg1_build_msg2       # noqa: E402
from src.gateway_verifier import AuthFailureReason                 # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEFAULT_KEYSTORE = REPO / "gateway_keystore.json"
SETTINGS_RE = re.compile(r"epoch (\d+) s, beacon repeat (\d+) s")


def kcv(key: bytes) -> str:
    """Key check value: proves both sides hold the same key, reveals nothing useful."""
    return hashlib.sha256(b"GLIDE-KCV" + key).digest()[:4].hex()


class Bridge:
    """The gateway side of one serial connection. Transport-agnostic: `send`
    writes one line to the mote; feed() handles one line from the mote."""

    def __init__(self, keystore, epoch_state, send, *, epoch_s, repeat_s,
                 drop_msg2=0, replay=False, log=print):
        self.keystore, self.state, self.send = keystore, epoch_state, send
        self.epoch_s, self.repeat_s = epoch_s, repeat_s
        self.drop_msg2, self.replay, self.log = drop_msg2, replay, log
        self.next_beacon_at = 0.0
        self.expected_kcv = None
        self.captured_msg1 = None
        self.result = None          # "MATCH", "MISMATCH", "SETTINGS_MISMATCH"
        self.counts = {"accepted": 0, "retransmissions": 0, "refused": 0, "dropped_msg2": 0}

    # -- outgoing --------------------------------------------------------------
    def tick(self, now):
        """Send the current beacon every repeat interval. current_beacon() also
        rolls the epoch on time."""
        if now >= self.next_beacon_at:
            b = self.state.current_beacon()
            self.send("BEACON:" + b.to_bytes().hex())
            self.next_beacon_at = now + self.repeat_s
            return b
        return None

    def _send_msg2(self, msg2):
        if self.drop_msg2 > 0:
            self.drop_msg2 -= 1
            self.counts["dropped_msg2"] += 1
            self.log("[BRIDGE] (demo) MSG_2 deliberately NOT sent: the mote must resend MSG_1")
            return
        self.send("MSG2:" + msg2.hex())

    # -- incoming --------------------------------------------------------------
    def feed(self, line):
        """Handle one line from the mote. Returns False to stop the bridge."""
        self.log(f"[MOTE]   {line}")
        m = SETTINGS_RE.search(line)
        if m and "GLIDE device up" in line:
            mote = (int(m.group(1)), int(m.group(2)))
            if mote != (self.epoch_s, self.repeat_s):
                self.log(f"[BRIDGE] ERROR: mote uses epoch {mote[0]} s / repeat {mote[1]} s, "
                         f"bridge uses {self.epoch_s} s / {self.repeat_s} s. Rebuild one side.")
                self.result = "SETTINGS_MISMATCH"
                return False
            return True
        if "MSG1:" in line:
            try:
                msg1 = bytes.fromhex(line.split("MSG1:", 1)[1].strip())
            except ValueError:
                self.log("[BRIDGE] MSG1 line is not valid hex; ignored")
                return True
            self._on_msg1(msg1)
            return True
        if "KCV:" in line and self.expected_kcv is not None:
            got = line.split("KCV:", 1)[1].strip()
            self.result = "MATCH" if got == self.expected_kcv else "MISMATCH"
            self.log(f"[BRIDGE] key check value: mote {got}, gateway {self.expected_kcv} -> {self.result}")
            if self.result == "MATCH" and self.replay:
                self._replay_demo()
            return True
        return True

    def _on_msg1(self, msg1):
        r = gateway_process_msg1_build_msg2(self.keystore, msg1, epoch_state=self.state)
        if r.success:
            self.counts["accepted"] += 1
            self.expected_kcv = kcv(r.session_key)
            self.captured_msg1 = msg1
            self.log(f"[BRIDGE] MSG_1 ({len(msg1)} B) accepted. Device: {r.device_did}")
            self.log(f"[BRIDGE] MSG_2 built: {len(r.msg2_bytes)} B; gateway KCV {self.expected_kcv}")
            self._send_msg2(r.msg2_bytes)
        elif r.reason is AuthFailureReason.RETRANSMISSION:
            self.counts["retransmissions"] += 1
            self.log("[BRIDGE] identical MSG_1 again: stored MSG_2 resent (T2, no new acceptance)")
            self._send_msg2(r.msg2_bytes)
        else:
            self.counts["refused"] += 1
            self.log(f"[BRIDGE] MSG_1 refused: {r.reason.value} ({r.detail}); nothing sent")

    def _replay_demo(self):
        """An attacker replays the captured MSG_1 straight to the gateway logic."""
        self.log("[REPLAY] replaying the captured MSG_1 in the same epoch ...")
        r = gateway_process_msg1_build_msg2(self.keystore, self.captured_msg1, epoch_state=self.state)
        self.log(f"[REPLAY]   -> {r.reason.value if r.reason else 'ACCEPTED'}; "
                 f"new acceptance: {'YES' if r.success else 'no'}; sheet entries: {self.state.occupancy}")
        self.replay_after_epoch_at = time.monotonic() + self.epoch_s + 1

    def maybe_replay_after_epoch(self, now):
        at = getattr(self, "replay_after_epoch_at", None)
        if at is not None and now >= at:
            self.replay_after_epoch_at = None
            self.state.current_beacon()                     # roll if due
            r = gateway_process_msg1_build_msg2(self.keystore, self.captured_msg1, epoch_state=self.state)
            self.log(f"[REPLAY] same MSG_1 after the epoch rolled -> "
                     f"{r.reason.value if r.reason else 'ACCEPTED'}; "
                     f"new acceptance: {'YES' if r.success else 'no'}")
            return True
        return False


def serve(conn, bridge, duration=0.0):
    """Run the bridge on a connected socket until the mote disconnects,
    `duration` seconds pass (0 = no limit), or the bridge stops."""
    conn.settimeout(0.2)
    buf, start = b"", time.monotonic()
    while True:
        now = time.monotonic()
        if duration and now - start >= duration:
            return
        bridge.tick(now)
        bridge.maybe_replay_after_epoch(now)
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            bridge.log("[BRIDGE] mote disconnected")
            return
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            line = raw.decode("utf-8", errors="replace").strip()
            if line and not bridge.feed(line):
                return


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=60001)
    ap.add_argument("--epoch-s", type=int, default=300)
    ap.add_argument("--repeat-s", type=int, default=30)
    ap.add_argument("--max-devices", type=int, default=8)
    ap.add_argument("--duration", type=float, default=0.0)
    ap.add_argument("--drop-msg2", type=int, default=0)
    ap.add_argument("--replay", action="store_true")
    ap.add_argument("--keystore", type=Path, default=DEFAULT_KEYSTORE)
    a = ap.parse_args()

    from src.gateway_keystore import load_keystore
    print("=" * 60)
    print("[BRIDGE] GLIDE gateway for Cooja (Fix 2: epoch beacon)")
    print("=" * 60)
    try:
        keystore = load_keystore(a.keystore)
    except Exception as e:
        print(f"[BRIDGE] ERROR loading keystore: {e}")
        sys.exit(1)
    print(f"[BRIDGE] Keystore loaded. Issuer: {keystore.pinned_issuer.issuer_did}")
    print(f"[BRIDGE] epoch {a.epoch_s} s, beacon every {a.repeat_s} s, sheet for {a.max_devices} devices")

    state = EpochState(a.epoch_s, a.max_devices)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("localhost", a.port))
    server.listen(1)
    print(f"[BRIDGE] Listening on localhost:{a.port}. Start the Cooja simulation (speed 100%).")
    conn, addr = server.accept()
    print(f"[BRIDGE] Cooja connected from {addr}")

    def send(line):
        conn.sendall((line + "\n").encode())

    bridge = Bridge(keystore, state, send, epoch_s=a.epoch_s, repeat_s=a.repeat_s,
                    drop_msg2=a.drop_msg2, replay=a.replay)
    try:
        serve(conn, bridge, a.duration)
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        server.close()
    c = bridge.counts
    print()
    print(f"[BRIDGE] accepted {c['accepted']}, retransmissions {c['retransmissions']}, "
          f"refused {c['refused']}, MSG_2 deliberately dropped {c['dropped_msg2']}")
    print(f"[BRIDGE] key check: {bridge.result or 'no KCV received'}")
    sys.exit(0 if bridge.result == "MATCH" else 1)


if __name__ == "__main__":
    main()
'''

NEW["contiki/sim/glide.csc"] = r'''<?xml version="1.0" encoding="UTF-8"?>
<simconf version="2023090101">
  <simulation>
    <title>GLIDE Fix 2: epoch beacon + EDHOC subset, one Cooja native mote</title>
    <speedlimit>1.0</speedlimit>
    <randomseed>123456</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      org.contikios.cooja.radiomediums.UDGM
      <transmitting_range>50.0</transmitting_range>
      <interference_range>100.0</interference_range>
      <success_ratio_tx>1.0</success_ratio_tx>
      <success_ratio_rx>1.0</success_ratio_rx>
    </radiomedium>
    <events>
      <logoutput>40000</logoutput>
    </events>
    <motetype>
      org.contikios.cooja.contikimote.ContikiMoteType
      <description>GLIDE device (device_auth_main.c)</description>
      <source>[CONFIG_DIR]/../device_auth_main.c</source>
      <commands>$(MAKE) -j$(CPUS) device_auth_main.cooja TARGET=cooja</commands>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Battery</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiVib</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRS232</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiBeeper</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRadio</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiButton</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiPIR</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiClock</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiLED</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiCFS</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiEEPROM</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="43.24349378250882" y="87.43681492180366" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>1</id>
        </interface_config>
      </mote>
    </motetype>
  </simulation>
  <plugin>
    org.contikios.cooja.plugins.Visualizer
    <plugin_config>
      <moterelations>true</moterelations>
      <skin>org.contikios.cooja.plugins.skins.IDVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.GridVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.TrafficVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.UDGMVisualizerSkin</skin>
      <viewport>0.9090909090909091 0.0 0.0 0.9090909090909091 154.687732924992 91.51198643472394</viewport>
    </plugin_config>
    <bounds x="1" y="1" height="400" width="400" />
  </plugin>
  <plugin>
    org.contikios.cooja.serialsocket.SerialSocketClient
    <mote_arg>0</mote_arg>
    <plugin_config>
      <host>localhost</host>
      <port>60001</port>
      <bound>true</bound>
    </plugin_config>
    <bounds x="400" y="160" height="120" width="290" z="1" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.TimeLine
    <plugin_config>
      <mote>0</mote>
      <showRadioRXTX />
      <showRadioHW />
      <showLEDs />
      <zoomfactor>500.0</zoomfactor>
    </plugin_config>
    <bounds x="0" y="588" height="166" width="690" z="2" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.Notes
    <plugin_config>
      <notes>Start the bridge first: python -m scripts.cooja_serial_bridge (repo root). This file keeps the speed limit at 100% (real time): the bridge times beacons on the wall clock, the mote on simulated time.</notes>
      <decorations>true</decorations>
    </plugin_config>
    <bounds x="400" y="0" height="160" width="290" z="3" />
  </plugin>
</simconf>
'''

NEW["contiki/test/host/bridge_test.py"] = r'''#!/usr/bin/env python3
"""
bridge_test.py -- scripts/cooja_serial_bridge.py against the REAL device
firmware, without Cooja.

Usage (repo root):  python3 contiki/test/host/bridge_test.py [path/to/contiki-ng]
                    (default contiki-ng path: ../contiki-ng)

Builds device_auth_main.c for Contiki-NG's native target (throwaway
credential made with src/, epoch 10 s, repeat 1 s, ASan/UBSan) and connects it
to the bridge's serve() loop through a socket pair, exactly where Cooja's
Serial Socket would be. Checks:
  T1 the mote authenticates; bridge KCV check = MATCH
  T2 --drop-msg2 1: the mote resends MSG_1, the bridge resends the stored
     MSG_2 (RETRANSMISSION), KCV MATCH
  T3 settings mismatch (bridge repeat 2 s, firmware 1 s) is detected and stops
  T4 --replay: the captured MSG_1 replayed in the same epoch gives no new
     acceptance; after the epoch rolls it is refused (signature_invalid)
and that the session key never appears in mote or bridge output.
Prints verdicts only.
"""
import os, shutil, socket, subprocess, sys, tempfile, threading, time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
CNG = Path(sys.argv[1] if len(sys.argv) > 1 else REPO.parent / "contiki-ng").resolve()
sys.path.insert(0, str(REPO))

import scripts.cooja_serial_bridge as cb                                      # noqa: E402
from scripts.cooja_serial_bridge import Bridge, serve                        # noqa: E402
from src.beacon import EpochState                                            # noqa: E402
from src.cert_info import encode_cert_info                                   # noqa: E402
from src.ecqv_core import (device_derive_private_key, device_generate_contribution,  # noqa: E402
                           issuer_generate_cert, issuer_generate_keypair, point_to_compressed)
from src.gateway_keystore import (Keystore, PinnedIssuer, _compute_q_ca_hash,  # noqa: E402
                                  _generate_gateway_identity)

ISSUER_DID = "did:web:host-test.invalid"
EPOCH_S, REPEAT_S = 10, 1

# Record every session key the gateway derives, so the test can prove that
# none of them ever appears in the mote's or the bridge's output.
KEYS = []
_real_gateway = cb.gateway_process_msg1_build_msg2


def _recording_gateway(*a, **k):
    r = _real_gateway(*a, **k)
    if r.session_key:
        KEYS.append(r.session_key.hex())
    return r


cb.gateway_process_msg1_build_msg2 = _recording_gateway


def carr(n, b):
    return f"#define {n}_LEN {len(b)}\nstatic const uint8_t {n}[{n}_LEN] = {{{', '.join('0x%02x' % x for x in b)}}};\n"


def build(work):
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
    return (src / "build/native/device_auth_main.native") if r.returncode == 0 else None, keystore, r


def run(exe, keystore, *, repeat_s=REPEAT_S, duration, **opts):
    """One mote process wired to one Bridge through a socket pair."""
    gw_end, mote_end = socket.socketpair()
    p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, bufsize=0)
    seen = []

    def to_mote():
        while True:
            try:
                data = mote_end.recv(4096)
            except OSError:
                return
            if not data:
                return
            try:
                p.stdin.write(data); p.stdin.flush()
            except (BrokenPipeError, ValueError):
                return

    def from_mote():
        for line in iter(p.stdout.readline, b""):
            try:
                mote_end.sendall(line)
            except OSError:
                return

    threading.Thread(target=to_mote, daemon=True).start()
    threading.Thread(target=from_mote, daemon=True).start()
    bridge = Bridge(keystore, EpochState(EPOCH_S, 8), lambda l: gw_end.sendall((l + "\n").encode()),
                    epoch_s=EPOCH_S, repeat_s=repeat_s, log=seen.append, **opts)

    stop_when_done = opts.get("replay") is not True
    start = time.monotonic()

    def done():
        if bridge.result == "SETTINGS_MISMATCH":
            return True
        if stop_when_done:
            return bridge.result is not None
        return any("after the epoch rolled" in l for l in seen)

    # serve() in slices so the test can stop as soon as the outcome is known
    while time.monotonic() - start < duration and not done():
        serve(gw_end, bridge, duration=0.5)
    p.kill(); p.wait()
    err = p.stderr.read().decode(errors="replace")
    gw_end.close(); mote_end.close()
    clean = "AddressSanitizer" not in err and "runtime error" not in err
    return bridge, seen, clean


def main() -> int:
    for need in (CNG / "Makefile.include", CNG / "arch/platform/native"):
        if not need.exists():
            print("ABORT: not found:", need); return 1
    work = Path(tempfile.mkdtemp(prefix="glide_bridge_"))
    try:
        exe, keystore, r = build(work)
        print(f"build (native, ASan/UBSan): {'ok' if exe else 'FAILED'}")
        if not exe:
            print((r.stdout + r.stderr)[-2500:]); return 1
        results = {}

        def no_key(seen):
            return bool(KEYS) and not any(k in l for k in KEYS for l in seen)

        b, seen, clean = run(exe, keystore, duration=20)
        results["T1 mote authenticates through the bridge; KCV MATCH"] = (
            b.result == "MATCH" and b.counts["accepted"] == 1 and clean and no_key(seen))

        b, seen, clean = run(exe, keystore, duration=25, drop_msg2=1)
        results["T2 --drop-msg2 1: mote resends, stored MSG_2 resent, KCV MATCH"] = (
            b.result == "MATCH" and b.counts["dropped_msg2"] == 1
            and b.counts["retransmissions"] >= 1 and b.counts["accepted"] == 1 and clean and no_key(seen))

        b, seen, clean = run(exe, keystore, duration=10, repeat_s=2)
        results["T3 settings mismatch detected; bridge stops"] = b.result == "SETTINGS_MISMATCH" and clean

        b, seen, clean = run(exe, keystore, duration=EPOCH_S + 15, replay=True)
        same = [l for l in seen if l.startswith("[REPLAY]   ->")]
        after = [l for l in seen if "after the epoch rolled" in l]
        results["T4 --replay: no new acceptance in-epoch; signature_invalid after rollover"] = (
            b.result == "MATCH" and bool(same) and "new acceptance: no" in same[0]
            and bool(after) and "signature_invalid" in after[0] and "new acceptance: no" in after[0]
            and clean and no_key(seen))

        for label, ok in results.items():
            print(f"  [{'ok ' if ok else 'BAD'}] {label}")
        good = all(results.values())
        print("bridge <-> device firmware (native), ASan/UBSan clean:", "ALL PASS" if good else "FAILURES")
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
    p = ROOT / BRIDGE
    if not p.exists():
        print(f"ABORT: {BRIDGE} not found (run from the repo root)")
        return 1
    old = p.read_text()
    if "class Bridge" in old:
        print("ABORT: edits already applied (the bridge already has class Bridge).")
        return 1
    bad = []
    ok = all(m in old for m in MARKERS)
    print(f"  [{'ok ' if ok else 'BAD'}] {BRIDGE}: replace whole file  (old-version markers {'found' if ok else 'MISSING'})")
    if not ok:
        bad.append(BRIDGE)
    for f in NEW:
        absent = not (ROOT / f).exists()
        print(f"  [{'ok ' if absent else 'BAD'}] {f}: new file  ({'absent' if absent else 'ALREADY EXISTS'})")
        if not absent:
            bad.append(f)
    if bad:
        print(f"\nABORT: {len(bad)} check(s) failed; NOTHING was written.")
        return 1
    if mode == "--diff":
        if not only or BRIDGE in only:
            sys.stdout.writelines(difflib.unified_diff(
                old.splitlines(True), BRIDGE_NEW.splitlines(True),
                fromfile=f"a/{BRIDGE}", tofile=f"b/{BRIDGE}"))
        for f, text in NEW.items():
            if not only or f in only:
                sys.stdout.writelines(difflib.unified_diff(
                    [], text.splitlines(True), fromfile="/dev/null", tofile=f"b/{f}"))
        print("\n(diff only: nothing written)")
        return 0
    p.write_text(BRIDGE_NEW)
    print(f"  wrote {BRIDGE}")
    for f, text in NEW.items():
        (ROOT / f).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / f).write_text(text)
        print(f"  wrote {f}")
    print("\nApplied. Next: python3 contiki/test/host/bridge_test.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
