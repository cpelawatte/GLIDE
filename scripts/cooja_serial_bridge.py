#!/usr/bin/env python3
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
