# GLIDE: ICAC 2026 camera-ready artefacts

Code, Tamarin model and measurement evidence for the paper
"GLIDE: Gateway-Assisted Lightweight Implicit-Certificate Authentication with
Ledger-Free Decentralised Identifiers for Constrained IoT Devices",
8th IEEE International Conference on Advancements in Computing (ICAC 2026).

**Use the tag `icac-camera-ready`.** Other branches in this repository hold later
work for a journal extension; their figures differ from the paper.

## What this version contains

The protocol as described in the paper. The gateway public key `Q_gw` is bound
into the device signature (cross-gateway relay fix) in the Python reference
implementation (`src/edhoc_subset.py`), the firmware (`contiki/device_auth.c`)
and the Tamarin model. The model also contains a replay lemma, `No_Replay`.
The firmware draws the device nonce `n_d` from micro-ecc's RNG, the same source as
the ephemeral key; the submitted firmware used a fixed pattern. Relative to the
submitted version (tag `icatc-submission`), these are the only protocol, model and
firmware changes; the rest is cleanup.

## Reproduce every figure (one command)

    git clone https://github.com/cpelawatte/GLIDE.git && cd GLIDE
    git checkout icac-camera-ready
    python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt
    CONTIKI_NG_PATH=/path/to/contiki-ng MAUDE=/path/to/maude bash reproduce_icac.sh

Raw outputs are written to `evidence/<timestamp>/`. Toolchain used for the
evidence below: Python 3.12.3, arm-none-eabi-gcc 13.2.1, Contiki-NG `bd08e3273`
(with submodules, for micro-ecc; three `LOG_DBG` lines in `os/lib/random.c` were
removed locally because they do not compile with gcc 13, with no functional effect), Tamarin 1.12.0, Maude 3.5.1. Optional:
`MAUDE_ALT=/path/to/second/maude` repeats the Tamarin run with a second engine.

## Expected results (measured at commit `b6b11a0`)

| Quantity | Value |
|---|---|
| Credential (R 33 B + cert_info 66 B, issuer `did:web:issuer.example`) | 99 B |
| MSG_1 / MSG_2 / handshake | 231 / 126 / 357 B |
| Python test suite (host) | 166 passed |
| CC2538 full image, ROM (text) / RAM (data + bss) | 79,960 / 16,117 B |
| CC2538 protocol-isolated image, ROM / RAM | 64,403 / 9,963 B |

| Lemma | Type | Result | Steps | Meaning |
|---|---|---|---|---|
| Executability | exists-trace | verified | 14 | honest run completes |
| sanity_gateway_reachable | exists-trace | verified | 12 | gateway acceptance reachable |
| Gateway_Authenticates_Device_Origin | all-traces | verified | 13 | G1: accepted credentials were issued |
| Device_Authenticates_Gateway | all-traces | verified | 6 | device accepts only the genuine gateway |
| Session_Key_Agreement | all-traces | verified | 10 | key determinism at one party |
| Session_Key_Secrecy | all-traces | verified | 34 | session keys stay secret |
| Gateway_Authenticates_Device | all-traces | verified | 18 | addressed-gateway agreement (relay fixed) |
| Gateway_Replay_Possible | exists-trace | verified | 23 | reachability: two acceptances of one device |
| No_Replay | all-traces | falsified | 21 | replay is possible (G4 not achieved) |

## Evidence in this tag

- `evidence/20261026_072618/`: camera-ready run (commit `b6b11a0`), all figures above.
- `evidence/20261026_064729/`: run before the nonce fix (commit `34c5009`); identical
  except ROM 79,952 / 64,387 B. The relay fix alone costs +64 B over the submitted
  version; the nonce fix adds +8 B (full) and +16 B (isolated).
- `evidence/control_icatc-submission_20261026_060049/`: the same script on the
  submitted version (tag `icatc-submission`). It reproduces every figure in the
  submitted paper, including the relay lemma falsified at 12 steps, 165 tests and
  ROM 79,888 / 64,323 B.

The tagged commit adds only this README and evidence files to `b6b11a0`.

## Cooja handshake (simulation)

    cp contiki/sim/gateway_keystore.sim.json gateway_keystore.json   # simulation-only keys
    python -m scripts.cooja_serial_bridge                            # terminal 1, repo root
    cd /path/to/contiki-ng/tools/cooja && ./gradlew run              # terminal 2: open contiki/sim/glide.csc, Start

The bridge runs the Python gateway; the Cooja mote runs `device_auth_main.c` with the
credentials in `contiki/credentials.h`. A successful run shows the gateway accepting
MSG_1 and both sides deriving the same session key. Because the gateway verifies the
device signature over `E_d || R || cert_info || nonce_d || Q_gw`, a successful
handshake also confirms that the firmware binds `Q_gw`. The embedded credential uses
the local demo issuer `did:web:127.0.0.1%3A5000`, so MSG_1 is 233 B in this run; the
paper's 231 B uses the benchmark issuer. Evidence: `evidence/cooja_20261026_final/`
(two runs: fresh nonces, matching session keys). `evidence/cooja_20261026_pre-nonce-fix/`
shows the earlier fixed nonce.

## Notes

- Firmware: `device_auth_main_footprint.c` is the CC2538 build measured above;
  `device_auth_main.c` runs in Cooja (Sky mote). Both use the same protocol code
  (`device_auth.c`, `hkdf_sha256.c`, `sha256_impl.c`). `device_auth_main_cc2538.c`
  is not used for any reported figure.
- `contiki/credentials.h` holds simulation-only keys, including a device private
  key. Do not reuse them. Its embedded cert_info is 68 B; the paper's size figures
  use the 66 B benchmark credential from the Python tests.
- The full image uses IPv6 with null routing (no RPL); the isolated image uses NullNet.
- Model assumptions: ECQV is abstracted as issuer attestation; each gateway holds
  its own key pair (the relay binding depends on this); forward secrecy and
  revocation are not modelled.
- Known limitations: replay is not prevented; the revocation list is not signed in
  this prototype; the gateway keeps no session state, so revocation affects new
  authentications only; results come from compilation and simulation, not
  physical hardware.
- Maude 3.2: the optional cross-check gives identical results, but Tamarin 1.12.0
  reports 3.2 as unsupported.
- The script's "rejection keyword" line is a sanity check on test names, not a
  reported figure.
- `docs/` holds development notes. Where they differ from this README, the README
  is authoritative.
