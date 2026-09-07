# Threat Model and Security Analysis

**Architectural note:** The implementation exposes only `bootstrap_pinned()`
as a public API; trust-on-first-use is not a callable function. This is a
deliberate design decision (see `docs/DESIGN_DECISIONS.md` DD-001) to
eliminate the possibility of accidentally downgrading to insecure first-use
trust. `bootstrap_mode` is restricted to `"pinned"` at load time.

**Why not mutual TLS with X.509?** An obvious alternative for the bootstrap
layer is mTLS with a pre-installed root CA cert. We reject this because it
reintroduces exactly what our device-layer architecture eliminates: X.509
certificate chains, CA-based trust hierarchies, and a single-point-of-failure
root CA. A reviewer tracing our architecture should see: constrained devices
use implicit certificates (no CA runtime trust), gateways verify via
reconstructed public keys (no signature chain), issuers publish via DID
documents (no CA issuance chain). Inserting X.509 at the gateway's bootstrap
layer would collapse this narrative at the most critical trust point. We
document this as future work for deployments that have existing X.509
infrastructure they wish to leverage, but our architectural commitment is
to not require it.

---

## 1. System Overview

The system authenticates resource-constrained IoT devices to gateways using
two-pass L-ECQV implicit certificates anchored in a dual-DID trust model.
Four actors participate:

- **Device**: constrained IoT node holding an L-ECQV credential and its derived
  private key `d`. Identified by a `did:key` derived from its public key. The
  device also holds the gateway's long-term public key `Q_gw`, compiled into
  firmware at provisioning.
- **Issuer (CA)**: trusted authority that issues implicit certificates.
  Identified by a `did:web` DID whose document contains the issuer's public
  key `Q_ca` in JWK format.
- **Gateway**: semi-trusted verifier. Bootstraps by fetching the issuer's DID
  document and verifying its public key against a pre-configured hash, pins
  that key, and thereafter verifies devices offline.
- **DID Registry**: HTTPS server hosting the issuer's DID document and a
  revocation list.

Trust anchors:
- The gateway trusts only a `Q_ca` whose SHA-256 hash matches the
  pre-configured expected value supplied out of band at deployment. There is
  no first-use trust path (DD-001).
- Devices trust the `d` they derive during provisioning, assuming the issuer
  honestly produced `(R, s)` and the provisioning channel was authenticated
  (see A2).
- Devices trust the `Q_gw` compiled into their firmware. There is no runtime
  path by which a device can learn that this key has been compromised
  (see A5).

## 2. Adversary Model

We adopt a **computational Dolev-Yao adversary** with the following capabilities:

- **Network control**: the adversary can read, modify, drop, inject, reorder,
  and replay any message on any link between Device, Issuer, Gateway, and
  Registry.
- **Cryptographic limits**: the adversary is computationally bounded. It cannot
  break SHA-256 collision resistance, the elliptic curve discrete log problem
  over P-256, or ECDSA signature unforgeability.
- **Corruption**: the adversary may statically corrupt at most one of:
  - Any number of Devices (other than the one under attack)
  - The Gateway (but not the Issuer concurrently)
  - The Issuer (but not the Gateway concurrently)

Static corruption means: the adversary fixes who is corrupted before the
protocol starts. Adaptive corruption is out of scope for this analysis.

The formal model additionally permits **long-term key reveal**, used to
establish forward secrecy (G7).

### Explicit non-goals

- **Post-quantum security**: P-256 is broken by a sufficiently large quantum
  computer. This work assumes classical adversaries only.
- **Side-channel resistance**: timing attacks, power analysis, and fault
  injection on the device are out of scope. We assume the device environment
  resists physical attack.
- **Denial of service**: the adversary may drop messages, but protecting
  availability is not a goal of this work.
- **Privacy / unlinkability**: devices reveal a stable `did:key` across sessions.
  Unlinkable authentication is future work.

## 3. Security Goals

The protocol aims to achieve the following properties against the adversary
defined above. Each goal notes whether it is established by formal
verification, by informal argument, or not achieved.

### G1: Device Authentication — VERIFIED
Only a device holding a valid `(d, R, cert_info)` tuple issued by the honest
issuer can successfully authenticate to the gateway.
*Tamarin: `Gateway_Authenticates_Device` (all-traces, 21 steps).*

### G2: Credential Integrity — VERIFIED
An adversary that modifies `R` or `cert_info` in transit cannot cause the
gateway to accept authentication from the affected device.
*Tamarin: `Gateway_Authenticates_Device_Origin` (all-traces, 13 steps).*

### G3: No Key Escrow — ARGUED
The issuer, given its view `{U, R, s, k_ca, k, cert_info}` during provisioning,
cannot compute the device's private key `d`. This requires that `u` never
leaves the device. Established by the argument in §4, not by the formal model.

### G4: Replay Resistance — NOT ACHIEVED
Goal: a recorded authentication transcript cannot be replayed. The two-message
design does not meet this goal — it carries no gateway-contributed freshness,
so a recorded MSG_1 replays within the credential validity window.
*Tamarin: `Gateway_Replay_Possible` (exists-trace, 22 steps) — an existence
lemma documenting the limitation, not a property claimed.* Replay does not
compromise the session key (G8). See A3.

### G5: Revocation Completeness — ARGUED
A device revoked at time `T` is rejected by the gateway for all authentication
attempts at times `T' > T + Δ`, where `Δ` is the bounded revocation sync
window determined by the sync interval `I` and grace window `G`.

**Default parameters:** `I = 60s`, `G = 300s`, yielding a worst-case
exposure window of `I + G = 360s` (6 minutes) before the gateway fails closed.
Under active adversarial conditions — specifically, a network-position
adversary selectively blocking G↔Registry traffic — the gateway is forced into
GRACE state deliberately, extending the exposure window to the full
`I + G = 360s` ceiling before fail-closed OFFLINE behaviour activates. This
represents the adversarially-achievable worst case; **the nominal
(non-adversarial) bound is `I = 60s`.**

The 60-second sync interval balances registry load (approximately 17 req/s
for a population of 1000 gateways) against revocation freshness. The
5-minute grace window tolerates transient network partitions typical of
LPWAN deployments without prematurely denying service. Both values are
configurable in `revocation_sync.py`.

This bound is analytical. The G↔Registry channel is not represented in the
Tamarin model, so G5 is argued rather than machine-checked. Formalising it is
future work.

### G6: Offline-Capable Verification — ARGUED
After a single pinned bootstrap, the gateway can verify device authentications
without contacting the issuer or registry, subject to the revocation freshness
window.

### G7: Forward Secrecy — VERIFIED
Compromise of a long-term key does not expose session keys established before
the compromise.
*Tamarin: `Forward_Secrecy_Device` (all-traces, 11 steps),
`Forward_Secrecy_Gateway` (all-traces, 27 steps), both under long-term key
reveal.*

### G8: Session Key Secrecy and Agreement — VERIFIED
The session key is not learnable by the adversary, and both parties derive the
same key.
*Tamarin: `Session_Key_Secrecy` (all-traces, 38 steps);
`Session_Key_Agreement` (all-traces, 10 steps).*

> **Note on G8 scope.** `Session_Key_Agreement` establishes determinism at a
> single party — that a given party derives one key and not two. Cross-party
> agreement is established by `Device_Authenticates_Gateway` via the shared
> `sk` term. These are deliberately separate claims and should not be
> conflated.

### G9: Gateway Authentication — VERIFIED
A device accepts a response only from the gateway whose long-term key it was
provisioned with.
*Tamarin: `Device_Authenticates_Gateway` (all-traces, 7 steps).*

### G10: Gateway Addressing — VERIFIED (after correction)
A first message addressed to one gateway is not accepted by a different
gateway pinning the same issuer. See §5, A7 — this goal was added after formal
analysis falsified G1 in its original form.

## 4. Informal Security Arguments

### G1 (Authentication) — Sketch
The device signs `(E_d ‖ R ‖ cert_info ‖ n_d ‖ Q_gw)` with its long-term key
`d`, where `n_d` is a device-generated nonce and `Q_gw` is the pre-provisioned
gateway public key. Given the reconstruction identity `d·G = e·R + Q_ca`, a
valid signature verifies under the gateway's reconstructed `Q_dev` only if the
signer possesses `d`. Under ECDSA's EUF-CMA assumption on P-256, no
polynomial-time adversary can forge such a signature without `d`.

Forging `d` for a new `(R, s, cert_info)` requires either: (i) knowing `k_ca`
to compute a valid `s`, which contradicts the issuer honesty assumption and
ECDL hardness, or (ii) finding `(u', R', s')` such that the device's signature
under `d' = e'·u' + s'` verifies under the same pinned `Q_ca`, which reduces
to forging ECDSA signatures.

Note that `Q_gw` appears in the signed payload but is **not transmitted** —
both parties hold it already. Its inclusion costs nothing on the wire and is
what establishes G10 (see A7).

### G2 (Integrity of `R` and `cert_info`) — Sketch
Both values are inputs to the hash `e = H(R ‖ cert_info)`. Any modification
changes `e`, which changes the reconstructed `Q_dev = e·R + Q_ca`. The device's
signature, produced with `d` derived from the original values, will not verify
under the tampered reconstruction. By collision resistance of SHA-256, an
adversary cannot find alternative `(R', cert_info')` yielding the same `e`.

### G2' (Integrity of `s`) — Transitive
`s` does not appear in the gateway's reconstruction formula. Its integrity is
guaranteed **transitively**: if `s` is tampered in transit, the device derives
an incorrect `d`, and its subsequent signatures fail to verify against the
correctly-reconstructed `Q_dev`. An adversary cannot produce a tampered
`s'` that yields a signing-capable `d'` without knowing `k_ca`.

### G3 (No Key Escrow) — Argument
Issuer's view: `{U, R, s, k_ca, k, cert_info}`. Device's `d = e·u + s`. The
issuer knows `s` and `cert_info`, so can compute `e`. It does not know `u`.
Deriving `u` from `U = u·G` requires solving ECDL on P-256, which is
computationally infeasible. Therefore the issuer cannot compute `d`.

### G4 (Replay Resistance) — Not Met
An earlier challenge-response design (gateway issues nonce `n`, device signs
it) would have resisted replay at the cost of a third message. The implemented
two-message protocol has no gateway challenge: the device generates its own
nonce and the gateway stores no seen nonces, so a captured MSG_1 replays
successfully. Impact is bounded to gateway-side resource use and to the
gateway's inability to establish liveness; session-key secrecy holds (G8,
Tamarin verified). A gateway-side nonce cache would bound exact replays
without adding a message, and is identified as future work.

### G5 (Revocation Completeness) — Conditional
Under the ONLINE state (last sync within interval `I`), the gateway has a
revocation list at most `I` seconds stale. A device revoked at time `T` is
rejected by `T + I`.

Under GRACE state (sync failed but within grace window `G`), the gateway
continues to operate with stale revocation data, which may accept a device
revoked during the gap. This is a documented trade-off for availability;
operators choosing smaller `G` get tighter bounds at cost of higher rejection
rates under transient network failures.

Under OFFLINE state (grace exceeded), the gateway fails closed — all
authentication is rejected until sync is restored.

### G6 (Offline Verification) — Argument
After pinned bootstrap, the gateway holds `Q_ca` locally. Reconstruction
`Q_dev = e·R + Q_ca` and signature verification are purely local computations.
The only external dependency is revocation freshness (G5).

## 5. Attack Scenarios and Mitigations

### A1: Network eavesdropping during provisioning
**Threat**: Adversary observes `(U, R, s, cert_info)` in transit.
**Impact**: None. `U` and `R` are public; `s` is integrity-bound transitively
via signature verification. Without `u` (never transmitted) or `k_ca`, the
adversary cannot derive or forge `d`.

### A2: Active MITM during provisioning
**Threat**: Adversary modifies `U`, `R`, `s`, or `cert_info` in transit
during provisioning.

**Impact and mitigations**:
- **Modifying `U`** → device derives unrelated `d`; binding to the intended
  `cert_info` holder is broken.
- **Modifying `R` or `cert_info`** → G2 applies; the device's signatures,
  produced using `d` derived from the original values, fail verification
  against the tampered reconstruction at the gateway.
- **Modifying `s`** → G2' (transitive integrity) applies; the device derives
  an incorrect `d` and its signatures fail verification.

**Deployment assumption (provisioning channel)**: The protocol assumes
provisioning occurs over an authenticated out-of-band channel — specifically
**factory provisioning over a wired connection during device manufacturing**.
In our Cooja simulation, this is modelled by pre-loading the device's
credentials `(d, R, cert_info)` and the gateway public key `Q_gw` into the
mote firmware at compile time, equivalent to post-manufacturing flashing over
a physically-controlled production line network. This matches real-world
constrained-IoT deployment practice (e.g. Zigbee, Matter, Philips Hue), where
cryptographic material is installed before a device ships and never
re-provisioned over an untrusted network. Network-layer enrolment protocols
with mutual authentication (e.g. EAP-based enrolment, pre-shared-key
handshakes) are architecturally compatible with our design but out of scope
for this work.

### A3: Replay of captured authentication transcript
**Threat**: Adversary records a valid authentication and replays it.
**Status**: NOT MITIGATED. Replay succeeds within the credential validity
window (see G4). Bounded to resource consumption and loss of liveness
guarantee; the session key differs on each run and stays secret (G8).

### A4: Rogue DID document on first contact
**Threat**: An adversary controls the network on the gateway's first fetch
of the issuer's DID document and serves an impostor `Q_ca`.

**Status**: MITIGATED BY DESIGN (DD-001). The gateway does not pin whatever
key it first sees. The operator pre-loads the expected SHA-256 hash of the
issuer's public key `Q_ca` into the gateway's configuration before first
contact with the registry. On bootstrap, the gateway fetches the DID document,
computes the hash of the embedded public key, and compares against the
pre-configured expected hash. A mismatch aborts bootstrap; no pinning occurs.

Trust-on-first-use was considered and **removed from the implementation**
rather than documented as a limitation: exposing it as a callable path creates
the risk that an operator defaults to it for convenience. `bootstrap_mode` is
restricted to `"pinned"` at load time, making the insecure path
architecturally unreachable.

This places the trust anchor at an operational provisioning step rather than
at network first-contact, consistent with standard IoT deployment practice
(e.g. Zigbee network keys distributed via physical touchlink or manufacturer
installation codes).

**Architectural alternatives** (out of scope but compatible):
- Certificate Transparency logs for public auditability of issuer keys
- DNSSEC-signed did:web URLs leveraging existing internet infrastructure
- Blockchain-anchored DID documents for decentralised verification

### A5: Compromised gateway
**Threat**: Gateway is corrupted; attacker reads all gateway state including
the pinned `Q_ca` and the gateway's own long-term private key `k_gw`.

**Impact**:
- The attacker can **impersonate the gateway** to any device provisioned with
  the corresponding `Q_gw`, since it holds the signing key for MSG_2.
- The attacker controls verification and can accept devices it should reject,
  or reject valid devices (denial of service, out of scope).
- The attacker learns the session key for any session it participates in.

**Bounds on impact**:
- The attacker **cannot forge credentials** for new devices without `k_ca`,
  which is held only by the offline issuer.
- The attacker **cannot recover device private keys**; `d` never leaves the
  device.
- The attacker **cannot decrypt sessions established before the compromise**
  (G7, forward secrecy under long-term key reveal, Tamarin verified).

**Detection**: none at the device. `Q_gw` is compiled into firmware and there
is no revocation path for gateway keys, no device-side clock, and no second
opinion available to the device. A compromised gateway is indistinguishable
from a healthy one from the device's perspective. This is a known limitation;
gateway key rotation and gateway attestation are identified as future work.

The gateway is inside the trust boundary by construction — it holds the
verification state the device cannot.

### A6: Revocation bypass during GRACE window
**Threat**: A device is revoked at `T`, network partition begins at `T - ε`,
gateway remains in GRACE state until `T + G - ε`.
**Impact**: During the interval `(T, T + G - ε)`, the gateway accepts the
revoked device.
**Mitigation**: `G` is configurable; operators set it based on acceptable
exposure window. A network-position adversary can induce this state
deliberately, which is why 360s is stated as the adversarial ceiling in G5.

### A7: Cross-gateway relay
**Threat**: An adversary captures a MSG_1 addressed to gateway A and replays
it unchanged to gateway B, where B pins the same issuer.

**Status**: FOUND BY FORMAL ANALYSIS, MITIGATED.

In the original design the device signature covered
`(E_d ‖ R ‖ cert_info ‖ n_d)` — it did not commit to the identity of the
intended gateway. Any gateway pinning the same issuer would therefore accept
a message addressed to a different gateway. This is a relay, distinct from the
same-gateway replay of A3, and it was **not anticipated by informal threat
modelling**. Tamarin falsified `Gateway_Authenticates_Device` with a
counterexample trace at 12 steps.

**Mitigation**: the gateway's long-term public key `Q_gw` is bound into the
device's signed payload, which becomes
`(E_d ‖ R ‖ cert_info ‖ n_d ‖ Q_gw)`. Gateway B reconstructs the signing
payload using **its own** `Q_gw`, the signature fails to verify, and the
relayed message is rejected. Applied across all three layers: the Tamarin
model, `src/edhoc_subset.py`, and `contiki/device_auth.c`.

`Gateway_Authenticates_Device` re-verifies at 21 steps. The measured cost is
**64 bytes of ROM and zero bytes on the wire**, because both parties already
hold `Q_gw` from provisioning.

**Deployment precondition**: this mitigation is sound only if each gateway
holds a **distinct** long-term keypair. If an operator deploys the same
gateway key across multiple sites, the relay returns — and the Tamarin model
would not detect it, because it never constructs that configuration. This is
stated as a deployment requirement, not a protocol property.

## 6. Limitations and Future Work

### Formal model scope
The Tamarin model (v1.12.0, verified under Maude 3.5.1 and 3.2 with identical
verdicts and step counts) covers the D↔G communication channel. The adversary
controls all messages between Device and Gateway. Ten lemmas are analysed:
seven all-traces properties, all verified, and three exists-trace lemmas —
`Executability` and `sanity_gateway_reachable` as vacuity guards, and
`Gateway_Replay_Possible` documenting the limitation in G4.

Not covered by the formal model:
- The **provisioning phase** (`Issuer_Setup`, `Issuer_Provision_Device`) and
  gateway bootstrap (`!GatewayPinnedIssuer`, `!IssuerKey`) are modelled as
  trusted setup outside adversary reach — consistent with the
  factory-provisioning and pinned-bootstrap assumptions in A2 and A4.
- The **G↔Registry channel** (revocation sync). Its properties are argued
  separately in G5 and A6.
- **Implementation-level behaviour.** The model reasons about the protocol as
  specified, not the C or Python as written. Memory-safety faults, encoder
  bugs, and side channels are outside its scope; the 166-test corpus covers a
  different failure class.

### Explicit scope limitations
- **Adaptive corruption** is out of scope; only static corruption is
  considered, alongside the long-term key reveal used for G7.
- **Privacy (unlinkability)** is not addressed. Devices present a stable
  public key across all authentication sessions, permitting correlation
  by a passive observer. Unlinkable variants (e.g. verifiable credentials
  with selective disclosure) are future work.
- **Post-quantum migration** is discussed architecturally but not
  implemented. P-256 is broken by Shor's algorithm on a sufficiently
  large quantum computer. Migration to post-quantum signatures (e.g.
  CRYSTALS-Dilithium) is compatible with the ECQV structure.
- **Denial of service resistance** is not addressed. Check ordering
  (cheapest-first, no elliptic-curve work on malformed input) limits the cost
  of invalid messages, but there is no rate limiting and DoS is not modelled.

### Implementation-specific limitations
- **Gateway key rotation** is not implemented. `Q_gw` is compiled into device
  firmware, which is what removes runtime resolution but binds each device to
  exactly one gateway. Rotation or roaming currently requires reflashing.
  A provisioned update path, or a small set of authorised gateway keys, is
  future work.
- **Issuer key rotation** is not implemented. Rotating `k_ca` requires the
  gateway to re-execute pinned bootstrap against the new `Q_ca`. Concurrent
  old-and-new key validity during rotation is future work.
- **Multi-issuer federation** is out of scope. Each gateway pins exactly
  one issuer.
- **Persistent revocation storage** is not implemented. The registry holds
  revocation entries in volatile memory; entries are lost on server
  restart. Production deployments require durable storage with periodic
  signed snapshots for integrity.
- **HSM protection of `k_ca`** is not implemented. The issuer's private
  key is stored in a plaintext JSON file (`issuer_key.json`) with POSIX
  0600 permissions. Production deployments require PKCS#11, TPM, or
  equivalent hardware-backed key protection.
- **Clock synchronisation** between devices and gateways is assumed. The
  `cert_info.issued_at + max_age` field is evaluated against the gateway's
  local clock. Drifted clocks may reject valid credentials or accept expired
  ones. NTP or equivalent is a deployment assumption.
- **Side-channel resistance** of the device-side ECQV implementation is
  not evaluated. Timing attacks, power analysis, and fault injection on
  the constrained device are out of scope; we assume the device enclosure
  provides physical protection.
- **No physical hardware validation.** All measurements are from compiled
  binaries and simulation. No energy or wall-clock latency figure is claimed.
