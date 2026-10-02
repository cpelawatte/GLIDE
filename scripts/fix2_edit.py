"""Fix 2 (epoch beacon): edit a copy of the Fix 5 Tamarin model.

usage:  python fix2_edit.py after  <model.spthy>    full Fix 2 model (rules + lemmas + header fixes)
        python fix2_edit.py before <model.spthy>    Fix 5 model + only the No_Replay lemma (the 'before' run)

Every target must match exactly once or NOTHING is written."""
import re, sys
from pathlib import Path

mode, path = sys.argv[1], sys.argv[2]
s = Path(path).read_text()

def flex(lit):
    """literal text, but any run of whitespace matches any run of whitespace"""
    return r"\s+".join(re.escape(p) for p in lit.split())

def sub1(old, new):
    global s
    s2, n = re.subn(flex(old), lambda m: new, s)
    if n != 1:
        raise SystemExit(f"ABORT, nothing written. expected 1 match, found {n} for:\n{old[:150]!r}")
    s = s2

NO_REPLAY = '''
/*
 * Strict replay -- the before/after lemma of Fix 2.
 * "No trace exists in which ONE device send (and no other send to this
 * gateway) leads the same gateway to accept the same device twice."
 * Unlike Gateway_Replay_Possible, honest re-authentication (two sends)
 * does NOT satisfy this, so it isolates genuine replay.
 * Key theft is excluded: a stolen key can forge fresh messages, which is
 * not replay.  Before Fix 2 this lemma is FALSIFIED (the counterexample is
 * the replay attack); after Fix 2 it is VERIFIED.
 */
lemma No_Replay:
    "not (Ex G Q sk1 sk2 D msg1 n E #i1 #i2 #j.
            GatewayAuthenticatedDevice(G, Q, sk1) @i1
          & GatewayAuthenticatedDevice(G, Q, sk2) @i2
          & not(#i1 = #i2)
          & DeviceSentMSG1(D, G, msg1, n, E) @j
          & #j < #i1 & #j < #i2
          & (All D2 m2 n2 E2 #k.
                DeviceSentMSG1(D2, G, m2, n2, E2) @k ==> #k = #j)
          & not (Ex #rv. RevealedKey(Q) @rv))"
'''

def append_before_end(block):
    global s
    body = s.rstrip()
    if not body.endswith("end"):
        raise SystemExit("ABORT, nothing written. file does not end with 'end'")
    s = body[:-3].rstrip() + "\n" + block + "\nend\n"

if mode == "before":
    if "lemma No_Replay" in s:
        raise SystemExit("ABORT, nothing written. No_Replay already present")
    append_before_end(NO_REPLAY)
    Path(path).write_text(s)
    print("OK: 'before' model written (Fix 5 model + No_Replay)")
    sys.exit(0)

assert mode == "after"
if "GwEpoch" in s:
    raise SystemExit("ABORT, nothing written. this file already contains Fix 2 edits")

# ---------------- header comments that are stale or contradict the paper ----------------
sub1(''' * SCOPE: This model verifies the mutual authentication property and
 * session-key agreement. Secrecy is now modeled (Session_Key_Secrecy).
 * Forward secrecy and DoS resistance are future work. See
 * ban_logic_analysis.md for informal reasoning on those properties.''',
''' * SCOPE (Fix 2 model, GLIDE-Access): gateway-side authentication of the
 * device (with injective agreement and recentness, via the epoch beacon),
 * device-side authentication of the gateway, session-key agreement and
 * secrecy, forward secrecy against long-term key reveal, and key-compromise
 * impersonation (KCI). GLIDE does NOT claim mutual authentication in the
 * explicit-key-confirmation sense (no MSG_3). Denial of service is not
 * modeled: Tamarin proves safety properties, not availability.''')
sub1(''' *    itself, which is outside the scope of this work and assumed correct
 *    per the informal BAN-logic analysis.''',
''' *    itself, which is outside the scope of this work. ECQV is relied on
 *    through its standard (SEC 4) and its security reduction (Brown,
 *    Gallant and Vanstone, 2001).''')
sub1('functions: cert_info/3  /* cert_info(issuer_did, timestamp, max_age) */',
     'functions: cert_info/3  /* opaque; real encoding (Fix 7): issuer_id(4 B) | issued_at(uint32) | max_age(uint16, hours) */')

# ---------------- Gateway_Bootstrap: first epoch ----------------
sub1('''[ !IssuerPubKey($I, Q_ca)
    , Fr(~gw_key)
    ]
  --[ GatewayBootstrap($G, $I, Q_ca) ]->''',
'''[ !IssuerPubKey($I, Q_ca)
    , Fr(~gw_key)
    , Fr(~r0)                      /* first epoch's beacon value (Fix 2) */
    ]
  --[ GatewayBootstrap($G, $I, Q_ca)
    , EpochStart($G, ~r0)
    ]->''')
sub1(''', Out(pk(~gw_key))   /* gateway public key is public */
    ]''',
''', Out(pk(~gw_key))   /* gateway public key is public */
    , GwEpoch($G, ~gw_key, ~r0)    /* progress through epochs: linear, one at a time, used ONLY by Gateway_New_Epoch */
    , !GwEp($G, ~gw_key, ~r0)      /* an epoch value that exists: persistent, read by the receive rule */
    , Out(~r0)                     /* the beacon value is public once announced */
    ]''')

# ---------------- new rule: Gateway_New_Epoch ----------------
sub1('/* Device is provisioned with gateway public key */',
'''/* Fix 2: the bell rings. The gateway ends the current epoch, picks a fresh
 * random value and announces it. The strict rule (decision 5: an ended epoch
 * is never accepted again) is the Epoch_Is_Current restriction below, and the
 * per-epoch nonce sheet is Nonce_Sheet_Once_Per_Epoch: it is keyed by the
 * epoch value, so a new epoch starts with an empty sheet. */
rule Gateway_New_Epoch:
    [ GwEpoch($G, ~gw_key, ~r_old)
    , Fr(~r_new)
    ]
  --[ EpochEnd($G, ~r_old)
    , EpochStart($G, ~r_new)
    ]->
    [ GwEpoch($G, ~gw_key, ~r_new)
    , !GwEp($G, ~gw_key, ~r_new)
    , Out(~r_new)
    ]

/* Device is provisioned with gateway public key */''')

# ---------------- Device_Send_MSG1: read a beacon, sign it ----------------
sub1('payload = <E_d, ~R, Q_dev, ci, ~nonce_d, Q_gw>',
     'payload = <E_d, ~R, Q_dev, ci, ~nonce_d, Q_gw, br>')
sub1(''', !DeviceGWKey($D, $G, Q_gw)
    , Fr(~xed)''',
''', !DeviceGWKey($D, $G, Q_gw)
    , In(br)                       /* any beacon the network hands the device; it does not check it (decision 2) */
    , Fr(~xed)''')
sub1('--[ DeviceSentMSG1($D, $G, msg1, ~nonce_d, E_d) ]->',
'''--[ DeviceSentMSG1($D, $G, msg1, ~nonce_d, E_d)
    , DeviceSignedBeacon($D, $G, ~nonce_d, br)
    ]->''')

# ---------------- Gateway_Recv_MSG1_Send_MSG2: check against its OWN epoch value ----------------
sub1('payload = <E_d, R, Q_dev, ci, nonce_d, pk(~gw_key)>',
     'payload = <E_d, R, Q_dev, ci, nonce_d, pk(~gw_key), ~ep>')
sub1(''', !GatewayPinnedIssuer($G, $I, Q_ca)
    , In(<E_d, R, Q_dev, cert_sig, ci, nonce_d, sig_d>)''',
''', !GatewayPinnedIssuer($G, $I, Q_ca)
    , !GwEp($G, ~gw_key, ~ep)       /* the gateway's OWN epoch value; nothing from the message is trusted */
    , In(<E_d, R, Q_dev, cert_sig, ci, nonce_d, sig_d>)''')
sub1(''', GatewayAuthenticatedDevice($G, Q_dev, sk)''',
''', GatewayAuthenticatedDevice($G, Q_dev, sk)
    , GwAccept($G, Q_dev, nonce_d, ~ep)''')

# ---------------- restriction: the nonce sheet ----------------
sub1('''restriction Inequality:
    "All x #i. Neq(x,x) @i ==> F"''',
'''restriction Inequality:
    "All x #i. Neq(x,x) @i ==> F"

/* Fix 2, decision 6: the per-epoch nonce sheet. The gateway never accepts the
 * same (device, nonce) twice within one epoch value. Size limit (2 x N) and
 * fail-closed overflow are implementation guarantees measured in Cooja, not
 * proven here: Tamarin state is unbounded. */
/* Fix 2, decision 5 (strict): once an epoch has ended the gateway no longer
 * accepts messages signed for it. */
restriction Epoch_Is_Current:
    "All G Q n r #i #e.
        GwAccept(G, Q, n, r) @i & EpochEnd(G, r) @e ==> #i < #e"

restriction Nonce_Sheet_Once_Per_Epoch:
    "All G Q n r #i #j.
        GwAccept(G, Q, n, r) @i & GwAccept(G, Q, n, r) @j ==> #i = #j"''')

# ---------------- new lemmas ----------------
append_before_end(NO_REPLAY + '''
/* Injective agreement, device -> gateway (Lowe's strongest rung for this direction):
 * every acceptance has a matching send by a device addressed to that gateway,
 * and no second acceptance uses the same nonce -- unless the device key had been
 * revealed before that second acceptance (a thief can forge; that is not replay). */
lemma Gateway_Injective_Agreement:
    "All G Q n r #i.
        GwAccept(G, Q, n, r) @i
      ==>
          (Ex D msg1 E #j.
              DeviceSentMSG1(D, G, msg1, n, E) @j & #j < #i
            & not (Ex G2 Q2 r2 #i2.
                     GwAccept(G2, Q2, n, r2) @i2 & not(#i2 = #i)
                   & not (Ex #rv2. RevealedKey(Q2) @rv2 & #rv2 < #i2)))
        | (Ex #rv. RevealedKey(Q) @rv & #rv < #i)"

/* Recentness / no pre-play: the device signed the gateway's real epoch value
 * only AFTER that epoch began, and the message was accepted while that epoch
 * was still current. "Created and delivered within one epoch." */
lemma Gateway_Recentness:
    "All G Q n r #i.
        GwAccept(G, Q, n, r) @i
      ==>
          (Ex D #j #s. DeviceSignedBeacon(D, G, n, r) @j
                     & EpochStart(G, r) @s
                     & #s < #j & #j < #i
                     & not (Ex #e. EpochEnd(G, r) @e & #e < #i))
        | (Ex #rv. RevealedKey(Q) @rv & #rv < #i)"

/* A fake beacon never leads to acceptance: if a device signed a value that is
 * no gateway's real epoch value, then no gateway accepts a message carrying that
 * device's nonce -- unless the accepted key had been revealed first (a thief
 * signing with a stolen key is forgery, not a beacon attack). */
lemma Fake_Beacon_Never_Accepted:
    "All D G n br #j G3 Q r #i.
        DeviceSignedBeacon(D, G, n, br) @j
      & GwAccept(G3, Q, n, r) @i
      ==>
          (Ex G2 #s. EpochStart(G2, br) @s)
        | (Ex #rv. RevealedKey(Q) @rv & #rv < #i)"

/* Non-vacuity guards for the new rule and restriction. */
lemma Second_Epoch_Accept_Reachable:
    exists-trace
    "Ex G r0 r1 Q n #a #b #i.
        EpochStart(G, r0) @a & EpochEnd(G, r0) @b & EpochStart(G, r1) @b
      & #a < #b
      & GwAccept(G, Q, n, r1) @i & #b < #i"

lemma Two_Accepts_Same_Epoch_Reachable:
    exists-trace
    "Ex G Q1 Q2 n1 n2 r #i1 #i2.
        GwAccept(G, Q1, n1, r) @i1 & GwAccept(G, Q2, n2, r) @i2
      & not(#i1 = #i2)"
''')

if "BAN" in s or "ban_logic" in s:
    raise SystemExit("ABORT, nothing written. a BAN-logic reference is still present")
Path(path).write_text(s)
print("OK: Fix 2 model written")
