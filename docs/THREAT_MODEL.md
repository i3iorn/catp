# CATP threat model

Non-normative. Section 12 of `docs/PROTOCOL.md` states what CATP provides and
does not, piece by piece; this document collects the attacker capabilities
those pieces assume into one place, so a claim in §12 can be checked against a
common baseline instead of each reader reconstructing the model from context.
If this document and §12 ever disagree, §12 is the authority — file an issue.

## Attacker capabilities considered

### 1. On-path, passive

Can observe every datagram on the wire: every `msg_type`, `sender_id`,
`format`, `datagram_offset`, and payload byte, in both directions, for every
node in the deployment (§12.4). CATP provides no confidentiality against this
attacker by design — it is not a goal, not a gap. What it does *not* get: the
device secrets, the derived epoch or time keys, or the ability to produce a
datagram that verifies.

### 2. On-path, active

Everything attacker 1 has, plus the ability to inject, modify, replay, drop,
delay, and reorder datagrams arbitrarily (§3, §12.1). This is the attacker
§7's authentication and §10's replay protection exist for. Against it, CATP
claims: modification is detected (MAC failure), forgery without key material
is computationally infeasible at the tag length configured (§12.2), replay is
rejected within the acceptance window (§9.3, §10.2), and a datagram cannot be
reattributed to another node, direction, epoch, or capture instant (§7.1,
§7.3). This attacker can still flood a receiver — see attacker 4.

### 3. Holder of one node's `device_secret`

Can derive every past and future `epoch_key` and `time_key` for that one node
and forge arbitrary datagrams attributed to it, indistinguishable from
genuine ones (§12.3). Per §9.2.1 (secrets are per-device, never derived from a
fleet root) and §9.2.3, this exposure is confined to the compromised node —
it grants no ability to forge as any other node, and no ability to derive the
collector's view of any other peer's traffic. CATP has no defense once a
device's secret is extracted; that requires hardware-backed storage,
forward-secure key evolution, or asymmetric signatures, all out of scope for
this specification (§12.3, §15).

### 4. Unauthenticated flood

Can send arbitrary UDP datagrams at a receiver with no key material at all —
the attacker capability §12.5 bounds. CATP does not prevent this (no protocol
can, at the UDP layer, without a network-level defense); what it bounds is
*cost*: one MAC computation per datagram regardless of fleet size, because
`sender_id` selects exactly one key rather than triggering trial decryption
against many (§4.4.1's prohibition on multi-key trial exists to preserve
this). Per-`sender_id` state is allocated only at provisioning time (§12.5),
so this attacker cannot exhaust receiver memory by inventing identifiers, and
cannot exhaust replay-window memory by varying offsets (§10.2's window is
fixed-size regardless of which offsets are observed). Under `cipher_id`
`0x04`'s shorter tag, this bound additionally depends on the mandatory
receiver-side rate limit (§8.1.1) actually being configured — without it, the
tag-length argument does not hold.

### 5. Controller of a node's time source

Can manipulate what a node believes the current time is — feeding it a false
`TIME_ANNOUNCE`, or degrading its access to accurate time entirely (§11, §12.6).
Bounded to influencing *epoch selection* (which key gets used, and whether a
node can authenticate at all): §11.6 and §11.7 argue this attacker gains
denial-of-service (the node fails to authenticate, or is silenced) but not
forgery — it cannot produce a valid MAC without the underlying secret, which
this attacker does not have merely by controlling time. This is the most
load-bearing claim in the specification and the one most wanting independent
review (tracked in #31); treat §11.6/§11.7's guarantee as provisional until
that review happens.

## What is explicitly out of scope

Physical device compromise beyond secret extraction (attacker 3 already
covers extraction itself); side-channel attacks against the HMAC/cipher
implementations of the underlying crates; compromise of the provisioning
channel used to distribute `device_secret` in the first place (§8.3, §9.2.1 —
provisioning is assumed out-of-band and trustworthy); an attacker who has
compromised the collector itself, which holds every node's secret and is
therefore a single point of catastrophic failure by design (§9.2.3 documents
this tradeoff rather than hiding it).

## Using this document

A claim in §12 should name which attacker (1-5 above) it is made against. If
you are evaluating CATP for a deployment, check your actual adversary against
this list before checking any individual §12 claim — most disputes about
whether CATP "protects against X" turn out to be a mismatch between the
attacker the reader has in mind and the one a given guarantee assumes.
