# Compact Authenticated Telemetry Protocol (CATP)

**Version:** 1
**Status:** Draft
**Date:** 2026-09-01

---

## Abstract

CATP is a connectionless, byte-efficient telemetry protocol over UDP providing
message authentication and integrity without confidentiality. Payloads are
transmitted in plaintext; each datagram carries a Message Authentication Code
(MAC) that allows a receiver holding the shared key to detect any modification,
forgery, or replay.

CATP is designed for constrained links where per-packet overhead matters, where
round-trips are unavailable or undesirable, and where packet delivery is
best-effort. Every datagram is independently interpretable and independently
verifiable. No datagram is retransmitted, acknowledged, or assumed delivered.

Keys are derived from wall-clock time rather than established by a handshake.
This is the protocol's central design decision: it eliminates key-establishment
round-trips entirely, and in exchange makes a synchronized clock a hard
prerequisite. Section 11 addresses what a device does before it has one.

---

## Table of contents
1. [Requirements language](#1-requirements-language)
2. [Design goals and non-goals](#2-design-goals-and-non-goals)
3. [Transport](#3-transport)
4. [Datagram format](#4-datagram-format)
5. [Version handling](#5-version-handling)
6. [Message types](#6-message-types)
7. [Authentication](#7-authentication)
8. [Cipher suites](#8-cipher-suites)
9. [Key epochs](#9-key-epochs)
10. [Datagram offset and replay protection](#10-datagram-offset-and-replay-protection)
11. [Cold start and time recovery](#11-cold-start-and-time-recovery)
12. [Security considerations](#12-security-considerations)
13. [IANA considerations](#13-iana-considerations)
14. [Conformance](#14-conformance)
15. [Open items](#15-open-items)
16. [References](#16-references)

---

## 1. Requirements language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY, and
OPTIONAL in this document are to be interpreted as described in RFC 2119.

---

## 2. Design goals and non-goals

### 2.1 Goals

- **Tamper evidence.** A receiver detects any modification to a datagram.
- **Forgery resistance.** An attacker without the key cannot produce an
  acceptable datagram.
- **Replay resistance.** A previously valid datagram cannot be re-accepted.
- **Explicit peer identity.** Every datagram names its peer inside the
  authenticated region, so receiver state is never keyed on spoofable
  network-layer addressing.
- **Compactness.** Fixed overhead is 41 bytes over IPv4 including IP and UDP
  headers, exclusive of payload, at the shortest tag length.
- **No round-trips.** No handshake precedes data transmission. Control messages
  are asynchronous, idempotent, and individually optional.
- **Loss tolerance.** Any datagram may be lost without permanent
  desynchronization. All protocol state is either derived from the clock or
  recoverable without a peer's cooperation.
- **Self-describing framing.** Every record carries its own length and its own
  capture instant, so a receiver delimits and timestamps data without
  out-of-band configuration, and batching, queueing, and reordering do not
  corrupt the time series.

### 2.2 Non-goals

- **Confidentiality.** CATP does not encrypt. Payloads are readable on the wire.
  If confidentiality is required, CATP is not the correct protocol.
- **Delivery guarantees.** No acknowledgement, retransmission, or ordering.
- **Non-repudiation.** Symmetric MACs are verifiable only by keyholders; a
  receiver cannot prove to a third party which peer originated a datagram.
- **Cryptographic agility.** There is no in-band cipher negotiation and no
  in-band downgrade defence. Cipher selection is deployment configuration,
  provisioned over the same out-of-band channel that carries key material
  (Section 8.3).
- **Protection after key compromise.** An adversary who extracts current key
  material can forge datagrams from that point forward. See Section 12.
- **Stateful replication.** CATP carries readings, not replicated state. A
  receiver holds no application state that a datagram updates incrementally, so
  nothing in this protocol can silently diverge from the sender. Deployments
  needing snapshot/delta semantics must build them above CATP, where the
  resynchronization machinery they require does not distort a protocol whose
  datagrams are otherwise independently interpretable.

---

## 3. Transport

CATP datagrams are carried in UDP payloads. IP and UDP headers are unmodified
and are NOT covered by the MAC (Section 7.3).

Fixed overhead per datagram, using an 8-byte tag:

| Layer | IPv4 | IPv6 |
|---|---|---|
| IP header | 20 | 40 |
| UDP header | 8 | 8 |
| CATP header | 9 | 9 |
| MAC tag | 4 | 4 |
| **Total** | **41** | **61** |

The table assumes the 4-byte tag of `cipher_id` `0x04`. Add 4 bytes to each
column for the 8-byte tags of `0x01` and `0x02`, or 12 bytes for the 16-byte tag
of `0x03`.

### 3.1 Datagram size limits

CATP does not fragment or reassemble at its own layer. It relies on every
datagram fitting the path unfragmented.

Path MTU is not reliably knowable to a sender. It varies by route, changes
mid-session, and is reduced silently by tunnels, VPNs, and PPPoE. Classical Path
MTU Discovery depends on ICMP "fragmentation needed" messages, which firewalls
commonly drop, producing a black hole: oversized datagrams disappear with no
error and the sender receives no signal to reduce size.

Senders MUST therefore observe a configured `max_datagram_size` rather than
attempt to infer the path MTU. The following defaults are REQUIRED in the
absence of measurement:

| Network | Default `max_datagram_size` | Basis |
|---|---|---|
| IPv4 | 512 bytes | Conservative fit within the 576-byte reassembly minimum |
| IPv6 | 1232 bytes | 1280-byte guaranteed link MTU, less 48 bytes of IPv6 and UDP headers |

These are UDP payload sizes, inclusive of the CATP header, payload, and MAC tag.
Subtracting CATP's fixed overhead leaves, for application payload:

| Network | 4-byte tag | 8-byte tag | 16-byte tag |
|---|---|---|---|
| IPv4 | 499 bytes | 495 bytes | 487 bytes |
| IPv6 | 1219 bytes | 1215 bytes | 1207 bytes |

`max_datagram_size` MAY be raised above these defaults only where the deployment
controls every hop on the path and has measured the achievable size directly, or
where a deployment implements Datagram Packetization Layer PMTUD (RFC 8899),
which probes upward without depending on ICMP delivery. It MUST NOT be raised on
the assumption that a link reporting a 1500-byte MTU will carry 1500 bytes
end-to-end.

Senders MUST set the IP Don't Fragment flag (IPv4 DF bit; inherent in IPv6).
This converts an oversized datagram into an immediate local error rather than
silent fragmentation, so a misconfiguration fails loudly at the sender instead
of degrading delivery invisibly.

Senders MUST NOT construct a datagram exceeding `max_datagram_size`. A sender
whose payload does not fit MUST reduce it — by carrying fewer records
(Section 6.6), or by splitting across datagrams — rather than emitting an
oversized datagram.

#### 3.1.1 Why fragmentation is worse here than usual

If a datagram is fragmented, loss of any single fragment destroys the whole
datagram; CATP cannot authenticate or use a partial payload. A datagram split
into `f` fragments on a link with per-packet loss `p` fails with probability
approximately `1 - (1-p)^f`, so three fragments on a 2% link fail roughly 6% of
the time.

This compounds with batching. A fragmented 20-record `MESSAGE` converts a 2%
link into roughly a 6% chance of losing 20 consecutive records. Fragmentation and
batching multiply each other's loss amplification, which makes staying inside
`max_datagram_size` a correctness concern rather than an efficiency one.

---

## 4. Datagram format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ver |msg_type | cipher_id|epoch_low|  reserved | datagram_offset
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        datagram_offset (cont.)        |         sender_id
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                sender_id (cont.)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  followed by:  payload (variable)  ||  MAC tag (length per cipher)
```

The header is 9 bytes. All multi-byte integers are network byte order
(big-endian).

### 4.1 Header fields

| Field | Width | Description |
|---|---|---|
| `version` | 3 bits | Protocol version. This document specifies version 1 (`0b001`). |
| `msg_type` | 5 bits | Message type (Section 6). |
| `cipher_id` | 4 bits | Cipher suite in use for this datagram (Section 8). |
| `epoch_low` | 4 bits | Low 4 bits of the 32-bit `epoch_id` (Section 9.3). |
| `reserved` | 5 bits | Must-ignore extension bits (Section 4.2). |
| `datagram_offset` | 19 bits | Position within the epoch, in 1/4096-second ticks (Section 10). |
| `sender_id` | 4 bytes | Node identity for this association (Section 4.4). |
| `payload` | variable | Message-type-dependent content. |
| `MAC tag` | per cipher | Authentication tag (Section 7). |

Extraction:

```
version         = (byte0 >> 5) & 0x07
msg_type        =  byte0       & 0x1F
cipher_id       = (byte1 >> 4) & 0x0F
epoch_low       =  byte1       & 0x0F
reserved        = (byte2 >> 3) & 0x1F
datagram_offset = ((byte2 & 0x07) << 16) | (byte3 << 8) | byte4
sender_id       = be32(byte5..byte8)
```

`datagram_offset` is the only header field that straddles a byte boundary: its
high 3 bits are the low 3 bits of byte 2. Implementations MUST assemble it from
all three bytes rather than reading bytes 3 and 4 as a 16-bit value, which
silently truncates every offset past 65,535 — that is, everything after the
first sixteen seconds of an epoch.

#### 4.1.1 Why the offset is in the header

Every datagram needs a position within its epoch: it is the replay key
(Section 10), the nonce source for nonce-requiring suites (Section 7.2), and the
timestamp a receiver records against the reading. An earlier draft took it from
the first record's own timestamp for data types and from an explicit payload
field for control types, which worked but made the value's location depend on
the message type.

Two things forced it into the header. `NUMBER` (Section 6.3) carries a bare
numeric literal with no record structure to hold an offset, and would otherwise
have needed the same payload-prefix workaround control messages used. And
because the offset was read from the payload, a receiver had to parse framing
before it could check replay, inverting the natural verification order
(Section 7.4).

With the offset in the header both problems disappear: every message type has
one, in the same place, readable before the payload is touched. Control
messages and `NUMBER` carry no prefix, and Section 7.4 returns to checking
replay immediately after the MAC.

The cost is 3 bytes on every datagram, offset against 2 bytes saved on every
record (Section 6.4). A datagram carrying a single record is 1 byte larger than
before; one carrying ten is 17 bytes smaller, and one carrying fifty is 97
bytes smaller. The trade favours exactly the batching the protocol wants to
encourage.

### 4.2 Reserved bits are must-ignore

The 5 reserved bits are the protocol's extension point.

- Senders implementing this document MUST set both bits to zero.
- Receivers MUST ignore reserved bits whose meaning they do not know. A
  receiver MUST NOT reject a datagram because a reserved bit is set, and MUST
  process the datagram exactly as though the bit were clear.

This is a deliberate reversal of the more common must-reject rule, and it is
what allows the protocol to be extended without spending a `version` value, of
which Section 4.3 leaves eight in total.

#### 4.2.1 Why ignoring is safe here

Must-ignore bits are normally a downgrade hazard: if an attacker can set a bit
that a receiver silently disregards, they can strip a security signal. That
does not apply here. The reserved bits sit inside the MAC scope (Section 7.3),
so an attacker cannot set, clear, or flip them without possessing the key. The
only party that can populate them is the legitimate sender, which is precisely
the party an extension is a message from.

What is lost is the free malformed-traffic check the old must-reject rule
provided, and the guarantee that an unaware receiver fails loudly rather than
quietly. The second is the real cost, and it constrains what may be built here.

#### 4.2.2 Constraints on future extensions

Because unaware receivers ignore these bits, any extension assigned to them
MUST be **semantically optional**: a receiver that does not implement it must
still arrive at a correct, if less informed, interpretation of the datagram.

Accordingly, a reserved bit MUST NOT be used to signal any of the following,
because an unaware receiver would misparse rather than under-interpret:

- the presence, absence, or length of any field or payload region;
- a change to record framing (Section 6.4);
- a change to how `epoch_low` or `datagram_offset` are interpreted;
- any cryptographic parameter, including tag length or key derivation;
- an obligation the receiver must discharge for the sender to be correct.

Extensions of that kind change how the datagram must be parsed or trusted, and
MUST therefore use a new `version` or a new `msg_type`. An extension describing
payload content should instead claim a `format` value (Section 6.4.2), which is
the designated space for exactly that, and which is far larger than either.

With 5 bits available, an implementation may treat them as up to five
independent must-ignore flags, or as one 32-valued advisory field, or any
partition between. This document assigns none of them.

Note what they cannot become. A channel or stream selector, for instance, is
not a legal use: a receiver ignoring it would attribute readings to the wrong
stream, which is misinterpretation rather than under-interpretation. Anything
of that kind needs a new `msg_type`, of which the standard data range still has
three free.

### 4.3 Field order and packing

Header layout by byte offset:

| Offset | Width | Field |
|---|---|---|
| 0 | 1 | `version` (3 bits), `msg_type` (5 bits) |
| 1 | 1 | `cipher_id` (4 bits), `epoch_low` (4 bits) |
| 2 | 1 | `reserved` (5 bits), `datagram_offset` (high 3 bits) |
| 3–4 | 2 | `datagram_offset` (low 16 bits) |
| 5–8 | 4 | `sender_id` |

`version` occupies the high 3 bits of byte 0 and MUST remain at that offset in
all future versions. A receiver cannot know how to parse a datagram until it has
read the version, so the version field's position is the one part of the layout
that can never move.

At 3 bits the protocol admits **eight wire versions**, of which this document
claims one. The bit comes from `msg_type`, which gave up little: a message type
is a protocol verb and the standard space still holds more than have ever been
claimed (Section 6), whereas a wire version is unrecoverable once spent.
Exhaustion remains an end-of-life condition, as with the epoch space
(Section 9.3), and the must-ignore bits of Section 4.2 exist to absorb
extensions that would otherwise consume one.

Only `datagram_offset` straddles a byte boundary (Section 4.1); every other
field is a shift and a mask within one byte.

The header is deliberately packed rather than aligned. At 9 bytes, `sender_id`
begins at offset 5, which is not a 4-byte boundary. This costs nothing, because
implementations MUST deserialize byte-wise regardless: all multi-byte fields are
big-endian, so casting the header to a packed struct produces wrong values on
little-endian architectures whatever the alignment happens to be. Given that
every implementation must therefore assemble fields byte by byte, spending
padding to buy alignment it cannot use would trade wire bytes for nothing.

### 4.4 Node identity

`sender_id` is a 4-byte identifier naming the **node** endpoint of an
association, unique within a deployment. It is assigned together with that
node's `device_secret` (Section 9.2) and is never negotiated, derived, or
changed at runtime.

`sender_id` names the node in **both directions**. A datagram travelling from
the collector to a node carries that node's `sender_id`, not an identifier for
the collector; the `direction` byte in the key derivation (Section 9.2.2)
distinguishes which end originated it. Section 9.2.3 explains why this, rather
than giving the collector an identity of its own, is the security-preserving
arrangement.

All per-peer receiver state — `epoch_key` selection, replay windows
(Section 10.2), and liveness timers — MUST be keyed on `sender_id` and MUST NOT
be keyed on source IP address or UDP port. Network-layer addressing is outside
the MAC scope, rewritten by NAT, and trivially spoofed; keying state on it would
let an attacker create fresh state entries with empty replay windows simply by
changing source port.

Because `sender_id` is inside the MAC scope, a receiver resolves it before
verification to select the correct key, then verifies. A forged or altered
`sender_id` fails verification and the datagram is discarded.

`0x00000000` is reserved and MUST NOT be assigned, so a zero-filled buffer does
not name a valid node.

#### 4.4.1 Self-assignment and fleet size

The 4-byte width permits identifiers to be **self-assigned** — drawn from a
cryptographic random source at provisioning time, or derived from a hardware
unique identifier — without a central registry, provided the deployment stays
within the fleet sizes below. This is the intended mode of operation: requiring
registry operations before a single node can transmit would defeat the
protocol's zero-ceremony premise.

Self-assignment is a birthday problem. Probability that a fleet of `n`
independently random identifiers contains at least one collision:

| Fleet size | P(at least one collision) |
|---|---|
| 100 | 1 in 860,000 |
| 1,000 | 1 in 8,600 |
| 5,000 | 1 in 340 |
| 10,000 | 1 in 86 |
| 50,000 | 1 in 4 |
| 77,000 | 1 in 2 |

Accordingly:

- Deployments of **up to 1,000 nodes** MAY self-assign with no further
  precaution. This is the RECOMMENDED operating range, and the size CATP is
  designed for.
- Deployments of **1,000 to 10,000 nodes** SHOULD self-assign but MUST verify
  uniqueness against the collector's provisioned set before a node enters
  service, reissuing on collision. That check is one lookup at provisioning
  time, not a registry.
- Deployments **above 10,000 nodes** MUST use centrally assigned identifiers. At
  that scale a collision is an operational certainty over the fleet's lifetime.

A collision is not silent. Two nodes sharing a `sender_id` hold different
`device_secret` values, so the collector derives one key and one of the two
nodes fails MAC verification on every datagram it sends. The symptom is a node
that is provisioned, transmitting, and totally invisible — distinctive enough to
diagnose, and repaired by reissuing that node's identifier and secret.

Receivers MUST NOT attempt to resolve a collision by trialling multiple keys.
Doing so reintroduces the per-datagram cost that Section 7.4 step 4 exists to
bound, converting a flood of junk datagrams into a fleet-sized amount of work
per datagram.

`sender_id` values MUST NOT be reused across physical devices, including reissue
of a decommissioned node's identifier while any receiver still holds state for
it. Reuse causes two nodes to share replay-window state at the receiver, and
datagrams from one will be rejected as replays of the other. At 2^32 values,
retiring identifiers rather than recycling them is affordable at any fleet size
this protocol targets.

---

## 5. Version handling

`version` is self-describing per datagram. There is no version negotiation
handshake, and none is needed: a receiver supporting multiple versions branches
on the field it observes.

- A receiver MUST silently discard datagrams with an unsupported `version`.
  Version `0b001` is this document; the remaining seven values are unassigned.
- A receiver MUST NOT change its own transmit version in response to a received
  datagram. Version selection is a local configuration decision.
- `CAPABILITY_ADVERTISE` (Section 6.7.1) MAY communicate a peer's maximum
  supported version. This is advisory only.

Adding a version negotiation handshake would introduce a downgrade attack
surface for no benefit, since each datagram is already independently
interpretable.

---

## 6. Message types

`msg_type` is a 5-bit field occupying the low 5 bits of header byte 0, so its
range is `0x00`-`0x1F`.

| Range         | Namespace |
|---------------|---|
| `0x00`        | Reserved, invalid. MUST be rejected. |
| `0x01`-`0x07` | Standard data types. |
| `0x08`-`0x0F` | Vendor data types. Never assigned by this specification. |
| `0x10`-`0x17` | Standard control types. |
| `0x18`-`0x1F` | Vendor control types. Never assigned by this specification. |

`msg_type & 0x10` separates control from data; `msg_type & 0x08` separates
vendor from standard.

**Framing is a property of the individual type, not of the range.** Most data
types are record-framed (Section 6.4), but `NUMBER` is not, and control types
have fixed layouts. The tables below state the framing for every type, and a
receiver MUST take it from there rather than inferring it from the range. An
earlier draft let a single bit decide; `NUMBER` exists precisely to skip record
framing, so that shortcut no longer holds.

`0x00` is permanently unassigned so that zero-filled or truncated buffers decode
as invalid rather than silently matching a real type.

Receivers MUST reject any `msg_type` they do not implement, vendor types
included. Unlike the reserved bits of Section 4.2, message types are not
must-ignore: a type a receiver does not understand is a payload it cannot frame.

### 6.1 Data types (`0x01`-`0x0F`)

| Value | Name | Framing | Description |
|---|---|---|---|
| `0x01` | `MESSAGE` | Records | Ordinary data. One or more records (Section 6.4). |
| `0x02` | `EVENT` | Records | Discrete occurrence, not periodic. Exactly one record. |
| `0x03` | `ALARM` | Records | Threshold breach or fault condition. Exactly one record. |
| `0x04` | `NUMBER` | Bare | A single numeric literal (Section 6.3). |
| `0x05`-`0x07` | — | — | Reserved. |
| `0x08`-`0x0F` | — | Records | Vendor data types. |

`MESSAGE` is the ordinary carrier for structured application data, and the type
a deployment reaches for by default. It carries one record or many; because
records are self-delimiting (Section 6.4), a single record and a batch of fifty
are the same message type with the same parsing.

`EVENT` and `ALARM` are structurally different from `MESSAGE`. They exist as 
distinct types because they carry different handling obligations: neither may be 
batched, and both outrank `MESSAGE` in the shedding policy of Section 10.3.

`NUMBER` is the minimal case: one value, no record header, no schema. It exists
because a large fraction of telemetry is a single reading, and for that case the
5-byte record header and the layout registry behind it cost more than the data.

Vendor data types (`0x08`-`0x0F`) are record-framed exactly as standard ones are,
so a deployment defining one still gets `format`, `schema_version`, and `size`
validated by the protocol.

### 6.2 Control types (`0x10`-`0x1F`)

| Value         | Name                   | Description |
|---------------|------------------------|---|
| `0x10`        | `EPOCH_ANNOUNCE`       | Assert current key epoch (Section 9.4). |
| `0x11`        | `TIME_ANNOUNCE`        | Cold-start time recovery (Section 11). |
| `0x12`        | `TIME_REQUEST`         | Cold-start time recovery (Section 11). |
| `0x13`        | `HEARTBEAT`            | Liveness signal. Empty payload. |
| `0x14`        | `CAPABILITY_ADVERTISE` | Supported versions, ciphers, and layouts. |
| `0x15`-`0x17` | —                      | Reserved. |
| `0x18`-`0x1F` | —                      | Vendor control types. Fixed layout. |

Earlier drafts assigned `SNAPSHOT`, `DELTA`, `RESYNC_REQUEST`, and
`SESSION_RESET` to a stateful-replication profile. That profile is withdrawn and
those code points are reserved. Snapshot/delta replication requires a receiver
that holds application state, a return path to request resynchronization, and
timers to bound the divergence between them — three properties that contradict
the premise that every CATP datagram is independently interpretable. A
deployment needing them should build them above this protocol rather than inside
it.

Deployments needing operational reporting SHOULD define it as a vendor data type
(`0x08`-`0x0F`), which gives it the same framing protection every other data type
receives. Loss rates, shed-record counts, and authentication-failure counts
referenced elsewhere in this document are local observability concerns; nothing
in the protocol depends on them crossing the wire.

### 6.3 NUMBER (`0x04`)

The payload is a numeric literal in ASCII, and nothing else. There is no record
header, no `format`, and no `schema_version`; the datagram's timestamp and
replay position come from the header `datagram_offset` (Section 4.1).

```
number = [ "-" ] int [ "." frac ]
int    = "0" / ( %x31-39 *DIGIT )
frac   = 1*DIGIT
```

Receivers MUST reject a `NUMBER` payload that does not match this grammar
exactly. Specifically:

- The payload MUST be between 1 and 32 bytes.
- Every byte MUST be a digit (`0x30`-`0x39`), a single leading minus sign
  (`0x2D`), or the single decimal point (`0x2E`).
- At most one `.` may appear, and it MUST have at least one digit on each side.
  `23.` and `.5` are invalid; `23.0` and `0.5` are the correct spellings.
- The integer part MUST NOT carry leading zeros unless it is exactly `0`.
  `007` is invalid.
- `-0` is invalid, as are `+`, exponents, whitespace, and any other character.

The grammar is canonical: exactly one byte sequence encodes any given value.
This matters because the payload is inside the MAC scope, so two spellings of
one reading are two different authenticated datagrams and two different replay
entries. Trailing zeros in the fractional part are the deliberate exception —
`23.50` and `23.5` are distinct encodings because they assert different
measurement precision, which is information a telemetry protocol should not
discard.

#### 6.3.1 What NUMBER does not carry

`NUMBER` has no units, no sensor identifier, and no schema. A receiver learns
only that a particular `sender_id` reported a particular value at a particular
instant. The meaning of that value MUST therefore be fixed for the lifetime of
the `sender_id` and recorded out of band.

This is a real constraint, and it bounds where `NUMBER` fits. A node reporting
one quantity — a meter, a probe, a counter — is served well by it. A node
reporting several is not: there is nowhere to say which is which, and using
`NUMBER` for more than one quantity per node makes the readings
indistinguishable at the receiver. Such a deployment MUST use `MESSAGE`, where
`schema_version` names a layout that can carry several fields, or MUST allocate
a distinct `sender_id` per quantity.

#### 6.3.2 Cost

At 41 bytes of IPv4 overhead, a `NUMBER` datagram carrying `23.5` is 45 bytes on
the wire. The equivalent `MESSAGE` — a 3-byte record header plus a 2-byte
fixed-point body — is 46, and requires a provisioned layout at both ends.

ASCII is not the most compact encoding of a number, and this document does not
claim otherwise: `23.5` costs 4 bytes where a scaled `int16` costs 2. What
`NUMBER` removes is the 3-byte record header and the entire layout registry, and
for a single short reading that trade comes out ahead. For long values, high
precision, or several fields, it does not, and `MESSAGE` is the better choice.

### 6.4 Record format

Record-framed payloads carry one or more **records**. A record is a 3-byte
header followed by a variable-length body.

The header is a single 24-bit big-endian packed word:

| Bits (of 24, MSB first) | Width | Field |
|---|---|---|
| 23–20 | 4 | `format` |
| 19–12 | 8 | `schema_version` |
| 11–0 | 12 | `size` |

```
record_header  = (format << 20) | (schema_version << 12) | size

format         = (record_header >> 20) & 0x00F
schema_version = (record_header >> 12) & 0x0FF
size           =  record_header        & 0xFFF
```

| Field | Width | Description |
|---|---|---|
| `format` | 4 bits | Encoding of `body` (Section 6.4.2). |
| `schema_version` | 8 bits | Layout version within that encoding (Section 6.4.2.1). |
| `size` | 12 bits | Length of `body` in bytes. MUST be at least 1. |
| `body` | `size` | Application content. |

Total record length is `3 + size`. `schema_version` and `size` each straddle a
byte boundary, so implementations MUST assemble all three bytes into a 24-bit
integer and mask rather than reading fields as bytes.

Records are packed with no padding and no alignment; implementations MUST read
them byte-wise, as Section 4.3 already requires for the datagram header.

#### 6.4.1 Records do not carry a timestamp

An earlier draft gave every record its own 19-bit `epoch_offset`, so a batch was
a small time series. That field is now in the datagram header (Section 4.1.1),
and records no longer carry one.

The consequence is worth stating plainly: **every record in a datagram shares
one capture instant**, the datagram's `datagram_offset`. Batching now means
"several readings taken together", not "a time series in one datagram".

For the common batching case — several sensors sampled in one pass, or several
fields of one observation — this loses nothing, because the readings genuinely
do share an instant. For a sender accumulating readings over seconds and
flushing them periodically, it does: those readings had distinct capture times
and the protocol no longer carries them. Such a sender MUST either accept the
datagram's instant for the whole batch, or carry per-reading timestamps in the
record body, where the schema defines them.

In exchange each record costs 3 bytes rather than 5, which is what makes
batching cheap enough to be the primary compactness lever (Section 6.6).

#### 6.4.2 format

`format` names the serialization used for `body`.

| Value | Name | Meaning |
|---|---|---|
| `0x00` | — | Invalid. MUST be rejected. |
| `0x01` | `NONE` | No framing imposed. Opaque octets; layout is entirely deployment-defined. |
| `0x02` | `CBOR` | Concise Binary Object Representation, RFC 8949. |
| `0x03` | `MSGPACK` | MessagePack. |
| `0x04` | `PROTOBUF` | Protocol Buffers, wire format only. |
| `0x05` | `FLATBUFFERS` | FlatBuffers. |
| `0x06` | `CAPNPROTO` | Cap'n Proto, unpacked encoding. |
| `0x07`-`0x0F` | — | Reserved for protocol extensions. |

`0x00` is permanently unassigned so that a zero-filled or truncated buffer does
not decode as a valid record, matching `msg_type` `0x00` and `sender_id`
`0x00000000`.

Every assigned encoding is a compact binary serialization, which is deliberate.
An earlier draft offered UTF-8 `key=value` and JSON alongside the binary
options; both are withdrawn. A protocol whose fixed overhead is 38 bytes should
not bless an encoding in which a single reading costs 60, and a deployment that
genuinely wants text can carry it under `NONE` without this document appearing
to recommend it.

`NONE` (`0x01`) imposes no structure at all and is the right choice for
fixed-width binary telemetry, where the body is a handful of packed fields and
any self-describing encoding would cost more than the data. It is also the
escape hatch for encodings this registry does not name.

The four bits admit sixteen values and six are assigned. Because `format` names
a *serialization* rather than an application concept, the space is adequate: new
values are needed only when a new general-purpose encoding achieves broad
adoption, which is a decade-scale event. Deployment-specific structure belongs
in `schema_version`.

##### 6.4.2.1 schema_version

`schema_version` identifies the **layout** carried inside the chosen encoding.
The pair `(format, schema_version)` is what a receiver resolves to decide how to
read a body: `format` says which parser to use, `schema_version` says which
field definition to hand it.

- `0x00` is reserved and MUST NOT be transmitted, so a zero-filled buffer does
  not decode as a valid record.
- Values `0x01`-`0xFF` are assigned by the deploying organization, independently
  per `format`.
- A receiver MUST discard a record whose `(format, schema_version)` pair it holds
  no definition for, after MAC verification (Section 6.4.4).
- Any change to field layout, field widths, field order, or units MUST be
  published as a new `schema_version`. Values MUST NOT be redefined once
  deployed.

This field restores a property an earlier draft lost. When record encoding was
labelled but layout was not, a deployment that reordered two same-width fields
produced datagrams that framed correctly, authenticated correctly, and decoded
to wrong readings — silently, indefinitely, with no error anywhere in the
system. `schema_version` makes that a clean rejection: the receiver holds no
definition for the new version and discards the record instead of misreading it.

The cost is one byte on every record, which does not amortize across a batch.
That is the correct price for the failure it prevents: a misread field is
undetectable by any other mechanism in the protocol, because the MAC attests the
bytes and not their meaning.

Note that `schema_version` is meaningful even under self-describing encodings.
`CBOR` and `MSGPACK` tell a receiver the *shape* of the data but not what a
field means or in what units, and `PROTOBUF` requires the matching `.proto` to
interpret field numbers at all. Only the pair identifies a layout.

256 versions per format is ample for a field that increments when a layout
changes. A deployment approaching exhaustion has revised one layout 255 times
and should allocate a second `format` value or reconsider its schema discipline.

#### 6.4.3 size

`size` is the length of `body` in bytes and makes records self-delimiting: a
receiver locates record boundaries from the datagram alone, without knowing the
application's field widths and without understanding `format`.

- `size` MUST be at least 1. A zero-length body carries nothing the record
  header does not already carry, and forbidding it means a zero-filled buffer
  does not decode as a valid record.
- The 12-bit field permits 4095 bytes, which no payload budget in Section 3.1
  reaches. The datagram size limit always binds first, capping a single record
  at 496 bytes on IPv4 with the shortest tag.

The field is wider than any reachable body because the three spare bits in the
24-bit record header had no better use: widening `size` costs nothing, commits
to nothing, and avoids inventing a second must-ignore space at record level with
its own extension rules. A receiver still validates `size` against the remaining
payload (Section 6.4.4), so the extra range creates no new failure mode.

#### 6.4.4 Parsing and validation

A receiver parses a record-framed payload by reading a 3-byte record header,
then `size` bytes of body, repeating until the payload is consumed. Receivers
MUST discard the entire datagram if any of the following holds:

1. The payload is shorter than 3 bytes — a record-framed datagram MUST carry at
   least one record.
2. Fewer than 3 bytes remain when a record header is expected.
3. A record's `size` overruns the remaining payload.
4. Any record has `size` of 0.
5. Any record has `format` of `0x00` or `schema_version` of `0x00`.
6. Parsing does not end exactly at the payload boundary.
7. `msg_type` is `EVENT` or `ALARM` and the payload contains more than one
   record.

Framing rejection is all-or-nothing. A receiver MUST NOT accept the records it
managed to parse and discard the remainder: a payload that does not frame
cleanly has an unknown relationship to what the sender meant, even though the
MAC verified over its bytes. The MAC attests the bytes, not their division into
records.

**Unknown layouts are different.** A record whose `format` and
`schema_version` are well-formed but whose pair the receiver holds no definition
for — a reserved `format` it does not implement, or a `schema_version` newer
than anything it was provisioned with — MUST be discarded individually. The receiver MUST NOT discard the rest of the datagram on its
account, and SHOULD count the occurrence locally.

This is safe precisely because framing does not depend on `format`: `size` tells
the receiver exactly where the unknown record ends, so the surrounding records
are known-intact rather than merely assumed so. Skipping is therefore the
record-level counterpart of the must-ignore rule for reserved bits
(Section 4.2), and it rests on the same footing — the sender is authenticated,
and the receiver's uncertainty is bounded to a region it can measure. Where the
message type permits only one record, discarding that record discards everything
the datagram carried, and the two rules coincide.

Where a `(format, schema_version)` pair names a fixed-width layout, receivers
MUST additionally verify that `size` equals the width that pair implies, and
MUST discard the record on mismatch. This catches a layout whose field widths
changed without a version bump — a defect `size` alone cannot detect, because a
self-delimiting record frames correctly at any length.

#### 6.4.5 Ordering

Records within a datagram are delivered in the order they appear, and that order
is preserved end to end. It carries no timestamp meaning: all records in a
datagram share the header's `datagram_offset` (Section 6.4.1), so their sequence
is whatever the sender chose, most usefully the schema's own field order.

Across datagrams a receiver orders by `(epoch_id, datagram_offset)`, which is a
total order per sender: Section 10.1 forbids two datagrams from sharing an
offset within an epoch. This is stronger than the partial order earlier drafts
provided, and it comes free from moving the offset into the header.

#### 6.4.6 Mixed formats

A datagram MAY carry records of differing `format`. Nothing in the framing
requires them to agree, and a sender with a packed binary reading and a CBOR
diagnostic to report in the same epoch may pack both.

Senders SHOULD nonetheless keep batches homogeneous where they can. `format`
and `schema_version` occupy 12 of the 24 bits of every record header and do not
amortize across a batch, so a homogeneous batch of fifty 4-byte bodies spends
75 of its 391 wire bytes restating a layout that never changes. That is the
standing price of per-record self-description, and Section 6.4.2.1 argues it is
worth paying; it is not a reason to avoid batching, which remains by a wide
margin the most effective compactness lever the protocol offers.

### 6.5 Payload framing versus field semantics

This specification defines **framing** — how a receiver locates and delimits the
records inside a payload, when each was captured, and which encoding each
claims. It does not define **field semantics** — what the values inside a `body`
mean once decoded. That is fixed per `format` value and, for the
deployment-defined range, communicated out of band.

Framing cannot be left to the application. Two implementations that agree on
sensor field layout but disagree on how records are delimited will not
interoperate, and the failure is silent: a misframed payload still authenticates
correctly, because the MAC covers the bytes and not their interpretation.

`size`, `format`, and `schema_version` catch three different failures and none
substitutes for another. `size` establishes where a record ends; `format`
establishes which parser reads it; `schema_version` establishes which field
definition that parser is handed. A deployment that reorders two same-width
fields breaks only the third, which is exactly the case Section 6.4.2.1 exists
to make detectable.

### 6.6 Datagram capacity

The number of records a datagram carries is bounded by `max_datagram_size`
(Section 3.1), not by any count field:

```
payload_budget = max_datagram_size - header_len - tag_len
```

where `header_len` is 9. With the IPv4 default of 512 and the 4-byte tag of
`cipher_id` `0x04` that is 499 bytes, which holds 71 records of a 4-byte body,
or 33 of a 12-byte body, or one record of up to 496.

Senders MUST NOT exceed `payload_budget`, and SHOULD stop well short of it on
loss-sensitive links (Section 6.6.1).

Earlier drafts carried an explicit `count` byte and derived record boundaries
from a per-deployment `sample_size` constant. The `size` field replaces both,
and buys variable-length bodies, framing that validates without out-of-band
configuration, and the removal of `sample_size` from the wire protocol
altogether.

#### 6.6.1 Batching and loss

A lost multi-record `MESSAGE` loses every record in it rather than one. Senders
SHOULD weigh batch size against the observed loss rate: at loss rate `p`,
batching `n` records converts scattered single-record gaps into a `p`
probability of an `n`-record blackout. Trend data usually tolerates this; data
where short gaps are material does not.

`ALARM` (`0x06`) and `EVENT` (`0x05`) MUST carry exactly one record. Both are
discrete and not superseded by subsequent transmissions, and delaying one to
fill a batch defeats the purpose of a distinct message type. They are
transmitted immediately.

Senders SHOULD bound batch latency with a flush timer as well as a size target,
transmitting on whichever triggers first, so that a slow data source does not
hold records indefinitely. A flush delay now moves the whole batch's timestamp,
not just its arrival, so the timer bounds a real error rather than a cosmetic
one (Section 6.4.1).

A datagram MUST NOT span an epoch boundary. Records are addressed relative to
the epoch named in the header, so a sender reaching a boundary with a partially
filled buffer MUST flush it under the old epoch before beginning a new one.

### 6.7 Control message payloads

`EPOCH_ANNOUNCE` and `TIME_ANNOUNCE` are specified in Sections 9.4 and 11.
`HEARTBEAT` (`0x13`) carries an empty payload.

Control messages (`0x10`-`0x1F`) are not record-framed. They carry neither
`format`, `schema_version`, nor `size`; their layouts are fixed by this document
and identified by `msg_type` alone.

Earlier drafts required every control payload to begin with an explicit
`datagram_offset`, because replay protection needed a value the header did not
carry. Section 4.1.1 moved that field into the header, so the prefix is gone and
`HEARTBEAT` is once again a datagram with no payload at all — 13 bytes on the
wire with the shortest tag, of which 9 are header and 4 are the tag.

#### 6.7.1 CAPABILITY_ADVERTISE (`0x14`)

| Field | Width | Description |
|---|---|---|
| `max_version` | 1 byte | Highest protocol version supported. |
| `cipher_count` | 1 byte | Number of `cipher_id` values following. |
| `ciphers` | `cipher_count` | Supported `cipher_id` values, one byte each. |
| `layout_count` | 1 byte | Number of layout entries following. |
| `layouts` | `layout_count * 2` | Per entry: `format` and `schema_version`, one byte each. |

Receivers MUST verify the payload length equals
`3 + cipher_count + (layout_count * 2)`.

`format` occupies 4 bits on the wire but a whole byte here, with the high nibble
zero; a control message optimised for compactness would be optimising the wrong
thing, and byte-aligned entries are easier to extend.

All values are advisory descriptions of the sender's own configuration. A
receiver MUST NOT change its own transmit behaviour solely because a peer
advertised something (Section 5); the message exists so that mismatches are
detectable and diagnosable, not so that parameters are negotiated in band.

In particular, advertising a `(format, schema_version)` pair does not make a
receiver able to read it. The receiver must hold the field definition behind that
pair, which this message does not carry and deliberately cannot. What it does provide
is early, authenticated warning that a peer intends to send something the
receiver will otherwise silently skip (Section 6.4.4).

### 6.8 Absence of an authentication-failure message

This specification deliberately defines no message type reporting MAC
verification failure. A datagram that fails verification has no established
origin; responding to it provides an attacker a forgery oracle and a reflection
vector triggered by unauthenticated input.

Receivers MUST silently discard datagrams failing verification. Authentication
failures SHOULD be surfaced locally through logs or metrics.

---

## 7. Authentication

### 7.1 Authenticated header image

The MAC is computed over an expanded form of the header in which the 1-byte
`epoch_low` is replaced by the full 32-bit `epoch_id` (Section 9.3). This
`auth_header` is 13 bytes:

| Offset | Width | Field |
|---|---|---|
| 0 | 1 | `version`, `msg_type` |
| 1 | 1 | `cipher_id`, with the 4 `epoch_low` bits set to zero |
| 2 | 1 | `reserved`, `datagram_offset` (high 3 bits) |
| 3–4 | 2 | `datagram_offset` (low 16 bits) |
| 5–8 | 4 | `epoch_id` (full 32-bit value) |
| 9–12 | 4 | `sender_id` |

The `epoch_low` bits are zeroed rather than retained, so the epoch appears
exactly once in the authenticated image — as the full 32-bit `epoch_id`. Every
other header field is covered exactly as transmitted, `datagram_offset` and the
reserved bits included.

Reserved bits are covered exactly as transmitted, including bits the receiver
does not understand. This is what makes must-ignore safe (Section 4.2.1).

`auth_header` is never transmitted; both endpoints construct it locally. For
`TIME_ANNOUNCE` (Section 11), where no epoch is defined, `epoch_id` in
`auth_header` is `0x00000000`.

### 7.2 Tag computation

For `cipher_id` `0x01` and `0x02`:

```
tag = truncate(MAC(epoch_key, auth_header || payload), 8)
```

For `cipher_id` `0x03` (ChaCha20-Poly1305, AAD-only):

```
nonce = 0x00 * 10 || datagram_offset         (12 bytes, big-endian offset)
tag   = ChaCha20-Poly1305-Seal(
            key        = epoch_key,
            nonce      = nonce,
            plaintext  = "" (empty),
            aad        = auth_header || payload
        ).tag                                (16 bytes)
```

The plaintext is empty, so the construction produces no ciphertext and CATP
remains a plaintext protocol; only the 16-byte Poly1305 tag is transmitted.

`epoch_key` is derived per Section 9.2.

#### 7.2.1 Why cipher 0x03 requires a per-datagram nonce

Poly1305 is a one-time authenticator. Two distinct messages authenticated under
the same Poly1305 key allow an attacker to solve for the key and forge
arbitrarily, so applying it directly as `MAC(epoch_key, message)` across an
epoch — up to 65,536 datagrams under one key — would be a total break rather
than a weakening.

The RFC 8439 construction avoids this by deriving a fresh one-time Poly1305 key
from ChaCha20 keyed by `(epoch_key, nonce)`. Its safety therefore rests entirely
on `(key, nonce)` never repeating. CATP already guarantees this without adding a
wire field: `epoch_key` is unique per `(device_secret, epoch_id, direction)` by
Section 9.2, and `datagram_offset` is unique within an epoch by Section 10.1.
The nonce is the offset, and the existing rules make it a nonce.

This is the reason Section 10.1's prohibition on offset reuse is a correctness
requirement rather than a replay-hygiene preference. Under `cipher_id` `0x01`,
`0x02`, or `0x04`, a reused offset costs replay protection. Under `0x03`, it
costs the key.

Note that the clock supplies this uniqueness for free across a restart, which a
counter did not: see Section 10.4.

### 7.3 Coverage

The MAC covers the entire CATP header and payload. It does NOT cover IP or UDP
headers, which are legitimately rewritten in transit (NAT port translation, TTL
decrement, checksum recomputation); including them would break authentication at
the first hop.

Because `version`, `cipher_id`, `msg_type`, `sender_id`, `datagram_offset`, the
full 32-bit `epoch_id`, and the reserved bits are all inside the MAC scope, an
attacker cannot relabel a captured datagram — retagging a `MESSAGE` as an
`EPOCH_ANNOUNCE`, or re-attributing one node's telemetry to another — without
possessing the key.

The payload is covered in full, so each record's `format`, `schema_version`, and
`size` are authenticated exactly as its `body` is, and a `NUMBER` literal is
authenticated digit by digit. An attacker can no more relabel a record's layout,
alter a reading, or move a datagram in time than forge one outright. An attacker can no more
relabel a record's encoding or relocate a reading in time than alter the reading
itself. That these fields moved out of the header (Section 4.1) changes what
they cost on the wire, not what they are protected by.

### 7.4 Verification order

Receivers MUST perform checks in this order and MUST discard silently on any
failure:

1. Datagram length is at least `header_len + tag_len` for the indicated cipher.
2. `version` is supported.
3. `msg_type` is not `0x00` and is implemented.
4. `sender_id` is known to the receiver.
5. `cipher_id` is the suite configured for that `sender_id` (Section 8.3).
6. `epoch_low` reconstructs (Section 9.3) to an `epoch_id` within the
   acceptance window.
7. **MAC tag verifies**, using the key derived for that `sender_id` and the
   reconstructed `epoch_id`.
8. `datagram_offset` passes the replay window check (Section 10.2).
9. The payload frames cleanly — into records for a record-framed type
   (Section 6.4.4), against the grammar for `NUMBER` (Section 6.3), or against
   the fixed layout for a control type (Section 6.7).
10. Records of unrecognized `(format, schema_version)` are skipped individually
    (Section 6.4.4). This is the only step that discards part of a datagram
    rather than all of it.

Reserved bits appear nowhere in this list, and that is deliberate. Per
Section 4.2 they are must-ignore: a receiver that branches on a bit it does not
understand has implemented rejection, not ignoring.

The replay check precedes framing. An earlier draft had to invert this, because
`datagram_offset` lived in the payload and could not be read until the payload
had been parsed. With the field in the header (Section 4.1.1) the natural order
is restored: a receiver authenticates, admits or rejects the datagram as a
replay, and only then spends effort interpreting what it carries. A
malformed-but-authentic datagram from a defective sender is now rejected at
step 9 having already consumed its offset, which is correct — the offset was
genuinely used.

Steps 1–6 are inexpensive and reject malformed or policy-violating traffic
before the MAC computation, limiting the cost of a flood of junk datagrams.
Step 4 in particular means a receiver performs exactly one MAC computation per
datagram regardless of fleet size, rather than trialling every provisioned key.

Steps 1–6 are filters only. A receiver MUST NOT mutate any persistent state —
the replay window, the highest accepted epoch, the last known time, peer
liveness timers — until **step 7** has succeeded. All of those fields are
attacker-writable before the MAC verifies, and updating them early converts a
cheap flood into a state-corruption attack.

Tag comparison MUST be constant-time.

---

## 8. Cipher suites

### 8.1 Registry

| `cipher_id` | Algorithm | Tag length | Nonce required |
|---|---|---|---|
| `0x00` | Reserved, invalid | — | — |
| `0x01` | HMAC-SHA256, truncated | 8 bytes | no |
| `0x02` | SipHash-2-4 | 8 bytes | no |
| `0x03` | ChaCha20-Poly1305, AAD-only (RFC 8439) | 16 bytes | yes, per Section 7.2 |
| `0x04` | HMAC-SHA256, truncated | 4 bytes | no |
| `0x05`–`0x0F` | Unassigned | — | — |

Tag length is implied by `cipher_id`, not carried on the wire. Both endpoints
resolve it from this table.

The 4-bit field admits 16 suites. That is ample precisely because Section 8.3
removed cryptographic agility: with no in-band negotiation and one configured
suite per association, the registry grows only when this document adds a
primitive, which is a rare event measured against the four entries it has needed
so far.

#### 8.1.1 cipher_id 0x04 and the 4-byte tag

`0x04` is the same HMAC-SHA256 construction as `0x01`, truncated to 4 bytes
instead of 8. It exists because on a constrained link the tag is the single
largest remaining cost: at 4 bytes it is a tenth of the 38-byte IPv4 overhead
rather than a fifth of 42, and for a datagram carrying one small reading it is
no longer larger than the data.

A 4-byte tag gives roughly 2^-32 forgery probability per attempt, which is not
adequate on its own. A receiver accepting `0x04` MUST therefore enforce a
per-`sender_id` inbound rate limit (Section 10.5), and deployments MUST NOT
select it where that limit cannot be enforced. This is a MUST rather than the
SHOULD that applies to other suites: at 8 bytes rate limiting is defence in
depth, while at 4 bytes it is what makes the tag length defensible at all. At a
limit of 128 datagrams per second an attacker needs roughly a year of sustained
flooding per expected forgery, and each attempt is a datagram the receiver
counts.

`0x04` is the right default for battery-powered or duty-cycled links where bytes
translate directly into energy, and for deployments whose telemetry has little
value to an attacker. It is the wrong choice for anything where a single forged
reading has consequence, or where the receiver cannot rate-limit. Where the
threat model is unclear, `0x01` is the safer default and costs 4 bytes.

`0x01` is the RECOMMENDED default. `0x02` is a lateral alternative for senders
where SHA-256 is disproportionately expensive. `0x03` is for deployments
requiring a tag longer than 64 bits (Section 12.2). `0x04` trades tag strength
for wire bytes under the conditions of Section 8.1.1.

Any future suite added at this `cipher_id` width MUST state whether it requires
a nonce, and if so MUST derive it from `datagram_offset` exactly as Section 7.2
does. A
suite that needs unique nonces and does not say so is the failure mode that
Section 7.2.1 exists to prevent recurring.

### 8.2 The registry is append-only

New `cipher_id` values MAY be added. A published `(cipher_id, algorithm, tag
length)` binding MUST NOT be modified. If a suite is later found weak it is
marked deprecated and no longer configured; its code point is not reused, so
captured historical traffic remains honestly labeled.

`cipher_id` is an identifier and carries no ordering.

### 8.3 Cipher selection is configuration, not negotiation

Each association uses exactly one cipher suite, configured out of band per
`sender_id` alongside the `device_secret`. A receiver MUST reject any datagram
whose `cipher_id` differs from the configured value for that `sender_id`, at
step 5 of Section 7.4, before computing a MAC.

Earlier drafts of this document carried a `security_level` per suite, an
`accepted_level` high-water mark per peer, and a `CIPHER_ANNOUNCE` message, so
that cipher strength could only ratchet upward in band. That machinery is
removed. Its reasoning does not survive contact with CATP's provisioning model:
a deployment that can distribute a 32-byte `device_secret` out of band can
distribute a one-byte cipher selection over the same channel, and doing so gives
a strictly stronger guarantee. Configuration is enforced from the first
datagram, whereas a high-water mark is only as good as the highest datagram a
receiver happened to have seen.

The removed mechanism also had no recovery path by construction.
`accepted_level` was monotonic, persistent across restarts, and deliberately
immune to in-band reset, so a single datagram verifying at an elevated level
would permanently lock out a legitimate peer that later fell back — with no way
to clear it short of touching the receiver's storage. If an operator must touch
the receiver either way, the configuration is the better place to express the
policy.

Migrating an association to a different suite is therefore a provisioning
operation: update the receiver's configuration for that `sender_id`, then the
sender's. Datagrams sent under the old suite between those two steps are
rejected. Deployments that cannot tolerate that gap SHOULD provision the
receiver to accept a configured pair of suites for the duration of the
migration, and MUST narrow it to one when the migration completes.

`cipher_id` remains a header field despite carrying no negotiation. It costs no
additional bytes, it makes captured traffic self-describing during exactly the
migration window described above, and it keeps the per-datagram check in Section
7.4 a comparison rather than an assumption.

### 8.4 Unrecognized cipher_id

If a receiver observes an unregistered `cipher_id`, or one that does not match
the configured suite for that `sender_id`, it MUST discard the datagram before
computing a MAC and SHOULD raise a local metric. The receiver continues
operating normally with its configured suite.

---

## 9. Key epochs

### 9.1 Epoch duration

Epochs advance on fixed 128-second boundaries derived from a shared time base.
Advancement is implicit: both endpoints roll over independently on the clock and
no message is required in steady state.

`EPOCH_ANNOUNCE` exists for convergence acceleration and for out-of-band
compromise response, not for routine rotation.

### 9.2 Key derivation

Each node holds its own `device_secret`: 32 bytes of independently generated
random data, provisioned out of band and unique to that `sender_id`. A collector
holds the `device_secret` of every node it communicates with.

```
PRK = HKDF-Extract(salt = "", IKM = device_secret)

epoch_key = HKDF-Expand(
    PRK,
    info = "CATP1" || sender_id || epoch_id || direction,
    L    = 32
)
```

where `sender_id` is 4 bytes, `epoch_id` is the full 32-bit value, and
`direction` is one byte: `0x00` for node-to-collector, `0x01` for
collector-to-node. HKDF is as defined in RFC 5869, instantiated with SHA-256.

A second key, used only for cold-start time recovery and derived without any
epoch input, is specified in Section 11.2.

Endpoints MUST NOT transmit `device_secret` or any derived key on the wire.

#### 9.2.1 Why keys are per-device, not fleet-wide

A single fleet-wide secret would make `sender_id` decorative. Every node would
hold the key needed to produce a valid MAC over any `sender_id`, so any
compromised or malicious node could impersonate any other, and a receiver could
not distinguish them. The identity field would authenticate nothing.

Per-device secrets mean a receiver's key lookup *is* the identity check: a
datagram claiming `sender_id` X verifies only under X's key. Compromise of one
device exposes that device's traffic and no other's.

The cost is collector-side storage and provisioning: 32 bytes per node, and a
provisioning step that generates and distributes a distinct secret per device.
At the fleet sizes of Section 4.4.1 that is at most a few hundred kilobytes.
Deployments MUST NOT substitute a fleet-wide secret to avoid this cost.

Deriving `device_secret` from a fleet root (`device_secret = KDF(root,
sender_id)`) is NOT permitted. It reintroduces the same failure: any device
whose root is extracted yields every other device's key.

#### 9.2.2 Direction separation

The `direction` byte prevents a datagram sent by a node from being replayed back
to it as though the collector had sent it. Without it, both directions share one
key and a reflected datagram verifies.

#### 9.2.3 Why the collector has no identity of its own

Both directions of an association key on the **node's** `device_secret` and the
node's `sender_id`, separated only by `direction`. The collector holds no secret
of its own and is never named on the wire.

The alternative — giving the collector its own `sender_id` and `device_secret`,
as a naive reading of "sender" would suggest — quietly destroys the property
Section 9.2.1 establishes. Every node would need the collector's secret in order
to verify collector-originated messages. That single secret would then sit in
the firmware of every device in the fleet, and extracting it from any one node
would let the attacker impersonate the collector to every other node. It is the
fleet-wide-key failure reintroduced through the return path.

Under the arrangement specified here, a node holds exactly one secret: its own.
Extracting it yields the ability to forge collector traffic to **that node
only**, which the attacker already fully controls, so the return path adds no
blast radius beyond the compromise itself.

The cost is that collectors are not mutually distinguishable to a node: any
party holding a node's `device_secret` can speak to it as the collector. In a
deployment with several collectors sharing provisioning data, one collector can
impersonate another to a node. Deployments needing to separate collectors MUST
add a collector identifier to the `info` string of Section 9.2 and provision
per-collector keys accordingly; this document does not define that, because the
single-collector case is the one CATP targets.

#### 9.2.4 Epoch derivation from the clock

```
epoch_id = floor(unix_time_seconds / 128)
```

`unix_time_seconds` is UTC seconds since 1970-01-01, ignoring leap seconds. Both
endpoints compute this independently; the value is never negotiated. This
formula is normative — an implementation using a different origin or divisor
will fail to authenticate against a conforming one, and the failure presents as
a MAC error rather than as a clock problem.

### 9.3 Epoch representation and acceptance window

`epoch_id` is a 32-bit unsigned integer. At 128 seconds per epoch the space
spans roughly 17,000 years and does not wrap within any plausible deployment
lifetime, so `epoch_id` is compared as a plain unsigned integer with no modular
arithmetic. Implementations MUST treat exhaustion of the epoch space as an
end-of-life condition and MUST NOT wrap to zero.

Only the low 4 bits are transmitted, in the `epoch_low` header field. The
receiver reconstructs the full value:

1. Compute `local_epoch` from its own clock.
2. Select the candidate in `{local_epoch - 1, local_epoch}` whose low 4 bits
   equal the received `epoch_low`.
3. If neither matches, discard the datagram.

Receivers MUST accept the current epoch and SHOULD accept the immediately
preceding epoch, to absorb clock skew and datagrams in flight across a boundary.
Receivers MUST NOT accept epochs older than the preceding one. The acceptance
window is therefore 2 epochs wide, and 4 bits distinguish two adjacent
candidates with considerable margin.

`epoch_low` does not carry the epoch — it selects between two candidates the
receiver has already computed from its own clock. One bit would suffice for
that. The additional three exist to widen the range over which drift is rejected
cheaply: a sender up to fifteen epochs adrift, roughly half an hour, fails the
pre-MAC check in Section 7.4 rather than reaching the MAC.

Beyond that the field aliases, and a badly desynchronized sender's datagram
reconstructs to a plausible-looking epoch, derives the wrong key, and fails the
MAC instead. That is a correctness-preserving outcome, not a weakness — but it
diagnoses a clock problem as an authentication failure, which is the single most
misleading thing this protocol can do to an operator. The width is what pushes
that boundary out to half an hour, which covers ordinary NTP failure before it
covers anything else. Deployments SHOULD still instrument the MAC-failure
counter against a local clock-quality metric.

The MAC is computed over the **full 32-bit `epoch_id`** (Section 7.1), not over
the transmitted `epoch_low`. This makes reconstruction self-checking: a receiver
whose clock has drifted far enough to reconstruct the wrong epoch derives the
wrong key, the MAC fails, and the datagram is silently discarded. Truncation
therefore saves 3 bytes per datagram without weakening authentication, and adds
no trust assumption beyond the clock synchronization the protocol already
requires.

All internal state — monotonicity tracking, `EPOCH_ANNOUNCE` comparison, key
derivation, `datagram_offset` interpretation — operates on the full 32-bit value.
Only the wire representation is truncated.

Note that `epoch_low` is not a redundant transmission of the clock: it is what
lets a receiver distinguish "sender is one epoch behind me" from "sender is
badly desynchronized", and it fails closed in the latter case.

### 9.4 EPOCH_ANNOUNCE

Payload:

| Field | Width | Description |
|---|---|---|
| `target_epoch` | 4 bytes | Absolute 32-bit epoch being asserted, untruncated. |

The message asserts absolute state, never a delta. A relative instruction such
as "advance by one" would desynchronize permanently on loss; an absolute
assertion is idempotent under loss, duplication, and reordering.

No nonce field is present. `datagram_offset` already provides per-datagram
replay protection, and the message is idempotent: a replayed announcement
asserting already-accepted state changes nothing.

Receivers MUST reject announcements whose `target_epoch` is at or below the
highest previously accepted value from that `sender_id`. Without this check, an
adversary holding an expired epoch key could replay an old announcement and
force a return to compromised key material.

Senders SHOULD transmit each announcement more than once, spaced over several
seconds, rather than relying on a single datagram.

---

## 10. Datagram offset and replay protection

### 10.1 Semantics

Every datagram carries a `datagram_offset`: its position within the current
epoch, measured in 1/4096-second ticks, in the range `0`-`524287`.

It is a header field (Section 4.1), present in every datagram of every type and
readable before any payload is parsed.

```
datagram_offset = floor((unix_time - (epoch_id * 128)) * 4096)
```

A 128-second epoch contains exactly 524,288 ticks of 1/4096 second, so the
19-bit field covers the epoch precisely: every value is reachable, none is out
of range, and no value is ambiguous. Combined with the `epoch_id` a receiver has
already reconstructed in order to verify the datagram (Section 9.3), every
datagram carries an unambiguous absolute instant at approximately 244
microsecond resolution.

That instant is both the transmission position the replay window keys on and the
capture time a receiver records against the readings inside. For `NUMBER` and
for single-record datagrams the two coincide exactly. For a batch they coincide
only as well as the sender's flush timer allows, which is why Section 6.6.1 asks
senders to bound it.

Senders MUST NOT reuse a `(sender_id, epoch_id, direction, datagram_offset)`
tuple. Under `cipher_id` `0x01`, `0x02`, or `0x04` a reuse costs replay
protection; under `0x03` it is a full key compromise (Section 7.2.1).

Because the offset is a tick of the clock rather than a free-running count, this
prohibition has a direct operational reading: **a sender transmits at most one
datagram per 1/4096-second tick**, and therefore at most 4096 datagrams per
second and 524,288 per epoch. A sender with two datagrams ready in one tick MUST delay
the second to the next tick or drop it (Section 10.3).

Batching relieves this ceiling proportionally: a datagram of 55 records consumes
one tick, and each record still carries its own capture instant, so increasing
batch size costs latency rather than time resolution. At the IPv4 payload budget
that is over 200,000 records per second per sender, which is far beyond what
this protocol's target deployments generate.

#### 10.1.1 Why the offset replaces a counter

Earlier drafts carried a separate 2-byte `counter` in the header, incremented
per datagram and reset each epoch, alongside a per-record timestamp. Both are
now this one field: it is monotonic within an epoch, unique per tick, and it
means something.

Folding them together buys three things:

**Bytes off every datagram**, since one field serves as timestamp, sequence
number, and nonce source rather than three.

**Restart safety for free.** A counter restarts at zero when a device reboots,
reusing tuples it has already sent — the failure that earlier drafts closed with
a mandatory non-volatile write per epoch. A clock does not rewind, so a rebooted
sender's offsets are naturally beyond any it has used. See Section 10.4.

**A replay window measured in time.** A bitmap of N offsets covers N ticks of
wall clock regardless of the sender's rate, rather than N datagrams whose span
depends on it. Section 10.2 states the window as a duration for this reason.

**A total order across datagrams**, since no two datagrams from one sender share
an offset within an epoch. `(epoch_id, datagram_offset)` therefore sorts a
sender's traffic exactly, which the per-record offsets it replaced could not do
(Section 6.4.5).

The cost is that the rate ceiling becomes a **pacing** constraint rather than a
budget. A counter permitted a burst of any size so long as the per-epoch total
stayed within 65,536; the offset permits no two datagrams in the same 244
microsecond tick, however small the burst. In practice a sender that would
violate this is one emitting hundreds of datagrams per second, which the former
`max_rate` guidance already discouraged — but the constraint is now structural
rather than advisory, and it is enforced by the receiver rather than trusted to
the sender.

### 10.2 Replay window

Receivers maintain, per `sender_id` and per epoch, the highest
`datagram_offset` observed and a bitmap of recently seen values.

Because Section 9.3 permits acceptance of both the current and the immediately
preceding epoch, receivers MUST maintain a separate window for each. A single
shared window is incorrect: offsets reset to zero at each epoch boundary, so the
first datagrams of a new epoch would fall below a window still tracking the old
one and be rejected as replays. Windows for epochs outside the acceptance window
are discarded.

- An offset above the window high-water mark is accepted; the window advances.
- An offset inside the window and not previously seen is accepted and marked.
- An offset inside the window and already seen MUST be rejected.
- An offset below the window MUST be rejected.

A window of 16,384 entries is RECOMMENDED. That is 2 KiB of state per
`sender_id` per epoch and, because offsets are clock ticks, exactly 4 seconds of
reordering tolerance — a figure that does not change with the sender's rate.
Deployments on paths with known worse reordering, or with tighter memory, should
size the window in seconds and convert: `entries = tolerance_seconds * 4096`.

The finer tick makes this window eight times larger in entries than the same
tolerance would have cost at a coarser tick. A receiver tracking many senders
may prefer a
1-second window (4096 entries, 512 bytes), which still exceeds observed
reordering on most paths by a wide margin.

### 10.3 Rate limiting and shedding

**Hard bound.** A sender:

- MUST NOT transmit two datagrams with the same `datagram_offset` within one
  epoch and direction.
- MUST NOT transmit a datagram whose `datagram_offset` is not strictly greater
  than that of its previous datagram in the same epoch and direction. A sender
  tracks the last value it emitted and refuses to go backwards, which also
  covers a small backward step in the clock (Section 10.4).
- MUST cease transmission until the next epoch if the clock has not advanced
  past its last emitted offset.
- MUST start each epoch with offsets derived afresh from the clock.

**Operating budget.** Senders SHOULD enforce a configured `max_rate` well below
the 4096-per-second ceiling, leaving headroom for bursts. A budget of 128 per
second is RECOMMENDED as a default. Note that `cipher_id` `0x04` makes a
receiver-side limit mandatory rather than advisory (Section 8.1.1).

**Burst handling.** Peak rate, not average rate, determines whether a deployment
fits. Alarm storms, post-outage backlog flushes, and retry loops in application
code can exceed steady-state rates by orders of magnitude. Senders SHOULD
implement a token bucket sized to `max_rate`, and MUST coalesce rather than
queue when the bucket is empty: several readings that arrive within one tick
belong in one datagram as several records, which costs one offset instead of
several and is the behaviour the record format exists to make cheap.

**Shedding policy.** On exhausting its budget a sender MUST drop datagrams
rather than queue them unboundedly, and SHOULD drop by priority: `MESSAGE`
before `EVENT`, and `EVENT` before `ALARM`, on the reasoning that periodic data
is superseded by the next transmission whereas discrete occurrences are not. A
sender that has shed records SHOULD surface the count locally.

**Receiver side.** Receivers SHOULD apply an independent inbound rate limit per
`sender_id`, enforced after authentication, so that a compromised or
malfunctioning node cannot exhaust receiver resources. Under `cipher_id` `0x04`
this is a MUST (Section 8.1.1). It is separate from the pre-authentication
network-layer limiting of Section 12.5.

**Control messages.** `EPOCH_ANNOUNCE`, `HEARTBEAT`, and `CAPABILITY_ADVERTISE`
consume offsets like any other datagram. Their retransmission schedules MUST fit
within the sender's budget and MUST NOT be exempted from it. `TIME_ANNOUNCE` is
the sole exception (Section 11.3), because it is transmitted when no epoch is in
effect.

### 10.4 Restart behaviour

A sender that restarts mid-epoch resumes emitting offsets derived from the
clock, which has advanced during the outage. Its new offsets are therefore
strictly greater than any it emitted before the restart, and no tuple is reused.
This holds without any non-volatile state, and it is the principal practical
advantage of keying replay protection on the clock rather than on a count.

Two residual cases need care, and both are cheap:

**A restart within a single tick.** A device that reboots and retransmits inside
244 microseconds could repeat an offset. No device this protocol targets boots
that quickly, but a sender MUST NOT transmit until it has observed the clock
advance at least one tick past its own start, which closes the case at the cost
of a single comparison.

**A backward clock step.** If a time source corrects the clock backwards — an
NTP step, or a `TIME_ANNOUNCE` accepted after a cold start — offsets could
repeat. The strictly-increasing rule of Section 10.3 covers this: a sender
holds its last emitted offset in volatile memory and refuses to emit a value at
or below it, waiting instead for the clock to catch up or for the epoch to
change.

Earlier drafts required a 32-bit `last_epoch` written to non-volatile storage on
every epoch, solely to stop a rebooted sender from reusing counter values. That
requirement is withdrawn for this purpose; the clock now provides the guarantee.
`last_epoch` is still persisted, but only as the monotonic floor for cold-start
time recovery (Section 11.4), where nothing else can supply it — so a node that
has an authenticated time source and does not implement `TIME_ANNOUNCE` needs no
non-volatile state at all.

### 10.5 Offset gaps are not errors

Gaps in observed `datagram_offset` values are the expected result of packet
loss, and are also the normal state of affairs: a sender transmitting at 10
datagrams per second uses 10 of the 4096 ticks available each second, so the
overwhelming majority of offsets are never emitted at all.

Receivers MUST NOT treat a gap as an error condition, MUST NOT infer a loss rate
from gap counts, and MUST NOT use gaps to trigger resynchronization. Unlike a
dense counter, an offset sequence carries no information about how many
datagrams were sent, so the arithmetic that a counter permitted is simply
unavailable here.

A deployment that needs a loss-rate metric MUST carry a transmitted-datagram
count in application data, where the sender can state it directly.

## 11. Cold start and time recovery
### 11.1 The bootstrapping problem

CATP derives keys from wall-clock time (Section 9.2.4) and accepts only a
two-epoch window (Section 9.3). A device whose clock is not set to within
roughly two minutes of true time can neither produce a datagram any collector
will accept nor verify one it receives. It is not degraded; it is silent.

This is the price of having no handshake, and it is a real obstacle for the
device class CATP targets. A node without a battery-backed real-time clock boots
with no usable time. The obvious remedy — synchronize with NTP first — is
partly circular: unauthenticated NTP lets an attacker who can control the time
source choose the node's epoch, and authenticated time (NTS, RFC 8915) requires
the handshake and round-trips CATP exists to avoid.

Deployments with an authenticated time source available — GNSS, PTP, NTS, or a
battery-backed RTC set at manufacture — SHOULD use it, and MAY omit this section
entirely. TIME_REQUEST and TIME_ANNOUNCE exist for deployments that have none.
### 11.2 The time key

TIME_REQUEST and TIME_ANNOUNCE are authenticated under a key derived with
no epoch input, so that a node with no clock can use the protocol:

```
time_key = HKDF-Expand(
PRK,
info = "CATP1-time" || sender_id || direction,
L    = 32
)
```

with PRK as in Section 9.2.

The direction byte is part of the key derivation and has protocol meaning:

    0x00 — node to collector
    0x01 — collector to node

Thus TIME_REQUEST and TIME_ANNOUNCE use distinct directional keys even
though both are in the time-recovery domain. A receiver MUST verify a message
using the key for the message's defined direction; it MUST NOT accept a tag
generated with the opposite direction.

For TIME_REQUEST, sender_id identifies the node sending the request.
For TIME_ANNOUNCE, sender_id identifies the node to which the collector is
sending the announcement, as with all collector-to-node traffic (Section 4.4).

The distinct "CATP1-time" label domain-separates these keys from every
epoch_key, so possession of a time-recovery key grants nothing about an
epoch key. time_key is long-lived: it changes only when device_secret does.

Both message types use HMAC-SHA256 with the truncated tag defined for
cipher_id 0x01. This is required regardless of the suite configured for
the association. The time-recovery messages are not encrypted and do not use
the epoch-derived AEAD suite.
### 11.3 TIME_REQUEST (0x12)

TIME_REQUEST is sent by a node that has no valid clock to request a
TIME_ANNOUNCE from its collector.

The message has no payload.

A TIME_REQUEST MUST carry:

    sender_id — the node's identifier.
    cipher_id 0x01 (HMAC-SHA256, truncated).
    epoch_low 0b0000.
    header datagram_offset 0.

The MAC is computed over auth_header with epoch_id 0x00000000
(Section 7.1).

A node MUST send TIME_REQUEST only while it has no valid clock. It SHOULD
rate-limit requests and MUST NOT transmit them continuously. A recommended
implementation sends an initial request and retries with exponential backoff,
subject to a configured maximum rate.

The collector MUST verify the request under the node's time_key using
direction 0x00 before acting on it. An invalid request MUST be discarded
without producing a response.

A valid TIME_REQUEST does not itself establish or advance time. The collector
responds by sending a TIME_ANNOUNCE to the requesting node, subject to the
collector's own rate limits and time-availability policy.

TIME_REQUEST is intentionally small and carries no claimed time. In
particular, a node cannot use it to propose, select, or influence the time that
the collector will announce.

Because a captured TIME_REQUEST can be replayed, collectors MUST rate-limit
responses to repeated requests from the same node. Replay of a request can
cause an additional announcement, but cannot cause the collector to accept
attacker-chosen time or disclose epoch keys.
### 11.4 TIME_ANNOUNCE (0x11)

Payload:
Field	Width	Description
asserted_time	8 bytes	Collector's UTC seconds since 1970-01-01, signed 64-bit.

Header constraints. A TIME_ANNOUNCE MUST carry:

    sender_id — the node's identifier, as with all collector-to-node traffic
    (Section 4.4).
    cipher_id 0x01 (HMAC-SHA256, truncated). This is REQUIRED regardless of
    the suite configured for the association, and is the one place Section 8.3's
    configured-suite check is relaxed.
    epoch_low 0b0000 and header datagram_offset 0.

Receivers MUST reject a TIME_ANNOUNCE violating any of these. The MAC is
computed over auth_header with epoch_id 0x00000000 (Section 7.1), using
the collector-to-node time_key with direction 0x01.

cipher_id 0x01 is mandatory here because 0x03 is unusable: its nonce is
datagram_offset (Section 7.2), and a message transmitted outside any epoch has
no offset space to draw a unique nonce from. Two TIME_ANNOUNCE messages
asserting different times under a fixed time_key and a fixed zero offset
would repeat a Poly1305 nonce and disclose the key. A nonce-free MAC has no such
requirement, and the 64-bit tag is adequate for a message whose only effect is
bounded by Section 11.5.
### 11.5 Acceptance rules

A node MUST accept a TIME_ANNOUNCE only when all of the following hold:

    The node has no valid clock. A node whose clock is already set MUST silently
    discard TIME_ANNOUNCE without evaluating it further.
    The MAC verifies under the collector-to-node time_key, using direction
    0x01.
    asserted_time is strictly greater than last_epoch * 128, where
    last_epoch is the persisted value of Section 10.4.

On acceptance the node sets its clock to asserted_time, updates last_epoch
to floor(asserted_time / 128), persists it, and marks its clock valid. It MUST
then discard all further TIME_ANNOUNCE messages until its next cold start.

Rule 1 is what keeps this from being a clock-manipulation channel against
running nodes. Rule 3 is what keeps it from being a rollback channel: the node
will not accept a time at or before one it has already operated in, so a
captured TIME_ANNOUNCE cannot walk a node backwards into an epoch whose keys
an attacker has recovered.

The comparison in Rule 3 is against the persisted epoch floor, not against the
previous asserted_time. Consequently, an announcement within a later epoch
is sufficient even if its timestamp is less than a previously received
announcement that was never accepted. The protocol requirement is solely that
the accepted time lie strictly beyond the persisted last_epoch floor.

Note that Section 10.4's transmit rule composes with this: having set
last_epoch from asserted_time, the node still waits for the epoch to advance
past it before its first transmission.
### 11.6 Collector behaviour

A collector SHOULD respond to an authenticated TIME_REQUEST from a node that
has no usable clock by sending TIME_ANNOUNCE to that node. The collector MUST
rate-limit responses to repeated requests from the same node.

A collector SHOULD also transmit TIME_ANNOUNCE proactively to a node from
which it has received no authenticated datagram for a configured
silence_timeout, repeating at a rate-limited interval with exponential
backoff up to a configured ceiling. It SHOULD stop proactive announcements on
receipt of any authenticated datagram from that node.

RECOMMENDED defaults are a silence_timeout of 300 seconds, an initial
retransmission interval of 60 seconds, and a ceiling of 3600 seconds.

Silence usually means the node is powered off rather than clockless, so an
unthrottled collector would transmit continuously for the duration of every
outage, once per silent node.

TIME_REQUEST does not replace this proactive behavior. It provides a
clockless node with a way to solicit recovery when it is able to transmit but
has no epoch-derived keys.
### 11.7 Residual exposure

An attacker who can replay a captured TIME_ANNOUNCE to a booting node can pin
it to any time the collector genuinely asserted after that node's last_epoch —
that is, to a stale but real point in the past. The node then transmits in an
epoch the collector has long since moved past, its datagrams fall outside the
two-epoch acceptance window, and they are discarded.

An attacker who can replay a captured TIME_REQUEST can cause the collector to
send additional TIME_ANNOUNCE messages to the associated node, subject to the
collector's rate limits. The request contains no attacker-controlled time and
does not provide an authentication or key-recovery oracle.

The result is therefore still a denial-of-service exposure, not a forgery:
the attacker cannot choose an arbitrary time, cannot move a node backwards past
last_epoch, cannot affect a node with a working clock, and gains no key
material.

Deployments for which even this residual exposure is unacceptable MUST
provision an authenticated time source and disable TIME_REQUEST and
TIME_ANNOUNCE.


---

## 12. Security considerations

### 12.1 What CATP provides

Against an adversary who can observe, modify, inject, and replay datagrams but
does not hold key material: modification is detected, forgery is computationally
infeasible, replay is rejected, and records cannot be reattributed to another
node, another encoding, or another capture time.

### 12.2 Tag length

An 8-byte tag gives approximately 2^-64 blind forgery probability per attempt.
Because receivers discard failed datagrams silently, an attacker gains no oracle
and must attack online against the receiver's processing rate. This places
practical forgery far beyond reach for typical deployments.

Deployments with multi-year operational lifetimes, high-value telemetry, or
compliance requirements mandating 96-bit or larger tags SHOULD configure
`cipher_id` `0x03`, which carries a 16-byte tag at a cost of 12 additional bytes
per datagram over the shortest suite.

At the other end, `cipher_id` `0x04` offers a 4-byte tag and roughly 2^-32
forgery probability per attempt. That figure is only defensible in combination
with the mandatory receiver-side rate limit of Section 8.1.1, which converts it
from a number an attacker can grind down into one bounded by wall-clock time.
Section 8.1.1 states the conditions; deployments that cannot meet them MUST NOT
select `0x04`.

### 12.3 Key compromise

An adversary extracting a node's `device_secret` can derive all of that node's
epoch keys, past and future, along with its `time_key`, and can forge arbitrary
datagrams attributed to it. Epoch rotation limits the blast radius of an exposed
single `epoch_key` but provides no protection once `device_secret` is recovered.
Per Section 9.2.3, the exposure is confined to that one node.

CATP does not defend against physical device compromise. Deployments where key
extraction from a device is a realistic threat require either hardware-backed
key storage, a forward-secure construction such as a hash-chain scheme (RFC 4082
TESLA), or asymmetric signatures — each at materially higher per-datagram cost.

### 12.4 No confidentiality

Payloads are plaintext. Any observer reads all telemetry content.

The exposure is not limited to payloads. `msg_type`, `sender_id`, `format`,
and `datagram_offset` are all in the clear, so a passive observer learns which node
sent what kind of message, when each reading was captured, at what rate each
node reports, and — without decoding a single sample byte — every time a node
raises an `ALARM` or an `EVENT`. For many plausible deployments that metadata is
the sensitive part, and it remains visible even where the sample values are not
meaningful to an outsider.

Deployments MUST confirm that both telemetry content and this metadata are
acceptable to disclose before selecting CATP. Where they are not, CATP is the
wrong protocol; a tunnel around it does not fix the design, it replaces it.

### 12.5 Denial of service

An attacker can flood a receiver with junk datagrams, forcing MAC computations.
The cheap pre-MAC checks in Section 7.4 reduce but do not eliminate this. Rate
limiting at the network layer is RECOMMENDED where the threat is material.

Because `sender_id` selects exactly one key, cost is bounded at one MAC
computation per datagram regardless of fleet size. An attacker who guesses a
valid `sender_id` — they are not secret, and appear in plaintext on the wire —
can still force that one computation per datagram, so `sender_id` is an
efficiency mechanism, not a defence. Section 4.4.1's prohibition on multi-key
trial exists to preserve this bound.

An attacker cannot exhaust replay-window memory by varying offsets: the window
is a fixed-size bitmap over tick space, sized in Section 10.2 and independent of
how many distinct offsets are observed.

Per-`sender_id` state is allocated at provisioning time, not on first contact.
Receivers MUST NOT allocate state for an unknown `sender_id`, or an attacker can
exhaust receiver memory by emitting datagrams with varying identifiers.

### 12.6 Time synchronization

Epoch advancement depends on a shared time base. Endpoints whose clocks drift
beyond the acceptance window will fail to authenticate one another, and the
failure presents as a MAC error rather than as a clock error — a diagnostic trap
worth instrumenting for explicitly.

Deployments SHOULD provision time synchronization with accuracy well inside the
128-second epoch. An adversary able to manipulate a device's clock can influence
epoch selection and can silence a node; time sources SHOULD be authenticated
where this is a concern. Section 11 specifies what a node does when it has no
clock at all, and Section 11.6 bounds what an attacker gains from that path.

---

## 13. IANA considerations

This document defines no IANA registries. The cipher suite table of Section 8.1
is maintained by this specification, as is the `format` registry of Section
6.4.1; `schema_version` values are assigned by the deploying organization.

Deployments select UDP ports locally. No well-known port is requested.

---

## 14. Conformance

### 14.1 Test vectors

A conforming implementation MUST publish and validate against frozen test
vectors. This specification does not embed them, because they must be generated
by a reference implementation rather than written by hand; the reference
implementation accompanying this document publishes them as
[test-vectors.txt](test-vectors.txt). The required set is:

- One accepted datagram per `msg_type`, each giving `device_secret`,
  `sender_id`, `epoch_id`, `datagram_offset`, payload, derived key, and expected
  tag bytes, for every registered `cipher_id`, including the 4-byte tag of
  `0x04`.
- For `cipher_id` `0x03` specifically: two datagrams differing only in
  `datagram_offset`, demonstrating distinct nonces, plus the constructed
  13-byte `auth_header` as AAD, with the `epoch_low` bits shown zeroed.
- One rejected datagram per rejection path in Section 7.4, each isolating a
  single fault: short length, unsupported version, `msg_type` `0x00`, an
  unimplemented `msg_type`, unknown `sender_id`, mismatched `cipher_id`,
  out-of-window epoch, corrupted tag, replayed `datagram_offset`, an offset at
  or below the window.
- An **accepted** datagram carrying each non-zero value of the reserved bits,
  identical in every other respect to a baseline vector and producing identical
  application output, confirming must-ignore behaviour (Section 4.2).
- Framing faults, one per rejection clause of Section 6.4.3: a payload shorter
  than 4 bytes; a trailing fragment of fewer than 3 bytes; a `size` overrunning
  the payload; a `size` of 0; a parse ending past the payload boundary; records
  an `EVENT` carrying two records. Plus a record whose `size` disagrees with a
  fixed-width `(format, schema_version)` pair.
- A boundary set: `datagram_offset` at `0` and at `524287`, first datagram of a
  new epoch, `size` at 1 and at 4095, and a datagram from the preceding epoch
  arriving after an epoch change.
- `NUMBER` acceptance: `0`, `-0.5`, `23.50`, and a 32-byte literal. Plus
  rejections: empty, `23.`, `.5`, `007`, `-0`, `+1`, `1e3`, `1.2.3`, a 33-byte
  literal, and any payload containing a non-grammar byte.
- Cold start: a `TIME_ANNOUNCE` accepted by a clockless node, one rejected for
  asserting a time at or below `last_epoch * 128`, and one rejected because the
  node's clock is already valid.

Vectors are the only practical defence against two implementations that each
believe they are correct. An implementation validated only against itself has
tested its own misreadings.

### 14.2 Required adversarial tests

Functional tests do not exercise the properties this protocol exists to provide.
Implementations MUST additionally test:

- Replay of a previously accepted datagram, immediately and after an epoch
  change.
- Bit-flips in every header field, confirming rejection rather than
  misinterpretation. Reserved-bit flips MUST also be rejected, not ignored:
  ignoring applies to bits a legitimate sender set inside the MAC scope, and a
  flipped bit fails the tag.
- Truncation and extension of the payload.
- Clock skew driven past the acceptance window in both directions.
- An `EPOCH_ANNOUNCE` replayed from an earlier epoch.
- Datagrams bearing a valid `sender_id` signed with a different device's key.
- A record whose `schema_version` is swapped for another of identical body
  width, confirming rejection rather than misdecoding.
- A multi-record datagram in which one record carries an unrecognized `format`,
  confirming that record alone is skipped and the others are delivered
  (Section 6.4.4).
- One accepted record per assigned `format` value, each with a non-zero
  `schema_version`. Plus rejections: `format` `0x00`, `format` in the reserved
  `0x07`-`0x0F` range, and `schema_version` `0x00`.
- Offset exhaustion: a sender reaching `524287` within an epoch, confirming it
  ceases rather than wrapping.
- Two datagrams generated within one 1/4096-second tick, confirming the sender
  delays or coalesces rather than reusing an offset.
- A `NUMBER` and a `MESSAGE` at the same `datagram_offset` within one epoch,
  confirming the second is rejected: the replay window is per sender, not per
  message type.
- A record header exercising both straddling fields: `schema_version` `0xFF` and
  `size` `4095` in one word, confirming the implementation masks rather than
  reads bytes (Section 6.4).
- A header whose `datagram_offset` exceeds 65,535, confirming the implementation
  assembles all three bytes rather than reading bytes 3-4 as a u16
  (Section 4.1).
- **Simulated reboot mid-epoch**, confirming the sender resumes at a
  clock-derived offset beyond any it previously emitted, and waits at least one
  tick past start (Section 10.4).
- **A backward clock step** mid-epoch, confirming the sender refuses to emit an
  offset at or below its last (Section 10.4).
- **`TIME_ANNOUNCE` replay** against a booting node, confirming the monotonic
  floor of Section 11.4 rejects it.
- Under `cipher_id` `0x03`, confirming that no two transmitted datagrams within
  one epoch and direction share a nonce.
- Under `cipher_id` `0x04`, confirming the receiver enforces its inbound rate
  limit and that exceeding it is counted rather than silently absorbed.

### 14.3 Interoperability

Version 1 is not complete until two independently written implementations
interoperate against the vectors of Section 14.1. A specification exercised by a
single implementation has undiscovered ambiguities by default; the framing, key
derivation, and collector-identity sections of this document were each added or
rewritten after exactly such an ambiguity was noticed.

---

## 15. Open items

The following are deliberately unresolved and require deployment-specific
decisions:

1. **`device_secret` provisioning and rotation** (Section 9.2): generation,
   injection at manufacture, storage at rest, and post-compromise reissue are
   out of scope for this document and are the largest remaining deployment task.
2. **Layout definition and distribution** (Section 6.4.2.1): assignment of
   `schema_version` values per `format`, and the per-field layout, widths, and
   units behind each, must be defined, version-controlled, and distributed to
   collectors out of band. The protocol detects a mismatch; it does not resolve
   one.
3. **Time synchronization mechanism** (Sections 11, 12.6): whether a deployment
   provisions GNSS, PTP, NTS, or a battery-backed RTC — and therefore whether it
   enables `TIME_ANNOUNCE` at all — is unspecified.
4. **Whether `TIME_ANNOUNCE` is implemented at all** (Sections 11, 10.4): a
   node with an authenticated time source needs no non-volatile state, since the
   clock now supplies restart safety. A node without one needs `last_epoch`
   persisted as a monotonic floor. This is the remaining driver of whether a
   deployment needs writable storage on the node.
5. **Records per datagram and flush timer** (Section 6.6.1): must be chosen
   against measured loss rate and acceptable latency, not set to whatever
   `payload_budget` allows.
6. **`max_datagram_size`** (Section 3.1): the defaults are deliberately
   conservative. Raising them requires either full path control with direct
   measurement or an RFC 8899 implementation.
7. **Peak per-sender datagram rate** (Sections 10.1, 10.3): `datagram_offset`
   paces a sender to at most one datagram per 1/4096-second tick, 4096 per
   second.
   This is a pacing constraint, not a budget: a burst of two datagrams in one
   tick violates it however low the average rate. Deployments must confirm their
   burst behaviour coalesces into records rather than datagrams.
8. **Multi-collector deployments** (Section 9.2.3): separating collectors
   cryptographically requires an extension to the key derivation that this
   document does not define.
9. **Reserved bit assignment** (Section 4.2): the 2 must-ignore bits are
   unassigned, and matter more than they did, since Section 4.3 leaves only
   four wire versions in total. Any use must satisfy the semantic-optionality constraints of
   Section 4.2.2, which rule out most of what an extension typically wants to
   do; whether a worthwhile use exists is open.

---

## 16. References

- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication
- RFC 4082 — TESLA: Multicast Source Authentication Transform
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols
- RFC 8899 — Packetization Layer Path MTU Discovery for Datagram Transports
- RFC 8915 — Network Time Security for the Network Time Protocol
- RFC 768 — User Datagram Protocol
