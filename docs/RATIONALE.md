# CATP design rationale

**Non-normative.** Nothing here constrains an implementation. Every rule an
implementer must follow is in [PROTOCOL.md](PROTOCOL.md); this document explains
why some of the less obvious ones are the way they are. Guidance on the choices
the specification leaves to a deployment is in [DEPLOYMENT.md](DEPLOYMENT.md).

It exists because the audiences differ. Someone writing an implementation needs
the rules and needs to be sure they have not missed one. Someone deciding
whether the design is sound, or proposing to change it, needs the arguments.
Someone standing a fleet up needs neither, and needs to know what to choose.
Interleaving the three served none of them.

Each entry names the section it justifies.

---

## R1. Why fragmentation is worse here than usual

Justifies [PROTOCOL.md](PROTOCOL.md) §3.1.

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

## R2. Why the offset is in the header

Justifies [PROTOCOL.md](PROTOCOL.md) §4.1.

Every datagram needs a position within its epoch: it is the replay key
(Section 10), the nonce source for nonce-requiring suites (Section 7.2), and the
timestamp a receiver records against the reading.

Two things put it in the header rather than in the payload. `NUMBER` (Section 6.3) carries a bare
numeric literal with no record structure to hold an offset, and would otherwise
have needed the same payload-prefix workaround control messages used. And
because the offset was read from the payload, a receiver had to parse framing
before it could check replay, inverting the natural verification order
(Section 7.4).

In the header, every message type has an offset in the same place, readable
before the payload is touched, and Section 7.4 can check replay immediately
after the MAC rather than waiting for the payload to be parsed.

The cost is 3 bytes on every datagram, against 2 bytes saved on every record
(Section 6.4). A single-record datagram is 1 byte larger; ten records are 17
bytes smaller and fifty are 97 bytes smaller. The trade favours the batching
the protocol wants to encourage.

---

## R3. Why ignoring is safe here

Justifies [PROTOCOL.md](PROTOCOL.md) §4.2.

Must-ignore bits are normally a downgrade hazard: if an attacker can set a bit
that a receiver silently disregards, they can strip a security signal. That
does not apply here. The reserved bits sit inside the MAC scope (Section 7.3),
so an attacker cannot set, clear, or flip them without possessing the key. The
only party that can populate them is the legitimate sender, which is precisely
the party an extension is a message from.

What is lost is the free malformed-traffic check the old must-reject rule
provided, and the guarantee that an unaware receiver fails loudly rather than
quietly. The second is the real cost, and it constrains what may be built here.

---

## R4. What NUMBER costs against an equivalent MESSAGE

Justifies [PROTOCOL.md](PROTOCOL.md) §6.3.

At 41 bytes of IPv4 overhead, a `NUMBER` datagram is 44 bytes on the wire,
fixed, regardless of what it carries: 3 payload bytes every time. The
equivalent `MESSAGE` — a 3-byte record header plus the same 3-byte body,
`scale` included — is 47, and requires a provisioned layout at both ends.

`NUMBER` was ASCII in earlier drafts of this document, which put its cost
inside a range (`23.5` cost 4 payload bytes, longer values cost more) and made
the comparison against `MESSAGE` a near-tie for short values. Fixed-point
removes the range: every `NUMBER` costs exactly 3 payload bytes, so it is
strictly smaller than the equivalent `MESSAGE` by exactly the 3-byte record
header, every time. What `NUMBER` still gives up against `MESSAGE` is range and
precision beyond `i16` at a chosen `scale`, and the ability to carry more than
one field — for either of those, `MESSAGE` is the better choice.

---

## R5. Why cipher 0x03 requires a per-datagram nonce

Justifies [PROTOCOL.md](PROTOCOL.md) §7.2.

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

---

## R6. One field, three jobs

Justifies [PROTOCOL.md](PROTOCOL.md) §10.1.

`datagram_offset` serves as timestamp, sequence number, and nonce source at
once. It is monotonic within an epoch, unique per tick, and unlike a
free-running counter it means something.

Carrying one field rather than a counter and a timestamp separately buys three
things:

**Bytes off every datagram**, since one field serves as timestamp, sequence
number, and nonce source rather than three.

**Restart safety for free.** A counter restarts at zero when a device reboots,
reusing tuples it has already sent, and closing that would require a
non-volatile write per epoch. A clock does not rewind, so a rebooted sender's
offsets are naturally beyond any it has used. See Section 10.4.

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

---

## R7. Why `UNSTRUCTURED` is reserved rather than deployment-assigned

Justifies [PROTOCOL.md](PROTOCOL.md) §6.4.2.2.

`schema_version` is mandatory, and some payloads genuinely have no layout to
name: log lines, a relayed third-party blob, a body still being designed. Such a
deployment could pick any value out of `0x01`-`0xFE` and simply define it to
mean "opaque", which is what makes the reservation look unnecessary.

The objection to that is not correctness but legibility. A deployment-assigned
value declaring "no layout" is indistinguishable, on the wire and in a capture,
from one declaring a real layout. Every receiver and every operator then has to
consult out-of-band documentation to learn that `0x07` in this fleet means
"do not parse this". Reserving one value makes the absence of a layout a
property of the record rather than of the paperwork, which is what keeps the
rest of the range meaningful: `0x01`-`0xFE` are claims, and a claim can be
checked.

The reservation costs one value out of 255, in a field that increments when a
layout changes, for a deployment that has already revised one layout 253 times.

**What it does not protect.** The protocol cannot see inside an `UNSTRUCTURED`
body and therefore cannot version what is in there. A deployment that grows an
ad-hoc structure inside such a body and later reorders two fields reintroduces
exactly the silent misread §6.4.2.1 exists to prevent, one layer down, where
`schema_version` can no longer catch it. The failure is not new -- it is the
pre-`schema_version` failure, reachable by declining to use the field. This is
the standing argument against the value existing at all: an escape hatch is the
path of least resistance, and a deployment that defaults to `0xFF` never
versions anything. §6.4.2.2 answers it with a MUST NOT rather than by
withholding the value, on the grounds that a deployment determined to skip
layout discipline can already pin `0x01` forever. The specification can make the
label available and require it be resolvable; it cannot make a deployment
honest.

---

## R8. Why cipher selection is configured rather than negotiated

Justifies [PROTOCOL.md](PROTOCOL.md) §8.3.

An in-band mechanism for ratcheting cipher strength upward does not survive
contact with the provisioning model. A deployment that can distribute a 32-byte
`device_secret` out of band can distribute a one-byte cipher selection over the
same channel, and doing so gives a strictly stronger guarantee: configuration is
enforced from the first datagram, whereas a high-water mark is only as good as
the highest datagram a receiver happened to have seen.

A negotiated floor would also have no recovery path. Being monotonic and
persistent across restarts, it would let a single datagram verifying at an
elevated level permanently lock out a legitimate peer that later fell back, with
no way to clear it short of touching the receiver's storage. If an operator must
touch the receiver either way, the configuration is the better place to express
the policy.

`cipher_id` remains a header field despite carrying no negotiation. It costs no
additional bytes, it makes captured traffic self-describing during exactly the
migration window §8.3 describes, and it keeps the per-datagram check in §7.4 a
comparison rather than an assumption.

---

## R9. What a fleet-wide secret would cost

Justifies [PROTOCOL.md](PROTOCOL.md) §9.2.1.

A single fleet-wide secret would make `sender_id` decorative. Every node would
hold the key needed to produce a valid MAC over any `sender_id`, so any
compromised or malicious node could impersonate any other, and a receiver could
not distinguish them. The identity field would authenticate nothing.

Per-device secrets mean a receiver's key lookup *is* the identity check, and
compromise of one device exposes that device's traffic and no other's. That is
the whole of what `sender_id` is worth, which is why the prohibition is absolute
rather than a recommendation: the storage it saves is a few hundred kilobytes at
the fleet sizes of §4.4.1, and what it spends is every identity guarantee in the
protocol.

Deriving per-device keys from a fleet root is the same failure wearing a KDF.
The root reduces provisioning cost by existing in one place, and any device
whose root is extracted yields every other device's key.

---

## R10. Why the collector has no identity of its own

Justifies [PROTOCOL.md](PROTOCOL.md) §9.2.3.

Giving the collector its own `sender_id` and `device_secret`, as a naive reading
of "sender" would suggest, quietly destroys the property §9.2.1 establishes.
Every node would need the collector's secret in order to verify
collector-originated messages. That single secret would then sit in the firmware
of every device in the fleet, and extracting it from any one node would let the
attacker impersonate the collector to every other node. It is the fleet-wide-key
failure of R9, reintroduced through the return path.

Under the arrangement §9.2.3 specifies, extracting a node's secret yields the
ability to forge collector traffic to **that node only** — which the attacker
already fully controls — so the return path adds no blast radius beyond the
compromise itself.

---

## R11. Why `scale` is a payload byte, not a reserved-bit selector

Justifies [PROTOCOL.md](PROTOCOL.md) §6.3.1.

The reserved bits of §4.2 look like the obvious place for a small selector:
`scale` needs only 3 bits, and 5 sit unused in every header. §4.2.1 rules this
out categorically, not as a style preference. An extension assigned to a
reserved bit MUST be semantically optional — a receiver ignoring it must still
reach a *correct, if less informed*, reading of the datagram. A receiver
ignoring an unknown `scale` cannot do that: it would decode `mantissa` as a
different value than the sender asserted, silently. That is misinterpretation,
not under-interpretation, which is precisely the failure §4.2.1 names a channel
or stream selector as an example of and forbids outright.

The distinction that matters is where the bits are checked. A receiver that
does not recognize a `NUMBER` datagram at all — an unsupported `version`, an
unimplemented `msg_type` — never reaches the byte that names `scale`, exactly
as it never reaches any other payload byte. A receiver that does recognize
`NUMBER` is already committed to parsing this specific 3-byte layout, and
`scale` is one more field inside it, no different in kind from `mantissa`
itself. Payload bytes are read by receivers that already know the format;
reserved bits are read by receivers that do not. `scale` belongs with the
former, unconditionally.

The cost is one byte per reading rather than zero. That byte is also what keeps
the reserved bits available for the extensions §4.2.1 actually permits, in a
space `PROTOCOL.md` §15 item 9 already flags as scarce.

---

## R12. What SERIES costs, and why a delta rather than an absolute offset

Justifies [PROTOCOL.md](PROTOCOL.md) §6.9.

Ten readings as individual `NUMBER` datagrams cost `10 * 44 = 440` bytes (R4's
44-byte figure: 41 bytes of fixed overhead plus 3 payload bytes, each paid ten
times). The same ten readings as one `SERIES` cost `41 + 1 + 2 + 9*4 = 80`
bytes: the 41-byte fixed overhead paid once, `scale` once, the first reading's
`mantissa`, and nine `(delta, mantissa)` pairs for the rest. `SERIES` wins by
amortizing exactly the cost R2 identifies `datagram_offset` as already
carrying for free in a single-reading datagram — the header's one instant — but
recovers the ability to give each reading its own, which batching into
`MESSAGE` cannot do at all (§6.4.1).

Each reading after the first costs a `delta` plus a `mantissa`: 4 bytes,
against 44 for the same reading sent alone. The saving is the header and tag
paid once instead of `n` times, which is the same batching argument
§6.6 makes for `MESSAGE` — `SERIES` is that argument applied to one field
sampled repeatedly rather than several fields sampled once.

`delta` is an offset from the *previous* reading, not from the datagram's own
`datagram_offset`: consecutive real samples are close together, so the
quantity that has to be wide is the gap between two adjacent samples, not the
span from the first sample to the last. A `u16` delta covers gaps up to
65535 ticks — approximately 16 seconds — between any two consecutive readings
in one datagram; a deployment sampling more sparsely than that either flushes
smaller batches (a `SERIES` of two is still cheaper than two `NUMBER`s) or
accepts individual `NUMBER` datagrams for that quantity. An absolute offset per
reading would need the same 19 bits `datagram_offset` itself uses to span an
epoch, three bytes rather than two, to buy range no real batch needs: two
samples far enough apart to want it are two samples that do not benefit from
batching in the first place.

---

## R13. Why `cipher_id` 0x02 truncates `epoch_key` rather than re-deriving

Justifies [PROTOCOL.md](PROTOCOL.md) §7.2.

`epoch_key` is a fixed 32 bytes regardless of which suite consumes it (§9.2),
but SipHash-2-4's native key is 128 bits, not 256. Two ways to close that gap:
truncate `epoch_key` to its first 16 bytes, or call HKDF-Expand a second time
with a 16-byte output length specific to `0x02`.

Truncation is what the specification requires, for two reasons:

1. **It costs nothing extra to verify.** `epoch_key` is already computed once
   per datagram today (`docs/DEPLOYMENT.md` D2 notes caching it per epoch as
   unimplemented future headroom); slicing its first 16 bytes is free either
   way. A second HKDF-Expand call is a second HMAC computation,
   doubling the per-datagram key-derivation cost for `0x02` specifically --
   the one suite this protocol offers *because* a sender finds SHA-256
   disproportionately expensive (§8.1.1). Making that sender's cheap cipher
   secretly require two HMAC-SHA256 computations to key would defeat the
   point of offering it.
2. **It is not a novel construction.** HKDF-Expand's output for a given
   `(PRK, info)` pair is indistinguishable from random up to its requested
   length; the first 16 bytes of a 32-byte pseudorandom string are
   themselves 16 bytes of pseudorandom output. This is the same "take a
   prefix of a longer derived key" pattern used throughout key-derivation
   practice (e.g. HKDF's own multi-key-from-one-`okm` usage), not something
   specific to this protocol that would need its own security argument.

The MUST NOT on using the remaining 16 bytes for anything exists so that a
future suite added at this cipher width can't accidentally end up keyed with
material `0x02` has already exposed the derivation of (via its tag, to anyone
who could break SipHash-2-4) -- there is currently no such suite, but the
prohibition is cheap and forecloses the question.

---

