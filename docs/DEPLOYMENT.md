# CATP deployment guide

**Non-normative.** Nothing here constrains an implementation. Every rule an
implementer must follow is in [PROTOCOL.md](PROTOCOL.md); the reasoning behind
the less obvious ones is in [RATIONALE.md](RATIONALE.md). This document is for
the third audience: someone standing a fleet up, who has to make the choices the
specification deliberately leaves open.

The specification says what a conforming implementation does. It does not say
which cipher suite your fleet should use, how large to size a replay window, or
what to do about key provisioning — those depend on your link, your threat
model, and your hardware. Answering them is the deployment task, and getting
them wrong produces a deployment that conforms to the letter of the protocol and
still fails in the field.

Each entry names the section it elaborates.

---

## D1. Choosing a cipher suite

Elaborates [PROTOCOL.md](PROTOCOL.md) §8.1.1.

`0x04` is the right default for battery-powered or duty-cycled links where bytes
translate directly into energy, and for deployments whose telemetry has little
value to an attacker. It is the wrong choice for anything where a single forged
reading has consequence, or where the receiver cannot rate-limit. Where the
threat model is unclear, `0x01` is the safer default and costs 4 bytes.

Note that the rate limit is not advice at `0x04`. §8.1.1 makes it a MUST, and
forbids selecting the suite where the limit cannot be enforced — at 8 bytes rate
limiting is defence in depth, while at 4 bytes it is what makes the tag length
defensible at all.

Migrating between suites is a provisioning operation, not a negotiation, and
there is a window during which datagrams are rejected. §8.3 gives the ordering
and the option that closes the gap.

---

## D2. Sizing the replay window

Elaborates [PROTOCOL.md](PROTOCOL.md) §10.2.

The RECOMMENDED 16,384 entries is 2 KiB of state per `sender_id` per epoch, and
because offsets are clock ticks it buys exactly 4 seconds of reordering
tolerance — a figure that does not change with the sender's rate.

The finer tick makes this window eight times larger in entries than the same
tolerance would have cost at a coarser tick. A receiver tracking many senders
may prefer a 1-second window (4096 entries, 512 bytes), which still exceeds
observed reordering on most paths by a wide margin. Deployments going the other
way — paths with known worse reordering — size in seconds and convert:
`entries = tolerance_seconds * 4096`.

Size this against measured reordering on your own paths. The cost of a window
too small is silently discarded legitimate traffic; the cost of one too large is
memory multiplied by your fleet size.

---

## D3. Choosing a format

Elaborates [PROTOCOL.md](PROTOCOL.md) §6.4.2.

`NONE` (`0x01`) is the right choice for fixed-width binary telemetry, where the
body is a handful of packed fields and any self-describing encoding would cost
more than the data.

A self-describing encoding — `CBOR`, `MSGPACK` — earns its overhead when bodies
vary in shape between readings, or when a body outlives the code that wrote it
by long enough that a field definition alone is a fragile contract. It does not
remove the need for a `schema_version`: those encodings carry the *shape* of the
data but not what a field means or in what units (§6.4.2.1).

No text format is registered. A deployment that wants text carries it under
`NONE`, or under `UNSTRUCTURED` (§6.4.2.2) where no field definition exists at
all.

---

## D4. Decisions a deployment must make

Elaborates [PROTOCOL.md](PROTOCOL.md) §15.

The following are deliberately unresolved in the specification. Each is a choice
a deployment makes for itself; none has a default this document can supply.

1. **`device_secret` provisioning and rotation** (§9.2): generation, injection
   at manufacture, storage at rest, and post-compromise reissue are out of scope
   for the specification and are the largest remaining deployment task. Note
   that §9.2.1 forbids the two shortcuts that would make it easy — a fleet-wide
   secret, and per-device keys derived from a fleet root.

2. **Layout definition and distribution** (§6.4.2.1): assignment of
   `schema_version` values per `format`, and the per-field layout, widths, and
   units behind each. The protocol detects a mismatch; it does not resolve one.
   §6.4.2.1 requires these definitions be version-controlled and distributed to
   collectors out of band.

3. **Time synchronization mechanism** (§§11, 12.6): whether a deployment
   provisions GNSS, PTP, NTS, or a battery-backed RTC — and therefore whether it
   enables `TIME_ANNOUNCE` at all.

4. **Whether `TIME_ANNOUNCE` is implemented at all** (§§11, 10.4): a node with
   an authenticated time source needs no non-volatile state, since the clock
   supplies restart safety. A node without one needs `last_epoch` persisted as a
   monotonic floor. This is the remaining driver of whether a deployment needs
   writable storage on the node.

5. **Records per datagram and flush timer** (§6.6.1): chosen against measured
   loss rate and acceptable latency, not set to whatever `payload_budget`
   allows. Batching `n` records converts scattered single-record gaps into a `p`
   probability of an `n`-record blackout at loss rate `p`. Trend data usually
   tolerates this; data where short gaps are material does not.

6. **`max_datagram_size`** (§3.1): the defaults are deliberately conservative.
   Raising them requires either full path control with direct measurement or an
   RFC 8899 implementation.

7. **Peak per-sender datagram rate** (§§10.1, 10.3): `datagram_offset` paces a
   sender to at most one datagram per 1/4096-second tick, 4096 per second. This
   is a pacing constraint, not a budget: a burst of two datagrams in one tick
   violates it however low the average rate. §10.3 requires a deployment to
   confirm that its burst behaviour coalesces into records rather than
   datagrams.

8. **Multi-collector deployments** (§9.2.3): separating collectors
   cryptographically requires an extension to the key derivation that the
   specification does not define. Until then, any party holding a node's
   `device_secret` can speak to it as the collector.

9. **Reserved bit assignment** (§4.2): the 5 must-ignore bits are unassigned,
   and matter more than they did, since §5 leaves only seven unassigned wire
   versions. The semantic-optionality constraints of §4.2.1 rule out most of
   what an extension typically wants to do; whether a worthwhile use exists is
   open.

---
