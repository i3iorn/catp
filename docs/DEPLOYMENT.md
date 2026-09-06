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

### Fleet-size memory (issue #40)

§9.3 keeps two epoch windows live per peer (current and previous), so the
bitmap cost above is paid twice per `sender_id` at steady state. That's the
whole of it only in theory, though — a `Collector` entry also carries a
`HashMap` bucket, the peer's `PeerConfig` (including its layout list and
secret), and its `Stats` counters (#36), all of which cost real bytes this
document had never measured.

Measured with `cargo run --release --example mem_probe`
(`examples/mem_probe.rs`), which provisions N peers and forces two live
epoch windows each, then reads the process's actual RSS delta from
`/proc/self/status` — a real number, not just the bitmap arithmetic:

| Peers | Window (default, 1 s/4096 entries) | Measured, incl. overhead | Window (RECOMMENDED, 4 s/16384 entries)\* |
|---|---|---|---|
| 100 | 100 KiB | 228 KiB (2.3 KB/peer) | ~475 KiB |
| 1,000 | 1 MiB | 1.8 MiB (1.9 KB/peer) | ~4.6 MiB |
| 10,000 | 10 MiB | 17 MiB (1.8 KB/peer) | ~46 MiB |

\*Extrapolated, not measured directly: `Collector` does not currently expose
per-peer window sizing (only `PeerState::with_window` does, one layer down),
so the RECOMMENDED-window column is: measured fixed overhead per peer
(~762 bytes, back-solved as measured-minus-two-default-bitmaps at the
10,000-peer point) plus two RECOMMENDED-size (2 KiB) bitmaps. Confirms the
issue's own back-of-envelope figure: "~40 MB of replay bitmap alone" for a
10,000-node fleet at the RECOMMENDED window size is right, plus roughly
another 15% for everything else `Collector` holds per peer.

Measured on a 4-core Intel Xeon @ 2.80GHz (a CI-class VM, not the constrained
target class this protocol is designed for — see #37/#43, below). Numbers
here are for capacity planning on the *host* side (the collector), which is
where a fleet-scale memory budget actually matters; a constrained *sender*
holds state for one peer, itself, not a fleet.

### Receiver throughput and the DoS cost bound (issue #40)

§12.5's bound — "cost is bounded at one MAC computation per datagram
regardless of fleet size" — is structurally true but says nothing about the
absolute number, which is what actually tells an operator how much junk
traffic a collector survives. `cargo bench` (`benches/codec.rs`) measures it,
on the same host as the memory table above:

| Operation | Time | Implied single-core rate |
|---|---|---|
| `decode`, reject at step 1 (too short) | ~63 ns | ~15.9M/s |
| `decode`, reject at step 7 (auth failure — the expensive path) | ~4.1 µs | ~244K/s |
| `decode`, full accept (`NUMBER`) | ~4.2 µs | ~238K/s |
| `encode` (`NUMBER`) | ~4.1 µs | ~244K/s |
| `epoch_key` derivation (HKDF-Expand) alone | ~2.6 µs | -- |

Two things worth reading off this table:

1. **Steps 1-6 really are cheap relative to the MAC**, by roughly 65x (63 ns
   vs 4.1 µs) on this hardware — the pre-MAC filtering §7.4 mandates is doing
   real work, not just adding a branch.
2. **`epoch_key` derivation is ~63% of a `decode`'s total cost** (2.6 µs of
   4.1-4.2 µs). `decode` runs it fresh per datagram; caching it per
   `(sender_id, epoch_id, direction)` tuple — trivial since it changes at
   most once per epoch per peer — is the obvious optimization the issue
   asked whether anyone needed. Nobody has implemented it, so it remains
   optimization headroom rather than a measured requirement; a receiver
   pushing close to the ~244K/s ceiling above is where it would start to
   matter.

At ~244K/s worst-case single-core rejection rate, the §10.3 pacing ceiling
of 4096 datagrams/second per sender is nowhere near this hardware's limit —
but this is a CI-class x86 core, not the constrained sender class §3.1
targets, and no equivalent number exists yet for that class (blocked on
#37's `no_std` split or #43's C implementation actually running on target
hardware). Treat the *relative* costs above (which step is expensive, what
dominates `decode`) as portable; treat the absolute rates as this-machine
numbers only.

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
