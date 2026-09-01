# CATP open issues

Review of commit `e1122fd` (spec v1 draft + reference implementation).

Severity: **blocker** = interoperability is impossible or wrong until fixed;
**high** = silently wrong behaviour; **medium** = correctness risk or
maintenance hazard; **low** = hygiene.

---

## 1. Spec contradicts itself on three control `msg_type` values — blocker

The §6.2 table and the section headings disagree. Three of the five control
types have two different assignments in the same document:

| Type | §6.2 table | Elsewhere |
|---|---|---|
| `TIME_ANNOUNCE` | `0x11` | `0x15` (§11.4 heading) |
| `HEARTBEAT` | `0x13` | `0x12` (§6.7 body text) |
| `CAPABILITY_ADVERTISE` | `0x14` | `0x21` (§6.7.1 heading) |

`TIME_REQUEST` is `0x12` in both places, but `0x12` is *also* where the §6.7
text puts `HEARTBEAT`, so the collision is live rather than merely editorial.

`0x21` is not even representable: `msg_type` has been 5 bits since the header
was repacked (§4.1), so the range is `0x00`–`0x1F`. That heading is a leftover
from the 6-bit numbering and cannot be right under any reading.

**Fix.** Pick one assignment and make §6.2 the single authority, then correct
the §11.4 and §6.7.1 headings and the §6.7 body reference to match. Everything
downstream (issues 2 and 3) depends on this being settled first.

---

## 2. Frozen test vectors encode the superseded numbering — blocker

`docs/test-vectors.txt` was generated before the renumbering. It contains:

```
msg_type     12   # labelled "HEARTBEAT, empty payload"
msg_type     13   # labelled "CAPABILITY_ADVERTISE"
```

Under the §6.2 table those bytes now mean `TIME_REQUEST` and `HEARTBEAT`.

This matters more than an ordinary stale artifact. §14.1 makes the vectors the
conformance authority, and §14.3 says version 1 is not complete until two
independent implementations interoperate against them. A second implementation
written today would faithfully reproduce the wrong message types and believe it
had passed.

**Fix.** After issue 1 is settled, regenerate:

```
cargo run --bin catp-vectors > docs/test-vectors.txt
```

Then add a `TIME_REQUEST` vector, which has none, and confirm
`cargo test --test vectors` still passes.

---

## 3. Implementation is behind the spec on time recovery — blocker

`src/lib.rs` and `src/wire.rs` predate the §11 rework:

- `MsgType` has `TimeAnnounce = 0x11`, `Heartbeat = 0x12`,
  `CapabilityAdvertise = 0x13`, and **no `TimeRequest` at all**.
- `DeviceSecret::time_key(sender_id)` hardcodes
  `Direction::CollectorToNode`. §11.2 now takes `direction` as a key-derivation
  input precisely so `TIME_REQUEST` (`0x00`) and `TIME_ANNOUNCE` (`0x01`) get
  distinct keys, and requires that a receiver "MUST NOT accept a tag generated
  with the opposite direction". The current signature cannot express that.
- There is no `TIME_REQUEST` encoder, no verifier, and no node-side backoff.

**Fix.** Change `time_key(sender_id, direction)`, renumber `MsgType` to match
issue 1, add `Datagram::time_request` / `decode_time_request`, and extend
`NodeClock` with the request-side rate limiting §11.3 requires. Note that
changing `time_key` changes the published `time_key` value in the vectors, so
this must land together with issue 2.

---

## 4. Reference sender reuses one `schema_version` for four incompatible layouts — high

`src/bin/sender.rs` tags every record `(Format::None, schema_version = 1)`, but
emits four different body layouts behind that one pair:

| Message | Body layout |
|---|---|
| `MESSAGE` | 12 bytes: `u16` seq, `i16` temp, `u16` humidity, `u16` pressure, `u16` battery, `i16` rssi |
| `EVENT` | `u16` seq + variable-length ASCII event name |
| `ALARM` | `u16` seq + `u8` severity length + ASCII severity + ASCII message |

§6.4.2.1 is explicit: "Any change to field layout, field widths, field order, or
units MUST be published as a new `schema_version`. Values MUST NOT be redefined
once deployed."

**This is not theoretical — it is reproducible today.** Running the pair:

```
sender:    sent EVENT ... seq=3 event=configuration_changed
collector: MESSAGE seq=3     temp=254.55C
```

`254.55` is the ASCII bytes `"co"` (`0x63 0x6F` = 25455) decoded as
centidegrees. The datagram authenticated correctly, framed correctly, and
produced a plausible-looking wrong reading — exactly the failure mode
`schema_version` was introduced to make impossible. The reference
implementation currently demonstrates the bug rather than the defence.

**Fix.** Allocate a distinct `schema_version` per layout (e.g. sensor tuple = 1,
event = 2, alarm = 3) and provision the collector with all three.

---

## 5. Collector ignores `msg_type` and indexes record bodies unchecked — high

Two defects in the same loop, `src/bin/collector.rs:76-83`:

```rust
for r in &acc.datagram.records {
    let seq  = u16::from_be_bytes([r.body[0], r.body[1]]);
    let temp = i16::from_be_bytes([r.body[2], r.body[3]]);
    println!("... MESSAGE seq={seq} temp={temp}");
}
```

**(a) `msg_type` is never consulted.** Every record is labelled `MESSAGE` and
decoded as the sensor layout, whether it arrived as `MESSAGE`, `EVENT`, or
`ALARM`. This is the proximate cause of the output in issue 4, and it would
remain wrong even after issue 4 is fixed, because the collector would then skip
the records as unknown layouts without ever saying which type they were.

**(b) Unchecked indexing — panic on a short body.** `r.body[3]` is read with no
length check. §6.4.3 permits `size` as low as 1, so any authenticated peer
sending a 1-byte record body terminates the collector process. Identified by
code inspection; not reproduced, because the current sender happens never to
emit a body shorter than 6 bytes.

That an authenticated peer can crash the receiver is worth treating as more than
cosmetic: §12.5 reasons carefully about bounding *pre*-authentication cost, and
a post-authentication panic bypasses all of it.

**Fix.** Match on `acc.datagram.msg_type`, dispatch per
`(format, schema_version)`, and validate `body.len()` before slicing.

---

## 6. `Pacer` is duplicated between the sender and the library — medium

`src/bin/sender.rs:34-68` defines a private `Pacer` that is a near-copy of
`catp::Pacer` in `src/lib.rs`. The library version is the tested one (four unit
tests: repeated tick, backward clock step, epoch rollover, simulated reboot);
the binary's copy has none.

They already differ. The library tracks `epoch: Option<u32>`; the binary uses
`epoch: u32` initialised to `0`, so a first datagram in epoch 0 would not reset
`last_offset`. Unreachable in practice — epoch 0 is 1970 — but it is exactly the
kind of divergence that duplication produces, and the next one may not be
harmless.

**Fix.** Delete the private copy and use `catp::Pacer`.

---

## 7. `last_epoch` cross-references point at the wrong section — medium

§11.5 twice cites "the persisted value of Section 10.5". §10.5 is *Offset gaps
are not errors*; the persistence rule is in §10.4 *Restart behaviour*.

Both references resolve to a real heading, so the automated check does not catch
them — they are simply pointing somewhere unhelpful. An implementer following
the citation finds a section that never mentions `last_epoch`.

**Fix.** Change both to §10.4.

---

## 8. `TIME_REQUEST` replay is bounded only by an unspecified rate limit — medium

§11.3 acknowledges that a captured `TIME_REQUEST` can be replayed and requires
collectors to "rate-limit responses to repeated requests from the same node",
but gives no default — unlike §11.6, which specifies `silence_timeout` 300 s,
initial retry 60 s, ceiling 3600 s for the announce side.

The structural reason it cannot be handled the usual way is worth stating in the
document: `TIME_REQUEST` carries `datagram_offset` 0 by construction, so the
replay window of §10.2 cannot cover it. Rate limiting is not defence in depth
here, it is the entire defence, and a deployment that omits it turns one
captured request into an unbounded `TIME_ANNOUNCE` generator.

**Fix.** State a RECOMMENDED default response rate, and say explicitly why the
replay window does not apply.

---

## 9. Repository hygiene — low

- `.idea/` is untracked but not ignored; it contains machine-specific
  `workspace.xml`. Add it to `.gitignore`.
- No `README`. A reader arriving at the repository has no entry point, and no
  statement that this is a hobby protocol rather than something to deploy.
- No `LICENSE`. Absent one, the default is all-rights-reserved, which blocks the
  second independent implementation §14.3 requires.
- `Cargo.toml` moved to `hmac 0.13` / `sha2 0.11` / `hkdf 0.13`, which are
  pre-1.0 and still moving. `Cargo.lock` is committed, so this is pinned — worth
  keeping that way rather than relaxing it.
