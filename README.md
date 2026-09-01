# CATP — Compact Authenticated Telemetry Protocol

Authenticated, connectionless telemetry over UDP. No handshake, no round trips,
no encryption.

CATP authenticates every datagram with a MAC and derives its keys from the
wall clock rather than from a handshake, so a sender can transmit its first
datagram without ever having heard from the collector. Fixed overhead is
**41 bytes over IPv4** including the IP and UDP headers.

> **This is a hobby protocol.** It has one implementation, has had no external
> review, and version 1 is still a draft. Section 14.3 of the specification says
> version 1 is not complete until two independently written implementations
> interoperate; that has not happened. Do not deploy it anywhere the
> consequences matter.

## What it does and does not do

**Does:** detects modification, forgery, and replay; names its sender inside the
authenticated region; survives arbitrary packet loss with no recovery mechanism;
timestamps every datagram to ~244 µs; runs on a node with no real-time clock.

**Does not:** encrypt anything — payloads are plaintext and so is the metadata
around them; acknowledge, retransmit, or order datagrams; negotiate anything in
band; defend against an attacker who has extracted a device's key.

If your telemetry content is itself sensitive, CATP is the wrong protocol. See
§12.4.

## Documents

| | |
|---|---|
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | The specification. Version 1, draft. |
| [`docs/RATIONALE.md`](docs/RATIONALE.md) | Non-normative. Why the less obvious rules are the way they are. |
| [`docs/test-vectors.txt`](docs/test-vectors.txt) | Frozen conformance vectors (§14.1). The authority a second implementation checks itself against. |

## Reference implementation

Rust, no unsafe, three dependencies (`hmac`, `sha2`, `hkdf`).

```
src/lib.rs      key schedule, epoch math, replay window, NUMBER grammar, pacer
src/wire.rs     datagram and record codec, verification order of §7.4
src/control.rs  EPOCH_ANNOUNCE, TIME_ANNOUNCE, TIME_REQUEST, HEARTBEAT, CAPABILITY_ADVERTISE
src/peer.rs     per-epoch replay windows, multi-peer collector, cold-start clock
```

Cipher suites `0x01` (HMAC-SHA256, 8-byte tag) and `0x04` (4-byte tag) are
implemented. `0x02` (SipHash) and `0x03` (ChaCha20-Poly1305) are registered in
the type but return `CipherUnimplemented` rather than pretending.

### Running it

Start a collector:

```bash
cargo run --bin catp-collector 127.0.0.1:9999
```

Point a sender at it — it emits MESSAGE, NUMBER, EVENT, and ALARM traffic:

```bash
cargo run --bin catp-sender 127.0.0.1:9999 4 3
```

```
127.0.0.1:52764  t=1788271313.368  MESSAGE  seq=1  temp=24.52C humidity=38.3% ...
127.0.0.1:52764  t=1788271313.702  EVENT    seq=3  configuration_changed
127.0.0.1:52764  t=1788271314.035  ALARM    seq=5  [CRITICAL] sensor_failure
```

### Tests

```bash
cargo test
```

Unit tests, end-to-end integration scenarios, and a conformance suite that
re-encodes every frozen vector and compares byte for byte. The vector suite is
what catches accidental wire-format drift — a dependency bump or a codec change
that alters any published byte fails it.

### Regenerating the vectors

Deliberate act, not a build step:

```bash
cargo run --bin catp-vectors > docs/test-vectors.txt
```

## Contributing

The most useful contribution is a **second implementation in another language**,
validated against `docs/test-vectors.txt`. A specification exercised by one
implementation has undiscovered ambiguities by default.

Open issues are tracked on GitHub.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
