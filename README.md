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
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Non-normative. Choosing the things the specification deliberately leaves open. |
| [`docs/test-vectors.txt`](docs/test-vectors.txt) | Frozen conformance vectors (§14.1). The authority a second implementation checks itself against. |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Non-normative. The attacker capabilities Section 12's claims assume. |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability, and what's a documented non-goal rather than one. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Ground rules, especially for a second implementation. |

## Reference implementation

Rust, no unsafe, three dependencies (`hmac`, `sha2`, `hkdf`).

```
src/lib.rs      key schedule, epoch math, replay window, NUMBER/SERIES codec, pacer
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

Point a sender at it — it emits MESSAGE, NUMBER, SERIES, EVENT, and ALARM
traffic:

```bash
cargo run --bin catp-sender 127.0.0.1:9999 4
```

```
127.0.0.1:46229  t=1788274214.060  MESSAGE  temp=24.52C humidity=38.3% pressure=1012.3hPa battery=89% rssi=-68dBm
127.0.0.1:46229  t=1788274214.060  MESSAGE  unstructured( 69B) "temp=24.52C humidity=38.3% pressure=1012.3hPa battery=89% rssi=-68dBm"
127.0.0.1:46229  t=1788274214.561  EVENT    seq=3     configuration_changed
127.0.0.1:46229  t=1788274215.062  ALARM    seq=5     [CRITICAL] sensor_failure
127.0.0.1:46229  t=1788274215.813  NUMBER   20.38
127.0.0.1:46229  t=1788274216.375  SERIES   19.47
127.0.0.1:46229  t=1788274216.424  SERIES   24.18
127.0.0.1:46229  t=1788274216.473  SERIES   20.38
```

The three `SERIES` lines above come from a single datagram: one quantity
batched across time, each reading still carrying the instant it was actually
taken (§6.9) — unlike a `MESSAGE` batch, which shares one capture instant
across all its records (§6.4.1).

Each MESSAGE carries one observation as two records: once under a layout the
collector holds a definition for, and once as `schema_version` `0xFF`
(`UNSTRUCTURED`, §6.4.2.2), where the sender claims no layout and the collector
may only hand the octets back. Both records share the datagram's one capture
instant, which is what §6.4.1 requires of a batch.

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
implementation has undiscovered ambiguities by default. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the ground rules — in particular,
implement from the specification, not from `src/`.

Open issues are tracked on GitHub. Found a vulnerability? See
[`SECURITY.md`](SECURITY.md) rather than filing a public issue.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
