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
| [`docs/test-vectors.json`](docs/test-vectors.json) | The same vectors, machine-readable. Generated from the same call sites as the text file, so they cannot drift. |
| [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) | Non-normative. Maps each §14.2 required adversarial test to the test that discharges it. |
| [`docs/CONFORMANCE_RUNNER.md`](docs/CONFORMANCE_RUNNER.md) | Non-normative. The subprocess contract a second implementation's own vector check speaks, plus the driver that runs it. |
| [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md) | Non-normative. Dependency policy: what a version bump requires, supply-chain tooling. |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Non-normative. The attacker capabilities Section 12's claims assume. |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability, and what's a documented non-goal rather than one. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Ground rules, especially for a second implementation. |

## Reference implementation

Rust, `unsafe_code` forbidden crate-wide, a two-package Cargo workspace
(issue #74): `catp` (this repository's root) is the library — codec, key
schedule, replay window, pacer — and `catp-tools` (`tools/`) holds the five
binaries below, so a build of the library alone (in particular, the `no_std`
bare-metal build) never touches anything binary-only needs.

`catp` has seven direct dependencies (`hmac`, `sha2`, `hkdf`, `subtle`,
`zeroize`, `siphasher`, `chacha20poly1305`) — RustCrypto crates plus their
constant-time and zeroizing-memory helpers, `siphasher` for cipher `0x02`,
`chacha20poly1305` for cipher `0x03` — pulling in their usual transitive tree
(`digest`, `crypto-common`, `typenum`, and the like). `catp-tools` adds
`getrandom`, for `catp-provision`'s CSPRNG need only. MSRV 1.88, tracked in
`Cargo.toml`'s `rust-version` and tested in CI.

`#![no_std]` (`catp`, `--no-default-features`, still needs `alloc`): the
codec, key schedule, replay window, and pacer build and lint clean against a
real bare-metal target (`thumbv7em-none-eabihf`), checked in CI as its own
job scoped to just this package — `catp-tools`'s binaries live in a separate
package now, so there's nothing `std`-only for that build to trip over.
`Collector` (the multi-peer, host-side registry) and `catp::provisioning`
(file I/O) are `std`-only — neither is something a constrained sender needs.
See [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md#no_std--alloc-issue-37) for
the feature flags and issue #37 for the allocation-free tier this doesn't
attempt.

```
src/lib.rs      key schedule, epoch math, replay window, NUMBER/SERIES codec, pacer
src/wire.rs     datagram and record codec, verification order of §7.4
src/control.rs  EPOCH_ANNOUNCE, TIME_ANNOUNCE, TIME_REQUEST, HEARTBEAT, CAPABILITY_ADVERTISE
src/peer.rs     per-epoch replay windows, multi-peer collector, cold-start clock
tools/src/bin/  catp-sender, catp-collector, catp-vectors, catp-provision, catp-conformance-iut
```

All four registered cipher suites are implemented: `0x01` (HMAC-SHA256,
8-byte tag), `0x02` (SipHash-2-4, 8-byte tag), `0x03` (ChaCha20-Poly1305,
AAD-only, 16-byte tag), and `0x04` (HMAC-SHA256, 4-byte tag).

### Running it

Start a collector:

```bash
cargo run --package catp-tools --bin catp-collector 127.0.0.1:9999
```

Point a sender at it — it emits MESSAGE, NUMBER, SERIES, EVENT, and ALARM
traffic:

```bash
cargo run --package catp-tools --bin catp-sender 127.0.0.1:9999 4
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

### Provisioning

Before any datagram can flow, a node and its collector each need the same
`sender_id`, `device_secret`, `cipher_id`, and layout list (PROTOCOL.md
§12.5, §9.2.1) — out-of-band, by design (§15). `catp-provision` generates,
inspects, and reissues the bundle files (`src/provisioning.rs`) that carry
that material between the two:

```bash
cargo run --package catp-tools --bin catp-provision -- generate --count 10 --cipher 01 --layouts 01:01,02:02 --out ./bundles
cargo run --package catp-tools --bin catp-provision -- inspect ./bundles/node-1a2b3c4d.bundle
cargo run --package catp-tools --bin catp-provision -- reissue ./bundles/node-1a2b3c4d.bundle --out ./bundles/node-1a2b3c4d.new.bundle
```

`catp-collector` accepts a bundle directory as an optional second argument to
bulk-provision from it, instead of the single hardcoded demo peer it uses
when none is given:

```bash
cargo run --package catp-tools --bin catp-collector 127.0.0.1:9999 ./bundles
```

Bundle files are `0600`-permissioned on Unix — a floor, not a substitute for
real secret storage; see `tools/src/bin/provision.rs`'s module docs for what this
tool deliberately does not attempt (an HSM backend, automated rotation, a
centralized `sender_id` registry for very large fleets).

### Tests

```bash
cargo test --workspace
```

Unit tests, end-to-end integration scenarios, and a conformance suite that
re-encodes every frozen vector and compares byte for byte. The vector suite is
what catches accidental wire-format drift — a dependency bump or a codec change
that alters any published byte fails it. `--workspace` also runs `catp-tools`'s
own unit tests (`tools/src/bin/*.rs`); plain `cargo test` from the repo root
only tests the `catp` library package, since the root `Cargo.toml` is both the
workspace manifest and that package's own manifest.

### Regenerating the vectors

Deliberate act, not a build step. Writes both the text file (to stdout, hence
the redirect) and `docs/test-vectors.json` (written directly by the binary):

```bash
cargo run --package catp-tools --bin catp-vectors > docs/test-vectors.txt
```

### Benchmarks

```bash
cargo bench
```

`encode`/`decode` cost, decode rejection cost by §7.4 step, and `epoch_key`
derivation cost. `docs/DEPLOYMENT.md` D2 has one worked run's numbers plus a
fleet-size memory table (`cargo run --release --example mem_probe`).

### Fuzzing

[`fuzz/`](fuzz/README.md) targets `decode` -- the entire pre-authentication
remote attack surface. CI runs both targets for a bounded 60 seconds per
push as a regression gate; see `fuzz/README.md` for running a real campaign
locally.

### Checking a second implementation against the vectors

`docs/CONFORMANCE_RUNNER.md` defines a small subprocess contract -- feed a
JSON-Lines vector on stdin, get `PASS`/`FAIL <reason>` back on stdout -- so a
second implementation can check itself against `docs/test-vectors.json`
without hand-writing a harness. `tools/run_conformance.py` (stdlib-only
Python) drives any program that speaks it:

```bash
python3 tools/run_conformance.py -- cargo run --quiet --package catp-tools --bin catp-conformance-iut
```

`catp-conformance-iut` is this crate's own reference implementation of that
contract, useful as a worked example and for exercising the driver in this
repository's own CI; it is not a substitute for `cargo test`'s conformance
suite (`tests/vectors.rs`), which remains this crate's authority on its own
conformance.

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
