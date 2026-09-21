# Conformance runner contract

Non-normative, tooling rather than protocol content. Addresses issue #35: a
second implementation (#43-#46) needs a language-neutral way to check itself
against `docs/test-vectors.json` without hand-writing a harness, and this
project needs a language-neutral way to drive that check in CI once a second
implementation exists.

This document defines a small subprocess protocol — the **implementation
under test (IUT) contract** — plus `tools/run_conformance.py`, a stdlib-only
driver that speaks it. `src/bin/conformance_iut.rs` (`catp-conformance-iut`)
is the reference IUT: it implements this contract against the Rust crate
itself, and is what proves the contract is actually implementable rather than
only specified.

## Scope

This is a **static vector conformance check**: does the IUT's codec agree
with `docs/test-vectors.json` (PROTOCOL.md §14.1) byte for byte? It is not a
live interop test between two running implementations exchanging real
datagrams over a socket — that mode is deliberately deferred (see
"Not covered here" below) until a second implementation exists to interop
with.

## The IUT contract

An IUT is any executable that:

1. Reads a stream of **JSON Lines** on stdin — one JSON object per line, each
   object being exactly one element of the `docs/test-vectors.json` array (in
   the field shapes below). The stream ends at EOF.
2. For each input line, performs the check its `kind` field names (below) and
   writes **exactly one line** to stdout before reading the next input line:
   - `PASS`, if the check succeeded, or
   - `FAIL <reason>`, if it did not — `<reason>` is a short, single-line,
     human-readable string (no newlines); its exact wording is not checked by
     the driver, only its presence.

   Nothing else goes to stdout — no banners, no progress output, no blank
   lines. Diagnostics, logging, and anything else an implementer wants to see
   belong on stderr, which the driver does not interpret.
3. Exits `0` if every line it wrote was `PASS`, and non-zero otherwise. (The
   driver determines pass/fail from the stdout lines, not the exit code, but
   a correct exit code lets the IUT be scripted directly in CI without the
   driver.)

Input and output are **strictly ordered and 1:1**: line *N* of output is the
verdict for line *N* of input. An IUT that buffers all input before emitting
any output is conformant; an IUT that emits output before reading the
corresponding input line is not (its output would not be attributable).

### Vector `kind`s and what "PASS" means for each

All hex fields are lowercase, no `0x` prefix, exactly as `docs/test-vectors.json`
already writes them. Integers are JSON numbers. Fields not listed for a given
`kind` may be absent; an IUT MUST NOT reject a vector object for carrying an
unrecognized *extra* field (forward compatibility: this contract may grow new
informational fields without becoming a breaking change).

- **`accept`** — fields: `device_secret` (32-byte hex), `sender_id` (hex,
  §4.4.1), `epoch_id` (integer), `direction` (`"00"` = node-to-collector,
  `"01"` = collector-to-node, §9.2.4), `cipher_id` (hex, §8.1), `msg_type`
  (hex), `offset` (integer, `datagram_offset`), `wire` (hex, the full UDP
  payload), `wire_len` (integer, byte length of `wire`).

  The IUT must decode `wire` as a datagram from `sender_id` under
  `device_secret`/`cipher_id`, treating `epoch_id` as the receiver's current
  epoch (so there is no clock skew to reason about) and `direction` as given,
  and the decode must succeed — every check PROTOCOL.md §7.4 requires must
  pass, including the MAC. The IUT must then **re-encode** the datagram it
  just decoded, from the same `sender_id`/`device_secret`/`epoch_id`/`direction`,
  and the result must equal `wire` **byte for byte**. `PASS` requires both:
  decode succeeds, and re-encoding reproduces `wire` exactly. This is the
  property that actually catches wire-format drift — a codec that decodes
  loosely but encodes differently is not conformant, and a vector-only decode
  check would miss it.

- **`accept_time_request`** — fields: `device_secret`, `sender_id`,
  `direction` (always `"00"`), `wire`, `wire_len` (§11.3). The IUT must
  verify `wire` as a `TIME_REQUEST` from `sender_id` under `device_secret`,
  and re-encoding a fresh `TIME_REQUEST` for that `sender_id`/`device_secret`
  must reproduce `wire` exactly (it carries no other input — PROTOCOL.md
  §11.3 pins every other field).

- **`accept_time_announce`** — fields: `device_secret`, `sender_id`,
  `direction` (always `"01"`), `asserted_time` (integer, signed, seconds since
  the Unix epoch), `wire`, `wire_len` (§11.4). The IUT must verify `wire` as a
  `TIME_ANNOUNCE` from `sender_id` under `device_secret`, extract the
  asserted time, and check it equals `asserted_time` exactly; re-encoding a
  `TIME_ANNOUNCE` for that `sender_id`/`device_secret`/`asserted_time` must
  reproduce `wire` exactly.

- **`number_payload`** — fields: `payload` (hex, the raw 3-byte `NUMBER`
  payload, §6.3), `outcome` (`"accept"` or `"reject"`). The IUT decodes
  `payload` against the `NUMBER` grammar of §6.3/§6.3.1 in isolation (no
  datagram, no MAC — this vector kind is about the payload grammar alone).
  `PASS` means the IUT's accept/reject decision matches `outcome`; for an
  `"accept"` vector, the IUT is not additionally required to report the
  decoded `(scale, mantissa)` anywhere the driver can see, since the driver
  only reads `PASS`/`FAIL`.

`epoch_key`, `time_key`, and `auth_header`, where present on a vector, are
intermediate values this project's own test suite (`tests/vectors.rs`) checks
as an extra internal cross-check on the *reference* implementation. An IUT is
not required to expose or compare them — decode-and-reencode already implies
they were computed correctly, since a wrong key or a wrong auth header would
make the tag fail to verify or the re-encode fail to match.

### Reasons a `FAIL` line's message should name

Not machine-parsed, but conventionally one of: `decode rejected` (the vector
should have been accepted but was not), `reencode mismatch` (decoded fine,
but re-encoding produced different bytes — include enough detail on stderr,
if useful, to see where), or `wrong outcome` (a `number_payload` vector's
accept/reject decision didn't match `outcome`).

## The reference IUT: `catp-conformance-iut`

```bash
cargo run --bin catp-conformance-iut < /dev/null   # reads stdin, writes stdout
```

Implements the contract above directly against `catp::wire` and
`catp::validate_number` — the same functions `tests/vectors.rs` already
exercises, so a bug here is a bug in the same code path the crate's own test
suite covers, not a second independent codec. Its purpose is to prove the
contract is implementable and to give `tools/run_conformance.py` something
real to run in this crate's own CI, not to be an alternative to
`tests/vectors.rs` for this crate's own conformance (that job stays with
`cargo test`).

## The driver: `tools/run_conformance.py`

Standard-library-only Python (no dependency to install — deliberately, so a
contributor testing a second implementation does not need this crate's Rust
toolchain, or any Python package, to run it):

```bash
python3 tools/run_conformance.py -- cargo run --quiet --bin catp-conformance-iut
python3 tools/run_conformance.py --vectors docs/test-vectors.json --report report.json -- ./my-iut
```

Everything after `--` is the IUT command line, run as a subprocess. The
driver:

1. Loads `docs/test-vectors.json` (or `--vectors PATH`).
2. Writes each vector to the IUT's stdin as one compact JSON line, then
   closes stdin.
3. Reads the IUT's stdout, one line per vector, in order.
4. Prints a summary: counts of `PASS`/`FAIL`, and for each `FAIL` its vector
   index, `kind`, `name` (if the vector has one), and the IUT's reason.
5. With `--report PATH`, also writes that summary as JSON.
6. Exits `0` only if every vector passed and the IUT produced exactly one
   output line per input line; exits `1` otherwise (including if the IUT
   exits early, produces too few/many lines, or writes something on stdout
   that isn't `PASS` or `FAIL ...`).

## Not covered here

**Live interop** — two running implementations exchanging real datagrams
over a socket, each checking the other's traffic under §7.4 in real time —
is a different, larger harness (a second process needs to *emit* traffic,
not just decode fixed vectors, and the two need a shared clock or a
simulated one). It is deliberately deferred: with one implementation, there
is nothing to interop against yet, and designing that harness now would be
speculative. When a second implementation exists (#43-#46), design its
interop mode against that implementation's actual constraints rather than
against a guess.

**Conformance report format beyond `--report`'s JSON** — no fixed schema is
promised for that file yet beyond what the driver documents in its own
`--help`; treat it as informational output, not a stable interface, until a
consumer other than a human reading it needs one.
