# Dependency policy

Non-normative, project-maintenance rather than protocol content. Addresses
issue #39: the whole security of this crate rests on several pre-1.0
RustCrypto crates, and that fact deserves a stated policy rather than silent
acceptance.

## Direct dependencies today

```
hmac              0.13
sha2              0.11
hkdf              0.13
subtle            2
zeroize           1 (+derive)
siphasher         1
chacha20poly1305  0.11 (+alloc)
```

`subtle`, `zeroize`, and `siphasher` are 1.x; `hmac`, `sha2`, `hkdf`, and
`chacha20poly1305` are pre-1.0.

`siphasher` (cipher `0x02`, PROTOCOL.md §7.2/§8.1, issue #33) is a single
pure-Rust implementation with no further transitive dependencies of its own —
the smallest possible addition for what it does, and there is no realistic
alternative crate for SipHash-2-4 in Rust worth comparing it against.

`chacha20poly1305` (cipher `0x03`, same sections, same issue) is the
RustCrypto AEAD implementation, pulled in with `default-features = false,
features = ["alloc"]` -- explicitly opting out of `getrandom`/`rand_core`
(this crate never generates a random nonce; PROTOCOL.md 7.2's nonce is
deterministic, derived from `datagram_offset`) and `zeroize` (already a
direct dependency for other reasons, wired in separately). It brings in
`chacha20`, `poly1305`, `cipher`, `aead`, `inout`, and `universal-hash` as its
own transitive tree.

## Pre-1.0 RustCrypto is accepted, deliberately

Pre-1.0 numbering here reflects API churn between releases, not doubt about
the primitives — these are the most-reviewed HMAC/SHA-2/HKDF implementations
available in Rust, used across the ecosystem. The tradeoff this project
accepts in exchange: **a minor-version bump on a pre-1.0 crate can carry a
breaking change**, and `Cargo.toml`'s `"0.13"`-style requirement permits it to
arrive without any signal beyond `cargo update`.

For a crate whose output is a MAC that must byte-match `docs/test-vectors.txt`
exactly, a dependency bump is a wire-compatibility event. The mitigation is
structural, not aspirational: `tests/vectors.rs` fails the moment re-encoding
stops reproducing a frozen vector, and CI (`.github/workflows/ci.yml`) runs
that suite on every push. **A dependency bump that changes wire output cannot
merge without that test turning red first** — that's the whole policy for
this specific risk, and it's already enforced, not just documented.

## What a version bump requires

1. `cargo test --all-targets` green, in particular `tests/vectors.rs` — if a
   bump changes any byte of `docs/test-vectors.txt`'s frozen output, that's a
   wire-format break and needs to be called out explicitly in the PR, not
   silently absorbed by regenerating the vectors.
2. If the bump *is* wire-relevant (vectors had to be regenerated to pass),
   say so in the commit message and PR description — a reader comparing two
   commits should be able to tell a dependency bump changed the wire format
   without diffing `Cargo.lock` against `docs/test-vectors.txt` themselves.
3. `cargo deny check` clean (below).

## New dependencies need justification

A new *direct* dependency should say, in the PR that adds it, why the
standard library or an existing dependency doesn't cover the need. This is a
crate whose entire trust model rests on a short, auditable dependency list;
growing that list is a real cost each time, not a free action.

## Supply-chain tooling

- **`cargo deny check`** (config: `deny.toml`) — advisories (RustSec
  advisory-db), licence policy (`Apache-2.0`, `MIT`, `BSD-3-Clause`,
  `Unicode-3.0` allowed — exactly what the current tree uses, nothing wider
  without deliberately updating the allow-list), and duplicate/banned-crate
  detection. Runs in CI (`.github/workflows/ci.yml`, `deny` job).
- **`Cargo.lock` is committed.** Correct for a crate that ships binaries
  (`catp-sender`, `catp-collector`, `catp-vectors`), and it's what makes the
  vector suite reproducible. It does *not* pin what a downstream `[dependency]`
  consumer resolves, though — a library consumer's build ignores this
  repository's lock file, so the versions actually tested here and the
  versions a consumer's Cargo resolves can differ.
- **`-Z minimal-versions` build** (nightly-only Cargo flag; `minimal-versions`
  job in CI, `continue-on-error: true` like `fmt` since it needs nightly and
  a floor failure here is a real finding, not a merge blocker on its own) —
  resolves every dependency to the *lowest* version each `Cargo.toml`
  requirement string permits, so a declared floor like `hmac = "0.13"` is
  checked against an actual `0.13.0` build rather than assumed compatible
  because the highest matching version happens to work. Run once by hand
  while writing this policy: it builds, with warnings (an old
  `zeroize_derive` floor triggers `non_local_definitions`) but no errors —
  informational, not a blocker, and not chased further here.

## Not covered here

Side-channel resistance of the underlying crates' implementations (constant-
time behavior of `hmac`/`sha2` is `docs/THREAT_MODEL.md`/#31 territory, not a
supply-chain question); vendoring source (not adopted — `cargo deny`'s
advisory/licence checks plus a committed lock file are judged sufficient for
a crate this size, and vendoring adds its own update burden).
