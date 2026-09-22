# Dependency policy

Non-normative, project-maintenance rather than protocol content. Addresses
issue #39: the whole security of this crate rests on several pre-1.0
RustCrypto crates, and that fact deserves a stated policy rather than silent
acceptance.

## Direct dependencies today

Two packages, one workspace (issue #74): `catp` (the library, this
repository's root `Cargo.toml`) and `catp-tools` (`tools/`, the five
binaries). Only `catp`'s dependency list matters for the `no_std` build --
`catp-tools` is a plain `std` binary crate and never builds for a
constrained target.

`catp`:

```
hmac              0.13
sha2              0.11 (no default features)
hkdf              0.13
subtle            2   (no default features)
zeroize           1   (no default features, +derive)
siphasher         1   (no default features)
chacha20poly1305  0.11 (no default features, +alloc)
```

`catp-tools`:

```
catp       (path dependency on the workspace's own library, features = ["std"])
getrandom  0.4
```

`subtle`, `zeroize`, and `siphasher` are 1.x; `hmac`, `sha2`, `hkdf`,
`chacha20poly1305`, and `getrandom` are pre-1.0.

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

`getrandom` (`catp-provision`, issue #34 — generating a fresh `sender_id` and
`device_secret` needs an actual OS CSPRNG, not a crate substitute) is used
directly (`getrandom::u32()`, `getrandom::fill()`). It is not linked into the
library itself or the wire-facing binaries (`catp-sender`, `catp-collector`,
`catp-vectors`) at all — only `catp-provision` calls it — and brings in only
`libc` (Unix) or `r-efi` (UEFI) transitively; no `std` feature is needed for
the platforms this project targets. It lives entirely in `catp-tools`'s own
`Cargo.toml` (issue #74), not `catp`'s: before the workspace split it had to
be an `optional = true` dependency of the single shared package, because
Cargo resolves a package's `[dependencies]` as a whole regardless of which
target is being built, and left non-optional it broke a `no_std`
library-only build outright (no backend exists for it on a bare-metal
target without a custom one). Splitting the binaries into their own package
removed the need for that workaround: `getrandom` is no longer part of
`catp`'s dependency graph at all, optional or not.

## `no_std` / `alloc` (issue #37)

```toml
[features]
default = ["std"]
std = []
```

Without the `std` feature, the crate is `#![no_std]` — but still links
`alloc` unconditionally (it is a sysroot crate, always available where a
global allocator exists, not something worth its own toggle here). The
codec, key schedule, replay window, and pacer — everything a constrained
*node* needs — compile and pass `cargo clippy` against a real bare-metal
target (`thumbv7em-none-eabihf`) with `--no-default-features`. `Collector`
(the multi-peer, host-side registry — a node never needs it) and
`catp::provisioning` (file I/O) are both `#[cfg(feature = "std")]`-gated.

CI checks this directly (`.github/workflows/ci.yml`, `no-std` job):
`cargo build --package catp --no-default-features --target
thumbv7em-none-eabihf`. It's a build-only smoke check — nothing in CI can
run a Cortex-M4/M4F binary, so there's no test execution on that target —
and it's scoped to just the `catp` package, which the workspace split
(issue #74) makes trivial: `catp-tools`'s five `std`-only binaries live in
a separate package now, so there's nothing for `--package catp` to
accidentally pull in.

This is the `alloc` tier of #37's two-tier split, not the allocation-free
tier (issue #75): `Vec<u8>` throughout `Record`/`Datagram`/`Capability` still
needs a heap allocator, just not an OS underneath it.

Three of the tightened `default-features = false` lines above exist
specifically for this: `sha2`'s defaults (`alloc`, `oid`) and `zeroize`'s
default (`alloc`) are both unneeded by what this crate actually calls, and
`subtle`'s default (`std`) linked `std` unconditionally regardless of this
crate's own `#![no_std]` attribute — that one doesn't merely bloat the
build, it breaks it outright for a target with no `std` to find.

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

1. `cargo test --workspace --all-targets` green, in particular `tests/vectors.rs` — if a
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
- **`Cargo.lock` is committed.** One lockfile for the whole workspace (issue
  #74), covering both `catp` and `catp-tools`'s binaries (`catp-sender`,
  `catp-collector`, `catp-vectors`, `catp-provision`, `catp-conformance-iut`)
  — that's what makes the vector suite reproducible. It does *not* pin what
  a downstream `[dependency]` consumer resolves, though — a library
  consumer depending on `catp` alone ignores this repository's lock file
  (and never sees `catp-tools` or its dependencies at all, since it isn't a
  dependency of the library), so the versions actually tested here and the
  versions a consumer's Cargo resolves can differ.
- **`-Z minimal-versions` build** (nightly-only Cargo flag; `minimal-versions`
  job in CI, `continue-on-error: true` since it needs nightly and a floor
  failure here is a real finding, not a merge blocker on its own) —
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
