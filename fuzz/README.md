# Fuzzing `decode`

Targets the pre-authentication decode path (issue #30): `decode` in
`src/wire.rs` parses attacker-controlled bytes off a UDP socket, and steps
1-6 of `PROTOCOL.md` §7.4 run before the MAC verifies. That is the entire
remote attack surface of the protocol.

## Targets

- **`decode`** — property: never panics on any input. `cargo-fuzz`'s
  libFuzzer harness catches panics and unbounded-allocation aborts
  automatically; there is nothing else this target asserts.
- **`decode-roundtrip`** — property: whenever `decode` accepts an input,
  re-encoding the result reproduces those exact bytes. The same property
  `every_accept_vector_verifies_and_reencodes` (`tests/vectors.rs`) checks for
  the frozen vectors, checked here for whatever libFuzzer's mutations happen
  to get past authentication.

Both use a fixed secret/`sender_id`/epoch matching `src/bin/vectors.rs`'s
generator, so the seed corpus below (derived from `docs/test-vectors.txt`)
starts libFuzzer from inputs that already decode successfully rather than
dying at step 1.

## Running locally

Requires nightly (libFuzzer needs sanitizer support stable Rust doesn't
expose) and `cargo-fuzz`:

```bash
cargo install cargo-fuzz
mkdir -p fuzz/corpus/decode fuzz/corpus/decode-roundtrip
cp fuzz/seeds/decode/* fuzz/corpus/decode/
cp fuzz/seeds/decode-roundtrip/* fuzz/corpus/decode-roundtrip/
cargo +nightly fuzz run decode              # runs until interrupted
cargo +nightly fuzz run decode-roundtrip
```

`fuzz/corpus/` and `fuzz/target/` are gitignored -- they're local working
state, not something to commit. `fuzz/seeds/` is the curated starting corpus
and *is* committed; it's copied into `fuzz/corpus/` rather than used in
place so a long local run doesn't turn a `git status` on this repository
into a diff of generated fuzzing artifacts.

CI (`fuzz-smoke` job) runs each target for 60 seconds on every push -- a
regression gate, not a real fuzzing campaign. If you have the time, a much
longer run (hours, out of band) is what actually finds something; `-max_total_time`
above controls the duration.

## A crash

`cargo fuzz run <target>` writes the failing input to `fuzz/artifacts/<target>/`
and prints its path. Reproduce with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```

Minimize before filing an issue:

```bash
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<crash-file>
```
