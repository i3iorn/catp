# Contributing

The most valuable contribution this project can receive is a **second,
independently written implementation** in another language (§14.3 of
`docs/PROTOCOL.md` — version 1 is not complete until two independent
implementations interoperate). See the tracking issue
([#47](https://github.com/i3iorn/catp/issues/47)) and the four language issues
(#43-#46) for what that means concretely. The rest of this document is ground
rules for that and for smaller contributions alike.

## The one rule that matters most: implement from the spec, not from `src/`

If you are writing a second implementation, write it from `docs/PROTOCOL.md`
alone. Do not read `src/` first, and ideally not at all until your
implementation is done. A translation of the Rust code satisfies nothing —
§14.3 exists to catch places where the specification is ambiguous or wrong,
and a port carries the Rust implementation's misreadings into the
implementation meant to catch them instead.

**Every ambiguity you find while doing this is valuable — file it as an issue
before resolving it in code.** Those filed ambiguities are the actual point of
writing a second implementation; the working code is almost a side effect.

## Where a change belongs

Three documents, three jobs (see #20, #25 for why they're split):

- **`docs/PROTOCOL.md`** — normative. RFC 2119 keywords (MUST/SHOULD/MAY) mean
  what they say. A wire-format change belongs here, and it also means the
  frozen vectors need regenerating (below).
- **`docs/RATIONALE.md`** — non-normative. *Why* a rule is the way it is. If
  you find yourself explaining a design decision inside `PROTOCOL.md`'s
  normative prose, it probably belongs here instead, cross-referenced.
- **`docs/DEPLOYMENT.md`** — non-normative. Choices the specification
  deliberately leaves open (cipher selection, rate limits, key storage) and
  guidance for making them.

`docs/THREAT_MODEL.md` collects the attacker capabilities §12's claims
assume; a new §12 claim should say which attacker (by number) it's against.

## Conformance vectors are generated, not hand-edited

`docs/test-vectors.txt` is authoritative and frozen (§14.1). If your change
touches the codec, wire format, or vector-generation logic in any way:

```bash
cargo run --bin catp-vectors > docs/test-vectors.txt
```

and commit the regenerated file alongside your code change in the same PR.
`tests/vectors.rs` will fail otherwise, deliberately — that's the test
catching wire-format drift, not a bug in the test.

## Before opening a PR (Rust reference implementation)

```bash
cargo build --all-targets
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

`cargo fmt --check` is currently advisory in CI
([#27](https://github.com/i3iorn/catp/issues/27)'s follow-up) — the repository
isn't fully rustfmt-clean yet, so a failure there alone isn't a blocker, but
please don't make the drift worse in new code.

## Issues

Open issues are the actual roadmap — read the tracking issue
([#47](https://github.com/i3iorn/catp/issues/47)) before starting anything
non-trivial, both to avoid duplicate work and because several issues have
ordering dependencies on each other (stated in that issue's "Suggested
ordering" section).
