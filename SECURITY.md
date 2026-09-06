# Security policy

CATP is a hobby protocol: one implementation, no external cryptographic
review, version 1 still a draft (tracked in
[#31](https://github.com/i3iorn/catp/issues/31)). Treat any report against it
in that light — this is not a project with an incident-response team or a
bug-bounty budget, just one maintainer's best effort.

## Reporting a vulnerability

Please use
[GitHub's private vulnerability reporting](https://github.com/i3iorn/catp/security/advisories/new)
rather than a public issue. That keeps a flaw off the tracker until there is
something a user can do about it, since there is no patched-version release
process yet ([#38](https://github.com/i3iorn/catp/issues/38)) — the realistic
alternative to a private report is a public one that helps an attacker before
it helps a user.

Include:

- what you found and why it matters (a forgery, a replay, a DoS amplifier,
  something that violates a MUST in `docs/PROTOCOL.md`);
- the smallest reproduction you have — a datagram, a byte sequence, a test
  case;
- which part of the specification or the reference implementation
  (`src/`) it concerns.

### Expected response

This is a one-person hobby project, not a company with an SLA. Acknowledgement
within a week is the realistic target; a fix or a public statement of the
tradeoff within a month for anything confirmed. If that timeline doesn't work
for your disclosure needs, say so in the report — coordinated disclosure is
negotiable, silence about the finding forever is not.

## What is in scope

A vulnerability here is something that breaks a guarantee `docs/PROTOCOL.md`
§12.1 claims: that modification is detected, forgery is infeasible under the
selected cipher suite, replay is rejected, and records cannot be reattributed
across node, encoding, or capture time. Also in scope: a panic or unbounded
allocation reachable from unauthenticated input (`decode` in `src/wire.rs`
runs steps 1-6 of §7.4 before the MAC is checked — see
[#30](https://github.com/i3iorn/catp/issues/30)), and any place the reference
implementation's behavior contradicts a MUST/MUST NOT in the specification.

### What is explicitly *not* a vulnerability — it's a documented non-goal

CATP's README and §12 of the specification already disclaim these. Reports
against them will be closed as working-as-designed, with a pointer back here:

- **No confidentiality.** Payloads are plaintext, and so is metadata
  (`msg_type`, `sender_id`, `format`, `datagram_offset`) — §12.4. If your
  report is "an observer can read X", check whether X is one of those fields
  before reporting; it's supposed to be readable.
- **No defense after key extraction.** An attacker holding a node's
  `device_secret` can forge arbitrary datagrams attributed to that node —
  §12.3. CATP has no forward secrecy and no asymmetric fallback.
- **No protection against a flood at the network layer**, only a bound on the
  *cost* of one — §12.5. "An attacker can send a lot of UDP packets at my
  collector" is not new information; whether the collector survives that
  within the stated cost bound is.
- **`cipher_id` `0x04`'s 4-byte tag is a real, documented tradeoff**, not an
  oversight — §8.1.1, §12.2. It requires the receiver-side rate limit to be
  configured; a report that it's "only 32 bits" without checking whether that
  limit is in place isn't actionable on its own.

## Current status, for context

One Rust implementation, no independent cryptographic review yet
([#31](https://github.com/i3iorn/catp/issues/31)), version 1 of the wire
format still a draft per specification §14.3. Do not deploy this anywhere the
consequences of a mistake — yours or the protocol's — matter, and factor that
status into how you disclose.
