# PROTOCOL.md 14.2 conformance audit

Non-normative. Maps each of §14.2's 19 required adversarial tests to the test
that discharges it, so conformance is demonstrated rather than assumed. (Issue
#32, which asked for this audit, said 20 — §14.2 has 19 bullets as of this
writing; corrected here rather than silently.) A
second implementation (#43-#46) should be able to use this table the same way:
check its own suite against each row rather than re-deriving the list from
prose.

Numbering is this document's own, in §14.2's bullet order — the specification
does not number them itself.

| # | §14.2 requirement | Discharged by |
|---|---|---|
| 1 | Replay, immediately and after an epoch change | `reordered_delivery_is_accepted_replay_is_not`, `same_offset_in_adjacent_epochs_is_not_a_replay` (tests/integration.rs) |
| 2 | Bit-flips in every header field rejected, reserved bits included | `tampering_any_bit_fails_auth` (src/wire.rs) flips every bit of every accept vector; `every_vector_is_tamper_evident` (tests/vectors.rs) does the same against the frozen vectors |
| 3 | Truncation and extension of the payload | `every_truncation_is_rejected`, `appended_bytes_are_rejected` (tests/integration.rs) |
| 4 | Clock skew past the acceptance window, both directions | `epoch_reconstruction_picks_current_or_previous` (src/lib.rs): the 4-bit `epoch_low` makes "sender ahead" and "sender behind" the same modular question, and the `back` loop sweeps all 16 residues — `back=1..15` covers skew in both directions at once; `epoch_rollover_accepts_previous_rejects_older` (tests/integration.rs) confirms it end-to-end through a real encode/decode |
| 5 | `EPOCH_ANNOUNCE` replayed from an earlier epoch | `epoch_announce_is_monotonic` (src/peer.rs) |
| 6 | Valid `sender_id`, signed with a different device's key | `one_senders_key_cannot_sign_for_another` (src/peer.rs), `compromised_node_cannot_impersonate_another` (tests/integration.rs) |
| 7 | `schema_version` swapped for another of identical body width: rejection, not misdecoding | `schema_version_swap_at_identical_width_is_skipped_not_misdecoded` (src/wire.rs) — added by this audit; was previously unconfirmed |
| 8 | Multi-record datagram, one record unrecognized `format`: that record alone skipped | `unknown_layout_skips_only_that_record` (src/wire.rs), `reserved_format_skips_one_record` (tests/integration.rs) |
| 9 | One accepted record per assigned `format`, non-zero `schema_version`; rejections for `format` `0x00`, `format` `0x07`-`0x0F`, `schema_version` `0x00` | `every_assigned_format_round_trips` and `format_and_schema_version_zero_are_rejected` (src/wire.rs, both added by this audit) cover acceptance and the two zero-value rejections; `reserved_format_skips_one_record` (tests/integration.rs) covers the reserved range — as a per-record skip (§6.4.4), not a whole-datagram reject, which is the behavior §14.2 actually wants here |
| 10 | Offset exhaustion at `524287`: ceases, does not wrap | `offset_extremes_round_trip` (tests/integration.rs) — accepts `TICKS_PER_EPOCH - 1`, then asserts `TICKS_PER_EPOCH` itself is a construction error |
| 11 | Two datagrams within one tick: sender delays/coalesces, does not reuse an offset | `pacer_rejects_repeated_tick` (src/lib.rs) |
| 12 | `NUMBER` and `MESSAGE` at the same offset: second rejected, replay window is per sender not per type | `number_and_message_share_one_replay_window` (src/wire.rs) |
| 13 | Record header straddling fields: `schema_version` `0xFF`, `size` `4095` together | `record_header_packs_at_field_maxima` (src/wire.rs) |
| 14 | `datagram_offset` beyond 65,535: all three bytes assembled | `offset_above_u16_survives_roundtrip` (src/wire.rs) |
| 15 | Simulated reboot mid-epoch: resumes past any prior offset | `pacer_survives_simulated_reboot` (src/lib.rs) |
| 16 | Backward clock step mid-epoch: refuses to emit at or below the last offset | `pacer_rejects_backward_clock_step` (src/lib.rs) |
| 17 | `TIME_ANNOUNCE` replay against a booting node | `replayed_time_announce_pins_but_cannot_rewind` (src/peer.rs) |
| 18 | Cipher `0x03`: no two datagrams in one epoch/direction share a nonce | **Blocked on #33** — `0x03` returns `CipherUnimplemented`, so this property has nothing to test yet |
| 19 | Cipher `0x04`: inbound rate limit enforced, exceeding it counted | `exceeding_the_inbound_limit_discards_authenticated_traffic_and_counts_it` (src/peer.rs), `rate_limit_is_enforced_through_the_collector` (tests/integration.rs) |

Row 18 is the one genuine gap, and it isn't closeable here: it requires `0x03`
to exist first (#33). Everything else in §14.2 has a test as of this audit —
rows 7 and 9 did not before it (added alongside this document) and row 4's
"both directions" property was true but unstated as such until this pass
looked for it.

## Using this table

A second implementation should not need to re-derive §14.2 into a checklist
the way this document did — check its own suite against each row above
instead, and file a specification issue (not a silent workaround) for any
row whose intent is ambiguous from `docs/PROTOCOL.md` alone.
