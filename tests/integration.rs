//! End-to-end scenarios against the CATP v1 spec.
//!
//! Each test names the section it exercises. These run the real codec over
//! byte buffers, so they catch anything the unit tests stub out.

use catp::wire::{decode_time_announce, Datagram, PeerConfig};
use catp::*;

const NODE: u32 = 0x0000_1234;
const OTHER: u32 = 0x0000_5678;
const SCHEMA: u8 = 1;

fn secret(seed: u8) -> DeviceSecret {
    DeviceSecret([seed; 32])
}

fn cfg(id: u32, seed: u8, cipher: CipherId) -> PeerConfig {
    PeerConfig {
        sender_id: id,
        secret: secret(seed),
        cipher,
        layouts: vec![(Format::None as u8, SCHEMA), (Format::Cbor as u8, SCHEMA)],
    }
}

fn rec(body: &[u8]) -> Record {
    Record::new(Format::None, SCHEMA, body.to_vec())
}

// ---------------------------------------------------------------- use cases

/// A weather node: one temperature reading per minute, sent as NUMBER.
/// No layout registry, no schema provisioning -- just a value and a time.
#[test]
fn usecase_single_value_node() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));

    let epoch = epoch_id_at(1_700_000_000);
    let readings = ["21.5", "21.6", "-0.5", "0", "1013.25"];
    let mut wire_total = 0usize;

    for (i, r) in readings.iter().enumerate() {
        let off = (i as u32 + 1) * 4096; // one per second
        let dg = Datagram::number(CipherId::HmacSha256T32, NODE, epoch, off, r).unwrap();
        let w = dg
            .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        wire_total += w.len();
        let acc = col.accept(&w, epoch, Direction::NodeToCollector).unwrap();
        assert_eq!(acc.datagram.number_literal(), Some(*r));
        assert_eq!(acc.datagram_offset, off);
    }
    // 9-byte header + literal + 4-byte tag, no record header anywhere.
    let expected: usize = readings.iter().map(|r| 9 + r.len() + 4).sum();
    assert_eq!(wire_total, expected);
}

/// A multi-sensor node: eight sensors sampled in one pass, batched into one
/// MESSAGE. This is the case PROTOCOL.md 6.4.1 is designed for -- the readings
/// genuinely share a capture instant, so one timestamp is correct.
#[test]
fn usecase_multisensor_batch() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let epoch = epoch_id_at(1_700_000_000);

    let records: Vec<Record> = (0..8u16)
        .map(|i| {
            // Sensor position and reading, both deployment-defined: the
            // protocol names neither (PROTOCOL.md 4.2, 6.4.2).
            let mut b = Vec::new();
            b.push(i as u8);
            b.extend_from_slice(&(2000 + i * 10).to_be_bytes());
            rec(&b)
        })
        .collect();
    let dg = Datagram::data(MsgType::Message, CipherId::HmacSha256T32, NODE, epoch, 500, records)
        .unwrap();
    let w = dg
        .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
        .unwrap();

    // 9 header + 8*(3 record header + 3 body) + 4 tag
    assert_eq!(w.len(), 9 + 8 * 6 + 4);
    let acc = col.accept(&w, epoch, Direction::NodeToCollector).unwrap();
    assert_eq!(acc.datagram.records.len(), 8);
    // Every record shares the datagram's instant (PROTOCOL.md 6.4.1).
    assert_eq!(acc.datagram_offset, 500);
}

/// Batching is the dominant compactness lever (PROTOCOL.md 6.6).
#[test]
fn usecase_batching_beats_individual_datagrams() {
    let epoch = epoch_id_at(1_700_000_000);
    let n = 50usize;

    let batched = Datagram::data(
        MsgType::Message,
        CipherId::HmacSha256T32,
        NODE,
        epoch,
        1,
        (0..n).map(|i| rec(&(i as u32).to_be_bytes())).collect(),
    )
    .unwrap()
    .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
    .unwrap()
    .len();

    let individually: usize = (0..n)
        .map(|i| {
            Datagram::data(
                MsgType::Message,
                CipherId::HmacSha256T32,
                NODE,
                epoch,
                i as u32 + 1,
                vec![rec(&(i as u32).to_be_bytes())],
            )
            .unwrap()
            .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap()
            .len()
        })
        .sum();

    // Batched pays the 9-byte header and 4-byte tag once instead of 50 times:
    // 50*(9+3+4+4) = 1000 bytes individually vs 9 + 50*7 + 4 = 363 batched.
    assert_eq!(individually, n * (9 + 3 + 4 + 4));
    assert_eq!(batched, 9 + n * (3 + 4) + 4);
    assert!(batched * 2 < individually, "batched {batched} vs {individually}");
}

/// Cold start: a node with no clock recovers time from TIME_ANNOUNCE, then
/// transmits (PROTOCOL.md 11).
#[test]
fn usecase_cold_start_then_transmit() {
    let s = secret(1);
    let boot_epoch = 13_281_000u32;
    let mut clock = NodeClock::clockless(boot_epoch);

    // The node cannot produce anything a collector would accept.
    assert_eq!(clock.now(0), Err(Error::NoClock));

    // Collector sends an unsolicited TIME_ANNOUNCE.
    let asserted = (boot_epoch as i64 + 10) * EPOCH_SECS as i64 + 7;
    let wire = Datagram::time_announce(NODE, asserted, &s).unwrap();
    // 9 header + 8 payload + 8 tag (cipher 0x01 is mandatory here).
    assert_eq!(wire.len(), 9 + 8 + 8);

    let got = decode_time_announce(&wire, NODE, &s).unwrap();
    assert_eq!(got, asserted);
    clock.accept_time_announce(got, 0).unwrap();
    assert!(clock.is_valid());

    // Now it can transmit, and the collector accepts.
    let epoch = epoch_id_at(clock.now(0).unwrap() as u64);
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let dg = Datagram::number(CipherId::HmacSha256T32, NODE, epoch, 128, "5.0").unwrap();
    let w = dg.encode(&s, epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
    assert!(col.accept(&w, epoch, Direction::NodeToCollector).is_ok());
}

/// A collector-to-node control message. The node is named in both directions
/// and the direction byte separates the keys (PROTOCOL.md 9.2.2, 9.2.3).
#[test]
fn usecase_collector_to_node_direction() {
    let s = secret(1);
    let epoch = epoch_id_at(1_700_000_000);
    let mut node_side = PeerState::new(cfg(NODE, 1, CipherId::HmacSha256T32));

    let body = Control::EpochAnnounce { target_epoch: epoch + 1 }.encode().unwrap();
    let dg =
        Datagram::control(MsgType::EpochAnnounce, CipherId::HmacSha256T32, NODE, epoch, 64, &body)
            .unwrap();
    let w = dg.encode(&s, epoch, Direction::CollectorToNode, MAX_DATAGRAM_IPV4).unwrap();

    // Verified in the collector-to-node direction: accepted.
    let acc = node_side.accept(&w, epoch, Direction::CollectorToNode).unwrap();
    match Control::parse(MsgType::EpochAnnounce, &acc.datagram.raw).unwrap() {
        Control::EpochAnnounce { target_epoch } => assert_eq!(target_epoch, epoch + 1),
        other => panic!("unexpected {other:?}"),
    }

    // The same bytes reflected back as node-to-collector must fail: that is
    // exactly what the direction byte exists to prevent.
    let mut fresh = PeerState::new(cfg(NODE, 1, CipherId::HmacSha256T32));
    assert_eq!(
        fresh.accept(&w, epoch, Direction::NodeToCollector).unwrap_err(),
        Error::AuthFailed
    );
}

// ----------------------------------------------------------- network reality

/// Reordering inside the replay window is accepted; a true replay is not
/// (PROTOCOL.md 10.2).
#[test]
fn reordered_delivery_is_accepted_replay_is_not() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let epoch = epoch_id_at(1_700_000_000);

    let wires: Vec<Vec<u8>> = (1..=5u32)
        .map(|i| {
            Datagram::number(CipherId::HmacSha256T32, NODE, epoch, i * 10, "1")
                .unwrap()
                .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
                .unwrap()
        })
        .collect();

    // Deliver out of order: 3, 1, 5, 2, 4.
    for idx in [2usize, 0, 4, 1, 3] {
        assert!(
            col.accept(&wires[idx], epoch, Direction::NodeToCollector).is_ok(),
            "reordered delivery of {idx} rejected"
        );
    }
    // Every one of them is now a replay.
    for (i, w) in wires.iter().enumerate() {
        assert_eq!(
            col.accept(w, epoch, Direction::NodeToCollector).unwrap_err(),
            Error::Replay,
            "datagram {i} accepted twice"
        );
    }
}

/// Loss is invisible and harmless: offsets are sparse by design, and a gap
/// carries no information (PROTOCOL.md 10.5).
#[test]
fn loss_leaves_no_trace() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let epoch = epoch_id_at(1_700_000_000);

    let mut delivered = 0;
    for i in 1..=100u32 {
        let w = Datagram::number(CipherId::HmacSha256T32, NODE, epoch, i * 41, "2.5")
            .unwrap()
            .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        if i % 3 == 0 {
            continue; // dropped in flight
        }
        assert!(col.accept(&w, epoch, Direction::NodeToCollector).is_ok());
        delivered += 1;
    }
    assert_eq!(delivered, 100 - 33);
}

/// A datagram from the previous epoch arriving after the boundary is accepted
/// (PROTOCOL.md 9.3); two epochs back is not.
#[test]
fn epoch_rollover_accepts_previous_rejects_older() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let now = 13_281_250u32;

    for (sent_in, want_ok) in [(now, true), (now - 1, true), (now - 2, false), (now - 5, false)] {
        let w = Datagram::number(CipherId::HmacSha256T32, NODE, sent_in, 77, "1")
            .unwrap()
            .encode(&secret(1), sent_in, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        let got = col.accept(&w, now, Direction::NodeToCollector);
        assert_eq!(got.is_ok(), want_ok, "epoch {sent_in} vs local {now}: {got:?}");
    }
}

/// The same offset in two adjacent epochs is not a replay: windows are per
/// epoch because offsets reset at the boundary (PROTOCOL.md 10.2).
#[test]
fn same_offset_in_adjacent_epochs_is_not_a_replay() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let now = 13_281_250u32;
    for epoch in [now - 1, now] {
        let w = Datagram::number(CipherId::HmacSha256T32, NODE, epoch, 12345, "9")
            .unwrap()
            .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        assert!(col.accept(&w, now, Direction::NodeToCollector).is_ok(), "epoch {epoch}");
    }
}

// --------------------------------------------------------------- adversarial

/// A fleet-wide key would make sender_id decorative; per-device secrets make
/// the key lookup the identity check (PROTOCOL.md 9.2.1).
#[test]
fn compromised_node_cannot_impersonate_another() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    col.provision(cfg(OTHER, 2, CipherId::HmacSha256T32));
    let epoch = epoch_id_at(1_700_000_000);

    // Attacker holds node 2's secret and forges traffic claiming to be node 1.
    let forged = Datagram::number(CipherId::HmacSha256T32, NODE, epoch, 5, "999")
        .unwrap()
        .encode(&secret(2), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
        .unwrap();
    assert_eq!(
        col.accept(&forged, epoch, Direction::NodeToCollector).unwrap_err(),
        Error::AuthFailed
    );
}

/// A peer configured for one suite may not use another, checked before the MAC
/// (PROTOCOL.md 8.3).
#[test]
fn cipher_downgrade_is_refused_pre_mac() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32)); // configured: 4-byte tag
    let epoch = epoch_id_at(1_700_000_000);

    let w = Datagram::number(CipherId::HmacSha256T64, NODE, epoch, 5, "1")
        .unwrap()
        .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
        .unwrap();
    assert_eq!(
        col.accept(&w, epoch, Direction::NodeToCollector).unwrap_err(),
        Error::CipherMismatch { got: 0x01, want: 0x04 }
    );
}

/// Truncation at every length must be rejected, never misparsed.
#[test]
fn every_truncation_is_rejected() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let epoch = epoch_id_at(1_700_000_000);
    let full = Datagram::data(
        MsgType::Message,
        CipherId::HmacSha256T32,
        NODE,
        epoch,
        3,
        vec![rec(b"abcd"), rec(b"ef")],
    )
    .unwrap()
    .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
    .unwrap();

    for n in 0..full.len() {
        assert!(
            col.accept(&full[..n], epoch, Direction::NodeToCollector).is_err(),
            "truncation to {n} bytes was accepted"
        );
    }
    assert!(col.accept(&full, epoch, Direction::NodeToCollector).is_ok());
}

/// Extension past the tag must be rejected too.
#[test]
fn appended_bytes_are_rejected() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let epoch = epoch_id_at(1_700_000_000);
    let mut w = Datagram::number(CipherId::HmacSha256T32, NODE, epoch, 3, "1.25")
        .unwrap()
        .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
        .unwrap();
    w.push(0x00);
    assert!(col.accept(&w, epoch, Direction::NodeToCollector).is_err());
}

/// A TIME_ANNOUNCE for one node must not verify at another, and a bit-flip
/// anywhere must fail (PROTOCOL.md 11.2).
#[test]
fn time_announce_is_bound_to_its_node_and_tamper_evident() {
    let s = secret(1);
    let wire = Datagram::time_announce(NODE, 1_700_000_000, &s).unwrap();
    assert!(decode_time_announce(&wire, NODE, &s).is_ok());

    // Different node id in the call: the header check catches it.
    assert!(decode_time_announce(&wire, OTHER, &s).is_err());
    // Different device secret: the MAC catches it.
    assert_eq!(decode_time_announce(&wire, NODE, &secret(2)).unwrap_err(), Error::AuthFailed);

    for byte in 0..wire.len() {
        for bit in 0..8 {
            let mut t = wire.clone();
            t[byte] ^= 1 << bit;
            assert!(
                decode_time_announce(&t, NODE, &s).is_err(),
                "TIME_ANNOUNCE flip at byte {byte} bit {bit} accepted"
            );
        }
    }
}

/// TIME_ANNOUNCE must not be reachable through the ordinary decode path: it is
/// keyed on time_key, not an epoch key.
#[test]
fn time_announce_rejected_by_ordinary_decode() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T64));
    let wire = Datagram::time_announce(NODE, 1_700_000_000, &secret(1)).unwrap();

    // TIME_ANNOUNCE pins epoch_low to 0, so pick a local epoch whose low nibble
    // is 0 and reconstruction succeeds -- otherwise the epoch filter fires
    // first and we would not be testing the msg_type rejection at all.
    let epoch = epoch_id_at(1_700_000_000) & !0x0F;
    assert!(matches!(
        col.accept(&wire, epoch, Direction::NodeToCollector),
        Err(Error::BadMsgType(_))
    ));

    // With any other local epoch it is still rejected, just by the cheaper
    // pre-MAC epoch filter.
    assert!(col.accept(&wire, epoch + 5, Direction::NodeToCollector).is_err());
}

// ------------------------------------------------------------------- framing

/// Both tag lengths round-trip and differ only in size.
#[test]
fn both_implemented_ciphers_round_trip() {
    let epoch = epoch_id_at(1_700_000_000);
    let mut lens = vec![];
    for c in [CipherId::HmacSha256T32, CipherId::HmacSha256T64] {
        let mut col = Collector::new();
        col.provision(cfg(NODE, 1, c));
        let w = Datagram::number(c, NODE, epoch, 21, "3.5")
            .unwrap()
            .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        assert!(col.accept(&w, epoch, Direction::NodeToCollector).is_ok());
        lens.push(w.len());
    }
    assert_eq!(lens[1] - lens[0], 4, "0x01 carries 4 more tag bytes than 0x04");
}

/// A record in a reserved format is skipped individually, not fatally
/// (PROTOCOL.md 6.4.3).
#[test]
fn reserved_format_skips_one_record() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let epoch = epoch_id_at(1_700_000_000);

    let mut odd = rec(b"??");
    odd.format = 0x0B; // in the reserved 0x07-0x0F block
    let w = Datagram::data(
        MsgType::Message,
        CipherId::HmacSha256T32,
        NODE,
        epoch,
        4,
        vec![rec(b"keep1"), odd, rec(b"keep2")],
    )
    .unwrap()
    .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
    .unwrap();

    let acc = col.accept(&w, epoch, Direction::NodeToCollector).unwrap();
    assert_eq!(acc.datagram.records.len(), 2);
    assert_eq!(acc.skipped.len(), 1);
    assert_eq!(acc.skipped[0].format, 0x0B);
}

/// A datagram that does not fit max_datagram_size must fail at the sender, not
/// be fragmented (PROTOCOL.md 3.1).
#[test]
fn oversize_fails_at_the_sender() {
    let epoch = epoch_id_at(1_700_000_000);
    let recs: Vec<Record> = (0..80).map(|_| rec(&[0u8; 10])).collect();
    let dg =
        Datagram::data(MsgType::Message, CipherId::HmacSha256T32, NODE, epoch, 1, recs).unwrap();
    assert!(matches!(
        dg.encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4),
        Err(Error::Oversize(_))
    ));
}

/// A full epoch of offsets is representable and the extremes survive.
#[test]
fn offset_extremes_round_trip() {
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let epoch = epoch_id_at(1_700_000_000);
    for off in [0u32, 1, 4095, 4096, 65_535, 65_536, 524_286, TICKS_PER_EPOCH - 1] {
        let w = Datagram::number(CipherId::HmacSha256T32, NODE, epoch, off, "1")
            .unwrap()
            .encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        let acc = col.accept(&w, epoch, Direction::NodeToCollector).unwrap();
        assert_eq!(acc.datagram_offset, off);
    }
    // Beyond the field is a construction error, not a silent truncation.
    assert!(Datagram::number(CipherId::HmacSha256T32, NODE, epoch, TICKS_PER_EPOCH, "1").is_err());
}

/// `UNSTRUCTURED` (PROTOCOL.md 6.4.2.2) is a reserved meaning, not a standing
/// permission. A receiver that has not been provisioned with the pair discards
/// the record like any other layout it does not hold; provisioning it is what
/// makes the record acceptable. Were `0xFF` accepted unconditionally, an
/// authenticated peer could sidestep the layout agreement by relabelling.
#[test]
fn unstructured_still_has_to_be_provisioned() {
    let epoch = epoch_id_at(1_700_000_000);

    let build = || {
        let dg = Datagram::data(
            MsgType::Message,
            CipherId::HmacSha256T32,
            NODE,
            epoch,
            700,
            vec![
                rec(b"structured"),
                Record::new(Format::None, SCHEMA_UNSTRUCTURED, b"opaque".to_vec()),
            ],
        )
        .unwrap();
        dg.encode(&secret(1), epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap()
    };

    // Not provisioned: the unstructured record is skipped, the rest survives.
    let mut col = Collector::new();
    col.provision(cfg(NODE, 1, CipherId::HmacSha256T32));
    let acc = col.accept(&build(), epoch, Direction::NodeToCollector).unwrap();
    assert_eq!(acc.datagram.records.len(), 1);
    assert_eq!(acc.skipped.len(), 1);
    assert_eq!(acc.skipped[0].schema_version, SCHEMA_UNSTRUCTURED);

    // Provisioned: both records are delivered, sharing one instant.
    let mut col = Collector::new();
    let mut c = cfg(NODE, 1, CipherId::HmacSha256T32);
    c.layouts.push((Format::None as u8, SCHEMA_UNSTRUCTURED));
    col.provision(c);
    let acc = col.accept(&build(), epoch, Direction::NodeToCollector).unwrap();
    assert_eq!(acc.datagram.records.len(), 2);
    assert!(acc.skipped.is_empty());
    assert_eq!(acc.datagram.records[1].body, b"opaque");
    assert_eq!(acc.datagram_offset, 700);
}
