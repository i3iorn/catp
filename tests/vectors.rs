//! Conformance against the frozen vectors of PROTOCOL.md 14.1.
//!
//! `docs/test-vectors.txt` is the authority, not this code. If a change to the
//! codec alters any byte in it, these tests fail — which is the point: the
//! vectors are what a second implementation checks itself against, so they must
//! not drift silently.
//!
//! Regenerate deliberately with:
//!     cargo run --bin catp-vectors > docs/test-vectors.txt

use catp::wire::{Datagram, PeerConfig, decode, decode_time_announce, decode_time_request};
use catp::*;
use std::collections::HashMap;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A minimal JSON parser, only as general as `docs/test-vectors.json` needs:
/// a top-level array of flat objects whose values are strings or bare
/// integers. Not a general-purpose parser -- no dependency is worth adding
/// for one docs artifact this crate itself generates deterministically.
mod tinyjson {
    use std::collections::HashMap;

    pub fn parse_array_of_objects(s: &str) -> Vec<HashMap<String, String>> {
        let mut chars = s.trim().char_indices().peekable();
        assert_eq!(
            chars.next().map(|(_, c)| c),
            Some('['),
            "expected top-level array"
        );
        let mut out = Vec::new();
        loop {
            skip_ws(&mut chars, s);
            match chars.peek().map(|&(_, c)| c) {
                Some(']') => break,
                Some('{') => out.push(parse_object(&mut chars, s)),
                Some(',') => {
                    chars.next();
                }
                other => panic!("unexpected {other:?} in array"),
            }
        }
        out
    }

    type Chars<'a> = std::iter::Peekable<std::str::CharIndices<'a>>;

    fn skip_ws(chars: &mut Chars, _s: &str) {
        while matches!(chars.peek(), Some(&(_, c)) if c.is_whitespace()) {
            chars.next();
        }
    }

    fn parse_object(chars: &mut Chars, s: &str) -> HashMap<String, String> {
        assert_eq!(chars.next().map(|(_, c)| c), Some('{'));
        let mut map = HashMap::new();
        loop {
            skip_ws(chars, s);
            match chars.peek().map(|&(_, c)| c) {
                Some('}') => {
                    chars.next();
                    break;
                }
                Some(',') => {
                    chars.next();
                }
                Some('"') => {
                    let key = parse_string(chars);
                    skip_ws(chars, s);
                    assert_eq!(chars.next().map(|(_, c)| c), Some(':'));
                    skip_ws(chars, s);
                    let value = match chars.peek().map(|&(_, c)| c) {
                        Some('"') => parse_string(chars),
                        _ => parse_number(chars),
                    };
                    map.insert(key, value);
                }
                other => panic!("unexpected {other:?} in object"),
            }
        }
        map
    }

    fn parse_string(chars: &mut Chars) -> String {
        assert_eq!(chars.next().map(|(_, c)| c), Some('"'));
        let mut out = String::new();
        loop {
            match chars.next().map(|(_, c)| c) {
                Some('"') => break,
                Some('\\') => match chars.next().map(|(_, c)| c) {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    other => panic!("unsupported escape {other:?}"),
                },
                Some(c) => out.push(c),
                None => panic!("unterminated string"),
            }
        }
        out
    }

    fn parse_number(chars: &mut Chars) -> String {
        let mut out = String::new();
        while matches!(chars.peek(), Some(&(_, c)) if c.is_ascii_digit() || c == '-') {
            out.push(chars.next().unwrap().1);
        }
        out
    }
}

/// Split the file into records: each blank-line-separated block of `key value`.
fn blocks() -> Vec<HashMap<String, String>> {
    let raw = std::fs::read_to_string("docs/test-vectors.txt")
        .expect("docs/test-vectors.txt missing; run `cargo run --bin catp-vectors`");
    let mut out = Vec::new();
    let mut cur = HashMap::new();
    for line in raw.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        let k = it.next().unwrap().to_string();
        let v = it.next().unwrap_or("").trim().to_string();
        cur.entry(k).or_insert(v);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn scalar_lines(key: &str) -> Vec<String> {
    std::fs::read_to_string("docs/test-vectors.txt")
        .unwrap()
        .lines()
        .filter_map(|l| l.strip_prefix(key).map(|r| r.trim().to_string()))
        .collect()
}

#[test]
fn vector_file_is_present_and_substantial() {
    let b = blocks();
    let accepts = b
        .iter()
        .filter(|m| m.get("kind").map(|k| k == "accept").unwrap_or(false))
        .count();
    assert!(
        accepts >= 20,
        "only {accepts} accept vectors; 14.1 asks for one per msg_type per cipher"
    );
}

/// Every `accept` vector must decode, and re-encoding must reproduce it byte
/// for byte. This is the test that catches accidental wire-format drift.
#[test]
fn every_accept_vector_verifies_and_reencodes() {
    let mut checked = 0;
    for m in blocks() {
        if m.get("kind").map(String::as_str) != Some("accept") {
            continue;
        }
        let secret = DeviceSecret::new(unhex(&m["device_secret"]).try_into().unwrap());
        let sender_id = u32::from_str_radix(&m["sender_id"], 16).unwrap();
        let epoch: u32 = m["epoch_id"].parse().unwrap();
        // Cross-epoch vectors (PROTOCOL.md 9.3's `{rx-1, rx}` window) carry the
        // epoch the datagram was encoded under separately from the receiver's.
        let enc_epoch: u32 = match m.get("encode_epoch") {
            Some(s) => s.parse().unwrap(),
            None => epoch,
        };
        let dir = match unhex(&m["direction"])[0] {
            0x00 => Direction::NodeToCollector,
            _ => Direction::CollectorToNode,
        };
        let cipher = CipherId::from_u8(unhex(&m["cipher_id"])[0]).unwrap();
        let wire = unhex(&m["wire"]);

        assert_eq!(
            wire.len(),
            m["wire_len"].parse::<usize>().unwrap(),
            "wire_len mismatch"
        );

        // The published epoch_key and auth_header must match what we derive.
        assert_eq!(
            secret.epoch_key(sender_id, enc_epoch, dir).to_vec(),
            unhex(&m["epoch_key"]),
            "epoch_key drifted"
        );

        // Decode it. Layouts are permissive here: we are checking the codec,
        // not a deployment's provisioning.
        let peer = PeerConfig {
            sender_id,
            secret: secret.clone(),
            cipher,
            layouts: (1u8..=6)
                .flat_map(|f| (0u8..=255).map(move |s| Layout::new(f, s)))
                .collect(),
            inbound_rate_limit: None, // decode() called directly; bypasses PeerState
        };
        let mut w = ReplayWindow::one_second();
        let acc = decode(&wire, &peer, epoch, dir, &mut w)
            .unwrap_or_else(|e| panic!("vector failed to decode: {e:?}"));

        assert_eq!(acc.datagram.sender_id, sender_id);
        assert_eq!(acc.epoch_id, enc_epoch);
        assert_eq!(acc.datagram_offset, m["offset"].parse::<u32>().unwrap());
        assert_eq!(acc.datagram.msg_type, unhex(&m["msg_type"])[0]);
        assert_eq!(
            acc.datagram.auth_header(enc_epoch).to_vec(),
            unhex(&m["auth_header"])
        );

        // Re-encode under the reconstructed epoch and compare byte for byte.
        let again = acc
            .datagram
            .encode(&secret, acc.epoch_id, dir, 65535)
            .expect("re-encode must succeed");
        assert_eq!(again, wire, "re-encoding did not reproduce the vector");
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} vectors exercised");
}

/// Reserved bits are must-ignore: every non-zero value (§14.1 requires the
/// frozen set to carry one vector per value) must decode to the same
/// application content as a baseline with none set (PROTOCOL.md 4.2).
#[test]
fn reserved_bit_vectors_are_ignored_not_rejected() {
    let sweep: Vec<_> = blocks()
        .into_iter()
        .filter(|m| m.get("offset").map(String::as_str) == Some("8") && m.contains_key("wire"))
        .collect();
    assert_eq!(sweep.len(), 31, "expected one vector per non-zero value");
    let secret = DeviceSecret::new(unhex(&sweep[0]["device_secret"]).try_into().unwrap());
    let peer = PeerConfig {
        sender_id: u32::from_str_radix(&sweep[0]["sender_id"], 16).unwrap(),
        secret,
        cipher: CipherId::from_u8(unhex(&sweep[0]["cipher_id"])[0]).unwrap(),
        layouts: vec![],
        inbound_rate_limit: None, // decode() called directly; bypasses PeerState
    };
    let mut last_value = 0u8;
    for m in &sweep {
        let wire = unhex(&m["wire"]);
        // Byte 2 holds reserved in its high 5 bits; the sweep covers 0x01..0x1F
        // exactly once each, in ascending order.
        let value = wire[2] >> 3;
        assert_eq!(value, last_value + 1, "sweep mismatch: {m:?}");
        last_value = value;
        let mut w = ReplayWindow::one_second();
        let acc = decode(
            &wire,
            &peer,
            m["epoch_id"].parse().unwrap(),
            Direction::NodeToCollector,
            &mut w,
        )
        .expect("reserved bits must not cause rejection");
        assert_eq!(acc.datagram.number_value(), Some((1, 10))); // 10 * 10^-1 = 1.0
    }
}

/// Every `reject_datagram` vector must be rejected by the reference §7.4
/// pipeline given the receiver state the vector spells out (PROTOCOL.md 14.1).
#[test]
fn every_reject_datagram_vector_is_rejected() {
    let rejects: Vec<_> = blocks()
        .into_iter()
        .filter(|m| m.get("kind").map(String::as_str) == Some("reject_datagram"))
        .collect();
    assert!(
        rejects.len() >= 16,
        "§7.4 paths + §6.4.4 framing faults missing: {len}",
        len = rejects.len()
    );
    for m in &rejects {
        let secret = DeviceSecret::new(unhex(&m["device_secret"]).try_into().unwrap());
        let receiver_sender = u32::from_str_radix(&m["receiver_sender"], 16).unwrap();
        let receiver_epoch: u32 = m["receiver_epoch"].parse().unwrap();
        let cipher = CipherId::from_u8(unhex(&m["configured_cipher"])[0]).unwrap();
        let dir = match unhex(&m["direction"])[0] {
            0x00 => Direction::NodeToCollector,
            _ => Direction::CollectorToNode,
        };
        let wire = unhex(&m["wire"]);
        let peer = PeerConfig {
            sender_id: receiver_sender,
            secret: secret.clone(),
            cipher,
            layouts: (1u8..=6)
                .flat_map(|f| (0u8..=255).map(move |s| Layout::new(f, s)))
                .collect(),
            inbound_rate_limit: None,
        };
        let mut w = ReplayWindow::one_second();
        if let Some(seen) = m.get("seen_offsets") {
            for o in seen.split(',') {
                w.check_and_set(o.parse().unwrap()).unwrap();
            }
        }
        let fault = m.get("fault").map(String::as_str).unwrap_or("?");
        assert!(
            decode(&wire, &peer, receiver_epoch, dir, &mut w).is_err(),
            "fault {fault:?} was accepted"
        );
    }
}

/// Every `series_payload` vector's outcome must match `validate_series`
/// against the anchor it names (PROTOCOL.md 6.9, 14.1).
#[test]
fn series_grammar_matches_the_vectors() {
    // `series_payload` vectors are scalar lines without their own "# name"
    // block, so this one reads the JSON mirror directly.
    let json_text = std::fs::read_to_string("docs/test-vectors.json")
        .expect("docs/test-vectors.json missing; run `cargo run --bin catp-vectors`");
    let mut accepts = 0;
    let mut rejects = 0;
    for m in tinyjson::parse_array_of_objects(&json_text) {
        if m.get("kind").map(String::as_str) != Some("series_payload") {
            continue;
        }
        let payload = unhex(&m["payload"]);
        let anchor: u32 = m["anchor_offset"].parse().unwrap();
        let ok = validate_series(&payload, anchor).is_ok();
        assert_eq!(
            ok,
            m["outcome"] == "accept",
            "series payload {} outcome mismatch",
            hex(&payload)
        );
        if ok {
            accepts += 1;
        } else {
            rejects += 1;
        }
    }
    assert!(accepts >= 3 && rejects >= 5, "SERIES vectors look thin");
}

/// Every `reject_time_announce` vector must verify as a MAC-genuine
/// announcement and then be rejected by the node's clock rules (§11.5).
#[test]
fn cold_start_reject_vectors_are_rejected() {
    let rejects: Vec<_> = blocks()
        .into_iter()
        .filter(|m| m.get("kind").map(String::as_str) == Some("reject_time_announce"))
        .collect();
    assert_eq!(rejects.len(), 2, "expected both 11.5 rejection vectors");
    for m in &rejects {
        let secret = DeviceSecret::new(unhex(&m["device_secret"]).try_into().unwrap());
        let sender_id = u32::from_str_radix(&m["sender_id"], 16).unwrap();
        let wire = unhex(&m["wire"]);
        let asserted: i64 = m["asserted_time"].parse().unwrap();
        let last_epoch: u32 = m["last_epoch"].parse().unwrap();
        decode_time_announce(&wire, sender_id, &secret).expect("MAC must verify");
        let mut clock = match m["clock_state"].as_str() {
            "cold" => NodeClock::clockless(last_epoch),
            _ => NodeClock::synced(last_epoch),
        };
        assert!(
            clock.accept_time_announce(asserted, asserted - 5).is_err(),
            "{:?} announce was accepted",
            m.get("name")
        );
    }
}

/// The TIME_ANNOUNCE vector verifies under its own key schedule.
#[test]
fn time_announce_vector_verifies() {
    let m = blocks()
        .into_iter()
        .find(|m| m.get("kind").map(String::as_str) == Some("accept_time_announce"))
        .expect("TIME_ANNOUNCE vector missing");
    let secret = DeviceSecret::new(unhex(&m["device_secret"]).try_into().unwrap());
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).unwrap();
    let wire = unhex(&m["wire"]);

    assert_eq!(
        secret
            .time_key(sender_id, Direction::CollectorToNode)
            .to_vec(),
        unhex(&m["time_key"]),
        "collector-to-node time_key drifted"
    );
    let got = decode_time_announce(&wire, sender_id, &secret).expect("must verify");
    assert_eq!(got, m["asserted_time"].parse::<i64>().unwrap());

    // And re-encoding reproduces it.
    assert_eq!(
        Datagram::time_announce(sender_id, got, &secret).unwrap(),
        wire
    );
}

/// The TIME_REQUEST vector verifies under the node-to-collector key, and must
/// NOT verify under the announce key (PROTOCOL.md 11.2).
#[test]
fn time_request_vector_verifies_and_is_directional() {
    let m = blocks()
        .into_iter()
        .find(|m| m.get("kind").map(String::as_str) == Some("accept_time_request"))
        .expect("TIME_REQUEST vector missing");
    let secret = DeviceSecret::new(unhex(&m["device_secret"]).try_into().unwrap());
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).unwrap();
    let wire = unhex(&m["wire"]);

    assert_eq!(
        secret
            .time_key(sender_id, Direction::NodeToCollector)
            .to_vec(),
        unhex(&m["time_key"]),
        "node-to-collector time_key drifted"
    );
    decode_time_request(&wire, sender_id, &secret).expect("must verify");
    assert_eq!(Datagram::time_request(sender_id, &secret).unwrap(), wire);

    // The two time keys are distinct, so a request must not pass as an announce.
    assert!(decode_time_announce(&wire, sender_id, &secret).is_err());
    assert_ne!(
        secret.time_key(sender_id, Direction::NodeToCollector),
        secret.time_key(sender_id, Direction::CollectorToNode)
    );
}

/// Every payload the vectors mark accepted must pass, and every one marked
/// rejected must fail (PROTOCOL.md 6.3, 6.3.1).
#[test]
fn number_grammar_matches_the_vectors() {
    let ok = scalar_lines("accept_number");
    let bad = scalar_lines("reject_number");
    assert!(ok.len() >= 6 && bad.len() >= 4, "NUMBER vectors look thin");

    for l in &ok {
        assert!(validate_number(&unhex(l)).is_ok(), "{l} should be accepted");
    }
    for l in &bad {
        assert!(
            validate_number(&unhex(l)).is_err(),
            "{l} should be rejected"
        );
    }
}

/// Corrupting any byte of any accept vector must make it fail. Cheap, broad,
/// and the property the whole protocol exists to provide.
#[test]
fn every_vector_is_tamper_evident() {
    for m in blocks() {
        if m.get("kind").map(String::as_str) != Some("accept") {
            continue;
        }
        let secret = DeviceSecret::new(unhex(&m["device_secret"]).try_into().unwrap());
        let sender_id = u32::from_str_radix(&m["sender_id"], 16).unwrap();
        let epoch: u32 = m["epoch_id"].parse().unwrap();
        let dir = match unhex(&m["direction"])[0] {
            0x00 => Direction::NodeToCollector,
            _ => Direction::CollectorToNode,
        };
        let cipher = CipherId::from_u8(unhex(&m["cipher_id"])[0]).unwrap();
        let wire = unhex(&m["wire"]);
        let peer = PeerConfig {
            sender_id,
            secret,
            cipher,
            layouts: (1u8..=6)
                .flat_map(|f| (0u8..=255).map(move |s| Layout::new(f, s)))
                .collect(),
            inbound_rate_limit: None, // decode() called directly; bypasses PeerState
        };
        // One flip per byte is enough breadth here; wire.rs flips every bit.
        for byte in 0..wire.len() {
            let mut t = wire.clone();
            t[byte] ^= 0x01;
            let mut w = ReplayWindow::one_second();
            assert!(
                decode(&t, &peer, epoch, dir, &mut w).is_err(),
                "corrupting byte {byte} was accepted"
            );
        }
    }
}

/// `docs/test-vectors.json` (issue #35) must be a faithful mirror of
/// `docs/test-vectors.txt` -- every field on every `accept` block must appear
/// identically in the JSON object for the same vector (matched by `wire`,
/// which is unique per vector). Both are written from the same call site in
/// `src/bin/vectors.rs`, so a mismatch here means that guarantee broke, not
/// that this test is checking something redundant.
#[test]
fn json_mirror_matches_the_text_vectors() {
    let json_text = std::fs::read_to_string("docs/test-vectors.json")
        .expect("docs/test-vectors.json missing; run `cargo run --bin catp-vectors`");
    let json_objects = tinyjson::parse_array_of_objects(&json_text);

    let text_accepts: Vec<_> = blocks()
        .into_iter()
        .filter(|m| m.get("kind").map(String::as_str) == Some("accept"))
        .collect();
    assert!(
        text_accepts.len() >= 20,
        "only {} accept blocks in the text file",
        text_accepts.len()
    );

    let json_accepts: Vec<_> = json_objects
        .iter()
        .filter(|o| o.get("kind").map(String::as_str) == Some("accept"))
        .collect();
    assert_eq!(
        text_accepts.len(),
        json_accepts.len(),
        "text file and JSON mirror disagree on how many accept vectors exist"
    );

    // Fields present in every text `accept` block, per accept() in
    // src/bin/vectors.rs.
    let fields = [
        "device_secret",
        "sender_id",
        "epoch_id",
        "direction",
        "cipher_id",
        "msg_type",
        "offset",
        "epoch_key",
        "auth_header",
        "wire",
        "wire_len",
    ];
    for text_obj in &text_accepts {
        let wire = &text_obj["wire"];
        let json_obj = json_accepts
            .iter()
            .find(|o| o.get("wire").map(String::as_str) == Some(wire.as_str()))
            .unwrap_or_else(|| panic!("no JSON vector with wire={wire}"));
        for field in fields {
            assert_eq!(
                &text_obj[field], &json_obj[field],
                "field {field} differs between text and JSON for wire={wire}"
            );
        }
    }
}

/// The §6.4.4 fixed-width vector (issue #93): the datagram carries two
/// records of the same `(format, schema_version)` pair, one at the layout's
/// fixed body width and one at a size that disagrees with it. The receiver
/// provisioned with `Layout::with_fixed_width` must accept the datagram,
/// deliver the record whose `size` matches, and skip the mismatching record
/// individually -- the surrounding records and the datagram itself survive.
#[test]
fn fixed_width_mismatch_skips_the_record_not_the_datagram() {
    let json_text = std::fs::read_to_string("docs/test-vectors.json")
        .expect("docs/test-vectors.json missing; run `cargo run --bin catp-vectors`");
    let fixed_width_vectors: Vec<_> = tinyjson::parse_array_of_objects(&json_text)
        .into_iter()
        .filter(|m| m.get("kind").map(String::as_str) == Some("accept"))
        .filter(|m| m.get("fixed_width").is_some())
        .collect();
    assert_eq!(
        fixed_width_vectors.len(),
        1,
        "expected one fixed-width vector"
    );

    let m = &fixed_width_vectors[0];
    let secret = DeviceSecret::new(unhex(&m["device_secret"]).try_into().unwrap());
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).unwrap();
    let epoch: u32 = m["epoch_id"].parse().unwrap();
    let dir = match unhex(&m["direction"])[0] {
        0x00 => Direction::NodeToCollector,
        _ => Direction::CollectorToNode,
    };
    let cipher = CipherId::from_u8(unhex(&m["cipher_id"])[0]).unwrap();
    let fixed_width: u16 = m["fixed_width"].parse().unwrap();
    let mut layout_fields = m["layout"].split_whitespace();
    let layout_format = u8::from_str_radix(
        layout_fields.next().expect("layout needs a format byte"),
        16,
    )
    .unwrap();
    let layout_schema = u8::from_str_radix(
        layout_fields
            .next()
            .expect("layout needs a schema_version byte"),
        16,
    )
    .unwrap();
    let wire = unhex(&m["wire"]);

    let peer = PeerConfig {
        sender_id,
        secret: secret.clone(),
        cipher,
        layouts: vec![Layout::with_fixed_width(
            layout_format,
            layout_schema,
            fixed_width,
        )],
        inbound_rate_limit: None,
    };
    let mut w = ReplayWindow::one_second();
    let acc = decode(&wire, &peer, epoch, dir, &mut w)
        .unwrap_or_else(|e| panic!("fixed-width vector failed to decode: {e:?}"));

    // Exactly one record delivered (its body is the fixed width) and exactly
    // one skipped (same pair, size disagrees with the width).
    assert_eq!(acc.datagram.records.len(), 1);
    let kept = &acc.datagram.records[0];
    assert_eq!(kept.body.len(), fixed_width as usize);
    assert_eq!(
        (kept.format, kept.schema_version),
        (layout_format, layout_schema)
    );
    assert_eq!(acc.skipped.len(), 1);
    let skipped = &acc.skipped[0];
    assert_ne!(skipped.body.len(), fixed_width as usize);
    assert_eq!(
        (skipped.format, skipped.schema_version),
        (layout_format, layout_schema)
    );
}
