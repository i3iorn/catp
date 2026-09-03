//! Conformance against the frozen vectors of PROTOCOL.md 14.1.
//!
//! `docs/test-vectors.txt` is the authority, not this code. If a change to the
//! codec alters any byte in it, these tests fail — which is the point: the
//! vectors are what a second implementation checks itself against, so they must
//! not drift silently.
//!
//! Regenerate deliberately with:
//!     cargo run --bin catp-vectors > docs/test-vectors.txt

use catp::wire::{decode, decode_time_announce, decode_time_request, Datagram, PeerConfig};
use catp::*;
use std::collections::HashMap;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
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
    let accepts = b.iter().filter(|m| m.get("kind").map(|k| k == "accept").unwrap_or(false)).count();
    assert!(accepts >= 20, "only {accepts} accept vectors; 14.1 asks for one per msg_type per cipher");
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
        let secret = DeviceSecret(unhex(&m["device_secret"]).try_into().unwrap());
        let sender_id = u32::from_str_radix(&m["sender_id"], 16).unwrap();
        let epoch: u32 = m["epoch_id"].parse().unwrap();
        let dir = match unhex(&m["direction"])[0] {
            0x00 => Direction::NodeToCollector,
            _ => Direction::CollectorToNode,
        };
        let cipher = CipherId::from_u8(unhex(&m["cipher_id"])[0]).unwrap();
        let wire = unhex(&m["wire"]);

        assert_eq!(wire.len(), m["wire_len"].parse::<usize>().unwrap(), "wire_len mismatch");

        // The published epoch_key and auth_header must match what we derive.
        assert_eq!(
            secret.epoch_key(sender_id, epoch, dir).to_vec(),
            unhex(&m["epoch_key"]),
            "epoch_key drifted"
        );

        // Decode it. Layouts are permissive here: we are checking the codec,
        // not a deployment's provisioning.
        let peer = PeerConfig {
            sender_id,
            secret: secret.clone(),
            cipher,
            layouts: (1u8..=6).flat_map(|f| (0u8..=255).map(move |s| (f, s))).collect(),
            inbound_rate_limit: None, // decode() called directly; bypasses PeerState
        };
        let mut w = ReplayWindow::one_second();
        let acc = decode(&wire, &peer, epoch, dir, &mut w)
            .unwrap_or_else(|e| panic!("vector failed to decode: {e:?}"));

        assert_eq!(acc.datagram.sender_id, sender_id);
        assert_eq!(acc.epoch_id, epoch);
        assert_eq!(acc.datagram_offset, m["offset"].parse::<u32>().unwrap());
        assert_eq!(acc.datagram.msg_type, unhex(&m["msg_type"])[0]);
        assert_eq!(acc.datagram.auth_header(epoch).to_vec(), unhex(&m["auth_header"]));

        // Re-encode and compare byte for byte.
        let again = acc
            .datagram
            .encode(&secret, epoch, dir, 65535)
            .expect("re-encode must succeed");
        assert_eq!(again, wire, "re-encoding did not reproduce the vector");
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} vectors exercised");
}

/// Reserved bits are must-ignore: the vector with all five set must decode to
/// the same application content as one with none set (PROTOCOL.md 4.2).
#[test]
fn reserved_bit_vector_is_ignored_not_rejected() {
    let m = blocks()
        .into_iter()
        .find(|m| m.get("offset").map(String::as_str) == Some("4") && m.contains_key("wire"))
        .expect("reserved-bits vector missing");
    let wire = unhex(&m["wire"]);
    // Byte 2 holds reserved in its high 5 bits.
    assert_eq!(wire[2] >> 3, 0x1F, "vector should have all reserved bits set");

    let secret = DeviceSecret(unhex(&m["device_secret"]).try_into().unwrap());
    let peer = PeerConfig {
        sender_id: u32::from_str_radix(&m["sender_id"], 16).unwrap(),
        secret,
        cipher: CipherId::from_u8(unhex(&m["cipher_id"])[0]).unwrap(),
        layouts: vec![],
        inbound_rate_limit: None, // decode() called directly; bypasses PeerState
    };
    let mut w = ReplayWindow::one_second();
    let acc = decode(&wire, &peer, m["epoch_id"].parse().unwrap(), Direction::NodeToCollector, &mut w)
        .expect("reserved bits must not cause rejection");
    assert_eq!(acc.datagram.number_literal(), Some("1"));
}

/// The TIME_ANNOUNCE vector verifies under its own key schedule.
#[test]
fn time_announce_vector_verifies() {
    let m = blocks()
        .into_iter()
        .find(|m| m.get("kind").map(String::as_str) == Some("accept_time_announce"))
        .expect("TIME_ANNOUNCE vector missing");
    let secret = DeviceSecret(unhex(&m["device_secret"]).try_into().unwrap());
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).unwrap();
    let wire = unhex(&m["wire"]);

    assert_eq!(
        secret.time_key(sender_id, Direction::CollectorToNode).to_vec(),
        unhex(&m["time_key"]),
        "collector-to-node time_key drifted"
    );
    let got = decode_time_announce(&wire, sender_id, &secret).expect("must verify");
    assert_eq!(got, m["asserted_time"].parse::<i64>().unwrap());

    // And re-encoding reproduces it.
    assert_eq!(Datagram::time_announce(sender_id, got, &secret).unwrap(), wire);
}

/// The TIME_REQUEST vector verifies under the node-to-collector key, and must
/// NOT verify under the announce key (PROTOCOL.md 11.2).
#[test]
fn time_request_vector_verifies_and_is_directional() {
    let m = blocks()
        .into_iter()
        .find(|m| m.get("kind").map(String::as_str) == Some("accept_time_request"))
        .expect("TIME_REQUEST vector missing");
    let secret = DeviceSecret(unhex(&m["device_secret"]).try_into().unwrap());
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).unwrap();
    let wire = unhex(&m["wire"]);

    assert_eq!(
        secret.time_key(sender_id, Direction::NodeToCollector).to_vec(),
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

/// Every literal the vectors mark accepted must pass, and every one marked
/// rejected must fail (PROTOCOL.md 6.3).
#[test]
fn number_grammar_matches_the_vectors() {
    let ok = scalar_lines("accept_number");
    let bad = scalar_lines("reject_number");
    assert!(ok.len() >= 8 && bad.len() >= 12, "grammar vectors look thin");

    for l in &ok {
        assert!(validate_number(l.as_bytes()).is_ok(), "{l} should be accepted");
    }
    for l in &bad {
        let raw = if l == "<empty>" { "" } else { l.as_str() };
        assert!(validate_number(raw.as_bytes()).is_err(), "{l} should be rejected");
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
        let secret = DeviceSecret(unhex(&m["device_secret"]).try_into().unwrap());
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
            layouts: (1u8..=6).flat_map(|f| (0u8..=255).map(move |s| (f, s))).collect(),
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
