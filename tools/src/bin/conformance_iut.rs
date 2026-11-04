//! `catp-conformance-iut`: the reference implementation-under-test (IUT) for
//! the conformance runner contract (`docs/CONFORMANCE_RUNNER.md`, issue #35).
//!
//! Reads JSON Lines from stdin -- one `docs/test-vectors.json` object per
//! line -- and writes `PASS` or `FAIL <reason>` per line to stdout, in order.
//! Run directly, or through `tools/run_conformance.py`:
//!
//! ```text
//! cargo run --quiet --bin catp-conformance-iut < some_vectors.jsonl
//! python3 tools/run_conformance.py -- cargo run --quiet --bin catp-conformance-iut
//! ```

use catp::wire::{Datagram, PeerConfig, decode, decode_time_announce, decode_time_request};
use catp::*;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;

/// A minimal single-line JSON object parser: exactly what one
/// `docs/test-vectors.json` element needs (flat object, string/number
/// values). Not general-purpose -- see `tests/vectors.rs`'s `tinyjson` for
/// the sibling parser this one is deliberately kept in step with.
mod tinyjson {
    use std::collections::HashMap;

    pub fn parse_object(s: &str) -> HashMap<String, String> {
        let mut chars = s.trim().char_indices().peekable();
        parse_object_from(&mut chars)
    }

    /// A top-level `[ {...}, {...}, ... ]` array, as `docs/test-vectors.json`
    /// is shaped. Only used by this binary's own tests, to check its verdicts
    /// against the real vector file without shelling out to itself.
    #[cfg(test)]
    pub fn parse_array_of_objects(s: &str) -> Vec<HashMap<String, String>> {
        let mut chars = s.trim().char_indices().peekable();
        assert_eq!(
            chars.next().map(|(_, c)| c),
            Some('['),
            "expected top-level array"
        );
        let mut out = Vec::new();
        loop {
            skip_ws(&mut chars);
            match chars.peek().map(|&(_, c)| c) {
                Some(']') => break,
                Some('{') => out.push(parse_object_from(&mut chars)),
                Some(',') => {
                    chars.next();
                }
                other => panic!("unexpected {other:?} in array"),
            }
        }
        out
    }

    fn parse_object_from(chars: &mut Chars) -> HashMap<String, String> {
        assert_eq!(
            chars.next().map(|(_, c)| c),
            Some('{'),
            "expected a JSON object"
        );
        let mut map = HashMap::new();
        loop {
            skip_ws(chars);
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
                    skip_ws(chars);
                    assert_eq!(chars.next().map(|(_, c)| c), Some(':'));
                    skip_ws(chars);
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

    type Chars<'a> = std::iter::Peekable<std::str::CharIndices<'a>>;

    fn skip_ws(chars: &mut Chars) {
        while matches!(chars.peek(), Some(&(_, c)) if c.is_whitespace()) {
            chars.next();
        }
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// All layouts permissive: this IUT checks the codec, not a deployment's
/// provisioning (mirrors `tests/vectors.rs`).
fn permissive_layouts() -> Vec<(u8, u8)> {
    (1u8..=6)
        .flat_map(|f| (0u8..=255).map(move |s| (f, s)))
        .collect()
}

fn check_accept(m: &HashMap<String, String>) -> Result<(), String> {
    let secret = DeviceSecret::new(
        unhex(&m["device_secret"])
            .try_into()
            .map_err(|_| "device_secret not 32 bytes".to_string())?,
    );
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).map_err(|e| e.to_string())?;
    let epoch: u32 = m["epoch_id"]
        .parse()
        .map_err(|_| "bad epoch_id".to_string())?;
    let dir = match unhex(&m["direction"]).first() {
        Some(0x00) => Direction::NodeToCollector,
        Some(_) => Direction::CollectorToNode,
        None => return Err("missing direction".into()),
    };
    let cipher_byte = *unhex(&m["cipher_id"]).first().ok_or("missing cipher_id")?;
    let cipher = CipherId::from_u8(cipher_byte)
        .ok_or_else(|| format!("unknown cipher_id {cipher_byte:#04x}"))?;
    let wire = unhex(&m["wire"]);

    let peer = PeerConfig {
        sender_id,
        secret: secret.clone(),
        cipher,
        layouts: permissive_layouts(),
        inbound_rate_limit: None,
    };
    let mut window: ReplayWindow = ReplayWindow::one_second();
    let acc = decode(&wire, &peer, epoch, dir, &mut window)
        .map_err(|e| format!("decode rejected: {e:?}"))?;

    // Re-encode under the epoch the datagram actually reconstructed to, which
    // for a cross-epoch vector (`encode_epoch` present) is not the receiver's
    // own epoch (PROTOCOL.md 9.3's `{rx-1, rx}` window).
    let enc_epoch: u32 = match m.get("encode_epoch") {
        Some(s) => s.parse().map_err(|_| "bad encode_epoch".to_string())?,
        None => epoch,
    };
    if acc.epoch_id != enc_epoch {
        return Err(format!(
            "reencode mismatch: reconstructed epoch {} != encode_epoch {enc_epoch}",
            acc.epoch_id
        ));
    }
    let again = acc
        .datagram
        .encode(&secret, acc.epoch_id, dir, u16::MAX as usize)
        .map_err(|e| format!("reencode failed: {e:?}"))?;
    if again != wire {
        return Err("reencode mismatch".into());
    }
    Ok(())
}

fn check_accept_time_request(m: &HashMap<String, String>) -> Result<(), String> {
    let secret = DeviceSecret::new(
        unhex(&m["device_secret"])
            .try_into()
            .map_err(|_| "device_secret not 32 bytes".to_string())?,
    );
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).map_err(|e| e.to_string())?;
    let wire = unhex(&m["wire"]);

    decode_time_request(&wire, sender_id, &secret)
        .map_err(|e| format!("decode rejected: {e:?}"))?;
    let again = Datagram::time_request(sender_id, &secret)
        .map_err(|e| format!("reencode failed: {e:?}"))?;
    if again != wire {
        return Err("reencode mismatch".into());
    }
    Ok(())
}

fn check_accept_time_announce(m: &HashMap<String, String>) -> Result<(), String> {
    let secret = DeviceSecret::new(
        unhex(&m["device_secret"])
            .try_into()
            .map_err(|_| "device_secret not 32 bytes".to_string())?,
    );
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).map_err(|e| e.to_string())?;
    let wire = unhex(&m["wire"]);
    let asserted_time: i64 = m["asserted_time"]
        .parse()
        .map_err(|_| "bad asserted_time".to_string())?;

    let got = decode_time_announce(&wire, sender_id, &secret)
        .map_err(|e| format!("decode rejected: {e:?}"))?;
    if got != asserted_time {
        return Err("wrong outcome: asserted_time mismatch".into());
    }
    let again = Datagram::time_announce(sender_id, got, &secret)
        .map_err(|e| format!("reencode failed: {e:?}"))?;
    if again != wire {
        return Err("reencode mismatch".into());
    }
    Ok(())
}

fn check_number_payload(m: &HashMap<String, String>) -> Result<(), String> {
    let payload = unhex(&m["payload"]);
    let want_accept = m["outcome"] == "accept";
    let got_accept = validate_number(&payload).is_ok();
    if got_accept != want_accept {
        return Err(format!("wrong outcome: expected {}", m["outcome"]));
    }
    Ok(())
}

fn check_reject_datagram(m: &HashMap<String, String>) -> Result<(), String> {
    let secret = DeviceSecret::new(
        unhex(&m["device_secret"])
            .try_into()
            .map_err(|_| "device_secret not 32 bytes".to_string())?,
    );
    let receiver_sender = u32::from_str_radix(&m["receiver_sender"], 16)
        .map_err(|_| "bad receiver_sender".to_string())?;
    let receiver_epoch: u32 = m["receiver_epoch"]
        .parse()
        .map_err(|_| "bad receiver_epoch".to_string())?;
    let configured = unhex(&m["configured_cipher"]);
    let cipher = CipherId::from_u8(*configured.first().ok_or("missing configured_cipher")?)
        .ok_or("configured_cipher unimplemented")?;
    let dir = match unhex(&m["direction"]).first() {
        Some(0x00) => Direction::NodeToCollector,
        Some(_) => Direction::CollectorToNode,
        None => return Err("missing direction".into()),
    };
    let wire = unhex(&m["wire"]);

    let peer = PeerConfig {
        sender_id: receiver_sender,
        secret: secret.clone(),
        cipher,
        layouts: permissive_layouts(),
        inbound_rate_limit: None,
    };
    let mut window = ReplayWindow::one_second();
    // Seed the replay window with the offsets the vector says the receiver has
    // already accepted, so replay / below-window vectors express their state.
    if let Some(seen) = m.get("seen_offsets") {
        for o in seen.split(',') {
            let o: u32 = o.parse().map_err(|_| "bad seen_offsets".to_string())?;
            window
                .check_and_set(o)
                .map_err(|e| format!("seeding seen offset {o} failed: {e:?}"))?;
        }
    }
    if decode(&wire, &peer, receiver_epoch, dir, &mut window).is_ok() {
        return Err(format!(
            "wrong outcome: decode accepted a {} vector",
            m.get("fault").map(String::as_str).unwrap_or("?")
        ));
    }
    Ok(())
}

fn check_series_payload(m: &HashMap<String, String>) -> Result<(), String> {
    let payload = unhex(&m["payload"]);
    let anchor: u32 = m["anchor_offset"]
        .parse()
        .map_err(|_| "bad anchor_offset".to_string())?;
    let want_accept = m["outcome"] == "accept";
    let got_accept = validate_series(&payload, anchor).is_ok();
    if got_accept != want_accept {
        return Err(format!("wrong outcome: expected {}", m["outcome"]));
    }
    Ok(())
}

fn check_reject_time_announce(m: &HashMap<String, String>) -> Result<(), String> {
    let secret = DeviceSecret::new(
        unhex(&m["device_secret"])
            .try_into()
            .map_err(|_| "device_secret not 32 bytes".to_string())?,
    );
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).map_err(|e| e.to_string())?;
    let wire = unhex(&m["wire"]);
    let asserted_time: i64 = m["asserted_time"]
        .parse()
        .map_err(|_| "bad asserted_time".to_string())?;
    let last_epoch: u32 = m["last_epoch"]
        .parse()
        .map_err(|_| "bad last_epoch".to_string())?;

    // The MAC is genuine; the wire must verify first. The rejection the vector
    // encodes happens in the node's clock state machine (PROTOCOL.md 11.5).
    decode_time_announce(&wire, sender_id, &secret)
        .map_err(|e| format!("wire should have verified: {e:?}"))?;
    let mut clock = match m["clock_state"].as_str() {
        "cold" => NodeClock::clockless(last_epoch),
        "valid" => NodeClock::synced(last_epoch),
        other => return Err(format!("unknown clock_state {other:?}")),
    };
    if clock
        .accept_time_announce(asserted_time, asserted_time - 5)
        .is_ok()
    {
        return Err("wrong outcome: announce was accepted".into());
    }
    Ok(())
}

fn verdict_of(m: &HashMap<String, String>) -> String {
    let result = match m.get("kind").map(String::as_str) {
        Some("accept") => check_accept(m),
        Some("accept_time_request") => check_accept_time_request(m),
        Some("accept_time_announce") => check_accept_time_announce(m),
        Some("number_payload") => check_number_payload(m),
        Some("reject_datagram") => check_reject_datagram(m),
        Some("series_payload") => check_series_payload(m),
        Some("reject_time_announce") => check_reject_time_announce(m),
        Some(other) => Err(format!("unrecognized kind {other:?}")),
        None => Err("missing kind".into()),
    };
    match result {
        Ok(()) => "PASS".to_string(),
        Err(reason) => format!("FAIL {reason}"),
    }
}

fn verdict(line: &str) -> String {
    verdict_of(&tinyjson::parse_object(line))
}

fn main() -> ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut all_passed = true;

    for line in stdin.lock().lines() {
        let line = line.expect("failed to read stdin");
        if line.trim().is_empty() {
            continue;
        }
        let v = verdict(&line);
        all_passed &= v == "PASS";
        writeln!(out, "{v}").expect("failed to write stdout");
    }

    if all_passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_known_good_vector() {
        let line = r#"{ "name": "t", "kind": "accept", "device_secret": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "sender_id": "12345678", "epoch_id": 13281250, "direction": "00", "cipher_id": "01", "msg_type": "04", "offset": 4096, "wire": "24120010001234567802092e51c98b042e369946", "wire_len": 20 }"#;
        assert_eq!(verdict(line), "PASS");
    }

    #[test]
    fn rejects_a_corrupted_vector() {
        let line = r#"{ "name": "t", "kind": "accept", "device_secret": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "sender_id": "12345678", "epoch_id": 13281250, "direction": "00", "cipher_id": "01", "msg_type": "04", "offset": 4096, "wire": "24120010001234567802092e51c98b042e369947", "wire_len": 20 }"#;
        assert!(verdict(line).starts_with("FAIL"));
    }

    #[test]
    fn number_payload_outcomes_match() {
        assert_eq!(
            verdict(r#"{"kind": "number_payload", "payload": "010000", "outcome": "accept"}"#),
            "PASS"
        );
        assert_eq!(
            verdict(r#"{"kind": "number_payload", "payload": "000001", "outcome": "reject"}"#),
            "PASS"
        );
        assert!(
            verdict(r#"{"kind": "number_payload", "payload": "000001", "outcome": "accept"}"#)
                .starts_with("FAIL")
        );
    }

    #[test]
    fn all_vectors_in_the_frozen_file_pass_through_this_iut() {
        // The IUT's own verdicts must agree with what tests/vectors.rs already
        // proves against docs/test-vectors.json -- this is the check that would
        // catch this binary drifting from the crate it wraps.
        //
        // `cargo test`'s CWD for a workspace member is that member's own
        // package directory, not the workspace root (verified empirically) --
        // so this can't use a plain "docs/..." relative path the way
        // tests/vectors.rs (in the root `catp` package) does. `catp`'s own
        // `Cargo.toml`, and `docs/` beside it, are this package's parent.
        let json = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../docs/test-vectors.json"
        ))
        .expect("vectors file missing");
        let objects = tinyjson::parse_array_of_objects(&json);
        for m in &objects {
            let v = verdict_of(m);
            assert_eq!(v, "PASS", "vector failed: {m:?} -> {v}");
        }
        assert!(
            objects.len() >= 30,
            "only checked {} vectors",
            objects.len()
        );
    }
}
