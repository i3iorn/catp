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

use catp::wire::{decode, decode_time_announce, decode_time_request, Datagram, PeerConfig};
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
        assert_eq!(chars.next().map(|(_, c)| c), Some('['), "expected top-level array");
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
        assert_eq!(chars.next().map(|(_, c)| c), Some('{'), "expected a JSON object");
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
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// All layouts permissive: this IUT checks the codec, not a deployment's
/// provisioning (mirrors `tests/vectors.rs`).
fn permissive_layouts() -> Vec<(u8, u8)> {
    (1u8..=6).flat_map(|f| (0u8..=255).map(move |s| (f, s))).collect()
}

fn check_accept(m: &HashMap<String, String>) -> Result<(), String> {
    let secret = DeviceSecret::new(
        unhex(&m["device_secret"]).try_into().map_err(|_| "device_secret not 32 bytes".to_string())?,
    );
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).map_err(|e| e.to_string())?;
    let epoch: u32 = m["epoch_id"].parse().map_err(|_| "bad epoch_id".to_string())?;
    let dir = match unhex(&m["direction"]).first() {
        Some(0x00) => Direction::NodeToCollector,
        Some(_) => Direction::CollectorToNode,
        None => return Err("missing direction".into()),
    };
    let cipher_byte = *unhex(&m["cipher_id"]).first().ok_or("missing cipher_id")?;
    let cipher = CipherId::from_u8(cipher_byte).ok_or_else(|| format!("unknown cipher_id {cipher_byte:#04x}"))?;
    let wire = unhex(&m["wire"]);

    let peer = PeerConfig {
        sender_id,
        secret: secret.clone(),
        cipher,
        layouts: permissive_layouts(),
        inbound_rate_limit: None,
    };
    let mut window = ReplayWindow::one_second();
    let acc = decode(&wire, &peer, epoch, dir, &mut window).map_err(|e| format!("decode rejected: {e:?}"))?;

    let again = acc.datagram.encode(&secret, epoch, dir, u16::MAX as usize).map_err(|e| format!("reencode failed: {e:?}"))?;
    if again != wire {
        return Err("reencode mismatch".into());
    }
    Ok(())
}

fn check_accept_time_request(m: &HashMap<String, String>) -> Result<(), String> {
    let secret = DeviceSecret::new(
        unhex(&m["device_secret"]).try_into().map_err(|_| "device_secret not 32 bytes".to_string())?,
    );
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).map_err(|e| e.to_string())?;
    let wire = unhex(&m["wire"]);

    decode_time_request(&wire, sender_id, &secret).map_err(|e| format!("decode rejected: {e:?}"))?;
    let again = Datagram::time_request(sender_id, &secret).map_err(|e| format!("reencode failed: {e:?}"))?;
    if again != wire {
        return Err("reencode mismatch".into());
    }
    Ok(())
}

fn check_accept_time_announce(m: &HashMap<String, String>) -> Result<(), String> {
    let secret = DeviceSecret::new(
        unhex(&m["device_secret"]).try_into().map_err(|_| "device_secret not 32 bytes".to_string())?,
    );
    let sender_id = u32::from_str_radix(&m["sender_id"], 16).map_err(|e| e.to_string())?;
    let wire = unhex(&m["wire"]);
    let asserted_time: i64 = m["asserted_time"].parse().map_err(|_| "bad asserted_time".to_string())?;

    let got = decode_time_announce(&wire, sender_id, &secret).map_err(|e| format!("decode rejected: {e:?}"))?;
    if got != asserted_time {
        return Err("wrong outcome: asserted_time mismatch".into());
    }
    let again =
        Datagram::time_announce(sender_id, got, &secret).map_err(|e| format!("reencode failed: {e:?}"))?;
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

fn verdict_of(m: &HashMap<String, String>) -> String {
    let result = match m.get("kind").map(String::as_str) {
        Some("accept") => check_accept(m),
        Some("accept_time_request") => check_accept_time_request(m),
        Some("accept_time_announce") => check_accept_time_announce(m),
        Some("number_payload") => check_number_payload(m),
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
        assert_eq!(verdict(r#"{"kind": "number_payload", "payload": "010000", "outcome": "accept"}"#), "PASS");
        assert_eq!(verdict(r#"{"kind": "number_payload", "payload": "000001", "outcome": "reject"}"#), "PASS");
        assert!(verdict(r#"{"kind": "number_payload", "payload": "000001", "outcome": "accept"}"#).starts_with("FAIL"));
    }

    #[test]
    fn all_vectors_in_the_frozen_file_pass_through_this_iut() {
        // The IUT's own verdicts must agree with what tests/vectors.rs already
        // proves against docs/test-vectors.json -- this is the check that would
        // catch this binary drifting from the crate it wraps.
        let json = std::fs::read_to_string("docs/test-vectors.json").expect("vectors file missing");
        let objects = tinyjson::parse_array_of_objects(&json);
        for m in &objects {
            let v = verdict_of(m);
            assert_eq!(v, "PASS", "vector failed: {m:?} -> {v}");
        }
        assert!(objects.len() >= 30, "only checked {} vectors", objects.len());
    }
}
