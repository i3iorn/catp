//! CATP reference collector: verifies datagrams and prints accepted records.
//!
//! Usage: catp-collector \[bind_addr\]
//!
//! Implements the receiver obligations of PROTOCOL.md 7.4: checks in order,
//! no persistent state mutated before the MAC verifies, silent discard on
//! failure (surfaced here as a local counter, per 6.8), and per-epoch replay
//! windows for the two-epoch acceptance window of 9.3.

use catp::wire::PeerConfig;
use catp::*;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

const SENDER_ID: u32 = 0x0000_1234;
const SECRET: [u8; 32] = [0x5A; 32];
const CIPHER: CipherId = CipherId::HmacSha256T32;
const SENSOR_SCHEMA: u8 = 1;
const EVENT_SCHEMA: u8 = 2;
const ALARM_SCHEMA: u8 = 3;
// PROTOCOL.md 6.4.2.2: reserved, means "no field definition is claimed".
const UNSTRUCTURED: u8 = SCHEMA_UNSTRUCTURED;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock before 1970").as_secs()
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock before 1970").as_millis() as u64
}

#[derive(Default)]
struct Stats {
    accepted: u64,
    auth_failed: u64,
    replayed: u64,
    framing: u64,
    other: u64,
    skipped_records: u64,
    // PROTOCOL.md 10.3: "counted rather than silently absorbed."
    rate_limited: u64,
}

fn label(mt: MsgType) -> &'static str {
    match mt {
        MsgType::Message => "MESSAGE",
        MsgType::Event => "EVENT",
        MsgType::Alarm => "ALARM",
        MsgType::Number => "NUMBER",
        MsgType::EpochAnnounce => "EPOCH",
        MsgType::TimeAnnounce => "TIME_ANN",
        MsgType::TimeRequest => "TIME_REQ",
        MsgType::Heartbeat => "HEARTBEAT",
        MsgType::CapabilityAdvertise => "CAPS",
    }
}

/// Render arbitrary octets as one printable string, losslessly.
///
/// Printable ASCII passes through; everything else becomes `\xNN`. This is
/// the most a receiver may do with an `UNSTRUCTURED` body (PROTOCOL.md
/// 6.4.2.2) -- hand the bytes back without imposing a reading on them. It is
/// deliberately not a decode: no length is assumed, no field is named.
fn escape(body: &[u8]) -> String {
    let mut out = String::with_capacity(body.len());
    for &b in body {
        match b {
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7E => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02X}")),
        }
    }
    out
}

/// Render a record body according to the layout its `(format, schema_version)`
/// names.
///
/// Every arm validates length before slicing. PROTOCOL.md 6.4.3 permits a
/// `size` as low as 1, so an authenticated peer can legitimately send a body
/// shorter than any layout expects; indexing it blindly would let that peer
/// terminate the collector.
fn render(r: &Record) -> String {
    const NONE: u8 = Format::None as u8;
    match (r.format, r.schema_version) {
        // No layout is claimed, so no layout may be applied: show the octets
        // and nothing else (PROTOCOL.md 6.4.2.2). Note that this arm is
        // reached only because the peer was provisioned with the pair --
        // 0xFF is a reserved meaning, not a bypass of the layout agreement.
        (_, UNSTRUCTURED) => format!("unstructured({:>3}B) \"{}\"", r.body.len(), escape(&r.body)),
        // Sensor tuple: temp, humidity, pressure, battery, rssi.
        (NONE, SENSOR_SCHEMA) if r.body.len() >= 10 => {
            let f = |i: usize| i16::from_be_bytes([r.body[i], r.body[i + 1]]);
            let u = |i: usize| u16::from_be_bytes([r.body[i], r.body[i + 1]]);
            format!(
                "temp={:.2}C humidity={:.1}% pressure={:.1}hPa battery={}% rssi={}dBm",
                f(0) as f32 / 100.0,
                u(2) as f32 / 10.0,
                u(4) as f32 / 10.0,
                u(6),
                f(8)
            )
        }
        // Event: seq, then a UTF-8 name.
        (NONE, EVENT_SCHEMA) if r.body.len() >= 3 => format!(
            "seq={:<5} {}",
            u16::from_be_bytes([r.body[0], r.body[1]]),
            String::from_utf8_lossy(&r.body[2..])
        ),
        // Alarm: seq, severity length, severity, message.
        (NONE, ALARM_SCHEMA) if r.body.len() >= 3 => {
            let n = r.body[2] as usize;
            if r.body.len() < 3 + n {
                return format!("MALFORMED alarm: severity length {n} overruns {} bytes", r.body.len());
            }
            format!(
                "seq={:<5} [{}] {}",
                u16::from_be_bytes([r.body[0], r.body[1]]),
                String::from_utf8_lossy(&r.body[3..3 + n]),
                String::from_utf8_lossy(&r.body[3 + n..])
            )
        }
        (NONE, v @ (SENSOR_SCHEMA | EVENT_SCHEMA | ALARM_SCHEMA)) => {
            format!("MALFORMED record for schema_version={v}: only {} bytes", r.body.len())
        }
        (f, v) => format!("unhandled layout (format=0x{f:02X}, schema_version={v}), {} bytes", r.body.len()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let bind = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:9999".into());

    // A real collector serves many nodes; state is allocated here at
    // provisioning time, never on first contact (PROTOCOL.md 12.5).
    let mut collector = Collector::new();
    collector
        .provision(PeerConfig {
            sender_id: SENDER_ID,
            secret: DeviceSecret::new(SECRET),
            cipher: CIPHER,
            layouts: vec![
                (Format::None as u8, SENSOR_SCHEMA),
                (Format::None as u8, EVENT_SCHEMA),
                (Format::None as u8, ALARM_SCHEMA),
                // Without this pair the unstructured records are discarded
                // unread, exactly like any other layout the receiver does not
                // hold (PROTOCOL.md 6.4.2.2).
                (Format::None as u8, UNSTRUCTURED),
            ],
            // Mandatory for CIPHER's 4-byte tag: without this, provision()
            // itself refuses (PROTOCOL.md 8.1.1). RECOMMENDED_DEFAULT is the
            // 128/sec §10.3 names.
            inbound_rate_limit: Some(RateLimit::RECOMMENDED_DEFAULT),
        })
        .expect("CIPHER requires an inbound_rate_limit, and one is configured above");

    let sock = UdpSocket::bind(&bind)?;
    eprintln!(
        "catp-collector on {bind}  sender_id=0x{SENDER_ID:08X} cipher=0x{:02X} \
         layouts=(NONE,v{SENSOR_SCHEMA}/v{EVENT_SCHEMA}/v{ALARM_SCHEMA}/v{UNSTRUCTURED})",
        CIPHER as u8
    );

    let mut stats = Stats::default();
    let mut buf = [0u8; 2048];

    loop {
        let (n, from) = sock.recv_from(&mut buf)?;
        let local_epoch = epoch_id_at(now_secs());

        match collector.accept(&buf[..n], local_epoch, Direction::NodeToCollector, now_ms()) {
            Ok(acc) => {
                stats.accepted += 1;
                stats.skipped_records += acc.skipped.len() as u64;
                // Every record in the datagram shares this instant
                // (PROTOCOL.md 6.4.1): the offset is a header field.
                let epoch_base = acc.epoch_id as u64 * EPOCH_SECS;
                let off = acc.datagram_offset as u64;
                let secs = epoch_base + off / TICKS_PER_SEC;
                let ms = ((off % TICKS_PER_SEC) * 1000) / TICKS_PER_SEC;
                let at = format!("t={secs}.{ms:03}");

                // Dispatch on msg_type. A record-framed type and NUMBER are
                // different shapes, and MESSAGE/EVENT/ALARM carry different
                // handling obligations even though they frame identically.
                match MsgType::from_u8(acc.datagram.msg_type) {
                    Some(MsgType::Number) => {
                        let lit = acc.datagram.number_literal().unwrap_or("<invalid utf-8>");
                        println!("{from}  {at}  NUMBER   {lit}");
                    }
                    Some(mt @ (MsgType::Message | MsgType::Event | MsgType::Alarm)) => {
                        for r in &acc.datagram.records {
                            println!("{from}  {at}  {:<8} {}", label(mt), render(r));
                        }
                    }
                    Some(mt) => println!("{from}  {at}  {:<8} ({} bytes)", label(mt), acc.datagram.raw.len()),
                    None => stats.other += 1,
                }
                for r in &acc.skipped {
                    println!(
                        "{from}  SKIP record format=0x{:02X} schema_version={} ({} bytes) \
                         - no layout held",
                        r.format,
                        r.schema_version,
                        r.body.len()
                    );
                }
            }
            // Discard silently on the wire; count locally (PROTOCOL.md 6.8).
            Err(Error::AuthFailed) => stats.auth_failed += 1,
            Err(Error::Replay) => stats.replayed += 1,
            Err(Error::Framing(_)) | Err(Error::BadNumber(_)) => stats.framing += 1,
            // Already authenticated and replay-checked; discarded for budget
            // (PROTOCOL.md 10.3), not for authenticity.
            Err(Error::RateLimited) => stats.rate_limited += 1,
            Err(_) => stats.other += 1,
        }

        if (stats.accepted
            + stats.auth_failed
            + stats.replayed
            + stats.framing
            + stats.other
            + stats.rate_limited)
            % 20
            == 0
        {
            eprintln!(
                "[stats] accepted={} auth_failed={} replayed={} framing={} other={} \
                 rate_limited={} skipped_records={}",
                stats.accepted,
                stats.auth_failed,
                stats.replayed,
                stats.framing,
                stats.other,
                stats.rate_limited,
                stats.skipped_records
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(sv: u8, n: usize) -> Record {
        Record::new(Format::None, sv, vec![0xAB; n])
    }

    #[test]
    fn each_layout_decodes_under_its_own_schema_version() {
        // The same bytes must read differently under different versions --
        // that is the whole point of the field (PROTOCOL.md 6.4.2.1).
        let body = vec![0x00, 0x07, b'b', b'o', b'o', b't'];
        let ev = render(&Record::new(Format::None, EVENT_SCHEMA, body.clone()));
        assert!(ev.contains("seq=7") && ev.contains("boot"), "{ev}");

        let mut alarm = vec![0x00, 0x09, 4];
        alarm.extend_from_slice(b"WARNbattery_low");
        let al = render(&Record::new(Format::None, ALARM_SCHEMA, alarm));
        assert!(al.contains("[WARN]") && al.contains("battery_low"), "{al}");

        // An alarm whose declared severity length overruns is reported, not
        // sliced out of bounds.
        let bad = render(&Record::new(Format::None, ALARM_SCHEMA, vec![0, 1, 200, 9]));
        assert!(bad.contains("MALFORMED"), "{bad}");
    }

    #[test]
    fn short_sensor_body_reports_rather_than_panicking() {
        // PROTOCOL.md 6.4.3 allows size as low as 1, so an authenticated peer
        // can send a body shorter than the layout expects. That must not be a
        // crash: a post-authentication panic bypasses every pre-auth cost bound
        // Section 12.5 establishes.
        for n in 1..10 {
            let out = render(&rec(SENSOR_SCHEMA, n));
            assert!(out.contains("MALFORMED"), "len {n} gave {out:?}");
        }
        assert!(render(&rec(SENSOR_SCHEMA, 10)).contains("temp="));
        for sv in [EVENT_SCHEMA, ALARM_SCHEMA] {
            for n in 1..3 {
                assert!(render(&rec(sv, n)).contains("MALFORMED"), "sv={sv} len={n}");
            }
        }
    }

    #[test]
    fn unknown_layout_is_named_not_guessed() {
        let out = render(&rec(99, 8));
        assert!(out.contains("unhandled layout"), "{out}");
        assert!(out.contains("schema_version=99"), "{out}");
    }

    #[test]
    fn unstructured_is_shown_not_decoded() {
        // Same bytes a sensor record would carry. Under UNSTRUCTURED the
        // collector must not read fields out of them (PROTOCOL.md 6.4.2.2).
        let body = vec![0x09, 0x1D, 0x01, 0x8A, 0x27, 0xF5, 0x00, 0x3C, 0xFF, 0xA2];
        let out = render(&Record::new(Format::None, UNSTRUCTURED, body));
        assert!(out.starts_with("unstructured("), "{out}");
        assert!(!out.contains("temp="), "{out}");
    }

    #[test]
    fn escape_is_lossless_and_printable() {
        // Every byte survives as printable characters, so an unstructured
        // body cannot smuggle control characters into the operator's terminal.
        let all: Vec<u8> = (0..=255u8).collect();
        let out = escape(&all);
        assert!(out.chars().all(|c| (' '..='~').contains(&c)), "{out}");
        assert!(out.contains("\\x00") && out.contains("\\xFF"));
        // A literal backslash is escaped rather than read as an escape.
        assert_eq!(escape(b"a\\x41"), "a\\\\x41");
    }

    #[test]
    fn unstructured_under_any_format_is_never_decoded() {
        for f in [Format::None, Format::Cbor] {
            let out = render(&Record::new(f, UNSTRUCTURED, vec![1, 2, 3]));
            assert!(out.starts_with("unstructured("), "{f:?} gave {out}");
        }
    }

    #[test]
    fn every_msg_type_has_a_label() {
        for v in 0u8..=0x1F {
            if let Some(mt) = MsgType::from_u8(v) {
                assert!(!label(mt).is_empty());
            }
        }
    }
}
