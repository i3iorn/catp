//! CATP reference collector: verifies datagrams and prints accepted records.
//!
//! Usage: catp-collector [bind_addr]
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

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock before 1970").as_secs()
}

#[derive(Default)]
struct Stats {
    accepted: u64,
    auth_failed: u64,
    replayed: u64,
    framing: u64,
    other: u64,
    skipped_records: u64,
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

/// Render a record body according to the layout its `(format, schema_version)`
/// names.
///
/// Every arm validates length before slicing. PROTOCOL.md 6.4.3 permits a
/// `size` as low as 1, so an authenticated peer can legitimately send a body
/// shorter than any layout expects; indexing it blindly would let that peer
/// terminate the collector.
fn render(r: &Record) -> String {
    const SENSOR: (u8, u8) = (Format::None as u8, SENSOR_SCHEMA);
    match (r.format, r.schema_version) {
        SENSOR if r.body.len() >= 4 => {
            let seq = u16::from_be_bytes([r.body[0], r.body[1]]);
            let temp = i16::from_be_bytes([r.body[2], r.body[3]]);
            format!("seq={seq:<5} temp={:.2}C", temp as f32 / 100.0)
        }
        SENSOR => format!("MALFORMED sensor record: {} bytes, need 4", r.body.len()),
        (f, v) => format!("unhandled layout (format=0x{f:02X}, schema_version={v}), {} bytes", r.body.len()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let bind = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:9999".into());

    // A real collector serves many nodes; state is allocated here at
    // provisioning time, never on first contact (PROTOCOL.md 12.5).
    let mut collector = Collector::new();
    collector.provision(PeerConfig {
        sender_id: SENDER_ID,
        secret: DeviceSecret(SECRET),
        cipher: CIPHER,
        layouts: vec![(Format::None as u8, SENSOR_SCHEMA)],
    });

    let sock = UdpSocket::bind(&bind)?;
    eprintln!(
        "catp-collector on {bind}  sender_id=0x{SENDER_ID:08X} cipher=0x{:02X} \
         layout=(NONE,v{SENSOR_SCHEMA})",
        CIPHER as u8
    );

    let mut stats = Stats::default();
    let mut buf = [0u8; 2048];

    loop {
        let (n, from) = sock.recv_from(&mut buf)?;
        let local_epoch = epoch_id_at(now_secs());

        match collector.accept(&buf[..n], local_epoch, Direction::NodeToCollector) {
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
            Err(_) => stats.other += 1,
        }

        if (stats.accepted + stats.auth_failed + stats.replayed + stats.framing + stats.other)
            % 20
            == 0
        {
            eprintln!(
                "[stats] accepted={} auth_failed={} replayed={} framing={} other={} \
                 skipped_records={}",
                stats.accepted,
                stats.auth_failed,
                stats.replayed,
                stats.framing,
                stats.other,
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
    fn short_sensor_body_reports_rather_than_panicking() {
        // PROTOCOL.md 6.4.3 allows size as low as 1, so an authenticated peer
        // can send a body shorter than the layout expects. That must not be a
        // crash: a post-authentication panic bypasses every pre-auth cost bound
        // Section 12.5 establishes.
        for n in 1..4 {
            let out = render(&rec(SENSOR_SCHEMA, n));
            assert!(out.contains("MALFORMED"), "len {n} gave {out:?}");
        }
        assert!(render(&rec(SENSOR_SCHEMA, 4)).contains("temp="));
        assert!(render(&rec(SENSOR_SCHEMA, 12)).contains("temp="));
    }

    #[test]
    fn unknown_layout_is_named_not_guessed() {
        let out = render(&rec(99, 8));
        assert!(out.contains("unhandled layout"), "{out}");
        assert!(out.contains("schema_version=99"), "{out}");
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
