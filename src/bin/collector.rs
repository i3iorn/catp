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
const SCHEMA_VERSION: u8 = 1;

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
        layouts: vec![(Format::None as u8, SCHEMA_VERSION)],
    });

    let sock = UdpSocket::bind(&bind)?;
    eprintln!(
        "catp-collector on {bind}  sender_id=0x{SENDER_ID:08X} cipher=0x{:02X} \
         layout=(NONE,v{SCHEMA_VERSION})",
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
                // (PROTOCOL.md 6.4.1): the offset is now a header field.
                let epoch_base = acc.epoch_id as u64 * EPOCH_SECS;
                let off = acc.datagram_offset as u64;
                let secs = epoch_base + off / TICKS_PER_SEC;
                let ms = ((off % TICKS_PER_SEC) * 1000) / TICKS_PER_SEC;

                if let Some(lit) = acc.datagram.number_literal() {
                    println!("{from}  t={secs}.{ms:03}  NUMBER  {lit}");
                }
                for r in &acc.datagram.records {
                    let seq = u16::from_be_bytes([r.body[0], r.body[1]]);
                    let temp = i16::from_be_bytes([r.body[2], r.body[3]]);
                    println!(
                        "{from}  t={secs}.{ms:03}  MESSAGE seq={seq:<5} temp={:.2}C",
                        temp as f32 / 100.0
                    );
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
