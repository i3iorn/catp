//! CATP reference sender: emits varied synthetic telemetry.
//!
//! Usage: catp-sender [collector_addr] [rate_hz] [records_per_datagram]
//!
//! Exercises several CATP message/framing paths against a live collector:
//!   - MESSAGE: batched synthetic sensor records
//!   - NUMBER:  bare numeric literal
//!   - EVENT:   discrete device events
//!   - ALARM:   varying-severity operational alarms
//!
//! Sender-side obligations from PROTOCOL.md 10.3/10.4:
//!   - offsets are derived from the clock;
//!   - offsets must strictly increase within an epoch;
//!   - a datagram must not span an epoch boundary.

use catp::wire::Datagram;
use catp::*;
use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SENDER_ID: u32 = 0x0000_1234;
const SECRET: [u8; 32] = [0x5A; 32];
const CIPHER: CipherId = CipherId::HmacSha256T32;
// One schema_version per body layout (PROTOCOL.md 6.4.2.1). Reusing a single
// value across layouts produces datagrams that authenticate and frame
// correctly but decode to wrong readings -- the exact failure this field
// exists to prevent.
const SENSOR_SCHEMA: u8 = 1;
const EVENT_SCHEMA: u8 = 2;
const ALARM_SCHEMA: u8 = 3;

fn now() -> (u64, u32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before 1970");

    (d.as_secs(), d.subsec_nanos())
}

/// Sender-side offset state for the current epoch (PROTOCOL.md 10.3, 10.4).
struct Pacer {
    epoch: u32,
    last_offset: Option<u32>,
}

impl Pacer {
    fn new() -> Self {
        Self {
            epoch: 0,
            last_offset: None,
        }
    }

    /// Claim an offset for a datagram to be sent now, or explain why not.
    ///
    /// Enforces strict increase, covering both a repeated clock tick and a
    /// backward clock step without requiring non-volatile state.
    fn claim(&mut self, secs: u64, nanos: u32) -> Result<(u32, u32), Error> {
        let epoch = epoch_id_at(secs);
        let offset = epoch_offset_at(secs, nanos);

        if epoch != self.epoch {
            self.epoch = epoch;
            self.last_offset = None;
        }

        match self.last_offset {
            Some(prev) if offset <= prev => Err(Error::OffsetReuse(offset)),
            _ => {
                self.last_offset = Some(offset);
                Ok((epoch, offset))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum MessageKind {
    Message,
    Number,
    Event,
    Alarm,
}

impl MessageKind {
    fn name(self) -> &'static str {
        match self {
            Self::Message => "MESSAGE",
            Self::Number => "NUMBER ",
            Self::Event => "EVENT  ",
            Self::Alarm => "ALERT  ",
        }
    }
}

/// Deterministic pseudo-random mixing.
///
/// This deliberately avoids an external RNG dependency. The generator only
/// needs repeatable variation, not cryptographic randomness.
fn mix(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x7FEB_352D);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846C_A68B);
    x ^= x >> 16;
    x
}

fn choose_kind(seq: u32) -> MessageKind {
    // Mostly telemetry, with regular event/alarm traffic.
    //
    // The irregular-looking pattern prevents the test stream from becoming
    // simply MESSAGE/NUMBER/EVENT/ALERT repeated forever.
    match mix(seq) % 16 {
        0..=7 => MessageKind::Message,
        8..=10 => MessageKind::Number,
        11..=13 => MessageKind::Event,
        _ => MessageKind::Alarm,
    }
}

fn sensor_values(seq: u32) -> (i16, u16, u16, u16, i16) {
    let r1 = mix(seq);
    let r2 = mix(seq.wrapping_add(0x1000));
    let r3 = mix(seq.wrapping_add(0x2000));
    let r4 = mix(seq.wrapping_add(0x3000));

    // Temperature: roughly 15.00 .. 29.99 C, hundredths of a degree.
    let temp = 1500 + (r1 % 1500) as i16;

    // Humidity: 35.0 .. 89.9 %, tenths.
    let humidity = 350 + (r2 % 550) as u16;

    // Pressure: roughly 980.0 .. 1040.0 hPa, tenths.
    let pressure = 9800 + (r3 % 600) as u16;

    // Battery: 20 .. 99 %.
    let battery = 20 + (r4 % 80) as u16;

    // Signal strength: roughly -95 .. -45 dBm.
    let signal = -95 + (mix(seq ^ 0xA5A5_A5A5) % 50) as i16;

    (temp, humidity, pressure, battery, signal)
}

fn make_records(seq: u32, per_dg: usize) -> Vec<Record> {
    let (temp, humidity, pressure, battery, signal) = sensor_values(seq);

    (0..per_dg)
        .map(|i| {
            let n = seq.wrapping_add(i as u32);

            let temp_i = temp.wrapping_add((i as i16) * 2);
            let humidity_i = humidity.wrapping_add((i as u16) % 7);

            let mut body = Vec::with_capacity(12);

            // Synthetic sensor id / sample number.
            body.extend_from_slice(&n.to_be_bytes()[2..4]);

            // Temperature, hundredths of a degree C.
            body.extend_from_slice(&temp_i.to_be_bytes());

            // Humidity, tenths of a percent.
            body.extend_from_slice(&humidity_i.to_be_bytes());

            // Pressure, tenths of hPa.
            body.extend_from_slice(&pressure.to_be_bytes());

            // Battery percentage.
            body.extend_from_slice(&battery.to_be_bytes());

            // RSSI, signed dBm.
            body.extend_from_slice(&signal.to_be_bytes());

            Record::new(Format::None, SENSOR_SCHEMA, body)
        })
        .collect()
}

fn make_number(seq: u32) -> String {
    let (temp, _, _, _, _) = sensor_values(seq);
    format!("{}.{:02}", temp / 100, temp % 100)
}

fn event_payload(seq: u32) -> &'static str {
    match mix(seq) % 10 {
        0 => "boot",
        1 => "sensor_attached",
        2 => "sensor_detached",
        3 => "configuration_changed",
        4 => "network_up",
        5 => "network_down",
        6 => "time_synchronized",
        7 => "battery_recovered",
        8 => "maintenance_started",
        _ => "maintenance_finished",
    }
}

fn alarm_payload(seq: u32) -> (&'static str, &'static str) {
    match mix(seq) % 12 {
        0 => ("INFO", "battery_recovered"),
        1 => ("INFO", "signal_restored"),
        2 => ("NOTICE", "sensor_reconnected"),
        3 => ("NOTICE", "clock_drift_detected"),
        4 => ("WARNING", "battery_low"),
        5 => ("WARNING", "signal_degraded"),
        6 => ("WARNING", "temperature_high"),
        7 => ("WARNING", "sensor_stale"),
        8 => ("CRITICAL", "battery_critical"),
        9 => ("CRITICAL", "temperature_critical"),
        10 => ("CRITICAL", "sensor_failure"),
        _ => ("CRITICAL", "collector_unreachable"),
    }
}

fn make_datagram(
    kind: MessageKind,
    seq: u32,
    epoch: u32,
    offset: u32,
    per_dg: usize,
) -> Result<Datagram, Error> {
    match kind {
        MessageKind::Message => {
            let records = make_records(seq, per_dg);

            Datagram::data(
                MsgType::Message,
                CIPHER,
                SENDER_ID,
                epoch,
                offset,
                records,
            )
        }

        MessageKind::Number => {
            let literal = make_number(seq);

            Datagram::number(
                CIPHER,
                SENDER_ID,
                epoch,
                offset,
                &literal,
            )
        }

        MessageKind::Event => {
            let event = event_payload(seq);

            let mut body = Vec::with_capacity(event.len() + 4);
            body.extend_from_slice(&(seq as u16).to_be_bytes());
            body.extend_from_slice(event.as_bytes());

            let record = Record::new(Format::None, EVENT_SCHEMA, body);

            Datagram::data(
                MsgType::Event,
                CIPHER,
                SENDER_ID,
                epoch,
                offset,
                vec![record],
            )
        }

        MessageKind::Alarm => {
            let (severity, message) = alarm_payload(seq);

            let mut body = Vec::with_capacity(severity.len() + message.len() + 4);
            body.extend_from_slice(&(seq as u16).to_be_bytes());
            body.push(severity.len() as u8);
            body.extend_from_slice(severity.as_bytes());
            body.extend_from_slice(message.as_bytes());

            let record = Record::new(Format::None, ALARM_SCHEMA, body);

            Datagram::data(
                MsgType::Alarm,
                CIPHER,
                SENDER_ID,
                epoch,
                offset,
                vec![record],
            )
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let addr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:9999".into());

    let rate_hz: u64 = args
        .get(2)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(4);

    let per_dg: usize = args
        .get(3)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(3);

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let secret = DeviceSecret(SECRET);
    let mut pacer = Pacer::new();

    eprintln!(
        "catp-sender -> {addr}  sender_id=0x{SENDER_ID:08X} cipher=0x{:02X} \
         {rate_hz} datagram/s x {per_dg} records",
        CIPHER as u8
    );

    let mut seq: u32 = 0;
    let mut shed = 0u64;

    loop {
        let (secs, nanos) = now();

        let (epoch, offset) = match pacer.claim(secs, nanos) {
            Ok(v) => v,
            Err(_) => {
                // Two datagrams in one tick: shed rather than reuse an offset.
                shed += 1;
                std::thread::sleep(Duration::from_micros(300));
                continue;
            }
        };

        seq = seq.wrapping_add(1);

        let kind = choose_kind(seq);

        let dg = match make_datagram(kind, seq, epoch, offset, per_dg) {
            Ok(dg) => dg,
            Err(e) => {
                eprintln!("datagram construction failed: {e}");
                continue;
            }
        };

        match dg.encode(
            &secret,
            epoch,
            Direction::NodeToCollector,
            MAX_DATAGRAM_IPV4,
        ) {
            Ok(wire) => {
                sock.send_to(&wire, &addr)?;

                let detail = match kind {
                    MessageKind::Message => {
                        let (temp, humidity, pressure, battery, signal) =
                            sensor_values(seq);

                        format!(
                            "temp={:.2}C humidity={:.1}% pressure={:.1}hPa \
                             battery={battery}% rssi={signal}dBm",
                            temp as f32 / 100.0,
                            humidity as f32 / 10.0,
                            pressure as f32 / 10.0,
                        )
                    }

                    MessageKind::Number => {
                        format!("value={}", make_number(seq))
                    }

                    MessageKind::Event => {
                        format!("event={}", event_payload(seq))
                    }

                    MessageKind::Alarm => {
                        let (severity, message) = alarm_payload(seq);
                        format!("severity={severity} alarm={message}")
                    }
                };

                println!(
                    "sent {} epoch={epoch} offset={offset} bytes={} seq={seq} \
                     {detail} shed={shed}",
                    kind.name(),
                    wire.len(),
                );
            }

            Err(e) => eprintln!("encode failed: {e}"),
        }

        std::thread::sleep(Duration::from_millis(
            1000 / rate_hz.max(1),
        ));
    }
}
