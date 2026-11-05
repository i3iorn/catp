//! Generate the frozen test vectors PROTOCOL.md 14.1 requires.
//!
//! Writes `docs/test-vectors.txt` to stdout, and `docs/test-vectors.json`
//! directly (issue #35): a machine-readable mirror for an implementation in
//! another language, which does not want to write a parser for the
//! human-readable format just to conform to it. Every vector is recorded into
//! both from the same call site, so they cannot drift from each other the
//! way two independently maintained files could.
//!
//! Run with: cargo run --bin catp-vectors > docs/test-vectors.txt

use catp::wire::Datagram;
use catp::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Minimal JSON string escaping. Every string this binary emits is either a
/// hex digit string or a short ASCII vector name; this covers both without
/// pulling in a JSON dependency for one docs artifact.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Collects JSON objects for `docs/test-vectors.json`, in the same order
/// they're printed to the text file.
#[derive(Default)]
struct JsonVectors(Vec<String>);

impl JsonVectors {
    /// `fields` are `(key, already-JSON-encoded value)` pairs, in the order
    /// they should appear in the object.
    fn push(&mut self, fields: &[(&str, String)]) {
        let body: Vec<String> = fields
            .iter()
            .map(|(k, v)| format!("{}: {v}", json_str(k)))
            .collect();
        self.0.push(format!("    {{ {} }}", body.join(", ")));
    }

    fn write(&self, path: &str) {
        let contents = format!("[\n{}\n]\n", self.0.join(",\n"));
        std::fs::write(path, contents).expect("failed to write JSON vector mirror");
    }
}

/// One accepted vector: inputs, derived key, and the exact bytes on the wire.
/// Prints the human-readable block and records the same fields into `json`.
fn accept(
    json: &mut JsonVectors,
    name: &str,
    secret: &DeviceSecret,
    epoch: u32,
    dir: Direction,
    dg: &Datagram,
) {
    accept_cross(json, name, secret, epoch, epoch, dir, dg);
}

/// An `accept` vector whose receiver configures the `Layout` named on the
/// wire with the fixed body width `fixed_width` (PROTOCOL.md 6.4.4): the
/// mismatched record must be skipped, the datagram accepted.
fn accept_fixed_width(
    json: &mut JsonVectors,
    name: &str,
    secret: &DeviceSecret,
    epoch: u32,
    dir: Direction,
    dg: &Datagram,
    layout: Layout,
) {
    let fixed_width = layout
        .fixed_width
        .expect("emitter requires a fixed-width layout");
    let wire = dg
        .encode(secret, epoch, dir, 65535)
        .expect("vector must encode");
    let key = secret.epoch_key(dg.sender_id, epoch, dir);
    let auth_header = dg.auth_header(epoch);
    println!("# {name}");
    println!("kind         accept");
    println!("device_secret {}", hex(secret.expose_secret()));
    println!("sender_id    {:08x}", dg.sender_id);
    println!("epoch_id     {epoch}");
    println!("direction    {:02x}", dir as u8);
    println!("cipher_id    {:02x}", dg.cipher_id);
    println!("msg_type     {:02x}", dg.msg_type);
    println!("offset       {}", dg.datagram_offset);
    println!("fixed_width  {fixed_width}");
    println!(
        "layout        {:02x} {:02x}",
        layout.pair().0,
        layout.pair().1
    );
    println!("epoch_key    {}", hex(&key[..]));
    println!("auth_header  {}", hex(&auth_header));
    println!("wire         {}", hex(&wire));
    println!("wire_len     {}", wire.len());
    println!();
    json.push(&[
        ("name", json_str(name)),
        ("kind", json_str("accept")),
        ("device_secret", json_str(&hex(secret.expose_secret()))),
        ("sender_id", json_str(&format!("{:08x}", dg.sender_id))),
        ("epoch_id", epoch.to_string()),
        ("direction", json_str(&format!("{:02x}", dir as u8))),
        ("cipher_id", json_str(&format!("{:02x}", dg.cipher_id))),
        ("msg_type", json_str(&format!("{:02x}", dg.msg_type))),
        ("offset", dg.datagram_offset.to_string()),
        ("fixed_width", fixed_width.to_string()),
        (
            "layout",
            json_str(&format!("{:02x} {:02x}", layout.pair().0, layout.pair().1)),
        ),
        ("epoch_key", json_str(&hex(&key[..]))),
        ("auth_header", json_str(&hex(&auth_header))),
        ("wire", json_str(&hex(&wire))),
        ("wire_len", wire.len().to_string()),
    ]);
}

/// As `accept`, but the datagram was *encoded* under `enc_epoch` while the
/// receiver sits at `rx_epoch` (PROTOCOL.md 9.3 accepts `{rx-1, rx}`). When
/// the two differ the vector carries an `encode_epoch` field; consumers derive
/// keys and re-encode from it, and treat `epoch_id` as the receiver's clock.
fn accept_cross(
    json: &mut JsonVectors,
    name: &str,
    secret: &DeviceSecret,
    enc_epoch: u32,
    rx_epoch: u32,
    dir: Direction,
    dg: &Datagram,
) {
    let wire = dg
        .encode(secret, enc_epoch, dir, 65535)
        .expect("vector must encode");
    let key = secret.epoch_key(dg.sender_id, enc_epoch, dir);
    let auth_header = dg.auth_header(enc_epoch);
    println!("# {name}");
    println!("kind         accept");
    println!("device_secret {}", hex(secret.expose_secret()));
    println!("sender_id    {:08x}", dg.sender_id);
    println!("epoch_id     {rx_epoch}");
    if enc_epoch != rx_epoch {
        println!("encode_epoch {enc_epoch}");
    }
    println!("direction    {:02x}", dir as u8);
    println!("cipher_id    {:02x}", dg.cipher_id);
    println!("msg_type     {:02x}", dg.msg_type);
    println!("offset       {}", dg.datagram_offset);
    println!("epoch_key    {}", hex(&key[..]));
    println!("auth_header  {}", hex(&auth_header));
    println!("wire         {}", hex(&wire));
    println!("wire_len     {}", wire.len());
    println!();
    let mut fields = vec![
        ("name", json_str(name)),
        ("kind", json_str("accept")),
        ("device_secret", json_str(&hex(secret.expose_secret()))),
        ("sender_id", json_str(&format!("{:08x}", dg.sender_id))),
        ("epoch_id", rx_epoch.to_string()),
    ];
    if enc_epoch != rx_epoch {
        fields.push(("encode_epoch", enc_epoch.to_string()));
    }
    fields.extend_from_slice(&[
        ("direction", json_str(&format!("{:02x}", dir as u8))),
        ("cipher_id", json_str(&format!("{:02x}", dg.cipher_id))),
        ("msg_type", json_str(&format!("{:02x}", dg.msg_type))),
        ("offset", dg.datagram_offset.to_string()),
        ("epoch_key", json_str(&hex(&key[..]))),
        ("auth_header", json_str(&hex(&auth_header))),
        ("wire", json_str(&hex(&wire))),
        ("wire_len", wire.len().to_string()),
    ]);
    json.push(&fields);
}

/// The receiver state a `reject_datagram` vector tells the IUT to assume
/// (docs/CONFORMANCE_RUNNER.md). Everything the §7.4 pipeline needs beyond the
/// wire bytes itself.
#[derive(Clone)]
struct Receiver {
    /// Sender the IUT is provisioned for; defaults to the wire's `sender_id`
    /// (only the `unknown_sender` fault sets something else).
    sender_id: u32,
    /// The receiver's current epoch, for §9.3 reconstruction.
    epoch: u32,
    /// The cipher suite the IUT configured for this sender.
    cipher: CipherId,
    /// Offsets the IUT must seed its replay window with before checking.
    seen_offsets: Vec<u32>,
}

impl Receiver {
    fn for_wire(d: &Datagram, epoch: u32) -> Self {
        Self {
            sender_id: d.sender_id,
            epoch,
            cipher: CipherId::from_u8(d.cipher_id).expect("vector cipher implemented"),
            seen_offsets: Vec::new(),
        }
    }
}

/// Emit a `reject_datagram` vector: authentic-or-not wire bytes plus receiver
/// state; PASS means the IUT's §7.4 pipeline rejects (PROTOCOL.md 14.1).
fn reject_datagram(
    json: &mut JsonVectors,
    name: &str,
    secret: &DeviceSecret,
    wire: &[u8],
    fault: &str,
    receiver: &Receiver,
) {
    println!("# {name}");
    println!("kind             reject_datagram");
    println!("fault            {fault}");
    println!("device_secret    {}", hex(secret.expose_secret()));
    println!("sender_id        {:08x}", sender_id_of(wire));
    println!("receiver_sender  {:08x}", receiver.sender_id);
    println!("receiver_epoch   {}", receiver.epoch);
    println!("configured_cipher {:02x}", receiver.cipher as u8);
    println!("direction        00");
    if !receiver.seen_offsets.is_empty() {
        let seen: Vec<String> = receiver
            .seen_offsets
            .iter()
            .map(|o| o.to_string())
            .collect();
        println!("seen_offsets     {}", seen.join(","));
    }
    println!("wire             {}", hex(wire));
    println!("wire_len         {}", wire.len());
    println!();
    let mut fields = vec![
        ("name", json_str(name)),
        ("kind", json_str("reject_datagram")),
        ("fault", json_str(fault)),
        ("device_secret", json_str(&hex(secret.expose_secret()))),
        (
            "sender_id",
            json_str(&format!("{:08x}", sender_id_of(wire))),
        ),
        (
            "receiver_sender",
            json_str(&format!("{:08x}", receiver.sender_id)),
        ),
        ("receiver_epoch", receiver.epoch.to_string()),
        (
            "configured_cipher",
            json_str(&format!("{:02x}", receiver.cipher as u8)),
        ),
        ("direction", json_str("00")),
        ("wire", json_str(&hex(wire))),
        ("wire_len", wire.len().to_string()),
    ];
    if !receiver.seen_offsets.is_empty() {
        let seen: Vec<String> = receiver
            .seen_offsets
            .iter()
            .map(|o| o.to_string())
            .collect();
        fields.push(("seen_offsets", json_str(&seen.join(","))));
    }
    json.push(&fields);
}

/// The `sender_id` of a wire datagram (bytes 5..9, PROTOCOL.md 4.1).
fn sender_id_of(wire: &[u8]) -> u32 {
    u32::from_be_bytes([wire[5], wire[6], wire[7], wire[8]])
}

/// Encode a datagram with a payload the codec would never produce itself —
/// authentic framing faults (§6.4.4) and malformed control bodies. Replicates
/// `encode`'s wire image from public pieces only: `auth_header` carries every
/// header byte except the `epoch_low` nibble (which is zeroed there), so the
/// header is rebuilt from it plus `d.epoch_low`.
fn authentic_with_payload(
    secret: &DeviceSecret,
    d: &Datagram,
    epoch: u32,
    dir: Direction,
    payload: &[u8],
) -> Vec<u8> {
    let cipher = CipherId::from_u8(d.cipher_id).expect("vector cipher implemented");
    let key = secret.epoch_key(d.sender_id, epoch, dir);
    let mut signed = Vec::new();
    signed.extend_from_slice(&d.auth_header(epoch));
    signed.extend_from_slice(payload);
    let tag = mac(cipher, &key, &signed, d.datagram_offset).expect("vector must mac");
    let ah = d.auth_header(epoch);
    let mut wire = vec![ah[0], ah[1] | d.epoch_low, ah[2], ah[3], ah[4]];
    wire.extend_from_slice(&ah[9..13]);
    wire.extend_from_slice(payload);
    wire.extend_from_slice(&tag);
    wire
}

/// Flip one wire byte; the wire is otherwise a valid datagram.
fn with_byte(mut wire: Vec<u8>, idx: usize, val: u8) -> Vec<u8> {
    wire[idx] = val;
    wire
}

/// A `SERIES` payload grammar vector (PROTOCOL.md 6.9), same shape as
/// `number_payload`: the IUT validates the payload in isolation against the
/// anchor offset, no datagram, no MAC.
fn series_payload(json: &mut JsonVectors, payload: &[u8], anchor: u32, outcome: &str) {
    println!(
        "{} {}",
        if outcome == "accept" {
            "accept_series"
        } else {
            "reject_series"
        },
        hex(payload)
    );
    println!("anchor_offset {anchor}");
    println!();
    json.push(&[
        ("kind", json_str("series_payload")),
        ("payload", json_str(&hex(payload))),
        ("anchor_offset", anchor.to_string()),
        ("outcome", json_str(outcome)),
    ]);
}

/// A `TIME_ANNOUNCE` the reference node MUST reject (PROTOCOL.md 11.5 rules 1
/// and 3): `clock_state` `"valid"` rejects everything; `"cold"` with
/// `asserted_time` at or below `last_epoch * 128` rejects as time rollback.
/// PASS means the IUT rejects after verifying the MAC.
fn reject_time_announce(
    json: &mut JsonVectors,
    name: &str,
    secret: &DeviceSecret,
    sender_id: u32,
    asserted_time: i64,
    clock_state: &str,
    last_epoch: u32,
) {
    let wire = Datagram::time_announce(sender_id, asserted_time, secret).expect("must encode");
    println!("# {name}");
    println!("kind             reject_time_announce");
    println!("device_secret    {}", hex(secret.expose_secret()));
    println!("sender_id        {sender_id:08x}");
    println!("direction        01");
    println!("asserted_time    {asserted_time}");
    println!("clock_state      {clock_state}");
    println!("last_epoch       {last_epoch}");
    println!("wire             {}", hex(&wire));
    println!("wire_len         {}", wire.len());
    println!();
    json.push(&[
        ("name", json_str(name)),
        ("kind", json_str("reject_time_announce")),
        ("device_secret", json_str(&hex(secret.expose_secret()))),
        ("sender_id", json_str(&format!("{sender_id:08x}"))),
        ("direction", json_str("01")),
        ("asserted_time", asserted_time.to_string()),
        ("clock_state", json_str(clock_state)),
        ("last_epoch", last_epoch.to_string()),
        ("wire", json_str(&hex(&wire))),
        ("wire_len", wire.len().to_string()),
    ]);
}

fn main() {
    let s = DeviceSecret::new([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]);
    let id = 0x1234_5678u32;
    let epoch = 13_281_250u32;
    let n2c = Direction::NodeToCollector;
    let mut json = JsonVectors::default();
    let mut number_payloads = Vec::new(); // (payload hex, "accept" | "reject")

    println!("# CATP v1 frozen test vectors (PROTOCOL.md 14.1)");
    println!("# Generated by `cargo run --bin catp-vectors`. Do not hand-edit.");
    println!("# All values hex, big-endian, no separators.");
    println!();

    // --- one accepted datagram per msg_type, per implemented cipher ---
    for cipher in [
        CipherId::HmacSha256T64,
        CipherId::HmacSha256T32,
        CipherId::SipHash24,
        CipherId::ChaCha20Poly1305,
    ] {
        let tag = cipher.tag_len();
        accept(
            &mut json,
            &format!("NUMBER, positive, scale 0x02, tag{tag}"),
            &s,
            epoch,
            n2c,
            &Datagram::number(cipher, id, epoch, 4096, 0x02, 2350).unwrap(),
        );
        accept(
            &mut json,
            &format!("NUMBER, negative, scale 0x02, tag{tag}"),
            &s,
            epoch,
            n2c,
            &Datagram::number(cipher, id, epoch, 4097, 0x02, -25).unwrap(),
        );
        accept(
            &mut json,
            &format!("NUMBER, zero, scale 0x01, tag{tag}"),
            &s,
            epoch,
            n2c,
            &Datagram::number(cipher, id, epoch, 0, 0x01, 0).unwrap(),
        );
        accept(
            &mut json,
            &format!("SERIES, three readings, tag{tag}"),
            &s,
            epoch,
            n2c,
            &Datagram::series(
                cipher,
                id,
                epoch,
                0x02,
                &[(4200, 2350), (4450, 2360), (4900, 2355)],
            )
            .unwrap(),
        );
        accept(
            &mut json,
            &format!("MESSAGE, single record, tag{tag}"),
            &s,
            epoch,
            n2c,
            &Datagram::data(
                MsgType::Message,
                cipher,
                id,
                epoch,
                100,
                vec![Record::new(Format::None, 1, vec![0xde, 0xad])],
            )
            .unwrap(),
        );
        accept(
            &mut json,
            &format!("MESSAGE, three records, mixed formats, tag{tag}"),
            &s,
            epoch,
            n2c,
            &Datagram::data(
                MsgType::Message,
                cipher,
                id,
                epoch,
                200,
                vec![
                    Record::new(Format::None, 1, vec![0x01]),
                    Record::new(Format::Cbor, 2, vec![0x02, 0x03]),
                    Record::new(Format::MsgPack, 0xff, vec![0x04, 0x05, 0x06]),
                ],
            )
            .unwrap(),
        );
        accept(
            &mut json,
            &format!("EVENT, one record, tag{tag}"),
            &s,
            epoch,
            n2c,
            &Datagram::data(
                MsgType::Event,
                cipher,
                id,
                epoch,
                300,
                vec![Record::new(Format::None, 7, vec![0xaa])],
            )
            .unwrap(),
        );
        accept(
            &mut json,
            &format!("ALARM, one record, tag{tag}"),
            &s,
            epoch,
            n2c,
            &Datagram::data(
                MsgType::Alarm,
                cipher,
                id,
                epoch,
                400,
                vec![Record::new(Format::None, 9, vec![0xbb, 0xcc])],
            )
            .unwrap(),
        );
        accept(
            &mut json,
            &format!("HEARTBEAT, empty payload, tag{tag}"),
            &s,
            epoch,
            n2c,
            &Datagram::control(MsgType::Heartbeat, cipher, id, epoch, 500, &[]).unwrap(),
        );
        accept(
            &mut json,
            &format!("EPOCH_ANNOUNCE, collector to node, tag{tag}"),
            &s,
            epoch,
            Direction::CollectorToNode,
            &Datagram::control(
                MsgType::EpochAnnounce,
                cipher,
                id,
                epoch,
                600,
                &Control::EpochAnnounce {
                    target_epoch: epoch + 1,
                }
                .encode()
                .unwrap(),
            )
            .unwrap(),
        );
        accept(
            &mut json,
            &format!("CAPABILITY_ADVERTISE, tag{tag}"),
            &s,
            epoch,
            n2c,
            &Datagram::control(
                MsgType::CapabilityAdvertise,
                cipher,
                id,
                epoch,
                700,
                &Capability {
                    max_version: 1,
                    ciphers: vec![0x01, 0x04],
                    layouts: vec![Layout::new(0x01, 1), Layout::new(0x02, 2)],
                }
                .encode()
                .unwrap(),
            )
            .unwrap(),
        );
    }

    // --- boundary set (PROTOCOL.md 14.1) ---
    accept(
        &mut json,
        "boundary: offset 0",
        &s,
        epoch,
        n2c,
        &Datagram::number(CipherId::HmacSha256T32, id, epoch, 0, SCALE_MIN, 10).unwrap(),
    );
    accept(
        &mut json,
        "boundary: offset 524287, last tick of the epoch",
        &s,
        epoch,
        n2c,
        &Datagram::number(
            CipherId::HmacSha256T32,
            id,
            epoch,
            TICKS_PER_EPOCH - 1,
            SCALE_MIN,
            10,
        )
        .unwrap(),
    );
    accept(
        &mut json,
        "boundary: offset 65536, first value past a 16-bit read",
        &s,
        epoch,
        n2c,
        &Datagram::number(CipherId::HmacSha256T32, id, epoch, 65_536, SCALE_MIN, 10).unwrap(),
    );
    accept(
        &mut json,
        "boundary: size 1",
        &s,
        epoch,
        n2c,
        &Datagram::data(
            MsgType::Message,
            CipherId::HmacSha256T32,
            id,
            epoch,
            1,
            vec![Record::new(Format::None, 1, vec![0x5a])],
        )
        .unwrap(),
    );
    accept(
        &mut json,
        "boundary: size 400 and schema_version 255, both straddling bytes",
        &s,
        epoch,
        n2c,
        &Datagram::data(
            MsgType::Message,
            CipherId::HmacSha256T32,
            id,
            epoch,
            2,
            vec![Record::new(Format::CapnProto, 0xff, vec![0x77; 400])],
        )
        .unwrap(),
    );
    accept(
        &mut json,
        "boundary: NUMBER scale 0x01 (coarsest), mantissa i16::MAX",
        &s,
        epoch,
        n2c,
        &Datagram::number(CipherId::HmacSha256T32, id, epoch, 3, SCALE_MIN, i16::MAX).unwrap(),
    );
    accept(
        &mut json,
        "boundary: NUMBER scale 0x07 (finest), mantissa i16::MIN",
        &s,
        epoch,
        n2c,
        &Datagram::number(CipherId::HmacSha256T32, id, epoch, 4, SCALE_MAX, i16::MIN).unwrap(),
    );
    accept(
        &mut json,
        "boundary: SERIES delta at 1 tick, the minimum",
        &s,
        epoch,
        n2c,
        &Datagram::series(
            CipherId::HmacSha256T32,
            id,
            epoch,
            SCALE_MIN,
            &[(5, 0), (6, 1)],
        )
        .unwrap(),
    );
    accept(
        &mut json,
        "boundary: SERIES delta at 65535 ticks, the maximum",
        &s,
        epoch,
        n2c,
        &Datagram::series(
            CipherId::HmacSha256T32,
            id,
            epoch,
            SCALE_MIN,
            &[(6, 0), (6 + 65_535, 1)],
        )
        .unwrap(),
    );
    // §14.1: one accepted datagram per non-zero reserved-bit value, identical
    // to a baseline apart from the bits — all must decode to the same output
    // (PROTOCOL.md 4.2 must-ignore).
    for v in 1u8..=0x1F {
        accept(
            &mut json,
            &format!("boundary: reserved bits {v:02x}, must be ignored by receivers"),
            &s,
            epoch,
            n2c,
            &{
                let mut d =
                    Datagram::number(CipherId::HmacSha256T32, id, epoch, 8, SCALE_MIN, 10).unwrap();
                d.reserved = v;
                d
            },
        );
    }

    // --- cipher 0x03: two datagrams differing only in datagram_offset,
    // confirming distinct nonces produce distinct tags under one epoch_key
    // (PROTOCOL.md 14.1, 14.2; RATIONALE.md R5) ---
    accept(
        &mut json,
        "cipher 0x03: nonce pair, offset 10",
        &s,
        epoch,
        n2c,
        &Datagram::number(CipherId::ChaCha20Poly1305, id, epoch, 10, SCALE_MIN, 10).unwrap(),
    );
    accept(
        &mut json,
        "cipher 0x03: nonce pair, offset 11 (same epoch_key, distinct nonce)",
        &s,
        epoch,
        n2c,
        &Datagram::number(CipherId::ChaCha20Poly1305, id, epoch, 11, SCALE_MIN, 10).unwrap(),
    );

    // --- §14.1: one rejected datagram per rejection path in §7.4, each
    // isolating a single fault. Receiver state a vector needs is spelled out
    // on the vector; PASS means the IUT's §7.4 pipeline rejects. ---
    let base = Datagram::number(CipherId::HmacSha256T64, id, epoch, 4096, 0x02, 2350).unwrap();
    let base_wire = base.encode(&s, epoch, n2c, 65535).unwrap();
    let rx = Receiver::for_wire(&base, epoch);

    reject_datagram(
        &mut json,
        "reject: datagram shorter than header + tag",
        &s,
        &base_wire[..base_wire.len() - 1],
        "short_length",
        &rx,
    );
    reject_datagram(
        &mut json,
        "reject: unsupported version 2",
        &s,
        &with_byte(base_wire.clone(), 0, (base_wire[0] & 0x1F) | (2 << 5)),
        "unsupported_version",
        &rx,
    );
    reject_datagram(
        &mut json,
        "reject: msg_type 0x00 is reserved",
        &s,
        &with_byte(base_wire.clone(), 0, base_wire[0] & 0xE0),
        "msg_type_0x00",
        &rx,
    );
    reject_datagram(
        &mut json,
        "reject: unimplemented msg_type 0x06",
        &s,
        &with_byte(base_wire.clone(), 0, (base_wire[0] & 0xE0) | 0x06),
        "unimplemented_msg_type",
        &rx,
    );
    // Unknown sender: a fully valid datagram from a sender the receiver does
    // not know, rebuilt under the stranger's own key so step 4 is the only
    // fault.
    let stranger = 0xdead_beefu32;
    let stranger_dg =
        Datagram::number(CipherId::HmacSha256T64, stranger, epoch, 4096, 0x02, 2350).unwrap();
    reject_datagram(
        &mut json,
        "reject: sender not provisioned with the receiver",
        &s,
        &stranger_dg.encode(&s, epoch, n2c, 65535).unwrap(),
        "unknown_sender",
        &Receiver {
            sender_id: id,
            ..Receiver::for_wire(&stranger_dg, epoch)
        },
    );
    // Cipher mismatch: the wire says 0x01, the receiver is provisioned 0x02.
    reject_datagram(
        &mut json,
        "reject: cipher_id differs from the configured suite",
        &s,
        &with_byte(base_wire.clone(), 1, (base_wire[1] & 0x0F) | (0x02 << 4)),
        "cipher_mismatch",
        &Receiver {
            cipher: CipherId::SipHash24,
            ..rx.clone()
        },
    );
    // Out-of-window epoch: low nibble 5; the receiver at 13281250 accepts only
    // low nibbles {1, 2} (its own and the one before).
    reject_datagram(
        &mut json,
        "reject: epoch_low outside the acceptance window",
        &s,
        &with_byte(base_wire.clone(), 1, (base_wire[1] & 0xF0) | 0x05),
        "epoch_out_of_window",
        &rx,
    );
    let mut corrupted = base_wire.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    reject_datagram(
        &mut json,
        "reject: tag does not verify",
        &s,
        &corrupted,
        "corrupted_tag",
        &rx,
    );
    // Replay: the arriving offset is already in the window.
    reject_datagram(
        &mut json,
        "reject: replayed datagram_offset",
        &s,
        &base_wire,
        "replayed_offset",
        &Receiver {
            seen_offsets: vec![4096],
            ..Receiver::for_wire(&base, epoch)
        },
    );
    // At or below the window: the window's high-water mark is far ahead of the
    // arriving offset.
    let old = Datagram::number(CipherId::HmacSha256T64, id, epoch, 50, 0x02, 2350).unwrap();
    reject_datagram(
        &mut json,
        "reject: offset at or below the window",
        &s,
        &old.encode(&s, epoch, n2c, 65535).unwrap(),
        "offset_below_window",
        &Receiver {
            seen_offsets: vec![100_000],
            ..Receiver::for_wire(&old, epoch)
        },
    );

    // --- §6.4.4 framing faults: authentic (MAC-valid), so each reaches step 9
    // and the rejection is about the body, not the tag. The seventh §14.1
    // fault -- `size` disagreeing with a fixed-width (format, schema_version)
    // pair -- is not emitted: fixed-width layouts are a per-deployment
    // provision and the codec has no width model to hold the check (see
    // issue #90's notes). ---
    let msg_base = Datagram::data(
        MsgType::Message,
        CipherId::HmacSha256T64,
        id,
        epoch,
        4096,
        vec![Record::new(Format::None, 1, vec![0x5a])],
    )
    .unwrap();
    // Record header word = (format << 20) | (schema_version << 12) | size,
    // transmitted as its low three bytes (PROTOCOL.md 6.4.2).
    let (r1, r2) = ([0x10u8, 0x10, 0x01], [0x10u8, 0x20, 0x01]);
    let body = |parts: &[&[u8]]| parts.concat();
    reject_datagram(
        &mut json,
        "reject: payload shorter than one record header",
        &s,
        &authentic_with_payload(&s, &msg_base, epoch, n2c, &[0x01]),
        "framing_short_body",
        &rx,
    );
    reject_datagram(
        &mut json,
        "reject: trailing fragment of fewer than 3 bytes",
        &s,
        &authentic_with_payload(
            &s,
            &msg_base,
            epoch,
            n2c,
            &body(&[&r1, &[0x5a], &[0xaa, 0xbb]]),
        ),
        "framing_trailing_fragment",
        &rx,
    );
    reject_datagram(
        &mut json,
        "reject: record size overruns the payload",
        &s,
        &authentic_with_payload(
            &s,
            &msg_base,
            epoch,
            n2c,
            &body(&[&[0x10, 0x1f, 0xff], &[0x5a]]),
        ),
        "framing_size_overrun",
        &rx,
    );
    reject_datagram(
        &mut json,
        "reject: record size 0",
        &s,
        &authentic_with_payload(
            &s,
            &msg_base,
            epoch,
            n2c,
            &body(&[&[0x10, 0x10, 0x00], &[0x5a]]),
        ),
        "framing_size_zero",
        &rx,
    );
    reject_datagram(
        &mut json,
        "reject: parse ends past the payload boundary",
        &s,
        &authentic_with_payload(
            &s,
            &msg_base,
            epoch,
            n2c,
            &body(&[&r1, &[0x5a], &[0x10, 0x1f, 0xff]]),
        ),
        "framing_past_boundary",
        &rx,
    );
    let event_base = Datagram::data(
        MsgType::Event,
        CipherId::HmacSha256T64,
        id,
        epoch,
        4096,
        vec![Record::new(Format::None, 7, vec![0xaa])],
    )
    .unwrap();
    reject_datagram(
        &mut json,
        "reject: EVENT carries two records",
        &s,
        &authentic_with_payload(
            &s,
            &event_base,
            epoch,
            n2c,
            &body(&[&r1, &[0x5a], &r2, &[0x22]]),
        ),
        "framing_event_two_records",
        &rx,
    );

    // --- §6.4.4 fixed-width layout: a `size` that disagrees with the layout's
    // fixed body width discards the record individually -- the datagram is
    // accepted and the held record delivered (the seventh §14.1 fault, issue
    // #93). The receiver holds (Format::None, 1) with fixed body width 8, so
    // the 8-byte record survives and the 6-byte one lands in `skipped`.
    accept_fixed_width(
        &mut json,
        "framing: fixed-width layout size mismatch skips the record, not the datagram",
        &s,
        epoch,
        n2c,
        &Datagram::data(
            MsgType::Message,
            CipherId::HmacSha256T32,
            id,
            epoch,
            3,
            vec![
                Record::new(Format::None, 1, vec![0x11; 8]),
                Record::new(Format::None, 1, vec![0x22; 6]),
            ],
        )
        .unwrap(),
        Layout::with_fixed_width(Format::None as u8, 1, 8),
    );

    // --- §14.1 boundary set: the size ceiling, and the epoch-boundary pair ---
    accept(
        &mut json,
        "boundary: size 4095, the largest a record size field can name",
        &s,
        epoch,
        n2c,
        &Datagram::data(
            MsgType::Message,
            CipherId::HmacSha256T32,
            id,
            epoch,
            2,
            vec![Record::new(Format::CapnProto, 0xff, vec![0x77; 4095])],
        )
        .unwrap(),
    );
    accept(
        &mut json,
        "boundary: first datagram of a new epoch",
        &s,
        epoch + 1,
        n2c,
        &Datagram::number(CipherId::HmacSha256T32, id, epoch + 1, 4096, SCALE_MIN, 10).unwrap(),
    );
    // Encoded under `epoch - 1`, arriving at a receiver that has already moved
    // to `epoch`: the two-epoch acceptance window admits it (PROTOCOL.md 9.3).
    accept_cross(
        &mut json,
        "boundary: preceding-epoch datagram after an epoch change",
        &s,
        epoch - 1,
        epoch,
        n2c,
        &Datagram::number(CipherId::HmacSha256T32, id, epoch - 1, 4096, SCALE_MIN, 10).unwrap(),
    );

    // --- SERIES payload grammar (PROTOCOL.md 6.9), accept and reject.
    // Payload = scale, first reading's mantissa (its instant is the anchor,
    // not on the wire), then 4-byte (delta, mantissa) entries. ---
    println!("# SERIES payloads, validated in isolation against the anchor");
    let ser = |scale: u8, first_m: i16, entries: &[(u16, i16)]| {
        let mut p = vec![scale];
        p.extend_from_slice(&first_m.to_be_bytes());
        for &(delta, mantissa) in entries {
            p.extend_from_slice(&delta.to_be_bytes());
            p.extend_from_slice(&mantissa.to_be_bytes());
        }
        p
    };
    // §14.1 SERIES acceptance: the minimum (two readings), the delta range's
    // ends, and a payload filling the 499-byte budget (Section 6.6: 3 + 4n,
    // n = 124).
    series_payload(&mut json, &ser(0x01, 0, &[(1, 1)]), 5, "accept");
    series_payload(&mut json, &ser(0x01, 0, &[(65_535, 1)]), 5, "accept");
    let mut budget = ser(0x01, 0, &[]);
    for i in 0..124i16 {
        budget.extend_from_slice(&1u16.to_be_bytes());
        budget.extend_from_slice(&i.to_be_bytes());
    }
    series_payload(&mut json, &budget, 5, "accept");
    // §14.1 SERIES rejections.
    series_payload(&mut json, &ser(0x02, 10, &[]), 4096, "reject"); // 3 bytes: one reading
    // Misaligned trailers: 3 + 4n + 1 and 3 + 4n + 2 bytes.
    let mut misaligned1 = ser(0x02, 10, &[(1, 20)]);
    misaligned1.push(0x00);
    series_payload(&mut json, &misaligned1, 4096, "reject");
    let mut misaligned2 = ser(0x02, 10, &[(1, 20)]);
    misaligned2.extend_from_slice(&[0x00, 0x00]);
    series_payload(&mut json, &misaligned2, 4096, "reject");
    // A delta of 0.
    series_payload(&mut json, &ser(0x02, 10, &[(0, 20)]), 4096, "reject");
    // Cumulative offset reaching TICKS_PER_EPOCH: anchor 524280, delta 8.
    series_payload(&mut json, &ser(0x01, 0, &[(8, 1)]), 524_280, "reject");
    println!();

    // --- §14.1 cold start: TIME_ANNOUNCE the node MUST reject (11.5) ---
    // The floor: last_epoch * 128 == 1_700_000_000 exactly, and the rule is
    // "strictly beyond", so the floor itself rejects.
    reject_time_announce(
        &mut json,
        "cold start: announcement at the floor is rejected as time rollback",
        &s,
        id,
        1_700_000_000,
        "cold",
        epoch,
    );
    reject_time_announce(
        &mut json,
        "cold start: a node whose clock is already valid rejects every announcement",
        &s,
        id,
        1_800_000_000,
        "valid",
        epoch,
    );

    // --- time recovery: its own key schedule, one key per direction ---
    let req = Datagram::time_request(id, &s).unwrap();
    let req_time_key = s.time_key(id, Direction::NodeToCollector);
    println!("# TIME_REQUEST, cipher 0x01 mandatory, node-to-collector time_key");
    println!("kind         accept_time_request");
    println!("device_secret {}", hex(s.expose_secret()));
    println!("sender_id    {id:08x}");
    println!("direction    00");
    println!("time_key     {}", hex(&req_time_key[..]));
    println!("wire         {}", hex(&req));
    println!("wire_len     {}", req.len());
    println!();
    json.push(&[
        (
            "name",
            json_str("TIME_REQUEST, cipher 0x01 mandatory, node-to-collector time_key"),
        ),
        ("kind", json_str("accept_time_request")),
        ("device_secret", json_str(&hex(s.expose_secret()))),
        ("sender_id", json_str(&format!("{id:08x}"))),
        ("direction", json_str("00")),
        ("time_key", json_str(&hex(&req_time_key[..]))),
        ("wire", json_str(&hex(&req))),
        ("wire_len", req.len().to_string()),
    ]);

    let asserted = 1_700_000_000i64;
    let wire = Datagram::time_announce(id, asserted, &s).unwrap();
    let announce_time_key = s.time_key(id, Direction::CollectorToNode);
    println!("# TIME_ANNOUNCE, cipher 0x01 mandatory, collector-to-node time_key");
    println!("kind         accept_time_announce");
    println!("device_secret {}", hex(s.expose_secret()));
    println!("sender_id    {id:08x}");
    println!("direction    01");
    println!("time_key     {}", hex(&announce_time_key[..]));
    println!("asserted_time {asserted}");
    println!("wire         {}", hex(&wire));
    println!("wire_len     {}", wire.len());
    println!();
    json.push(&[
        (
            "name",
            json_str("TIME_ANNOUNCE, cipher 0x01 mandatory, collector-to-node time_key"),
        ),
        ("kind", json_str("accept_time_announce")),
        ("device_secret", json_str(&hex(s.expose_secret()))),
        ("sender_id", json_str(&format!("{id:08x}"))),
        ("direction", json_str("01")),
        ("time_key", json_str(&hex(&announce_time_key[..]))),
        ("asserted_time", asserted.to_string()),
        ("wire", json_str(&hex(&wire))),
        ("wire_len", wire.len().to_string()),
    ]);

    // --- NUMBER payloads (PROTOCOL.md 6.3, 6.3.1) ---
    // scale at both ends of the defined range, mantissa at both ends of i16
    // and at zero.
    println!("# Accepted NUMBER payloads: scale 0x01/0x07, mantissa 0/MIN/MAX");
    for scale in [SCALE_MIN, SCALE_MAX] {
        for mantissa in [0i16, i16::MIN, i16::MAX] {
            let mut p = vec![scale];
            p.extend_from_slice(&mantissa.to_be_bytes());
            println!("accept_number {}", hex(&p));
            number_payloads.push((hex(&p), "accept"));
        }
    }
    println!();
    println!("# Rejected NUMBER payloads: every one MUST fail 6.3's fixed layout");
    // scale 0x00 and 0x08 bracket the defined 0x01..=0x07 range.
    for p in [
        &[0x00, 0x00, 0x01][..],
        &[0x08, 0x00, 0x01][..],
        // Wrong length: shorter and longer than the fixed 3 bytes.
        &[0x02, 0x00][..],
        &[0x02, 0x00, 0x01, 0x00][..],
    ] {
        println!("reject_number {}", hex(p));
        number_payloads.push((hex(p), "reject"));
    }

    for (payload, outcome) in &number_payloads {
        json.push(&[
            ("kind", json_str("number_payload")),
            ("payload", json_str(payload)),
            ("outcome", json_str(outcome)),
        ]);
    }

    json.write("docs/test-vectors.json");
}
