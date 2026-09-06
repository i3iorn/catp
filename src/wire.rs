//! Datagram and record encoding (PROTOCOL.md 4, 6.3, 6.4, 7).

use crate::*;

/// One record: a 24-bit packed header plus a body (PROTOCOL.md 6.4).
///
/// Records carry no timestamp. Every record in a datagram shares the header's
/// `datagram_offset` as its capture instant (PROTOCOL.md 6.4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub format: u8,
    pub schema_version: u8,
    pub body: Vec<u8>,
}

impl Record {
    pub fn new(format: Format, schema_version: u8, body: Vec<u8>) -> Self {
        Self { format: format as u8, schema_version, body }
    }

    pub fn wire_len(&self) -> usize {
        RECORD_HEADER_LEN + self.body.len()
    }

    /// `(format << 20) | (schema_version << 12) | size`
    ///
    /// `schema_version` and `size` both straddle byte boundaries, so this goes
    /// through a u32 and masks rather than writing bytes individually.
    fn header_word(&self) -> u32 {
        ((self.format as u32 & 0x0F) << 20)
            | ((self.schema_version as u32 & 0xFF) << 12)
            | (self.body.len() as u32 & 0xFFF)
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.body.is_empty() || self.body.len() > MAX_BODY {
            return Err(Error::BodyTooLarge(self.body.len()));
        }
        out.extend_from_slice(&self.header_word().to_be_bytes()[1..4]);
        out.extend_from_slice(&self.body);
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<(Record, usize), Error> {
        if buf.len() < RECORD_HEADER_LEN {
            return Err(Error::Framing("record header truncated"));
        }
        let w = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | buf[2] as u32;
        let format = ((w >> 20) & 0x0F) as u8;
        let schema_version = ((w >> 12) & 0xFF) as u8;
        let size = (w & 0xFFF) as usize;

        if format == 0 {
            return Err(Error::Framing("format 0x00 is invalid"));
        }
        if schema_version == 0 {
            return Err(Error::Framing("schema_version 0x00 is invalid"));
        }
        if size == 0 {
            return Err(Error::Framing("size 0 is invalid"));
        }
        let end = RECORD_HEADER_LEN + size;
        if buf.len() < end {
            return Err(Error::Framing("record body overruns payload"));
        }
        Ok((
            Record { format, schema_version, body: buf[RECORD_HEADER_LEN..end].to_vec() },
            end,
        ))
    }
}

/// A parsed CATP datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub version: u8,
    pub msg_type: u8,
    pub cipher_id: u8,
    pub epoch_low: u8,
    pub reserved: u8,
    pub datagram_offset: u32,
    pub sender_id: u32,
    /// Payload for record-framed types.
    pub records: Vec<Record>,
    /// Raw payload for `NUMBER` and control types.
    pub raw: Vec<u8>,
}

impl Datagram {
    fn base(msg_type: MsgType, cipher: CipherId, sender_id: u32, epoch_id: u32, off: u32) -> Self {
        Self {
            version: VERSION,
            msg_type: msg_type as u8,
            cipher_id: cipher as u8,
            epoch_low: (epoch_id & 0x0F) as u8,
            reserved: 0,
            datagram_offset: off,
            sender_id,
            records: Vec::new(),
            raw: Vec::new(),
        }
    }

    /// Build a record-framed datagram (`MESSAGE`, `EVENT`, `ALARM`).
    pub fn data(
        msg_type: MsgType,
        cipher: CipherId,
        sender_id: u32,
        epoch_id: u32,
        datagram_offset: u32,
        records: Vec<Record>,
    ) -> Result<Self, Error> {
        if !msg_type.is_record_framed() {
            return Err(Error::Framing("msg_type is not record-framed"));
        }
        if records.is_empty() {
            return Err(Error::Framing("record-framed datagram needs at least one record"));
        }
        if matches!(msg_type, MsgType::Event | MsgType::Alarm) && records.len() > 1 {
            return Err(Error::Framing("EVENT and ALARM carry exactly one record"));
        }
        if datagram_offset >= TICKS_PER_EPOCH {
            return Err(Error::Framing("datagram_offset exceeds 19 bits"));
        }
        let mut d = Self::base(msg_type, cipher, sender_id, epoch_id, datagram_offset);
        d.records = records;
        Ok(d)
    }

    /// Build a `NUMBER` datagram: a fixed-point reading, `mantissa *
    /// 10^-scale` (PROTOCOL.md 6.3). `scale` MUST be `0x01..=0x07`
    /// (Section 6.3.1).
    pub fn number(
        cipher: CipherId,
        sender_id: u32,
        epoch_id: u32,
        datagram_offset: u32,
        scale: u8,
        mantissa: i16,
    ) -> Result<Self, Error> {
        if !scale_is_valid(scale) {
            return Err(Error::BadNumber("scale must be 0x01..=0x07"));
        }
        if datagram_offset >= TICKS_PER_EPOCH {
            return Err(Error::Framing("datagram_offset exceeds 19 bits"));
        }
        let mut d = Self::base(MsgType::Number, cipher, sender_id, epoch_id, datagram_offset);
        d.raw = vec![scale];
        d.raw.extend_from_slice(&mantissa.to_be_bytes());
        Ok(d)
    }

    /// Build a `SERIES` datagram: `scale` shared by every reading, each at
    /// its own instant (PROTOCOL.md 6.9).
    ///
    /// `readings` are `(datagram_offset, mantissa)` pairs, absolute instants
    /// within the epoch, in strictly increasing order; there MUST be at
    /// least two (a single reading MUST use `number` instead). The first
    /// reading's instant becomes this datagram's `datagram_offset`; each
    /// later one is encoded as a `delta` from its predecessor, which MUST
    /// therefore fit in 16 bits (Section 6.9) -- consecutive readings more
    /// than 65535 ticks apart do not fit one `SERIES` batch.
    pub fn series(
        cipher: CipherId,
        sender_id: u32,
        epoch_id: u32,
        scale: u8,
        readings: &[(u32, i16)],
    ) -> Result<Self, Error> {
        if !scale_is_valid(scale) {
            return Err(Error::BadSeries("scale must be 0x01..=0x07"));
        }
        if readings.len() < 2 {
            return Err(Error::BadSeries("SERIES must carry at least two readings"));
        }
        let (first_offset, first_mantissa) = readings[0];
        if first_offset >= TICKS_PER_EPOCH {
            return Err(Error::Framing("datagram_offset exceeds 19 bits"));
        }
        let mut raw = Vec::with_capacity(NUMBER_PAYLOAD_LEN + SERIES_ENTRY_LEN * (readings.len() - 1));
        raw.push(scale);
        raw.extend_from_slice(&first_mantissa.to_be_bytes());
        let mut prev = first_offset;
        for &(offset, mantissa) in &readings[1..] {
            if offset <= prev {
                return Err(Error::BadSeries("reading instants must strictly increase"));
            }
            let delta: u16 = (offset - prev)
                .try_into()
                .map_err(|_| Error::BadSeries("gap between readings exceeds 65535 ticks"))?;
            raw.extend_from_slice(&delta.to_be_bytes());
            raw.extend_from_slice(&mantissa.to_be_bytes());
            prev = offset;
        }
        if prev >= TICKS_PER_EPOCH {
            return Err(Error::BadSeries("reading instant crosses the epoch boundary"));
        }
        let mut d = Self::base(MsgType::Series, cipher, sender_id, epoch_id, first_offset);
        d.raw = raw;
        Ok(d)
    }

    /// Build a control datagram. `body` is the whole fixed-layout payload.
    pub fn control(
        msg_type: MsgType,
        cipher: CipherId,
        sender_id: u32,
        epoch_id: u32,
        datagram_offset: u32,
        body: &[u8],
    ) -> Result<Self, Error> {
        if !is_control(msg_type as u8) {
            return Err(Error::Framing("not a control type"));
        }
        if datagram_offset >= TICKS_PER_EPOCH {
            return Err(Error::Framing("datagram_offset exceeds 19 bits"));
        }
        let mut d = Self::base(msg_type, cipher, sender_id, epoch_id, datagram_offset);
        d.raw = body.to_vec();
        Ok(d)
    }

    fn header_bytes(&self) -> [u8; HEADER_LEN] {
        let b0 = ((self.version & 0x07) << 5) | (self.msg_type & 0x1F);
        let b1 = ((self.cipher_id & 0x0F) << 4) | (self.epoch_low & 0x0F);
        let o = self.datagram_offset & 0x7_FFFF;
        let b2 = ((self.reserved & 0x1F) << 3) | ((o >> 16) as u8 & 0x07);
        let s = self.sender_id.to_be_bytes();
        [b0, b1, b2, (o >> 8) as u8, o as u8, s[0], s[1], s[2], s[3]]
    }

    /// The 13-byte authenticated header image (PROTOCOL.md 7.1).
    ///
    /// Identical to the wire header except that the 4 `epoch_low` bits are
    /// zeroed and the full 32-bit `epoch_id` is appended, so the epoch appears
    /// exactly once.
    pub fn auth_header(&self, epoch_id: u32) -> [u8; 13] {
        let h = self.header_bytes();
        let e = epoch_id.to_be_bytes();
        [
            h[0],
            h[1] & 0xF0, // epoch_low zeroed
            h[2],
            h[3],
            h[4],
            e[0],
            e[1],
            e[2],
            e[3],
            h[5],
            h[6],
            h[7],
            h[8],
        ]
    }

    fn payload(&self) -> Result<Vec<u8>, Error> {
        if !self.records.is_empty() {
            let mut p = Vec::new();
            for r in &self.records {
                r.encode_into(&mut p)?;
            }
            Ok(p)
        } else {
            Ok(self.raw.clone())
        }
    }

    /// Serialize and authenticate, producing the UDP payload.
    pub fn encode(
        &self,
        secret: &DeviceSecret,
        epoch_id: u32,
        dir: Direction,
        max_datagram_size: usize,
    ) -> Result<Vec<u8>, Error> {
        let cipher =
            CipherId::from_u8(self.cipher_id).ok_or(Error::CipherUnimplemented(self.cipher_id))?;
        let payload = self.payload()?;
        let key = secret.epoch_key(self.sender_id, epoch_id, dir);

        let mut signed = Vec::with_capacity(13 + payload.len());
        signed.extend_from_slice(&self.auth_header(epoch_id));
        signed.extend_from_slice(&payload);
        let tag = mac(cipher, &key, &signed)?;

        let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + tag.len());
        out.extend_from_slice(&self.header_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&tag);

        if out.len() > max_datagram_size {
            return Err(Error::Oversize(out.len()));
        }
        Ok(out)
    }

    /// Build a `TIME_ANNOUNCE` (PROTOCOL.md 11.3).
    ///
    /// Fixed by the spec: `cipher_id` `0x01`, `epoch_low` 0, `datagram_offset`
    /// 0. It is authenticated under `time_key`, which has no epoch input, so a
    /// node with no clock can verify it.
    pub fn time_announce(
        sender_id: u32,
        asserted_time: i64,
        secret: &DeviceSecret,
    ) -> Result<Vec<u8>, Error> {
        let d = Self {
            version: VERSION,
            msg_type: MsgType::TimeAnnounce as u8,
            // 0x01 is REQUIRED here: 0x03 draws its nonce from datagram_offset,
            // and a message sent outside any epoch has no offset space to make
            // one unique (PROTOCOL.md 11.3).
            cipher_id: CipherId::HmacSha256T64 as u8,
            epoch_low: 0,
            reserved: 0,
            datagram_offset: 0,
            sender_id,
            records: Vec::new(),
            raw: asserted_time.to_be_bytes().to_vec(),
        };
        let key = secret.time_key(sender_id, Direction::CollectorToNode);
        let mut signed = Vec::with_capacity(13 + 8);
        signed.extend_from_slice(&d.auth_header(0)); // epoch_id 0: no epoch
        signed.extend_from_slice(&d.raw);
        let tag = mac(CipherId::HmacSha256T64, &key, &signed)?;
        let mut out = Vec::with_capacity(HEADER_LEN + 8 + 8);
        out.extend_from_slice(&d.header_bytes());
        out.extend_from_slice(&d.raw);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Build a `TIME_REQUEST` (PROTOCOL.md 11.3).
    ///
    /// Empty payload, `cipher_id` `0x01`, `epoch_low` 0, `datagram_offset` 0,
    /// authenticated under the node-to-collector `time_key`. It carries no
    /// claimed time, so a node cannot use it to propose, select, or influence
    /// the time the collector will announce.
    pub fn time_request(sender_id: u32, secret: &DeviceSecret) -> Result<Vec<u8>, Error> {
        let d = Self {
            version: VERSION,
            msg_type: MsgType::TimeRequest as u8,
            cipher_id: CipherId::HmacSha256T64 as u8,
            epoch_low: 0,
            reserved: 0,
            datagram_offset: 0,
            sender_id,
            records: Vec::new(),
            raw: Vec::new(),
        };
        let key = secret.time_key(sender_id, Direction::NodeToCollector);
        let tag = mac(CipherId::HmacSha256T64, &key, &d.auth_header(0))?;
        let mut out = Vec::with_capacity(HEADER_LEN + 8);
        out.extend_from_slice(&d.header_bytes());
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// The `NUMBER` reading, if this is one: `(scale, mantissa)`
    /// (PROTOCOL.md 6.3).
    pub fn number_value(&self) -> Option<(u8, i16)> {
        if self.msg_type == MsgType::Number as u8 {
            validate_number(&self.raw).ok()
        } else {
            None
        }
    }

    /// The `SERIES` readings, if this is one: shared `scale` plus each
    /// reading's `(instant, mantissa)`, instants in strictly increasing
    /// order (PROTOCOL.md 6.9).
    pub fn series_values(&self) -> Option<(u8, Vec<(u32, i16)>)> {
        if self.msg_type == MsgType::Series as u8 {
            validate_series(&self.raw, self.datagram_offset).ok()
        } else {
            None
        }
    }
}

/// What a receiver learns from a successfully verified datagram.
#[derive(Debug)]
pub struct Accepted {
    pub datagram: Datagram,
    pub epoch_id: u32,
    pub datagram_offset: u32,
    /// Records whose `(format, schema_version)` the receiver holds no layout
    /// for. Skipped individually (PROTOCOL.md 6.4.3).
    pub skipped: Vec<Record>,
}

/// Receiver-side per-peer configuration.
pub struct PeerConfig {
    pub sender_id: u32,
    pub secret: DeviceSecret,
    pub cipher: CipherId,
    /// `(format, schema_version)` pairs this receiver can interpret.
    pub layouts: Vec<(u8, u8)>,
    /// Per-`sender_id` inbound rate limit (PROTOCOL.md 10.3, 8.1.1).
    ///
    /// `cipher`'s [`CipherId::requires_inbound_rate_limit`] decides whether
    /// this may be `None`: `PeerState::new` / `Collector::provision` refuse a
    /// config that pairs a mandatory-limit cipher with no limit, rather than
    /// silently accepting one.
    pub inbound_rate_limit: Option<RateLimit>,
}

/// Header constraints shared by `TIME_REQUEST` and `TIME_ANNOUNCE`.
///
/// Both travel outside any epoch, so these fields are pinned to a single
/// canonical form rather than carrying information (PROTOCOL.md 11.3, 11.4).
/// Returns the reserved bits, which remain must-ignore.
fn check_time_header(buf: &[u8], want: MsgType, sender_id: u32) -> Result<u8, Error> {
    if (buf[0] >> 5) & 0x07 != VERSION {
        return Err(Error::UnsupportedVersion((buf[0] >> 5) & 0x07));
    }
    if buf[0] & 0x1F != want as u8 {
        return Err(Error::BadMsgType(buf[0] & 0x1F));
    }
    if (buf[1] >> 4) & 0x0F != CipherId::HmacSha256T64 as u8 {
        return Err(Error::CipherMismatch {
            got: (buf[1] >> 4) & 0x0F,
            want: CipherId::HmacSha256T64 as u8,
        });
    }
    if buf[1] & 0x0F != 0 {
        return Err(Error::Framing("time-recovery epoch_low must be zero"));
    }
    let off = (((buf[2] & 0x07) as u32) << 16) | ((buf[3] as u32) << 8) | buf[4] as u32;
    if off != 0 {
        return Err(Error::Framing("time-recovery datagram_offset must be zero"));
    }
    let got = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
    if got != sender_id {
        return Err(Error::UnknownSender(got));
    }
    Ok((buf[2] >> 3) & 0x1F)
}

/// Verify a `TIME_REQUEST` under the node-to-collector `time_key`
/// (PROTOCOL.md 11.3).
///
/// A valid request neither establishes nor advances time; it only says that
/// this node is asking. Because it carries `datagram_offset` 0 by
/// construction, the replay window of Section 10.2 cannot cover it, so callers
/// MUST rate-limit their responses.
pub fn decode_time_request(
    buf: &[u8],
    sender_id: u32,
    secret: &DeviceSecret,
) -> Result<(), Error> {
    let tag_len = CipherId::HmacSha256T64.tag_len();
    if buf.len() != HEADER_LEN + tag_len {
        return Err(Error::TooShort);
    }
    let reserved = check_time_header(buf, MsgType::TimeRequest, sender_id)?;
    let d = Datagram {
        version: VERSION,
        msg_type: MsgType::TimeRequest as u8,
        cipher_id: CipherId::HmacSha256T64 as u8,
        epoch_low: 0,
        reserved,
        datagram_offset: 0,
        sender_id,
        records: Vec::new(),
        raw: Vec::new(),
    };
    let key = secret.time_key(sender_id, Direction::NodeToCollector);
    if !ct_eq(&mac(CipherId::HmacSha256T64, &key, &d.auth_header(0))?, &buf[HEADER_LEN..]) {
        return Err(Error::AuthFailed);
    }
    Ok(())
}

/// Verify a `TIME_ANNOUNCE` under the collector-to-node `time_key`
/// (PROTOCOL.md 11.4).
///
/// Separate from [`decode`] because it is the one message keyed on something
/// other than an epoch key, and the one a receiver must handle before it knows
/// what epoch it is in. Returns the asserted time; the caller applies the
/// acceptance rules of PROTOCOL.md 11.4 via [`crate::NodeClock`].
pub fn decode_time_announce(
    buf: &[u8],
    sender_id: u32,
    secret: &DeviceSecret,
) -> Result<i64, Error> {
    let tag_len = CipherId::HmacSha256T64.tag_len();
    if buf.len() != HEADER_LEN + 8 + tag_len {
        return Err(Error::TooShort);
    }
    let reserved = check_time_header(buf, MsgType::TimeAnnounce, sender_id)?;

    let payload = &buf[HEADER_LEN..HEADER_LEN + 8];
    let d = Datagram {
        version: VERSION,
        msg_type: MsgType::TimeAnnounce as u8,
        cipher_id: CipherId::HmacSha256T64 as u8,
        epoch_low: 0,
        reserved,
        datagram_offset: 0,
        sender_id,
        records: Vec::new(),
        raw: payload.to_vec(),
    };
    let key = secret.time_key(sender_id, Direction::CollectorToNode);
    let mut signed = Vec::with_capacity(13 + 8);
    signed.extend_from_slice(&d.auth_header(0));
    signed.extend_from_slice(payload);
    if !ct_eq(&mac(CipherId::HmacSha256T64, &key, &signed)?, &buf[HEADER_LEN + 8..]) {
        return Err(Error::AuthFailed);
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(payload);
    Ok(i64::from_be_bytes(b))
}

/// Verify a datagram against a peer, in the order of PROTOCOL.md 7.4.
///
/// `window` is mutated only after the MAC verifies (step 7).
pub fn decode(
    buf: &[u8],
    peer: &PeerConfig,
    local_epoch: u32,
    dir: Direction,
    window: &mut ReplayWindow,
) -> Result<Accepted, Error> {
    // --- step 1: length
    if buf.len() < HEADER_LEN {
        return Err(Error::TooShort);
    }
    let version = (buf[0] >> 5) & 0x07;
    let msg_type = buf[0] & 0x1F;
    let cipher_id = (buf[1] >> 4) & 0x0F;
    let epoch_low = buf[1] & 0x0F;
    let reserved = (buf[2] >> 3) & 0x1F; // must-ignore (PROTOCOL.md 4.2)
    let datagram_offset =
        (((buf[2] & 0x07) as u32) << 16) | ((buf[3] as u32) << 8) | buf[4] as u32;
    let sender_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);

    // --- step 2: version
    if version != VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    // --- step 3: msg_type
    let mt = MsgType::from_u8(msg_type).ok_or(Error::BadMsgType(msg_type))?;
    if matches!(mt, MsgType::TimeAnnounce | MsgType::TimeRequest) {
        // Keyed on time_key, not an epoch key; use the dedicated entry points.
        return Err(Error::BadMsgType(msg_type));
    }
    // --- step 4: sender_id
    if sender_id != peer.sender_id {
        return Err(Error::UnknownSender(sender_id));
    }
    // --- step 5: cipher_id matches configuration
    if cipher_id != peer.cipher as u8 {
        return Err(Error::CipherMismatch { got: cipher_id, want: peer.cipher as u8 });
    }
    let cipher = CipherId::from_u8(cipher_id).ok_or(Error::CipherUnimplemented(cipher_id))?;
    let tag_len = cipher.tag_len();
    if buf.len() < HEADER_LEN + tag_len {
        return Err(Error::TooShort);
    }
    // --- step 6: epoch reconstruction
    let epoch_id = reconstruct_epoch(local_epoch, epoch_low).ok_or(Error::EpochOutOfWindow)?;

    // --- step 7: MAC. No persistent state touched before this point.
    let payload = &buf[HEADER_LEN..buf.len() - tag_len];
    let tag = &buf[buf.len() - tag_len..];
    let mut out = Datagram {
        version,
        msg_type,
        cipher_id,
        epoch_low,
        reserved,
        datagram_offset,
        sender_id,
        records: Vec::new(),
        raw: Vec::new(),
    };
    let key = peer.secret.epoch_key(sender_id, epoch_id, dir);
    let mut signed = Vec::with_capacity(13 + payload.len());
    signed.extend_from_slice(&out.auth_header(epoch_id));
    signed.extend_from_slice(payload);
    if !ct_eq(&mac(cipher, &key, &signed)?, tag) {
        return Err(Error::AuthFailed);
    }

    // --- step 8: replay. The offset came from the header, so this precedes
    // framing (PROTOCOL.md 7.4).
    window.check_and_set(datagram_offset)?;

    // --- step 9: framing
    if mt.is_record_framed() {
        if payload.len() < RECORD_HEADER_LEN {
            return Err(Error::Framing("payload shorter than one record header"));
        }
        let mut pos = 0usize;
        let mut recs = Vec::new();
        while pos < payload.len() {
            let (r, used) = Record::decode(&payload[pos..])?;
            pos += used;
            recs.push(r);
        }
        if pos != payload.len() {
            return Err(Error::Framing("trailing bytes after final record"));
        }
        if matches!(mt, MsgType::Event | MsgType::Alarm) && recs.len() > 1 {
            return Err(Error::Framing("EVENT and ALARM carry exactly one record"));
        }
        out.records = recs;
    } else if mt == MsgType::Number {
        validate_number(payload)?;
        out.raw = payload.to_vec();
    } else if mt == MsgType::Series {
        validate_series(payload, datagram_offset)?;
        out.raw = payload.to_vec();
    } else {
        out.raw = payload.to_vec();
    }

    // --- step 10: skip records with unknown layouts, keep the rest
    let mut skipped = Vec::new();
    if !out.records.is_empty() {
        let (keep, drop): (Vec<_>, Vec<_>) = out
            .records
            .drain(..)
            .partition(|r| peer.layouts.contains(&(r.format, r.schema_version)));
        out.records = keep;
        skipped = drop;
    }

    Ok(Accepted { datagram: out, epoch_id, datagram_offset, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerConfig {
        PeerConfig {
            sender_id: 0xDEADBEEF,
            secret: DeviceSecret::new([42u8; 32]),
            cipher: CipherId::HmacSha256T32,
            layouts: vec![(Format::None as u8, 1)],
            // `decode()` is called directly in this module's tests, bypassing
            // PeerState::new's invariant check -- so this may stay None even
            // for a 0x04 peer.
            inbound_rate_limit: None,
        }
    }
    fn rec(body: &[u8]) -> Record {
        Record::new(Format::None, 1, body.to_vec())
    }
    const EPOCH: u32 = 13_281_250;

    #[test]
    fn record_header_packs_at_field_maxima() {
        let r = Record::new(Format::CapnProto, 0xFF, vec![7u8; 4095]);
        let mut buf = Vec::new();
        r.encode_into(&mut buf).unwrap();
        assert_eq!(buf.len(), RECORD_HEADER_LEN + 4095);
        let (back, used) = Record::decode(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(back, r);
    }

    /// PROTOCOL.md 14.2: "One accepted record per assigned `format` value,
    /// each with a non-zero `schema_version`." `CapnProto` and `None` are
    /// already exercised elsewhere in this module; this closes the rest.
    #[test]
    fn every_assigned_format_round_trips() {
        for fmt in [
            Format::None,
            Format::Cbor,
            Format::MsgPack,
            Format::Protobuf,
            Format::FlatBuffers,
            Format::CapnProto,
        ] {
            let r = Record::new(fmt, 7, vec![0xAB; 5]);
            let mut buf = Vec::new();
            r.encode_into(&mut buf).unwrap();
            let (back, used) = Record::decode(&buf).unwrap();
            assert_eq!(used, buf.len());
            assert_eq!(back, r, "format {:?} did not round-trip", fmt as u8);
        }
    }

    /// PROTOCOL.md 14.2: rejections for `format` `0x00` and `schema_version`
    /// `0x00`. Neither is reachable through `Record::new` (it takes the
    /// `Format` enum, which has no zero variant), so this constructs the
    /// header word directly -- exactly the bytes an attacker or a defective
    /// sender could put on the wire.
    #[test]
    fn format_and_schema_version_zero_are_rejected() {
        // format = 0x0, schema_version = 0x01, size = 1.
        let format_zero = [0x00u8, 0x10, 0x01, 0xAB];
        assert_eq!(
            Record::decode(&format_zero).unwrap_err(),
            Error::Framing("format 0x00 is invalid")
        );
        // format = 0x1 (None), schema_version = 0x00, size = 1.
        let schema_zero = [0x10u8, 0x00, 0x01, 0xAB];
        assert_eq!(
            Record::decode(&schema_zero).unwrap_err(),
            Error::Framing("schema_version 0x00 is invalid")
        );
    }

    /// PROTOCOL.md 14.2: "A record whose `schema_version` is swapped for
    /// another of identical body width, confirming rejection rather than
    /// misdecoding." A receiver holding only `(None, 1)` must not read a
    /// same-width `(None, 2)` body as if it were a `(None, 1)` one -- it
    /// must be skipped instead (PROTOCOL.md 6.4.4).
    #[test]
    fn schema_version_swap_at_identical_width_is_skipped_not_misdecoded() {
        let p = peer(); // layouts: only (Format::None, 1)
        let held = Record::new(Format::None, 1, vec![0x11; 8]);
        let same_width_unheld = Record::new(Format::None, 2, vec![0x22; 8]);
        let dg = Datagram::data(
            MsgType::Message,
            CipherId::HmacSha256T32,
            p.sender_id,
            EPOCH,
            5,
            vec![held.clone(), same_width_unheld.clone()],
        )
        .unwrap();
        let wire = dg.encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
        let mut w = ReplayWindow::one_second();
        let acc = decode(&wire, &p, EPOCH, Direction::NodeToCollector, &mut w).unwrap();
        assert_eq!(acc.datagram.records, vec![held]);
        assert_eq!(acc.skipped, vec![same_width_unheld]);
    }

    #[test]
    fn size_and_schema_version_straddle_bytes() {
        // 300 does not fit in one byte, and schema_version's low nibble shares
        // byte 1 with size's high nibble.
        let r = Record::new(Format::None, 0xAB, vec![0u8; 300]);
        let mut buf = Vec::new();
        r.encode_into(&mut buf).unwrap();
        let (back, _) = Record::decode(&buf).unwrap();
        assert_eq!(back.body.len(), 300);
        assert_eq!(back.schema_version, 0xAB);
    }

    #[test]
    fn offset_above_u16_survives_roundtrip() {
        // Regression guard for reading bytes 3..5 as a u16 (PROTOCOL.md 4.1).
        let p = peer();
        for off in [0u32, 65_535, 65_536, 300_000, TICKS_PER_EPOCH - 1] {
            let dg = Datagram::number(CipherId::HmacSha256T32, p.sender_id, EPOCH, off, 1, 15).unwrap();
            let wire = dg.encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
            let mut w = ReplayWindow::one_second();
            let acc = decode(&wire, &p, EPOCH, Direction::NodeToCollector, &mut w).unwrap();
            assert_eq!(acc.datagram_offset, off, "offset {off} did not survive");
        }
    }

    #[test]
    fn number_roundtrip_and_size() {
        let p = peer();
        let dg = Datagram::number(CipherId::HmacSha256T32, p.sender_id, EPOCH, 42, 1, 235).unwrap();
        let wire = dg.encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
        assert_eq!(wire.len(), HEADER_LEN + NUMBER_PAYLOAD_LEN + 4); // 9 header + 3 payload + 4 tag
        let mut w = ReplayWindow::one_second();
        let acc = decode(&wire, &p, EPOCH, Direction::NodeToCollector, &mut w).unwrap();
        assert_eq!(acc.datagram.number_value(), Some((1, 235))); // 235 * 10^-1 = 23.5
        assert_eq!(acc.datagram_offset, 42);
    }

    #[test]
    fn number_beats_equivalent_message_on_the_wire() {
        let p = peer();
        // Same value, same precision (scale=2, i.e. hundredths): 23.50.
        let n = Datagram::number(CipherId::HmacSha256T32, p.sender_id, EPOCH, 1, 2, 2350)
            .unwrap()
            .encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        let m = Datagram::data(MsgType::Message, CipherId::HmacSha256T32, p.sender_id, EPOCH, 1, vec![rec(&2350i16.to_be_bytes())])
            .unwrap()
            .encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        assert!(n.len() < m.len(), "NUMBER {} vs MESSAGE {}", n.len(), m.len());
    }

    #[test]
    fn malformed_number_rejected_after_auth() {
        let p = peer();
        // Authenticate a bad payload the way a defective sender would: same
        // length, but scale 0x00 is invalid (PROTOCOL.md 6.3.1).
        let mut dg = Datagram::number(CipherId::HmacSha256T32, p.sender_id, EPOCH, 7, 1, 10).unwrap();
        dg.raw = vec![0x00, 0x00, 0x01];
        let wire = dg.encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
        let mut w = ReplayWindow::one_second();
        assert!(matches!(
            decode(&wire, &p, EPOCH, Direction::NodeToCollector, &mut w),
            Err(Error::BadNumber(_))
        ));
    }

    #[test]
    fn roundtrip_and_replay() {
        let p = peer();
        let dg = Datagram::data(MsgType::Message, CipherId::HmacSha256T32, p.sender_id, EPOCH, 100, vec![rec(b"\x01\x02"), rec(b"\x03\x04")]).unwrap();
        let wire = dg.encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
        assert_eq!(wire.len(), HEADER_LEN + 2 * (RECORD_HEADER_LEN + 2) + 4);
        let mut w = ReplayWindow::one_second();
        let acc = decode(&wire, &p, EPOCH, Direction::NodeToCollector, &mut w).unwrap();
        assert_eq!(acc.datagram.records.len(), 2);
        assert_eq!(
            decode(&wire, &p, EPOCH, Direction::NodeToCollector, &mut w).unwrap_err(),
            Error::Replay
        );
    }

    #[test]
    fn tampering_any_bit_fails_auth() {
        let p = peer();
        let dg = Datagram::data(MsgType::Message, CipherId::HmacSha256T32, p.sender_id, EPOCH, 9, vec![rec(b"xy")]).unwrap();
        let wire = dg.encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
        for byte in 0..wire.len() {
            for bit in 0..8 {
                let mut t = wire.clone();
                t[byte] ^= 1 << bit;
                let mut w = ReplayWindow::one_second();
                assert!(
                    decode(&t, &p, EPOCH, Direction::NodeToCollector, &mut w).is_err(),
                    "flip at byte {byte} bit {bit} accepted"
                );
            }
        }
    }

    #[test]
    fn reserved_bits_ignored_across_all_32_values() {
        let p = peer();
        for rsv in 0..32u8 {
            let mut dg = Datagram::data(MsgType::Message, CipherId::HmacSha256T32, p.sender_id, EPOCH, 11, vec![rec(b"ab")]).unwrap();
            dg.reserved = rsv;
            let wire = dg.encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
            let mut w = ReplayWindow::one_second();
            let acc = decode(&wire, &p, EPOCH, Direction::NodeToCollector, &mut w)
                .unwrap_or_else(|e| panic!("reserved={rsv} rejected: {e:?}"));
            assert_eq!(acc.datagram.records[0].body, b"ab".to_vec());
            assert_eq!(acc.datagram_offset, 11);
        }
    }

    #[test]
    fn unknown_layout_skips_only_that_record() {
        let p = peer();
        let dg = Datagram::data(
            MsgType::Message,
            CipherId::HmacSha256T32,
            p.sender_id,
            EPOCH,
            5,
            vec![rec(b"ok"), Record::new(Format::Cbor, 9, b"??".to_vec()), rec(b"ok2")],
        )
        .unwrap();
        let wire = dg.encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
        let mut w = ReplayWindow::one_second();
        let acc = decode(&wire, &p, EPOCH, Direction::NodeToCollector, &mut w).unwrap();
        assert_eq!(acc.datagram.records.len(), 2);
        assert_eq!(acc.skipped.len(), 1);
    }

    #[test]
    fn time_request_round_trips_and_is_directional() {
        let s = DeviceSecret::new([3u8; 32]);
        let wire = Datagram::time_request(0x1234, &s).unwrap();
        assert_eq!(wire.len(), HEADER_LEN + 8); // no payload, 8-byte tag
        assert!(decode_time_request(&wire, 0x1234, &s).is_ok());

        // A request must not verify as an announce, nor under another node.
        assert!(decode_time_announce(&wire, 0x1234, &s).is_err());
        assert!(decode_time_request(&wire, 0x9999, &s).is_err());

        // The two directions derive different keys, so a tag made with the
        // wrong one is refused (PROTOCOL.md 11.2).
        let d = Datagram {
            version: VERSION,
            msg_type: MsgType::TimeRequest as u8,
            cipher_id: CipherId::HmacSha256T64 as u8,
            epoch_low: 0,
            reserved: 0,
            datagram_offset: 0,
            sender_id: 0x1234,
            records: Vec::new(),
            raw: Vec::new(),
        };
        let wrong = mac(
            CipherId::HmacSha256T64,
            &s.time_key(0x1234, Direction::CollectorToNode),
            &d.auth_header(0),
        )
        .unwrap();
        let mut forged = d.header_bytes().to_vec();
        forged.extend_from_slice(&wrong);
        assert_eq!(decode_time_request(&forged, 0x1234, &s).unwrap_err(), Error::AuthFailed);
    }

    #[test]
    fn time_request_is_tamper_evident() {
        let s = DeviceSecret::new([3u8; 32]);
        let wire = Datagram::time_request(0x1234, &s).unwrap();
        for byte in 0..wire.len() {
            for bit in 0..8 {
                let mut t = wire.clone();
                t[byte] ^= 1 << bit;
                assert!(
                    decode_time_request(&t, 0x1234, &s).is_err(),
                    "flip at byte {byte} bit {bit} accepted"
                );
            }
        }
    }

    #[test]
    fn heartbeat_has_empty_payload() {
        let p = peer();
        let dg = Datagram::control(MsgType::Heartbeat, CipherId::HmacSha256T32, p.sender_id, EPOCH, 77, &[]).unwrap();
        let wire = dg.encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
        assert_eq!(wire.len(), HEADER_LEN + 4);
        let mut w = ReplayWindow::one_second();
        let acc = decode(&wire, &p, EPOCH, Direction::NodeToCollector, &mut w).unwrap();
        assert_eq!(acc.datagram_offset, 77);
        assert!(acc.datagram.raw.is_empty());
    }

    #[test]
    fn number_and_message_share_one_replay_window() {
        let p = peer();
        let n = Datagram::number(CipherId::HmacSha256T32, p.sender_id, EPOCH, 500, 1, 10)
            .unwrap()
            .encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        let m = Datagram::data(MsgType::Message, CipherId::HmacSha256T32, p.sender_id, EPOCH, 500, vec![rec(b"z")])
            .unwrap()
            .encode(&p.secret, EPOCH, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        let mut w = ReplayWindow::one_second();
        assert!(decode(&n, &p, EPOCH, Direction::NodeToCollector, &mut w).is_ok());
        assert_eq!(
            decode(&m, &p, EPOCH, Direction::NodeToCollector, &mut w).unwrap_err(),
            Error::Replay
        );
    }
}
