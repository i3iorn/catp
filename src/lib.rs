//! CATP v1 reference implementation.
//!
//! Covers the core protocol of `docs/PROTOCOL.md`: the 9-byte datagram header,
//! 3-byte record framing, the fixed-point `NUMBER`/`SERIES` codec, HKDF epoch
//! keys, and offset-keyed replay protection.
//!
//! Cipher suites `0x01` (HMAC-SHA256-t64) and `0x04` (HMAC-SHA256-t32) are
//! implemented. `0x02` (SipHash) and `0x03` (ChaCha20-Poly1305) are registered
//! in [`CipherId`] but return [`Error::CipherUnimplemented`], so the framing and
//! key-schedule paths stay honest about what has actually been exercised.

#![forbid(unsafe_code)]

use hkdf::Hkdf;
// `KeyInit` supplies `new_from_slice`; it moved off `Mac` in digest 0.11.
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub mod control;
pub mod peer;
pub mod wire;

pub use control::{Capability, Control};
pub use peer::{Collector, NodeClock, PeerState, Stats};
pub use wire::{Datagram, Record};

/// Protocol version carried in the high 3 bits of header byte 0.
pub const VERSION: u8 = 1;

/// Epoch duration in seconds (PROTOCOL.md 9.1).
pub const EPOCH_SECS: u64 = 128;

/// `epoch_offset` ticks per second (PROTOCOL.md 6.4.2).
pub const TICKS_PER_SEC: u64 = 4096;

/// Ticks in one epoch. Exactly `2^19`, so the 19-bit field spans an epoch.
pub const TICKS_PER_EPOCH: u32 = 1 << 19;

const _: () = assert!(EPOCH_SECS * TICKS_PER_SEC == TICKS_PER_EPOCH as u64);

/// Largest `size` a record header can express (12 bits).
pub const MAX_BODY: usize = 4095;

/// Datagram header length in bytes.
pub const HEADER_LEN: usize = 9;

/// Record header length in bytes.
pub const RECORD_HEADER_LEN: usize = 3;

/// Fixed length of a `NUMBER` payload: one `scale` byte plus a 16-bit
/// `mantissa` (PROTOCOL.md 6.3).
pub const NUMBER_PAYLOAD_LEN: usize = 3;

/// Bytes per `(delta, mantissa)` entry after a `SERIES` payload's first
/// reading (PROTOCOL.md 6.9).
pub const SERIES_ENTRY_LEN: usize = 4;

/// Lowest valid `scale` (PROTOCOL.md 6.3.1): divisor `10^-1`.
pub const SCALE_MIN: u8 = 0x01;

/// Highest valid `scale` (PROTOCOL.md 6.3.1): divisor `10^-7`.
pub const SCALE_MAX: u8 = 0x07;

/// `schema_version` meaning "no field definition is claimed for this body"
/// (PROTOCOL.md 6.4.2.2).
///
/// Reserved under every `format`. A receiver still has to hold
/// `(format, SCHEMA_UNSTRUCTURED)` to accept such a record -- the value says
/// the body has no layout, not that the layout agreement does not apply.
pub const SCHEMA_UNSTRUCTURED: u8 = 0xFF;

/// Conservative IPv4 `max_datagram_size` (PROTOCOL.md 3.1).
pub const MAX_DATAGRAM_IPV4: usize = 512;

// ---------------------------------------------------------------- identifiers

/// Direction byte mixed into key derivation (PROTOCOL.md 9.2.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Direction {
    NodeToCollector = 0x00,
    CollectorToNode = 0x01,
}

/// Cipher suite registry (PROTOCOL.md 8.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum CipherId {
    HmacSha256T64 = 0x01,
    SipHash24 = 0x02,
    ChaCha20Poly1305 = 0x03,
    HmacSha256T32 = 0x04,
}

impl CipherId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::HmacSha256T64),
            0x02 => Some(Self::SipHash24),
            0x03 => Some(Self::ChaCha20Poly1305),
            0x04 => Some(Self::HmacSha256T32),
            _ => None,
        }
    }
    pub fn tag_len(self) -> usize {
        match self {
            Self::HmacSha256T64 | Self::SipHash24 => 8,
            Self::ChaCha20Poly1305 => 16,
            Self::HmacSha256T32 => 4,
        }
    }
    /// True for suites this reference implementation can actually compute.
    pub fn implemented(self) -> bool {
        matches!(self, Self::HmacSha256T64 | Self::HmacSha256T32)
    }

    /// Whether a receiver accepting this suite MUST enforce a per-`sender_id`
    /// inbound rate limit (PROTOCOL.md 8.1.1).
    ///
    /// True only for `0x04`: at an 8-byte tag, rate limiting is defence in
    /// depth (SHOULD, Section 10.3); at 4 bytes it is what makes the tag
    /// length defensible at all.
    pub fn requires_inbound_rate_limit(self) -> bool {
        matches!(self, Self::HmacSha256T32)
    }
}

/// Message types (PROTOCOL.md 6.1, 6.2). 5 bits: `0x00`-`0x1F`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MsgType {
    Message = 0x01,
    Event = 0x02,
    Alarm = 0x03,
    Number = 0x04,
    Series = 0x05,
    EpochAnnounce = 0x10,
    TimeAnnounce = 0x11,
    TimeRequest = 0x12,
    Heartbeat = 0x13,
    CapabilityAdvertise = 0x14,
}

impl MsgType {
    /// Framing is a property of the type, not the range (PROTOCOL.md 6).
    pub fn is_record_framed(self) -> bool {
        matches!(self, Self::Message | Self::Event | Self::Alarm)
    }
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Message),
            0x02 => Some(Self::Event),
            0x03 => Some(Self::Alarm),
            0x04 => Some(Self::Number),
            0x05 => Some(Self::Series),
            0x10 => Some(Self::EpochAnnounce),
            0x11 => Some(Self::TimeAnnounce),
            0x12 => Some(Self::TimeRequest),
            0x13 => Some(Self::Heartbeat),
            0x14 => Some(Self::CapabilityAdvertise),
            _ => None,
        }
    }
}

/// `msg_type & 0x10` selects control vs record-framed (PROTOCOL.md 6).
pub fn is_control(msg_type: u8) -> bool {
    msg_type & 0x10 != 0
}

/// `msg_type & 0x08` selects vendor vs standard (PROTOCOL.md 6).
pub fn is_vendor(msg_type: u8) -> bool {
    msg_type & 0x08 != 0
}

/// Record body encodings (PROTOCOL.md 6.4.1). 4 bits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Format {
    None = 0x01,
    Cbor = 0x02,
    MsgPack = 0x03,
    Protobuf = 0x04,
    FlatBuffers = 0x05,
    CapnProto = 0x06,
}

impl Format {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::None),
            0x02 => Some(Self::Cbor),
            0x03 => Some(Self::MsgPack),
            0x04 => Some(Self::Protobuf),
            0x05 => Some(Self::FlatBuffers),
            0x06 => Some(Self::CapnProto),
            _ => None,
        }
    }
}

// --------------------------------------------------------------------- errors

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Error {
    /// Datagram shorter than header + tag.
    TooShort,
    UnsupportedVersion(u8),
    /// `msg_type` is `0x00` or not implemented.
    BadMsgType(u8),
    UnknownSender(u32),
    /// `cipher_id` differs from the suite configured for this peer.
    CipherMismatch { got: u8, want: u8 },
    CipherUnimplemented(u8),
    /// `epoch_low` did not reconstruct within the acceptance window.
    EpochOutOfWindow,
    AuthFailed,
    Replay,
    /// Payload does not frame cleanly into records, or control layout is wrong.
    Framing(&'static str),
    /// Body exceeds what `size` can express.
    BodyTooLarge(usize),
    /// Datagram would exceed `max_datagram_size`.
    Oversize(usize),
    /// Sender may not reuse a `datagram_offset` within an epoch.
    OffsetReuse(u32),
    /// `NUMBER` payload violates the fixed layout of PROTOCOL.md 6.3.
    BadNumber(&'static str),
    /// `SERIES` payload violates the fixed layout of PROTOCOL.md 6.9.
    BadSeries(&'static str),
    /// `EPOCH_ANNOUNCE` at or below the highest accepted (PROTOCOL.md 9.4).
    EpochRollback { got: u32, hi: u32 },
    /// `TIME_ANNOUNCE` at or below the persisted floor (PROTOCOL.md 11.4).
    TimeRollback { asserted: i64, floor: i64 },
    /// `TIME_ANNOUNCE` arrived at a node whose clock is already set.
    ClockAlreadyValid,
    NoClock,
    /// This `sender_id`'s inbound rate limit (PROTOCOL.md 10.3, 8.1.1) has no
    /// tokens left. The datagram already authenticated and replay-checked
    /// successfully; it is discarded for budget, not for forgery.
    RateLimited,
    /// `cipher_id` `0x04` was configured for a peer with no
    /// `inbound_rate_limit` (PROTOCOL.md 8.1.1: the limit is a MUST, not a
    /// SHOULD, for the 4-byte tag). Refused at provisioning time rather than
    /// left to be discovered under attack.
    CipherRequiresRateLimit(u8),
}

/// Is `scale` one of the seven divisors PROTOCOL.md 6.3.1 defines?
pub fn scale_is_valid(scale: u8) -> bool {
    (SCALE_MIN..=SCALE_MAX).contains(&scale)
}

/// Render `mantissa * 10^-scale` in decimal, e.g. `(2, 2350) -> "23.50"`
/// (PROTOCOL.md 6.3.1). For display only; the wire value is the
/// `(scale, mantissa)` pair, not this string.
pub fn format_scaled(scale: u8, mantissa: i16) -> String {
    format!("{:.*}", scale as usize, mantissa as f64 / 10f64.powi(scale as i32))
}

/// Validate and decode a `NUMBER` payload (PROTOCOL.md 6.3): exactly
/// [`NUMBER_PAYLOAD_LEN`] bytes, a valid `scale`, and a big-endian `mantissa`.
/// Every bit pattern of `mantissa` is legal, so once `scale` and the length
/// check pass, decoding cannot fail.
pub fn validate_number(p: &[u8]) -> Result<(u8, i16), Error> {
    if p.len() != NUMBER_PAYLOAD_LEN {
        return Err(Error::BadNumber("payload must be exactly 3 bytes"));
    }
    let scale = p[0];
    if !scale_is_valid(scale) {
        return Err(Error::BadNumber("scale must be 0x01..=0x07"));
    }
    Ok((scale, i16::from_be_bytes([p[1], p[2]])))
}

/// Validate and decode a `SERIES` payload (PROTOCOL.md 6.9).
///
/// `anchor_offset` is the datagram's own `datagram_offset`, which is the
/// first reading's instant; each later reading's instant is the previous
/// one plus that entry's `delta`. Returns the shared `scale` and every
/// reading as `(instant, mantissa)`, instants in strictly increasing order.
///
/// Rejects a payload that isn't `3 + 4n` bytes for `n >= 1`, a `scale`
/// outside `0x01..=0x07`, any `delta` of `0`, and cumulative offsets that
/// would reach or exceed `TICKS_PER_EPOCH` -- a `SERIES` batch MUST NOT span
/// an epoch boundary, exactly as a `MESSAGE` batch MUST NOT (PROTOCOL.md
/// 10.3).
pub fn validate_series(p: &[u8], anchor_offset: u32) -> Result<(u8, Vec<(u32, i16)>), Error> {
    if p.len() < NUMBER_PAYLOAD_LEN {
        return Err(Error::BadSeries("shorter than scale + first reading"));
    }
    let scale = p[0];
    if !scale_is_valid(scale) {
        return Err(Error::BadSeries("scale must be 0x01..=0x07"));
    }
    let rest = &p[NUMBER_PAYLOAD_LEN..];
    if rest.is_empty() {
        return Err(Error::BadSeries("SERIES must carry at least two readings"));
    }
    let (entries, remainder) = rest.as_chunks::<SERIES_ENTRY_LEN>();
    if !remainder.is_empty() {
        return Err(Error::BadSeries("trailing entries must be 4 bytes each"));
    }
    if anchor_offset >= TICKS_PER_EPOCH {
        return Err(Error::BadSeries("datagram_offset exceeds 19 bits"));
    }
    let first = i16::from_be_bytes([p[1], p[2]]);
    let mut readings = Vec::with_capacity(1 + entries.len());
    readings.push((anchor_offset, first));
    let mut cum = anchor_offset;
    for entry in entries {
        let delta = u16::from_be_bytes([entry[0], entry[1]]);
        if delta == 0 {
            return Err(Error::BadSeries("delta must be at least 1 tick"));
        }
        cum = cum.checked_add(delta as u32).filter(|&c| c < TICKS_PER_EPOCH).ok_or(
            Error::BadSeries("reading's instant crosses the epoch boundary"),
        )?;
        let value = i16::from_be_bytes([entry[2], entry[3]]);
        readings.push((cum, value));
    }
    Ok((scale, readings))
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

// ------------------------------------------------------------------ key sched

/// Per-node 32-byte secret, provisioned out of band (PROTOCOL.md 9.2).
///
/// The field is private, and this type deliberately implements neither
/// `Debug` nor `Display`, so an accidental `{:?}` or log line cannot print
/// it -- a struct that embeds one gets the same protection for free, since
/// deriving `Debug` on it would fail to compile. Contents are zeroized on
/// drop.
///
/// Zeroization in safe Rust is best-effort: an optimizer is free to leave
/// copies elsewhere on the stack or in registers, and nothing here can see
/// or prevent that. It is a large improvement over none, not a guarantee.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DeviceSecret([u8; 32]);

impl DeviceSecret {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exposes the raw secret bytes.
    ///
    /// For provisioning and conformance-vector tooling only -- `catp-vectors`
    /// deliberately publishes plaintext secrets into `docs/test-vectors.txt`,
    /// which is what this exists for. Ordinary code has no reason to call
    /// it: derive a key with [`Self::epoch_key`] / [`Self::time_key`] instead
    /// of handling the secret itself.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    /// `epoch_key = HKDF-Expand(PRK, "CATP1" || sender_id || epoch_id || direction, 32)`
    ///
    /// Returned wrapped in [`Zeroizing`] so the derived key -- as sensitive as
    /// the secret it came from for the epoch it names -- doesn't outlive its
    /// last use unzeroized either.
    pub fn epoch_key(&self, sender_id: u32, epoch_id: u32, dir: Direction) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut info = Vec::with_capacity(5 + 4 + 4 + 1);
        info.extend_from_slice(b"CATP1");
        info.extend_from_slice(&sender_id.to_be_bytes());
        info.extend_from_slice(&epoch_id.to_be_bytes());
        info.push(dir as u8);
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).expect("32 is a valid HKDF length");
        Zeroizing::new(okm)
    }

    /// Epoch-independent bootstrap key (PROTOCOL.md 11.2).
    ///
    /// `direction` is a key-derivation input, so `TIME_REQUEST` (`0x00`) and
    /// `TIME_ANNOUNCE` (`0x01`) are authenticated under distinct keys. A
    /// receiver MUST NOT accept a tag generated with the opposite direction.
    pub fn time_key(&self, sender_id: u32, direction: Direction) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut info = Vec::with_capacity(10 + 4 + 1);
        info.extend_from_slice(b"CATP1-time");
        info.extend_from_slice(&sender_id.to_be_bytes());
        info.push(direction as u8);
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).expect("32 is a valid HKDF length");
        Zeroizing::new(okm)
    }
}

/// Compute a tag of `tag_len` bytes over `msg` under `key`.
pub fn mac(cipher: CipherId, key: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>, Error> {
    if !cipher.implemented() {
        return Err(Error::CipherUnimplemented(cipher as u8));
    }
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    m.update(msg);
    let full = m.finalize().into_bytes();
    Ok(full[..cipher.tag_len()].to_vec())
}

/// Constant-time comparison (PROTOCOL.md 7.4: "Tag comparison MUST be
/// constant-time").
///
/// Delegates to `subtle`, a vetted constant-time primitive, rather than a
/// hand-rolled accumulate-then-compare loop. The accumulate-then-compare
/// shape looks constant-time but isn't guaranteed to compile to constant-time
/// code: nothing in the Rust language stops LLVM from noticing that the
/// result is determined once `diff` is non-zero and introducing an early
/// exit, or from vectorizing the loop in a way that makes timing
/// input-dependent. `subtle` exists specifically to close that gap, with
/// optimization barriers a hand-written loop does not get for free.
///
/// The length check is a plain `!=`, not constant-time, and that is correct:
/// tag length is public (`cipher_id` announces it on the wire, unauthenticated
/// -- Section 4.1), so comparing it in variable time leaks nothing a
/// constant-time comparison would have hidden. Only the bytes of a
/// same-length secret-derived tag need the protection `subtle` provides.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// ------------------------------------------------------------------ epoch math

/// `epoch_id = floor(unix_time / 128)` (PROTOCOL.md 9.2.4).
pub fn epoch_id_at(unix_secs: u64) -> u32 {
    (unix_secs / EPOCH_SECS) as u32
}

/// Tick within the epoch for a given instant (PROTOCOL.md 6.4.2).
pub fn epoch_offset_at(unix_secs: u64, nanos: u32) -> u32 {
    let into_epoch = unix_secs % EPOCH_SECS;
    let ticks = into_epoch * TICKS_PER_SEC + (nanos as u64 * TICKS_PER_SEC) / 1_000_000_000;
    (ticks % TICKS_PER_EPOCH as u64) as u32
}

/// Reconstruct the full epoch from 4 transmitted bits (PROTOCOL.md 9.3).
///
/// Candidates are `{local - 1, local}`; the one whose low 2 bits match wins.
/// Returns `None` when neither matches, which is the out-of-window case.
pub fn reconstruct_epoch(local_epoch: u32, epoch_low: u8) -> Option<u32> {
    let low = epoch_low & 0x0F;
    if (local_epoch & 0x0F) as u8 == low {
        return Some(local_epoch);
    }
    if local_epoch > 0 && ((local_epoch - 1) & 0x0F) as u8 == low {
        return Some(local_epoch - 1);
    }
    None
}

// --------------------------------------------------------------- replay window

/// Sliding bitmap over tick space, per sender per epoch (PROTOCOL.md 10.2).
///
/// Because offsets are clock ticks, `entries` is a *duration*: at 4096 ticks per
/// second, 4096 entries is one second of reordering tolerance regardless of how
/// fast the sender transmits.
pub struct ReplayWindow {
    high: Option<u32>,
    bits: Vec<u64>,
    entries: u32,
}

impl ReplayWindow {
    pub fn new(entries: u32) -> Self {
        assert!(entries > 0 && entries.is_multiple_of(64), "entries must be a positive multiple of 64");
        Self { high: None, bits: vec![0; (entries / 64) as usize], entries }
    }

    /// One second of tolerance at the specified tick rate.
    pub fn one_second() -> Self {
        Self::new(TICKS_PER_SEC as u32)
    }

    fn mark(&mut self, off: u32) {
        let idx = (off % self.entries) as usize;
        self.bits[idx / 64] |= 1u64 << (idx % 64);
    }
    fn seen(&self, off: u32) -> bool {
        let idx = (off % self.entries) as usize;
        self.bits[idx / 64] & (1u64 << (idx % 64)) != 0
    }

    /// Accept `off`, or reject it as a replay. Mutates only on acceptance.
    pub fn check_and_set(&mut self, off: u32) -> Result<(), Error> {
        match self.high {
            None => {
                self.high = Some(off);
                self.mark(off);
                Ok(())
            }
            Some(hi) if off > hi => {
                // Clear the span we slid past, so wrapped indices are not stale.
                let advance = (off - hi).min(self.entries);
                for i in 1..=advance {
                    let clear = hi.wrapping_add(i);
                    let idx = (clear % self.entries) as usize;
                    self.bits[idx / 64] &= !(1u64 << (idx % 64));
                }
                self.high = Some(off);
                self.mark(off);
                Ok(())
            }
            Some(hi) => {
                if hi - off >= self.entries {
                    return Err(Error::Replay); // below the window
                }
                if self.seen(off) {
                    return Err(Error::Replay);
                }
                self.mark(off);
                Ok(())
            }
        }
    }
}

/// Sender-side offset allocation (PROTOCOL.md 10.3, 10.4).
///
/// Enforces strictly increasing `datagram_offset` within an epoch, which covers
/// both a repeated tick and a backward clock step without any non-volatile
/// state -- the clock does not rewind across a restart, so a rebooted sender's
/// offsets are naturally beyond any it used before.
#[derive(Debug, Clone, Default)]
pub struct Pacer {
    epoch: Option<u32>,
    last_offset: Option<u32>,
}

impl Pacer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim an offset for a datagram sent at this instant.
    ///
    /// Returns `OffsetReuse` when the clock has not advanced past the previous
    /// datagram; the caller must delay, coalesce into records, or shed.
    pub fn claim(&mut self, unix_secs: u64, nanos: u32) -> Result<(u32, u32), Error> {
        let epoch = epoch_id_at(unix_secs);
        let offset = epoch_offset_at(unix_secs, nanos);
        if self.epoch != Some(epoch) {
            self.epoch = Some(epoch);
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

/// Receiver-side per-`sender_id` inbound rate limit (PROTOCOL.md 10.3
/// "Receiver side", 8.1.1). `per_sec` is the steady-state budget; `burst`
/// caps how many tokens can accumulate, so a quiet peer cannot bank an
/// unbounded allowance and spend it in one instant.
///
/// A budget of 128/sec is RECOMMENDED as a default (Section 10.3), matching
/// the sender-side pacing budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub per_sec: u32,
    pub burst: u32,
}

impl RateLimit {
    pub const RECOMMENDED_DEFAULT: RateLimit = RateLimit { per_sec: 128, burst: 128 };
}

/// Token bucket implementing one [`RateLimit`].
///
/// # Where this sits relative to authentication
///
/// Section 7.4 is explicit that steps 1-6 are filters only and that a
/// receiver "MUST NOT mutate any persistent state ... until step 7 [MAC
/// verification] has succeeded", naming "peer liveness timers" as an example
/// of what that covers. A token bucket is exactly that shape of state, so
/// this type is only ever consulted -- and only ever consumes a token --
/// *after* a datagram has already authenticated and passed its replay check.
/// `PeerState::accept` enforces that ordering; this type has no way to see a
/// datagram earlier than that on its own.
///
/// That placement is consistent with Section 10.3's own words: the limit is
/// "enforced after authentication". It is also the reading under which this
/// limiter protects what Section 10.3 says it protects -- receiver resources
/// against "a compromised or malfunctioning node" -- since only genuinely
/// authenticated traffic from a real peer ever reaches it.
///
/// It is worth being explicit about what this placement does *not* give you.
/// Section 8.1.1 justifies the 4-byte tag of `cipher_id` 0x04 by a forgery-rate
/// argument -- "each attempt is a datagram the receiver counts" -- but a
/// forged datagram fails step 7 and therefore never reaches this limiter, so
/// nothing here bounds an attacker's *attempt* rate against a known
/// `sender_id`. The two requirements (Section 7.4's no-state-before-auth MUST,
/// and Section 8.1.1's forgery-rate MUST) cannot both be literally satisfied
/// by one post-authentication counter, and this implementation follows the
/// explicit MUST over the informal justification. See the tracking issue for
/// the spec question this raises.
#[derive(Debug, Clone)]
pub struct InboundLimiter {
    per_sec: u32,
    capacity_micro: u64,
    tokens_micro: u64,
    last_ms: u64,
}

impl InboundLimiter {
    pub fn new(limit: RateLimit) -> Self {
        let capacity_micro = (limit.burst.max(1) as u64) * 1_000_000;
        Self { per_sec: limit.per_sec, capacity_micro, tokens_micro: capacity_micro, last_ms: 0 }
    }

    /// Attempt to spend one token at `now_ms`, a caller-supplied monotonic
    /// millisecond clock (this type reads no clock of its own, matching
    /// `Pacer`). A backward step in `now_ms` is treated as zero elapsed time
    /// rather than negative refill.
    pub fn try_acquire(&mut self, now_ms: u64) -> bool {
        let elapsed_ms = now_ms.saturating_sub(self.last_ms);
        self.last_ms = now_ms;
        let refill = (self.per_sec as u64).saturating_mul(1000).saturating_mul(elapsed_ms);
        self.tokens_micro = (self.tokens_micro + refill).min(self.capacity_micro);
        if self.tokens_micro >= 1_000_000 {
            self.tokens_micro -= 1_000_000;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_rejects_repeated_tick() {
        let mut p = Pacer::new();
        assert!(p.claim(1000, 0).is_ok());
        // Same tick: 1/4096 s is ~244us, so 100us later is still tick 0.
        assert!(matches!(p.claim(1000, 100_000), Err(Error::OffsetReuse(_))));
        // Next tick is fine.
        assert!(p.claim(1000, 300_000).is_ok());
    }

    #[test]
    fn pacer_rejects_backward_clock_step() {
        let mut p = Pacer::new();
        let (_, a) = p.claim(1000, 500_000_000).unwrap();
        // NTP steps the clock back within the same epoch.
        assert!(matches!(p.claim(1000, 100_000_000), Err(Error::OffsetReuse(_))));
        // And recovers once the clock passes where it was.
        let (_, b) = p.claim(1000, 900_000_000).unwrap();
        assert!(b > a);
    }

    #[test]
    fn pacer_resets_at_epoch_boundary() {
        let mut p = Pacer::new();
        let (e1, o1) = p.claim(1000, 999_000_000).unwrap();
        // Crossing into the next epoch, offsets restart near zero and that is
        // not a reuse, because the epoch is part of the tuple.
        let (e2, o2) = p.claim(1024, 0).unwrap();
        assert_eq!(e2, e1 + 1);
        assert!(o2 < o1);
    }

    #[test]
    fn pacer_survives_simulated_reboot() {
        // PROTOCOL.md 10.4: a fresh Pacer after a restart still cannot reuse an
        // offset, because the clock advanced during the outage.
        let mut p = Pacer::new();
        let (_, before) = p.claim(1000, 0).unwrap();
        let mut rebooted = Pacer::new();
        let (_, after) = rebooted.claim(1002, 0).unwrap();
        assert!(after > before);
    }

    #[test]
    fn epoch_offset_spans_epoch_exactly() {
        assert_eq!(epoch_offset_at(0, 0), 0);
        // The final tick begins at 127 + 4095/4096 s = 127.999755859375 s.
        // 999_755_859 ns is a hair below that boundary and is still tick 4094.
        assert_eq!(epoch_offset_at(127, 999_755_859), TICKS_PER_EPOCH - 2);
        assert_eq!(epoch_offset_at(127, 999_755_860), TICKS_PER_EPOCH - 1);
        assert_eq!(epoch_offset_at(127, 999_999_999), TICKS_PER_EPOCH - 1);
        assert_eq!(epoch_offset_at(128, 0), 0);
    }

    #[test]
    fn epoch_reconstruction_picks_current_or_previous() {
        assert_eq!(reconstruct_epoch(100, (100 & 0xF) as u8), Some(100));
        assert_eq!(reconstruct_epoch(100, (99 & 0xF) as u8), Some(99));
        // 4 bits reject drift out to 15 epochs before aliasing (PROTOCOL.md 9.3).
        for back in 2..=15u32 {
            assert_eq!(reconstruct_epoch(100, ((100 - back) & 0xF) as u8), None, "back={back}");
        }
        // At 16 it aliases onto `local`; the MAC over the full epoch_id rejects it.
        assert_eq!(reconstruct_epoch(100, ((100 - 16) & 0xF) as u8), Some(100));
    }

    #[test]
    fn replay_window_rejects_repeats_and_stale() {
        let mut w = ReplayWindow::new(64);
        assert!(w.check_and_set(10).is_ok());
        assert_eq!(w.check_and_set(10), Err(Error::Replay));
        assert!(w.check_and_set(11).is_ok());
        assert!(w.check_and_set(9).is_ok()); // in-window, unseen
        assert_eq!(w.check_and_set(9), Err(Error::Replay));
        assert!(w.check_and_set(500).is_ok());
        assert_eq!(w.check_and_set(11), Err(Error::Replay)); // now below window
    }

    #[test]
    fn replay_window_clears_on_slide() {
        let mut w = ReplayWindow::new(64);
        assert!(w.check_and_set(5).is_ok());
        // Slide far enough that index 5 wraps to a fresh position.
        assert!(w.check_and_set(200).is_ok());
        assert!(w.check_and_set(197).is_ok());
    }

    #[test]
    fn unimplemented_ciphers_error_rather_than_lie() {
        let k = [0u8; 32];
        assert!(mac(CipherId::HmacSha256T64, &k, b"x").is_ok());
        assert!(mac(CipherId::HmacSha256T32, &k, b"x").is_ok());
        assert_eq!(mac(CipherId::SipHash24, &k, b"x"), Err(Error::CipherUnimplemented(0x02)));
        assert_eq!(
            mac(CipherId::ChaCha20Poly1305, &k, b"x"),
            Err(Error::CipherUnimplemented(0x03))
        );
    }

    #[test]
    fn tag_lengths_match_the_registry() {
        assert_eq!(CipherId::HmacSha256T64.tag_len(), 8);
        assert_eq!(CipherId::SipHash24.tag_len(), 8);
        assert_eq!(CipherId::ChaCha20Poly1305.tag_len(), 16);
        assert_eq!(CipherId::HmacSha256T32.tag_len(), 4);
        // t32 is a prefix of t64: same construction, different truncation.
        let k = [9u8; 32];
        let a = mac(CipherId::HmacSha256T64, &k, b"abc").unwrap();
        let b = mac(CipherId::HmacSha256T32, &k, b"abc").unwrap();
        assert_eq!(&a[..4], &b[..]);
    }

    #[test]
    fn ct_eq_is_length_and_content_sensitive() {
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abce"));
        assert!(!ct_eq(b"abcd", b"abc"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn ct_eq_catches_every_single_bit_flip() {
        // Same shape as tampering_any_bit_fails_auth: every bit of an
        // 8-byte tag-sized buffer, flipped one at a time, must compare
        // unequal to the original.
        let a = [0x5Au8; 8];
        for byte in 0..a.len() {
            for bit in 0..8u8 {
                let mut b = a;
                b[byte] ^= 1 << bit;
                assert!(!ct_eq(&a, &b), "flip at byte {byte} bit {bit} compared equal");
            }
        }
    }

    #[test]
    fn epoch_key_separates_direction_and_sender() {
        let s = DeviceSecret::new([7u8; 32]);
        let a = s.epoch_key(1, 5, Direction::NodeToCollector);
        let b = s.epoch_key(1, 5, Direction::CollectorToNode);
        let c = s.epoch_key(2, 5, Direction::NodeToCollector);
        let d = s.epoch_key(1, 6, Direction::NodeToCollector);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        // Time keys are distinct from every epoch key and from each other.
        let tq = s.time_key(1, Direction::NodeToCollector);
        let ta = s.time_key(1, Direction::CollectorToNode);
        assert_ne!(a, tq);
        assert_ne!(a, ta);
        assert_ne!(tq, ta, "TIME_REQUEST and TIME_ANNOUNCE must not share a key");
    }

    #[test]
    fn expose_secret_returns_exactly_what_was_provisioned() {
        let bytes = [9u8; 32];
        let s = DeviceSecret::new(bytes);
        assert_eq!(*s.expose_secret(), bytes);
    }

    #[test]
    fn derived_keys_are_zeroizing() {
        // Type-level: epoch_key/time_key return Zeroizing<[u8; 32]>, not a bare
        // array, so a copy that outlives its last use still gets wiped on drop.
        // This assigns to a binding annotated with the concrete type, which
        // would fail to compile if the return type ever regressed to a plain
        // array.
        let s = DeviceSecret::new([1u8; 32]);
        let _k: zeroize::Zeroizing<[u8; 32]> = s.epoch_key(1, 1, Direction::NodeToCollector);
        let _t: zeroize::Zeroizing<[u8; 32]> = s.time_key(1, Direction::NodeToCollector);
    }

    #[test]
    fn number_grammar() {
        // scale at both ends of the defined range, mantissa at both ends of
        // i16 and at zero (PROTOCOL.md 6.3, 6.3.1).
        for scale in [SCALE_MIN, SCALE_MAX] {
            for mantissa in [0i16, i16::MIN, i16::MAX] {
                let mut p = vec![scale];
                p.extend_from_slice(&mantissa.to_be_bytes());
                assert_eq!(validate_number(&p), Ok((scale, mantissa)), "{p:?}");
            }
        }
        // scale 0x00 and 0x08 are both invalid, one below and one above the
        // defined range.
        for bad_scale in [0x00u8, 0x08] {
            let p = [bad_scale, 0x00, 0x01];
            assert!(validate_number(&p).is_err(), "scale {bad_scale:#04x} should be invalid");
        }
        // Only exactly 3 bytes is legal.
        assert!(validate_number(&[0x02, 0x00]).is_err(), "2 bytes should be invalid");
        assert!(validate_number(&[0x02, 0x00, 0x01, 0x00]).is_err(), "4 bytes should be invalid");
    }

    #[test]
    fn series_grammar() {
        let anchor = 1000u32;

        // Two readings is the minimum, and the second's instant is anchor+delta.
        let p = [0x02, 0x00, 0x0A, 0x00, 0x05, 0x00, 0x14];
        assert_eq!(
            validate_series(&p, anchor),
            Ok((0x02, vec![(anchor, 10), (anchor + 5, 20)]))
        );

        // A single reading (no trailing entries) is invalid: use NUMBER instead.
        assert!(validate_series(&[0x02, 0x00, 0x0A], anchor).is_err());
        // Misaligned trailer.
        assert!(validate_series(&[0x02, 0x00, 0x0A, 0x00, 0x01, 0x00], anchor).is_err());
        // delta = 0 is invalid: readings must strictly increase.
        assert!(validate_series(&[0x02, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x05], anchor).is_err());
        // A cumulative offset reaching TICKS_PER_EPOCH must be rejected.
        let near_end = TICKS_PER_EPOCH - 3;
        let delta = 5u16.to_be_bytes();
        let p = [0x02, 0x00, 0x0A, delta[0], delta[1], 0x00, 0x05];
        assert!(validate_series(&p, near_end).is_err());
        // scale 0x00 is invalid here too.
        assert!(validate_series(&[0x00, 0x00, 0x0A, 0x00, 0x05, 0x00, 0x14], anchor).is_err());
    }

    #[test]
    fn namespace_bits() {
        assert!(!is_control(MsgType::Message as u8));
        assert!(!is_control(MsgType::Number as u8));
        assert!(is_control(MsgType::Heartbeat as u8));
        assert!(is_control(MsgType::TimeRequest as u8));
        assert_eq!(MsgType::from_u8(0x12), Some(MsgType::TimeRequest));
        assert_eq!(MsgType::from_u8(0x13), Some(MsgType::Heartbeat));
        assert_eq!(MsgType::from_u8(0x14), Some(MsgType::CapabilityAdvertise));
        assert!(MsgType::Message.is_record_framed());
        assert!(!MsgType::Number.is_record_framed());
        assert!(!MsgType::Series.is_record_framed());
        assert_eq!(MsgType::from_u8(0x05), Some(MsgType::Series));
        assert!(!is_vendor(MsgType::Message as u8));
        assert!(is_vendor(0x09));
        assert!(is_control(0x18) && is_vendor(0x18));
    }
}
