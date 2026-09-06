//! Receiver-side and node-side state machines.
//!
//! - [`PeerState`] holds the two-epoch replay windows one sender needs
//!   (PROTOCOL.md 9.3, 10.2) and the `EPOCH_ANNOUNCE` high-water mark (9.4).
//! - [`Collector`] is a multi-peer registry: one MAC computation per datagram
//!   regardless of fleet size (PROTOCOL.md 12.5).
//! - [`NodeClock`] is the cold-start state machine of PROTOCOL.md 11.4.
//! - [`Stats`] is the discard-counter snapshot both `PeerState` and
//!   `Collector` expose, categorized by the Section 7.4 step that would
//!   have rejected the datagram (Section 6.8).

use crate::wire::{decode, Accepted, PeerConfig};
use crate::*;
use std::collections::HashMap;

/// Discard counters, categorized by the PROTOCOL.md 7.4 step that would have
/// rejected the datagram. Section 6.8's whole design is that a failure is
/// "silent discard on the wire; counted locally" -- this is that count,
/// defined once by the library instead of rebuilt differently by every
/// caller.
///
/// A count here is not itself authenticated: everything through `auth_failed`
/// happens before or at step 7, so an attacker who cannot forge a MAC can
/// still inflate these counters by sending junk. That is expected -- it is
/// exactly the traffic Section 12.5 bounds the *cost* of, not traffic these
/// counters claim is genuine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Datagrams that passed every check and were handed back as [`Accepted`].
    pub accepted: u64,
    /// Step 1: shorter than `header_len + tag_len`.
    pub too_short: u64,
    /// Step 2: unsupported `version`.
    pub unsupported_version: u64,
    /// Step 3: `msg_type` is `0x00` or not implemented.
    pub bad_msg_type: u64,
    /// Step 4: `sender_id` is not provisioned. Only ever recorded by
    /// [`Collector`] -- a [`PeerState`] is already resolved to one sender and
    /// is never reached for an unknown one.
    pub unknown_sender: u64,
    /// Step 5: `cipher_id` does not match the suite configured for this
    /// sender.
    pub cipher_mismatch: u64,
    /// Step 6: `epoch_low` did not reconstruct to an `epoch_id` within the
    /// acceptance window.
    pub epoch_out_of_window: u64,
    /// Step 7: the MAC did not verify.
    pub auth_failed: u64,
    /// Step 8: `datagram_offset` failed the replay check.
    pub replay: u64,
    /// Step 9: the payload did not frame cleanly -- into records, against
    /// `NUMBER`/`SERIES`'s fixed layout, or against a control type's layout.
    pub framing: u64,
    /// Authenticated and not a replay, but discarded for exceeding the
    /// configured inbound rate limit (Section 10.3, 8.1.1) -- counted rather
    /// than silently absorbed, per Section 10.3's own wording.
    pub rate_limited: u64,
    /// Step 10, aggregated across every accepted datagram: records skipped
    /// for a `(format, schema_version)` pair this receiver holds no
    /// definition for. [`Accepted::skipped`] carries this per call; this is
    /// the running total.
    pub skipped_records: u64,
}

impl Stats {
    fn record_result(&mut self, result: &Result<Accepted, Error>) {
        match result {
            Ok(acc) => {
                self.accepted += 1;
                self.skipped_records += acc.skipped.len() as u64;
            }
            Err(e) => self.record_error(e),
        }
    }

    fn record_error(&mut self, e: &Error) {
        match e {
            Error::TooShort => self.too_short += 1,
            Error::UnsupportedVersion(_) => self.unsupported_version += 1,
            Error::BadMsgType(_) => self.bad_msg_type += 1,
            Error::UnknownSender(_) => self.unknown_sender += 1,
            Error::CipherMismatch { .. } => self.cipher_mismatch += 1,
            Error::EpochOutOfWindow => self.epoch_out_of_window += 1,
            Error::AuthFailed => self.auth_failed += 1,
            Error::Replay => self.replay += 1,
            Error::Framing(_) | Error::BadNumber(_) | Error::BadSeries(_) | Error::BodyTooLarge(_) => {
                self.framing += 1
            }
            Error::RateLimited => self.rate_limited += 1,
            // Everything else (CipherUnimplemented, Oversize, OffsetReuse,
            // EpochRollback, TimeRollback, ClockAlreadyValid, NoClock,
            // CipherRequiresRateLimit) is a sender-side or construction-time
            // error that `PeerState::accept`/`Collector::accept` never
            // return, so it never reaches this receive-path counter.
            _ => {}
        }
    }

    /// Fold another snapshot into this one. [`Collector::stats`] uses this to
    /// aggregate across every provisioned peer.
    pub fn merge(&mut self, other: &Stats) {
        self.accepted += other.accepted;
        self.too_short += other.too_short;
        self.unsupported_version += other.unsupported_version;
        self.bad_msg_type += other.bad_msg_type;
        self.unknown_sender += other.unknown_sender;
        self.cipher_mismatch += other.cipher_mismatch;
        self.epoch_out_of_window += other.epoch_out_of_window;
        self.auth_failed += other.auth_failed;
        self.replay += other.replay;
        self.framing += other.framing;
        self.rate_limited += other.rate_limited;
        self.skipped_records += other.skipped_records;
    }
}

/// Per-sender receiver state.
pub struct PeerState {
    pub config: PeerConfig,
    /// One window per accepted epoch. At most two are ever live, because
    /// Section 9.3 accepts only `{local-1, local}`.
    windows: HashMap<u32, ReplayWindow>,
    window_entries: u32,
    highest_epoch_announced: Option<u32>,
    /// `None` unless `config.inbound_rate_limit` was set; see
    /// [`CipherId::requires_inbound_rate_limit`] for when it must be.
    limiter: Option<InboundLimiter>,
    stats: Stats,
}

impl PeerState {
    /// Builds the state for one provisioned peer.
    ///
    /// Fails with [`Error::CipherRequiresRateLimit`] if `config.cipher`
    /// requires an inbound limit (PROTOCOL.md 8.1.1) and
    /// `config.inbound_rate_limit` is `None`. This is the "deployments MUST
    /// NOT select it where that limit cannot be enforced" half of Section
    /// 8.1.1, checked at the one place that can actually enforce it.
    pub fn new(config: PeerConfig) -> Result<Self, Error> {
        Self::with_window(config, TICKS_PER_SEC as u32)
    }

    /// `entries` is a duration: offsets are clock ticks, so N entries is
    /// `N / 4096` seconds of reordering tolerance (PROTOCOL.md 10.2).
    pub fn with_window(config: PeerConfig, entries: u32) -> Result<Self, Error> {
        if config.cipher.requires_inbound_rate_limit() && config.inbound_rate_limit.is_none() {
            return Err(Error::CipherRequiresRateLimit(config.cipher as u8));
        }
        let limiter = config.inbound_rate_limit.map(InboundLimiter::new);
        Ok(Self {
            config,
            windows: HashMap::new(),
            window_entries: entries,
            highest_epoch_announced: None,
            limiter,
            stats: Stats::default(),
        })
    }

    /// Windows for epochs outside the acceptance window are discarded
    /// (PROTOCOL.md 10.2).
    fn prune(&mut self, local_epoch: u32) {
        self.windows.retain(|&e, _| e + 1 >= local_epoch && e <= local_epoch);
    }

    /// Verify one datagram from this peer.
    ///
    /// `now_ms` is a caller-supplied monotonic millisecond clock, read by
    /// nothing in this crate (matching [`Pacer`]), and is spent against the
    /// inbound rate limit only *after* `decode` has already authenticated and
    /// replay-checked the datagram -- see [`InboundLimiter`] for why that
    /// ordering is load-bearing, not incidental.
    pub fn accept(
        &mut self,
        buf: &[u8],
        local_epoch: u32,
        dir: Direction,
        now_ms: u64,
    ) -> Result<Accepted, Error> {
        let result = self.accept_inner(buf, local_epoch, dir, now_ms);
        self.stats.record_result(&result);
        result
    }

    fn accept_inner(
        &mut self,
        buf: &[u8],
        local_epoch: u32,
        dir: Direction,
        now_ms: u64,
    ) -> Result<Accepted, Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::TooShort);
        }
        // Reconstruct the epoch to pick a window. This is a pure function of the
        // receiver's own clock and 4 header bits; it allocates at most two
        // windows per peer, so it is not a state-exhaustion vector even though
        // it runs before the MAC (PROTOCOL.md 12.5).
        let epoch = reconstruct_epoch(local_epoch, buf[1] & 0x0F).ok_or(Error::EpochOutOfWindow)?;
        self.prune(local_epoch);
        let entries = self.window_entries;
        let window = self
            .windows
            .entry(epoch)
            .or_insert_with(|| ReplayWindow::new(entries));
        let accepted = decode(buf, &self.config, local_epoch, dir, window)?;
        if let Some(limiter) = &mut self.limiter
            && !limiter.try_acquire(now_ms)
        {
            return Err(Error::RateLimited);
        }
        Ok(accepted)
    }

    /// Datagrams discarded for exceeding the inbound rate limit, after
    /// authenticating successfully (PROTOCOL.md 10.3).
    pub fn rate_limited_count(&self) -> u64 {
        self.stats.rate_limited
    }

    /// Discard counters for this one sender (PROTOCOL.md 6.8, 7.4). See
    /// [`Stats`].
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Apply an `EPOCH_ANNOUNCE` that has already been authenticated.
    ///
    /// PROTOCOL.md 9.4: reject any target at or below the highest previously
    /// accepted value, so an adversary holding an expired key cannot replay an
    /// old announcement to force a return to compromised material.
    pub fn accept_epoch_announce(&mut self, target_epoch: u32) -> Result<(), Error> {
        match self.highest_epoch_announced {
            Some(hi) if target_epoch <= hi => Err(Error::EpochRollback { got: target_epoch, hi }),
            _ => {
                self.highest_epoch_announced = Some(target_epoch);
                Ok(())
            }
        }
    }

    pub fn highest_epoch_announced(&self) -> Option<u32> {
        self.highest_epoch_announced
    }

    /// Number of live replay windows. At most 2 after any `accept`.
    pub fn live_windows(&self) -> usize {
        self.windows.len()
    }
}

/// A collector serving many senders.
pub struct Collector {
    peers: HashMap<u32, PeerState>,
    /// Only ever holds `too_short` and `unknown_sender`: both are decided
    /// before a peer is even looked up, so they can't live on a `PeerState`.
    own_stats: Stats,
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector {
    pub fn new() -> Self {
        Self { peers: HashMap::new(), own_stats: Stats::default() }
    }

    /// Provision a peer. PROTOCOL.md 12.5 requires state to be allocated here,
    /// not on first contact, so an attacker cannot exhaust memory by varying
    /// `sender_id`.
    ///
    /// Fails with [`Error::CipherRequiresRateLimit`] under the same condition
    /// as [`PeerState::new`]; no peer is inserted in that case.
    pub fn provision(&mut self, config: PeerConfig) -> Result<(), Error> {
        let sender_id = config.sender_id;
        self.peers.insert(sender_id, PeerState::new(config)?);
        Ok(())
    }

    pub fn peer_mut(&mut self, sender_id: u32) -> Option<&mut PeerState> {
        self.peers.get_mut(&sender_id)
    }

    /// Route a datagram to its peer and verify it.
    ///
    /// The `sender_id` lookup is what bounds cost at one MAC computation per
    /// datagram regardless of fleet size; an unknown sender is rejected without
    /// any cryptography at all.
    pub fn accept(
        &mut self,
        buf: &[u8],
        local_epoch: u32,
        dir: Direction,
        now_ms: u64,
    ) -> Result<Accepted, Error> {
        if buf.len() < HEADER_LEN {
            self.own_stats.too_short += 1;
            return Err(Error::TooShort);
        }
        let sender_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        let peer = match self.peers.get_mut(&sender_id) {
            Some(p) => p,
            None => {
                self.own_stats.unknown_sender += 1;
                return Err(Error::UnknownSender(sender_id));
            }
        };
        peer.accept(buf, local_epoch, dir, now_ms)
    }

    /// Discard counters aggregated across every provisioned peer, plus the
    /// `too_short`/`unknown_sender` discards that never reach a peer at all
    /// (PROTOCOL.md 6.8, 7.4). See [`Stats`].
    pub fn stats(&self) -> Stats {
        let mut total = self.own_stats;
        for peer in self.peers.values() {
            total.merge(&peer.stats());
        }
        total
    }
}

/// Node-side clock, including the cold-start path of PROTOCOL.md 11.
///
/// `last_epoch` is the single 32-bit value a node persists (PROTOCOL.md 11.4).
/// A node with an authenticated time source needs none of this.
#[derive(Debug, Clone)]
pub struct NodeClock {
    valid: bool,
    last_epoch: u32,
    /// Seconds to add to the platform clock once time has been recovered.
    correction: i64,
    /// Earliest monotonic instant at which another `TIME_REQUEST` may be sent.
    next_request_at: i64,
    /// Current backoff interval, doubling per attempt up to the ceiling.
    request_backoff: i64,
}

/// First `TIME_REQUEST` retry interval, seconds (PROTOCOL.md 11.3).
pub const TIME_REQUEST_BASE_SECS: i64 = 2;
/// Ceiling for `TIME_REQUEST` backoff, seconds.
pub const TIME_REQUEST_MAX_SECS: i64 = 3600;

impl NodeClock {
    /// A node that booted with no usable clock.
    pub fn clockless(last_epoch: u32) -> Self {
        Self {
            valid: false,
            last_epoch,
            correction: 0,
            next_request_at: i64::MIN,
            request_backoff: TIME_REQUEST_BASE_SECS,
        }
    }

    /// A node with an authenticated time source.
    pub fn synced(last_epoch: u32) -> Self {
        Self {
            valid: true,
            last_epoch,
            correction: 0,
            next_request_at: i64::MIN,
            request_backoff: TIME_REQUEST_BASE_SECS,
        }
    }

    /// May the node emit a `TIME_REQUEST` now (PROTOCOL.md 11.3)?
    ///
    /// False once the clock is valid — a node MUST send requests only while it
    /// has no clock — and false while the backoff interval has not elapsed.
    /// `now_monotonic` must come from a monotonic source, since the whole point
    /// is that the wall clock is not yet trustworthy.
    pub fn may_request_time(&self, now_monotonic: i64) -> bool {
        !self.valid && now_monotonic >= self.next_request_at
    }

    /// Record that a `TIME_REQUEST` was sent, and double the backoff.
    ///
    /// The spec requires only that a node not transmit continuously; doubling
    /// from 2 s to a 1 h ceiling keeps a node that never hears back from
    /// costing its collector anything measurable.
    pub fn record_time_request(&mut self, now_monotonic: i64) {
        self.next_request_at = now_monotonic.saturating_add(self.request_backoff);
        self.request_backoff = (self.request_backoff * 2).min(TIME_REQUEST_MAX_SECS);
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }
    pub fn last_epoch(&self) -> u32 {
        self.last_epoch
    }
    pub fn correction(&self) -> i64 {
        self.correction
    }

    /// Apply an authenticated `TIME_ANNOUNCE` (PROTOCOL.md 11.4).
    ///
    /// All three conditions must hold: the node has no clock, the MAC verified
    /// (the caller's responsibility), and the asserted time is strictly beyond
    /// the persisted floor. `raw_now` is the platform clock at the moment of
    /// acceptance, used only to compute the correction.
    pub fn accept_time_announce(&mut self, asserted: i64, raw_now: i64) -> Result<(), Error> {
        // Rule 1: a node whose clock is already set discards without evaluating.
        // This is what stops TIME_ANNOUNCE being a clock-manipulation channel
        // against a running node.
        if self.valid {
            return Err(Error::ClockAlreadyValid);
        }
        // Rule 3: strictly beyond the floor, so a captured announcement cannot
        // walk the node backwards into an epoch whose keys may be recovered.
        let floor = self.last_epoch as i64 * EPOCH_SECS as i64;
        if asserted <= floor {
            return Err(Error::TimeRollback { asserted, floor });
        }
        self.correction = asserted - raw_now;
        self.last_epoch = (asserted / EPOCH_SECS as i64) as u32;
        self.valid = true;
        self.request_backoff = TIME_REQUEST_BASE_SECS;
        Ok(())
    }

    /// Current time, or `NoClock` if cold start has not completed.
    pub fn now(&self, raw_now: i64) -> Result<i64, Error> {
        if !self.valid {
            return Err(Error::NoClock);
        }
        Ok(raw_now + self.correction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Datagram;

    fn cfg(id: u32) -> PeerConfig {
        PeerConfig {
            sender_id: id,
            secret: DeviceSecret::new([(id & 0xFF) as u8; 32]),
            cipher: CipherId::HmacSha256T32,
            layouts: vec![(Format::None as u8, 1)],
            inbound_rate_limit: Some(RateLimit::RECOMMENDED_DEFAULT),
        }
    }

    #[test]
    fn epoch_announce_is_monotonic() {
        let mut p = PeerState::new(cfg(1)).unwrap();
        assert!(p.accept_epoch_announce(100).is_ok());
        assert!(p.accept_epoch_announce(101).is_ok());
        // Replay of an older announcement must not roll the epoch back.
        assert!(p.accept_epoch_announce(100).is_err());
        assert!(p.accept_epoch_announce(101).is_err());
        assert_eq!(p.highest_epoch_announced(), Some(101));
    }

    #[test]
    fn windows_are_per_epoch_and_bounded() {
        let secret = DeviceSecret::new([1u8; 32]);
        let mut st = PeerState::new(PeerConfig {
            sender_id: 1,
            secret: secret.clone(),
            cipher: CipherId::HmacSha256T32,
            layouts: vec![(Format::None as u8, 1)],
            inbound_rate_limit: Some(RateLimit::RECOMMENDED_DEFAULT),
        })
        .unwrap();
        let e = 1000u32;
        // Same offset in two adjacent epochs: both accepted, because offsets
        // reset each epoch and each epoch has its own window.
        for epoch in [e - 1, e] {
            let dg = Datagram::number(CipherId::HmacSha256T32, 1, epoch, 4242, 1, 15).unwrap();
            let w = dg.encode(&secret, epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
            assert!(st.accept(&w, e, Direction::NodeToCollector, 0).is_ok(), "epoch {epoch}");
        }
        assert_eq!(st.live_windows(), 2, "acceptance window is exactly two epochs wide");
    }

    #[test]
    fn old_windows_are_pruned_as_the_clock_advances() {
        let secret = DeviceSecret::new([1u8; 32]);
        let mut st = PeerState::new(PeerConfig {
            sender_id: 1,
            secret: secret.clone(),
            cipher: CipherId::HmacSha256T32,
            layouts: vec![(Format::None as u8, 1)],
            inbound_rate_limit: Some(RateLimit::RECOMMENDED_DEFAULT),
        })
        .unwrap();
        for epoch in 1000..1010u32 {
            let dg = Datagram::number(CipherId::HmacSha256T32, 1, epoch, 7, 1, 10).unwrap();
            let w = dg.encode(&secret, epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
            st.accept(&w, epoch, Direction::NodeToCollector, 0).unwrap();
            assert!(st.live_windows() <= 2, "epoch {epoch}: {} windows", st.live_windows());
        }
    }

    #[test]
    fn collector_routes_by_sender_and_rejects_unknown() {
        let mut c = Collector::new();
        c.provision(cfg(0xAAAA)).unwrap();
        c.provision(cfg(0xBBBB)).unwrap();
        let e = 500u32;

        for id in [0xAAAAu32, 0xBBBB] {
            let dg = Datagram::number(CipherId::HmacSha256T32, id, e, 99, 1, 70).unwrap();
            let w = dg
                .encode(&cfg(id).secret, e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
                .unwrap();
            let acc = c.accept(&w, e, Direction::NodeToCollector, 0).unwrap();
            assert_eq!(acc.datagram.sender_id, id);
        }

        // An unprovisioned sender is rejected with no state allocated.
        let dg = Datagram::number(CipherId::HmacSha256T32, 0xCCCC, e, 99, 1, 70).unwrap();
        let w = dg
            .encode(&cfg(0xCCCC).secret, e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        assert_eq!(
            c.accept(&w, e, Direction::NodeToCollector, 0).unwrap_err(),
            Error::UnknownSender(0xCCCC)
        );
    }

    #[test]
    fn one_senders_key_cannot_sign_for_another() {
        let mut c = Collector::new();
        c.provision(cfg(0xAAAA)).unwrap();
        let e = 500u32;
        // Claim to be AAAA but sign with BBBB's secret (PROTOCOL.md 9.2.1).
        let dg = Datagram::number(CipherId::HmacSha256T32, 0xAAAA, e, 5, 1, 10).unwrap();
        let w = dg
            .encode(&cfg(0xBBBB).secret, e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        assert_eq!(c.accept(&w, e, Direction::NodeToCollector, 0).unwrap_err(), Error::AuthFailed);
    }

    #[test]
    fn cipher_0x04_without_a_rate_limit_is_refused_at_construction() {
        let mut c = cfg(1);
        c.inbound_rate_limit = None;
        match PeerState::new(c) {
            Err(e) => assert_eq!(e, Error::CipherRequiresRateLimit(CipherId::HmacSha256T32 as u8)),
            Ok(_) => panic!("expected CipherRequiresRateLimit"),
        }
    }

    #[test]
    fn cipher_0x01_needs_no_rate_limit() {
        let mut c = cfg(1);
        c.cipher = CipherId::HmacSha256T64;
        c.inbound_rate_limit = None;
        assert!(PeerState::new(c).is_ok());
    }

    #[test]
    fn exceeding_the_inbound_limit_discards_authenticated_traffic_and_counts_it() {
        let secret = DeviceSecret::new([1u8; 32]);
        let mut st = PeerState::new(PeerConfig {
            sender_id: 1,
            secret: secret.clone(),
            cipher: CipherId::HmacSha256T32,
            layouts: vec![(Format::None as u8, 1)],
            inbound_rate_limit: Some(RateLimit { per_sec: 10, burst: 2 }),
        })
        .unwrap();
        let e = 2000u32;
        let send = |off: u32| {
            Datagram::number(CipherId::HmacSha256T32, 1, e, off, 1, 10)
                .unwrap()
                .encode(&secret, e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
                .unwrap()
        };

        // Burst of 2 spends the full bucket; a third at the same instant is
        // discarded for budget, not for authenticity.
        assert!(st.accept(&send(1), e, Direction::NodeToCollector, 0).is_ok());
        assert!(st.accept(&send(2), e, Direction::NodeToCollector, 0).is_ok());
        assert_eq!(
            st.accept(&send(3), e, Direction::NodeToCollector, 0).unwrap_err(),
            Error::RateLimited
        );
        assert_eq!(st.rate_limited_count(), 1);

        // A discarded datagram still consumed its offset and its replay slot
        // (PROTOCOL.md 7.4: the offset was genuinely used), so replaying it
        // fails as a replay, not as a second rate-limit discard.
        assert_eq!(
            st.accept(&send(3), e, Direction::NodeToCollector, 0).unwrap_err(),
            Error::Replay
        );

        // Waiting for the bucket to refill (10/sec => 100ms per token) admits
        // the next one.
        assert!(st.accept(&send(4), e, Direction::NodeToCollector, 100).is_ok());
        assert_eq!(st.rate_limited_count(), 1);
    }

    #[test]
    fn cold_start_accepts_once_then_refuses() {
        let mut clk = NodeClock::clockless(1000);
        assert!(!clk.is_valid());
        assert_eq!(clk.now(0), Err(Error::NoClock));

        let floor = 1000 * EPOCH_SECS as i64;
        // At or below the floor is a rollback attempt.
        assert!(clk.accept_time_announce(floor, 0).is_err());
        assert!(clk.accept_time_announce(floor - 1, 0).is_err());

        // Beyond the floor is accepted.
        let t = floor + 5000;
        clk.accept_time_announce(t, 0).unwrap();
        assert!(clk.is_valid());
        assert_eq!(clk.now(0).unwrap(), t);
        assert_eq!(clk.last_epoch(), (t / EPOCH_SECS as i64) as u32);

        // Rule 1: once valid, further announcements are refused outright, so a
        // running node cannot have its clock moved.
        assert_eq!(
            clk.accept_time_announce(t + 100_000, 0).unwrap_err(),
            Error::ClockAlreadyValid
        );
        assert_eq!(clk.now(0).unwrap(), t);
    }

    #[test]
    fn time_request_backoff_grows_and_stops_when_clock_is_set() {
        let mut clk = NodeClock::clockless(1000);
        // First request is immediate.
        assert!(clk.may_request_time(0));
        clk.record_time_request(0);
        assert!(!clk.may_request_time(0), "must not transmit continuously");
        assert!(!clk.may_request_time(1));
        assert!(clk.may_request_time(TIME_REQUEST_BASE_SECS));

        // Backoff doubles.
        let mut t = TIME_REQUEST_BASE_SECS;
        clk.record_time_request(t);
        assert!(!clk.may_request_time(t + TIME_REQUEST_BASE_SECS));
        assert!(clk.may_request_time(t + TIME_REQUEST_BASE_SECS * 2));

        // And is capped.
        for _ in 0..40 {
            t += TIME_REQUEST_MAX_SECS;
            clk.record_time_request(t);
        }
        assert!(clk.may_request_time(t + TIME_REQUEST_MAX_SECS));

        // Once time is recovered the node stops asking entirely.
        clk.accept_time_announce(1000 * EPOCH_SECS as i64 + 5000, 0).unwrap();
        assert!(!clk.may_request_time(i64::MAX - 1));
    }

    #[test]
    fn synced_node_never_requests_time() {
        let clk = NodeClock::synced(1000);
        assert!(!clk.may_request_time(0));
        assert!(!clk.may_request_time(i64::MAX - 1));
    }

    #[test]
    fn synced_node_ignores_time_announce_entirely() {
        let mut clk = NodeClock::synced(1000);
        assert!(clk.accept_time_announce(i64::MAX, 0).is_err());
        assert_eq!(clk.last_epoch(), 1000);
    }

    #[test]
    fn replayed_time_announce_pins_but_cannot_rewind() {
        // PROTOCOL.md 11.6: an attacker replaying a captured announcement can
        // pin a booting node to a stale-but-real time, never before its floor.
        let mut clk = NodeClock::clockless(1000);
        let floor = 1000 * EPOCH_SECS as i64;
        let captured = floor + 60; // genuinely asserted once, now stale
        clk.accept_time_announce(captured, 0).unwrap();
        // Damage is bounded: the node is in a stale epoch (a DoS against
        // itself), but no epoch below its persisted floor.
        assert!(clk.now(0).unwrap() > floor);
    }

    // ------------------------------------------------------------- Stats (#36)

    #[test]
    fn accepted_and_skipped_records_are_counted() {
        let secret = DeviceSecret::new([1u8; 32]);
        let mut st = PeerState::new(PeerConfig {
            sender_id: 1,
            secret: secret.clone(),
            cipher: CipherId::HmacSha256T32,
            // Holds only v1; the datagram below carries v1 and v2 records, so
            // the v2 one must be skipped, not rejected (PROTOCOL.md 6.4.4).
            layouts: vec![(Format::None as u8, 1)],
            inbound_rate_limit: Some(RateLimit::RECOMMENDED_DEFAULT),
        })
        .unwrap();
        let e = 3000u32;
        let dg = Datagram::data(
            MsgType::Message,
            CipherId::HmacSha256T32,
            1,
            e,
            10,
            vec![Record::new(Format::None, 1, vec![0x01]), Record::new(Format::None, 2, vec![0x02])],
        )
        .unwrap();
        let w = dg.encode(&secret, e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
        st.accept(&w, e, Direction::NodeToCollector, 0).unwrap();

        let s = st.stats();
        assert_eq!(s.accepted, 1);
        assert_eq!(s.skipped_records, 1);
    }

    #[test]
    fn auth_failed_and_replay_are_counted_by_step() {
        let secret = DeviceSecret::new([1u8; 32]);
        let mut st = PeerState::new(PeerConfig {
            sender_id: 1,
            secret: secret.clone(),
            cipher: CipherId::HmacSha256T32,
            layouts: vec![(Format::None as u8, 1)],
            inbound_rate_limit: Some(RateLimit::RECOMMENDED_DEFAULT),
        })
        .unwrap();
        let e = 4000u32;

        // A bit-flip after encoding fails the MAC: step 7.
        let mut tampered =
            Datagram::number(CipherId::HmacSha256T32, 1, e, 10, 1, 5).unwrap().encode(
                &secret,
                e,
                Direction::NodeToCollector,
                MAX_DATAGRAM_IPV4,
            ).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(st.accept(&tampered, e, Direction::NodeToCollector, 0).unwrap_err(), Error::AuthFailed);

        // The same datagram sent twice is a replay on the second delivery:
        // step 8.
        let w = Datagram::number(CipherId::HmacSha256T32, 1, e, 20, 1, 5)
            .unwrap()
            .encode(&secret, e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        st.accept(&w, e, Direction::NodeToCollector, 0).unwrap();
        assert_eq!(st.accept(&w, e, Direction::NodeToCollector, 0).unwrap_err(), Error::Replay);

        let s = st.stats();
        assert_eq!(s.auth_failed, 1);
        assert_eq!(s.replay, 1);
        assert_eq!(s.accepted, 1);
    }

    #[test]
    fn rate_limited_is_counted_alongside_the_step_categories() {
        let secret = DeviceSecret::new([1u8; 32]);
        let mut st = PeerState::new(PeerConfig {
            sender_id: 1,
            secret: secret.clone(),
            cipher: CipherId::HmacSha256T32,
            layouts: vec![(Format::None as u8, 1)],
            inbound_rate_limit: Some(RateLimit { per_sec: 10, burst: 1 }),
        })
        .unwrap();
        let e = 5000u32;
        let send = |off: u32| {
            Datagram::number(CipherId::HmacSha256T32, 1, e, off, 1, 5)
                .unwrap()
                .encode(&secret, e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
                .unwrap()
        };
        st.accept(&send(1), e, Direction::NodeToCollector, 0).unwrap();
        assert_eq!(st.accept(&send(2), e, Direction::NodeToCollector, 0).unwrap_err(), Error::RateLimited);

        let s = st.stats();
        assert_eq!(s.rate_limited, 1);
        assert_eq!(s.accepted, 1);
        // rate_limited_count() is the same number, kept as a convenience
        // accessor rather than a second source of truth.
        assert_eq!(st.rate_limited_count(), 1);
    }

    #[test]
    fn collector_counts_too_short_and_unknown_sender_before_reaching_a_peer() {
        let mut c = Collector::new();
        c.provision(cfg(1)).unwrap();
        let e = 6000u32;

        // Shorter than the header: never even resolves a sender_id.
        assert_eq!(
            c.accept(&[0u8; 3], e, Direction::NodeToCollector, 0).unwrap_err(),
            Error::TooShort
        );

        // Long enough, but sender_id 2 was never provisioned.
        let dg = Datagram::number(CipherId::HmacSha256T32, 2, e, 5, 1, 5).unwrap();
        let w = dg
            .encode(&DeviceSecret::new([2u8; 32]), e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        assert_eq!(c.accept(&w, e, Direction::NodeToCollector, 0).unwrap_err(), Error::UnknownSender(2));

        let s = c.stats();
        assert_eq!(s.too_short, 1);
        assert_eq!(s.unknown_sender, 1);
        // Neither discard ever reached provisioned peer 1's own counters.
        assert_eq!(c.peer_mut(1).unwrap().stats().too_short, 0);
    }

    #[test]
    fn collector_stats_aggregates_across_every_provisioned_peer() {
        let mut c = Collector::new();
        c.provision(cfg(1)).unwrap();
        c.provision(cfg(2)).unwrap();
        let e = 7000u32;

        for id in [1u32, 2] {
            let dg = Datagram::number(CipherId::HmacSha256T32, id, e, 9, 1, 5).unwrap();
            let w = dg
                .encode(&DeviceSecret::new([(id & 0xFF) as u8; 32]), e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
                .unwrap();
            c.accept(&w, e, Direction::NodeToCollector, 0).unwrap();
        }

        assert_eq!(c.stats().accepted, 2);
    }
}
