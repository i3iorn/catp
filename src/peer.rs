//! Receiver-side and node-side state machines.
//!
//! - [`PeerState`] holds the two-epoch replay windows one sender needs
//!   (PROTOCOL.md 9.3, 10.2) and the `EPOCH_ANNOUNCE` high-water mark (9.4).
//! - [`Collector`] is a multi-peer registry: one MAC computation per datagram
//!   regardless of fleet size (PROTOCOL.md 12.5).
//! - [`NodeClock`] is the cold-start state machine of PROTOCOL.md 11.4.

use crate::wire::{decode, Accepted, PeerConfig};
use crate::*;
use std::collections::HashMap;

/// Per-sender receiver state.
pub struct PeerState {
    pub config: PeerConfig,
    /// One window per accepted epoch. At most two are ever live, because
    /// Section 9.3 accepts only `{local-1, local}`.
    windows: HashMap<u32, ReplayWindow>,
    window_entries: u32,
    highest_epoch_announced: Option<u32>,
}

impl PeerState {
    pub fn new(config: PeerConfig) -> Self {
        Self::with_window(config, TICKS_PER_SEC as u32)
    }

    /// `entries` is a duration: offsets are clock ticks, so N entries is
    /// `N / 4096` seconds of reordering tolerance (PROTOCOL.md 10.2).
    pub fn with_window(config: PeerConfig, entries: u32) -> Self {
        Self {
            config,
            windows: HashMap::new(),
            window_entries: entries,
            highest_epoch_announced: None,
        }
    }

    /// Windows for epochs outside the acceptance window are discarded
    /// (PROTOCOL.md 10.2).
    fn prune(&mut self, local_epoch: u32) {
        self.windows.retain(|&e, _| e + 1 >= local_epoch && e <= local_epoch);
    }

    /// Verify one datagram from this peer.
    pub fn accept(
        &mut self,
        buf: &[u8],
        local_epoch: u32,
        dir: Direction,
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
        decode(buf, &self.config, local_epoch, dir, window)
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
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector {
    pub fn new() -> Self {
        Self { peers: HashMap::new() }
    }

    /// Provision a peer. PROTOCOL.md 12.5 requires state to be allocated here,
    /// not on first contact, so an attacker cannot exhaust memory by varying
    /// `sender_id`.
    pub fn provision(&mut self, config: PeerConfig) {
        self.peers.insert(config.sender_id, PeerState::new(config));
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
    ) -> Result<Accepted, Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::TooShort);
        }
        let sender_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        let peer = self.peers.get_mut(&sender_id).ok_or(Error::UnknownSender(sender_id))?;
        peer.accept(buf, local_epoch, dir)
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
        }
    }

    #[test]
    fn epoch_announce_is_monotonic() {
        let mut p = PeerState::new(cfg(1));
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
        });
        let e = 1000u32;
        // Same offset in two adjacent epochs: both accepted, because offsets
        // reset each epoch and each epoch has its own window.
        for epoch in [e - 1, e] {
            let dg = Datagram::number(CipherId::HmacSha256T32, 1, epoch, 4242, "1.5").unwrap();
            let w = dg.encode(&secret, epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
            assert!(st.accept(&w, e, Direction::NodeToCollector).is_ok(), "epoch {epoch}");
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
        });
        for epoch in 1000..1010u32 {
            let dg = Datagram::number(CipherId::HmacSha256T32, 1, epoch, 7, "1").unwrap();
            let w = dg.encode(&secret, epoch, Direction::NodeToCollector, MAX_DATAGRAM_IPV4).unwrap();
            st.accept(&w, epoch, Direction::NodeToCollector).unwrap();
            assert!(st.live_windows() <= 2, "epoch {epoch}: {} windows", st.live_windows());
        }
    }

    #[test]
    fn collector_routes_by_sender_and_rejects_unknown() {
        let mut c = Collector::new();
        c.provision(cfg(0xAAAA));
        c.provision(cfg(0xBBBB));
        let e = 500u32;

        for id in [0xAAAAu32, 0xBBBB] {
            let dg = Datagram::number(CipherId::HmacSha256T32, id, e, 99, "7").unwrap();
            let w = dg
                .encode(&cfg(id).secret, e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
                .unwrap();
            let acc = c.accept(&w, e, Direction::NodeToCollector).unwrap();
            assert_eq!(acc.datagram.sender_id, id);
        }

        // An unprovisioned sender is rejected with no state allocated.
        let dg = Datagram::number(CipherId::HmacSha256T32, 0xCCCC, e, 99, "7").unwrap();
        let w = dg
            .encode(&cfg(0xCCCC).secret, e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        assert_eq!(
            c.accept(&w, e, Direction::NodeToCollector).unwrap_err(),
            Error::UnknownSender(0xCCCC)
        );
    }

    #[test]
    fn one_senders_key_cannot_sign_for_another() {
        let mut c = Collector::new();
        c.provision(cfg(0xAAAA));
        let e = 500u32;
        // Claim to be AAAA but sign with BBBB's secret (PROTOCOL.md 9.2.1).
        let dg = Datagram::number(CipherId::HmacSha256T32, 0xAAAA, e, 5, "1").unwrap();
        let w = dg
            .encode(&cfg(0xBBBB).secret, e, Direction::NodeToCollector, MAX_DATAGRAM_IPV4)
            .unwrap();
        assert_eq!(c.accept(&w, e, Direction::NodeToCollector).unwrap_err(), Error::AuthFailed);
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
}
