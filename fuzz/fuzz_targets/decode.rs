//! Fuzz `decode()` on arbitrary bytes -- the entire remote attack surface of
//! the protocol (issue #30). Steps 1-6 of PROTOCOL.md 7.4 run before the MAC,
//! against attacker-controlled bytes off a UDP socket, and this target is
//! seeded from `docs/test-vectors.txt` so libFuzzer starts from inputs that
//! are already well past step 1.
//!
//! Property: `decode` never panics on any input, and never allocates
//! unboundedly relative to the input length (Section 12.5's cost bound would
//! be worthless if a flood could also exhaust memory).
#![no_main]

use catp::wire::{decode, PeerConfig};
use catp::*;
use libfuzzer_sys::fuzz_target;

// Matches the vector generator (src/bin/vectors.rs) exactly, so the corpus
// seeded from docs/test-vectors.txt (fuzz/corpus/decode/) actually decodes
// successfully instead of dying at step 5 or 7 on every run.
fn seed_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }
    s
}

fuzz_target!(|data: &[u8]| {
    let peer = PeerConfig {
        sender_id: 0x1234_5678,
        secret: DeviceSecret::new(seed_secret()),
        cipher: CipherId::HmacSha256T64,
        layouts: (1u8..=6).flat_map(|f| (0u8..=255).map(move |s| (f, s))).collect(),
        inbound_rate_limit: None,
    };
    let mut window = ReplayWindow::one_second();
    // The only property under test is "does not panic"; the Result itself is
    // uninteresting -- most random inputs are rejected, correctly.
    let _ = decode(data, &peer, 13_281_250, Direction::NodeToCollector, &mut window);
});
