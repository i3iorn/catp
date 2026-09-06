//! Round-trip property (issue #30): whenever `decode` accepts an input,
//! re-encoding the result MUST reproduce those exact bytes. This is the same
//! property `every_accept_vector_verifies_and_reencodes` checks for the
//! frozen vectors; this target checks it for every input libFuzzer finds
//! that happens to decode successfully; the ratio will be small, but a valid
//! seed corpus derived from `docs/test-vectors.txt` gives it a fighting
//! chance of mutating past step 7's MAC check.
#![no_main]

use catp::wire::{decode, PeerConfig};
use catp::*;
use libfuzzer_sys::fuzz_target;

const SENDER_ID: u32 = 0x1234_5678;
const EPOCH: u32 = 13_281_250;
const DIR: Direction = Direction::NodeToCollector;

// Matches the vector generator (src/bin/vectors.rs) exactly, so the corpus
// seeded from docs/test-vectors.txt (fuzz/corpus/decode-roundtrip/) starts
// libFuzzer from inputs that already pass authentication.
fn seed_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }
    s
}

fuzz_target!(|data: &[u8]| {
    let secret = DeviceSecret::new(seed_secret());
    let peer = PeerConfig {
        sender_id: SENDER_ID,
        secret: secret.clone(),
        cipher: CipherId::HmacSha256T64,
        layouts: (1u8..=6).flat_map(|f| (0u8..=255).map(move |s| (f, s))).collect(),
        inbound_rate_limit: None,
    };
    let mut window = ReplayWindow::one_second();
    if let Ok(acc) = decode(data, &peer, EPOCH, DIR, &mut window) {
        let again = acc
            .datagram
            .encode(&secret, acc.epoch_id, DIR, usize::MAX)
            .expect("an accepted datagram must always re-encode");
        assert_eq!(again, data, "re-encoding an accepted datagram did not reproduce its bytes");
    }
});
