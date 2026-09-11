//! Measures `Collector`'s actual per-peer memory footprint at steady state
//! (issue #40): `docs/DEPLOYMENT.md` D2 states the replay window's bitmap
//! size analytically, but nothing measured what a `Collector` actually
//! allocates once fixed overhead (the `HashMap` entry, `PeerConfig`,
//! `Stats`, ...) is included.
//!
//! Reads `/proc/self/status`, so Linux-only; that's adequate for a
//! development-time measurement tool, not something shipped to users.
//!
//! Run with: `cargo run --release --example mem_probe`
//!
//! Provisions each peer with the crate's *default* replay window (1 second,
//! 4096 entries -- see `PeerState::new`), not PROTOCOL.md 10.2's RECOMMENDED
//! 4-second/16384-entry window, then forces two live epoch windows per peer
//! (9.3's steady state). `docs/DEPLOYMENT.md` D2 extrapolates from this
//! measurement to the RECOMMENDED window size, since `Collector` does not
//! currently expose a way to configure it per peer.

use catp::wire::PeerConfig;
use catp::*;
use std::fs;

fn rss_kb() -> u64 {
    let status = fs::read_to_string("/proc/self/status").expect("Linux-only: reads /proc/self/status");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.trim().trim_end_matches(" kB").trim().parse().unwrap();
        }
    }
    0
}

fn main() {
    for &n in &[100u32, 1000, 10000] {
        let mut c = Collector::new();
        let before = rss_kb();
        for i in 0..n {
            c.provision(PeerConfig {
                sender_id: i,
                secret: DeviceSecret::new([(i & 0xFF) as u8; 32]),
                cipher: CipherId::HmacSha256T64,
                layouts: vec![(Format::None as u8, 1)],
                inbound_rate_limit: None,
            })
            .unwrap();
        }
        // Force two live replay windows per peer (9.3's steady state: the
        // current epoch and the previous one both accepted).
        for epoch in [1000u32, 1001] {
            for i in 0..n {
                let dg = Datagram::number(CipherId::HmacSha256T64, i, epoch, 4096, 1, 5).unwrap();
                let w = dg
                    .encode(
                        &DeviceSecret::new([(i & 0xFF) as u8; 32]),
                        epoch,
                        Direction::NodeToCollector,
                        MAX_DATAGRAM_IPV4,
                    )
                    .unwrap();
                c.accept(&w, epoch, Direction::NodeToCollector, 0).unwrap();
            }
        }
        let after = rss_kb();
        println!(
            "n={n}: RSS delta = {} KiB ({:.1} bytes/peer)",
            after - before,
            (after - before) as f64 * 1024.0 / n as f64
        );
        std::mem::forget(c); // keep it alive so the next iteration's "before" is clean
    }
}
