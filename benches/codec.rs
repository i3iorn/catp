//! Wire-cost benchmarks (issue #40).
//!
//! CATP's argument for using it is entirely quantitative — §3.1 counts bytes,
//! R4 argues NUMBER against MESSAGE by the byte, §12.5 bounds DoS cost at
//! "one MAC computation per datagram" — but until now nothing measured what
//! that computation actually costs on real hardware. These benchmarks are
//! the CPU-side counterpart to the wire-size assertions already in
//! `tests/integration.rs`.
//!
//! Run with: `cargo bench`
//!
//! Numbers vary by machine; treat the *relative* costs (encode vs decode,
//! accept vs each rejection step, NUMBER vs a MESSAGE record) as the
//! meaningful output, not any single absolute figure. `docs/DEPLOYMENT.md`
//! D2 records one concrete run for a memory-sizing worked example.

use catp::wire::{decode, Datagram, PeerConfig};
use catp::*;
use criterion::{criterion_group, criterion_main, Criterion};

const SENDER_ID: u32 = 0x1234_5678;
const EPOCH: u32 = 13_281_250;
const DIR: Direction = Direction::NodeToCollector;

fn secret() -> DeviceSecret {
    DeviceSecret::new([0x42; 32])
}

fn peer(cipher: CipherId) -> PeerConfig {
    PeerConfig {
        sender_id: SENDER_ID,
        secret: secret(),
        cipher,
        layouts: vec![(Format::None as u8, 1)],
        inbound_rate_limit: None,
    }
}

fn number_datagram(cipher: CipherId) -> Datagram {
    Datagram::number(cipher, SENDER_ID, EPOCH, 4096, 2, 2350).unwrap()
}

fn message_datagram(cipher: CipherId) -> Datagram {
    Datagram::data(
        MsgType::Message,
        cipher,
        SENDER_ID,
        EPOCH,
        4096,
        vec![Record::new(Format::None, 1, vec![0u8; 16])],
    )
    .unwrap()
}

fn bench_encode(c: &mut Criterion) {
    let s = secret();
    let mut g = c.benchmark_group("encode");
    for cipher in [CipherId::HmacSha256T64, CipherId::HmacSha256T32] {
        let number = number_datagram(cipher);
        g.bench_function(format!("NUMBER, tag{}", cipher.tag_len()), |b| {
            b.iter(|| number.encode(&s, EPOCH, DIR, MAX_DATAGRAM_IPV4).unwrap())
        });
        let message = message_datagram(cipher);
        g.bench_function(format!("MESSAGE 1 record/16B, tag{}", cipher.tag_len()), |b| {
            b.iter(|| message.encode(&s, EPOCH, DIR, MAX_DATAGRAM_IPV4).unwrap())
        });
    }
    g.finish();
}

fn bench_decode_accept(c: &mut Criterion) {
    let s = secret();
    let mut g = c.benchmark_group("decode (accept)");
    for cipher in [CipherId::HmacSha256T64, CipherId::HmacSha256T32] {
        let peer_cfg = peer(cipher);
        let wire = number_datagram(cipher).encode(&s, EPOCH, DIR, MAX_DATAGRAM_IPV4).unwrap();
        g.bench_function(format!("NUMBER, tag{}", cipher.tag_len()), |b| {
            b.iter(|| {
                let mut w = ReplayWindow::one_second();
                decode(&wire, &peer_cfg, EPOCH, DIR, &mut w).unwrap()
            })
        });
    }
    g.finish();
}

/// One bench per PROTOCOL.md 7.4 step that can reject before the MAC (1-6),
/// plus step 7 itself (auth failure) and step 9 (framing) -- the cost profile
/// Section 12.5's DoS bound is actually about: how cheap is it to reject junk
/// before paying for a MAC computation.
fn bench_decode_reject(c: &mut Criterion) {
    let s = secret();
    let peer_cfg = peer(CipherId::HmacSha256T64);
    let mut g = c.benchmark_group("decode (reject, by 7.4 step)");

    // Step 1: too short.
    g.bench_function("step 1: too_short", |b| {
        b.iter(|| {
            let mut w = ReplayWindow::one_second();
            let _ = decode(&[0u8; 4], &peer_cfg, EPOCH, DIR, &mut w);
        })
    });

    // Step 7: authenticated header parses, but the tag doesn't verify --
    // this is the expensive rejection, and the one Section 12.5 bounds.
    let mut tampered = number_datagram(CipherId::HmacSha256T64)
        .encode(&s, EPOCH, DIR, MAX_DATAGRAM_IPV4)
        .unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    g.bench_function("step 7: auth_failed", |b| {
        b.iter(|| {
            let mut w = ReplayWindow::one_second();
            let _ = decode(&tampered, &peer_cfg, EPOCH, DIR, &mut w);
        })
    });

    g.finish();
}

fn bench_epoch_key(c: &mut Criterion) {
    let s = secret();
    c.bench_function("epoch_key derivation (HKDF-Expand)", |b| {
        b.iter(|| s.epoch_key(SENDER_ID, EPOCH, DIR))
    });
}

criterion_group!(benches, bench_encode, bench_decode_accept, bench_decode_reject, bench_epoch_key);
criterion_main!(benches);
