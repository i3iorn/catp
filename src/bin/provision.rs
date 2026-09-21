//! `catp-provision`: generates, inspects, and reissues provisioning bundles
//! (PROTOCOL.md 12.5, 9.2.1; `catp::provisioning`).
//!
//! ```text
//! catp-provision generate --count N --cipher HH --layouts f:s,f:s,... --out DIR
//! catp-provision inspect BUNDLE [--reveal-secret]
//! catp-provision reissue OLD_BUNDLE --out NEW_BUNDLE
//! ```
//!
//! Deliberately not attempted here (see issue #34): pluggable secure storage
//! or an HSM backend -- platform-specific enough to need its own design, and
//! this tool writing `0600`-permissioned files (Unix) is a floor, not that;
//! any kind of automated network rotation -- PROTOCOL.md §15 puts this out of
//! scope, and CATP has no provisioning channel to automate over; a
//! centralized `sender_id` registry for >10,000-node fleets (§4.4.1's third
//! tier) -- a real registry service is a different project.

use catp::CipherId;
use catp::provisioning::Bundle;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ! {
    eprintln!(
        "usage:\n\
         \x20 catp-provision generate --count N --cipher HH --layouts f:s,f:s,... --out DIR\n\
         \x20 catp-provision inspect BUNDLE [--reveal-secret]\n\
         \x20 catp-provision reissue OLD_BUNDLE --out NEW_BUNDLE"
    );
    std::process::exit(2);
}

/// A CSPRNG `sender_id`, honouring PROTOCOL.md 4.4.1: `0x00000000` is
/// reserved (a zero-filled buffer must not decode as a valid sender), so
/// resample rather than accept it. At 2^32 values this never loops more than
/// once in practice.
fn random_sender_id() -> u32 {
    loop {
        let id = getrandom::u32().expect("OS CSPRNG unavailable");
        if id != 0 {
            return id;
        }
    }
}

fn random_secret() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS CSPRNG unavailable");
    buf
}

fn parse_layouts(spec: &str) -> Vec<(u8, u8)> {
    if spec.is_empty() {
        return Vec::new();
    }
    spec.split(',')
        .map(|pair| {
            let (f, s) = pair.split_once(':').unwrap_or_else(|| {
                eprintln!("error: layout '{pair}' is not format:schema_version");
                std::process::exit(2);
            });
            let parse_byte = |s: &str, what: &str| {
                u8::from_str_radix(s, 16).unwrap_or_else(|_| {
                    eprintln!("error: layout {what} '{s}' is not a hex byte");
                    std::process::exit(2);
                })
            };
            (parse_byte(f, "format"), parse_byte(s, "schema_version"))
        })
        .collect()
}

fn cmd_generate(args: &[String]) -> ExitCode {
    let mut count = None;
    let mut cipher_id = None;
    let mut layouts = Vec::new();
    let mut out = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--count" => {
                count = Some(
                    args.get(i + 1)
                        .unwrap_or_else(|| usage())
                        .parse::<u32>()
                        .unwrap_or_else(|_| {
                            eprintln!("error: --count is not a number");
                            std::process::exit(2);
                        }),
                );
                i += 2;
            }
            "--cipher" => {
                let hex = args.get(i + 1).unwrap_or_else(|| usage());
                cipher_id = Some(u8::from_str_radix(hex, 16).unwrap_or_else(|_| {
                    eprintln!("error: --cipher is not a hex byte");
                    std::process::exit(2);
                }));
                i += 2;
            }
            "--layouts" => {
                layouts = parse_layouts(args.get(i + 1).unwrap_or_else(|| usage()));
                i += 2;
            }
            "--out" => {
                out = Some(PathBuf::from(args.get(i + 1).unwrap_or_else(|| usage())));
                i += 2;
            }
            _ => usage(),
        }
    }
    let (Some(count), Some(cipher_id), Some(out)) = (count, cipher_id, out) else {
        eprintln!("error: --count, --cipher, and --out are required");
        usage();
    };
    if CipherId::from_u8(cipher_id).is_none() {
        eprintln!("error: cipher_id 0x{cipher_id:02x} is not a registered suite (PROTOCOL.md 8.1)");
        return ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::create_dir_all(&out) {
        eprintln!("error: creating {}: {e}", out.display());
        return ExitCode::FAILURE;
    }

    // Self-assignment collision check within this batch (PROTOCOL.md 4.4.1),
    // extended to the directory this batch writes into: an operator running
    // `generate` a second time to grow a fleet must not have it silently
    // overwrite an already-provisioned node's bundle -- `write_file` always
    // truncates, so a collision here would replace a live device's secret
    // with a fresh one it was never given, desynchronizing it with no
    // warning. This is still not a check against a whole fleet's history
    // this tool has no visibility into (PROTOCOL.md 4.4.1's >1,000-node
    // tier needs that from the deployment itself), only against what is
    // actually on disk right here.
    let mut seen = HashSet::with_capacity(count as usize);
    let mut bundles = Vec::with_capacity(count as usize);
    while bundles.len() < count as usize {
        let sender_id = random_sender_id();
        if !seen.insert(sender_id) {
            continue; // collision within this batch; resample
        }
        if out.join(format!("node-{sender_id:08x}.bundle")).exists() {
            continue; // collision with an already-provisioned node; resample
        }
        bundles.push(Bundle {
            sender_id,
            device_secret: random_secret(),
            cipher_id,
            layouts: layouts.clone(),
        });
    }

    for b in &bundles {
        let path = out.join(format!("node-{:08x}.bundle", b.sender_id));
        if let Err(e) = b.write_file(&path) {
            eprintln!("error: writing {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!("{}", path.display());
    }
    eprintln!("generated {} bundle(s) in {}", bundles.len(), out.display());
    ExitCode::SUCCESS
}

fn cmd_inspect(args: &[String]) -> ExitCode {
    let mut reveal = false;
    let mut path = None;
    for a in args {
        match a.as_str() {
            "--reveal-secret" => reveal = true,
            _ if path.is_none() => path = Some(PathBuf::from(a)),
            _ => usage(),
        }
    }
    let Some(path) = path else { usage() };
    let bundle = match Bundle::read_file(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("sender_id     {:08x}", bundle.sender_id);
    if reveal {
        println!(
            "device_secret {}",
            bundle
                .device_secret
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    } else {
        println!("device_secret <hidden, pass --reveal-secret to print>");
    }
    println!("cipher_id     {:02x}", bundle.cipher_id);
    for (f, s) in &bundle.layouts {
        println!("layout        {f:02x} {s:02x}");
    }
    ExitCode::SUCCESS
}

fn cmd_reissue(args: &[String]) -> ExitCode {
    let mut old = None;
    let mut out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out = Some(PathBuf::from(args.get(i + 1).unwrap_or_else(|| usage())));
                i += 2;
            }
            _ if old.is_none() => {
                old = Some(PathBuf::from(&args[i]));
                i += 1;
            }
            _ => usage(),
        }
    }
    let (Some(old), Some(out)) = (old, out) else {
        eprintln!("error: OLD_BUNDLE and --out are required");
        usage();
    };
    let previous = match Bundle::read_file(&old) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: reading {}: {e}", old.display());
            return ExitCode::FAILURE;
        }
    };
    // sender_id, cipher_id, and layouts carry over; only the secret is fresh
    // -- this is reissue, not a new node. PROTOCOL.md §8.3 documents the
    // equivalent two-step cutover for a *cipher_id* migration (receiver
    // first, then sender, with a rejection window in between); the same
    // pattern applies here: load this new bundle into the collector, THEN
    // update the node, out of band, before it transmits again. This tool
    // does not perform that cutover -- CATP has no provisioning channel to
    // automate it over (§15) -- it only produces the new bundle.
    let reissued = Bundle {
        device_secret: random_secret(),
        ..previous
    };
    if let Err(e) = reissued.write_file(&out) {
        eprintln!("error: writing {}: {e}", out.display());
        return ExitCode::FAILURE;
    }
    eprintln!(
        "reissued sender_id {:08x}: new secret written to {}. \
         Load it into the collector, confirm, then update the node -- \
         datagrams under the old secret stop verifying the moment you do.",
        reissued.sender_id,
        out.display()
    );
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("generate") => cmd_generate(&args[1..]),
        Some("inspect") => cmd_inspect(&args[1..]),
        Some("reissue") => cmd_reissue(&args[1..]),
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catp::provisioning::load_bundles_dir;

    #[test]
    fn parse_layouts_handles_multiple_pairs() {
        assert_eq!(
            parse_layouts("01:01,02:03"),
            vec![(0x01, 0x01), (0x02, 0x03)]
        );
    }

    #[test]
    fn parse_layouts_handles_empty() {
        assert_eq!(parse_layouts(""), Vec::<(u8, u8)>::new());
    }

    #[test]
    fn random_sender_id_never_returns_zero() {
        for _ in 0..1000 {
            assert_ne!(random_sender_id(), 0);
        }
    }

    #[test]
    fn generate_then_load_bundles_dir_round_trips() {
        let dir =
            std::env::temp_dir().join(format!("catp-provision-bin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let code = cmd_generate(&[
            "--count".into(),
            "5".into(),
            "--cipher".into(),
            "01".into(),
            "--layouts".into(),
            "01:01".into(),
            "--out".into(),
            dir.to_string_lossy().into_owned(),
        ]);
        assert_eq!(code, ExitCode::SUCCESS);
        let loaded = load_bundles_dir(&dir).unwrap();
        assert_eq!(loaded.len(), 5);
        // All five self-assigned sender_ids must be distinct (the batch
        // collision check).
        let ids: HashSet<_> = loaded.iter().map(|b| b.sender_id).collect();
        assert_eq!(ids.len(), 5);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn generate_run_twice_never_overwrites_an_earlier_batch() {
        // An operator growing a fleet runs `generate` again into the same
        // directory. The first batch's bundles -- and in particular their
        // secrets -- must survive untouched; `write_file` always truncates,
        // so a sender_id collision with an earlier run must be resampled
        // away from, not written over.
        let dir =
            std::env::temp_dir().join(format!("catp-provision-bin-regrow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.to_string_lossy().into_owned();
        let generate_into = |count: &str| {
            cmd_generate(&[
                "--count".into(),
                count.into(),
                "--cipher".into(),
                "01".into(),
                "--layouts".into(),
                "01:01".into(),
                "--out".into(),
                out.clone(),
            ])
        };
        assert_eq!(generate_into("5"), ExitCode::SUCCESS);
        let first_batch = load_bundles_dir(&dir).unwrap();
        assert_eq!(first_batch.len(), 5);

        assert_eq!(generate_into("5"), ExitCode::SUCCESS);
        let second_batch = load_bundles_dir(&dir).unwrap();
        assert_eq!(second_batch.len(), 10, "second run must add, not replace");

        // Every bundle from the first run is still present, byte-for-byte
        // (same secret, not a freshly generated one under the same name).
        for b in &first_batch {
            assert!(
                second_batch.contains(b),
                "first batch bundle {:08x} was overwritten",
                b.sender_id
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reissue_keeps_identity_and_changes_only_the_secret() {
        let dir =
            std::env::temp_dir().join(format!("catp-provision-bin-reissue-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old_path = dir.join("old.bundle");
        let original = Bundle {
            sender_id: 0xAABBCCDD,
            device_secret: [0x11; 32],
            cipher_id: 0x01,
            layouts: vec![(1, 1)],
        };
        original.write_file(&old_path).unwrap();

        let new_path = dir.join("new.bundle");
        let code = cmd_reissue(&[
            old_path.to_string_lossy().into_owned(),
            "--out".into(),
            new_path.to_string_lossy().into_owned(),
        ]);
        assert_eq!(code, ExitCode::SUCCESS);

        let reissued = Bundle::read_file(&new_path).unwrap();
        assert_eq!(reissued.sender_id, original.sender_id);
        assert_eq!(reissued.cipher_id, original.cipher_id);
        assert_eq!(reissued.layouts, original.layouts);
        assert_ne!(reissued.device_secret, original.device_secret);
        std::fs::remove_dir_all(&dir).ok();
    }
}
