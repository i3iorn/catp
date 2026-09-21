//! Provisioning bundles: the out-of-band artifact a deployment uses to get a
//! `device_secret`, `sender_id`, `cipher_id`, and layout list onto both ends
//! of an association before a single datagram can flow (PROTOCOL.md 12.5,
//! 9.2.1).
//!
//! Not part of the wire protocol. This format is never transmitted, and
//! nothing in `docs/PROTOCOL.md` constrains it -- §15 item 1 leaves
//! provisioning, storage at rest, and reissue out of the specification's
//! scope on purpose. It exists only to give `catp-provision` and
//! `catp-collector` a shared, textual artifact to produce and consume,
//! rather than each deployment inventing its own.
//!
//! The text format mirrors `docs/test-vectors.txt`'s `key value` convention:
//! legible, diffable, greppable, and consistent with PROTOCOL.md §8.3's own
//! reasoning that a deployment able to distribute a 32-byte `device_secret`
//! out of band can distribute everything else over that same channel, so
//! there is no reason to make the bundle terser than legible.
//!
//! ```text
//! # CATP provisioning bundle v1
//! sender_id     12345678
//! device_secret 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
//! cipher_id     04
//! layout        01 01
//! layout        02 03
//! ```

use crate::wire::PeerConfig;
use crate::{CipherId, DeviceSecret, Error, RateLimit};
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

/// Everything that can go wrong producing or consuming a bundle. Distinct
/// from [`Error`]: that type covers wire-decode failures with `PartialEq` and
/// `Clone` for test assertions; this covers file I/O and a human-edited text
/// format, neither of which fits those constraints ([`io::Error`] is
/// neither).
#[derive(Debug)]
pub enum ProvisionError {
    Io(io::Error),
    /// A field is missing, malformed, or the wrong width. Carries a message
    /// naming the field, since (unlike [`Error`]'s wire-format variants)
    /// there is no frozen conformance vector fixing the exact wording.
    Format(String),
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "provisioning I/O error: {e}"),
            Self::Format(msg) => write!(f, "malformed provisioning bundle: {msg}"),
        }
    }
}

impl std::error::Error for ProvisionError {}

impl From<io::Error> for ProvisionError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// One node's provisioning material: identity, secret, cipher selection, and
/// the layouts it (and its collector) use.
///
/// This is deliberately not [`PeerConfig`] itself: `PeerConfig` also carries
/// `inbound_rate_limit`, which is a receiver-side policy choice (PROTOCOL.md
/// 10.3), not device identity -- the same bundle can reasonably be loaded by
/// collectors that apply different rate limits to it. See
/// [`Bundle::into_peer_config`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub sender_id: u32,
    pub device_secret: [u8; 32],
    pub cipher_id: u8,
    /// `(format, schema_version)` pairs, in file order. May be empty --
    /// PROTOCOL.md 6.7.1's `CAPABILITY_ADVERTISE` similarly allows zero
    /// layouts.
    pub layouts: Vec<(u8, u8)>,
}

const HEADER_COMMENT: &str = "# CATP provisioning bundle v1";

impl Bundle {
    /// Render as the `key value` text format shown in the module
    /// documentation.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(HEADER_COMMENT);
        out.push('\n');
        out.push_str(&format!("sender_id     {:08x}\n", self.sender_id));
        out.push_str("device_secret ");
        for b in &self.device_secret {
            out.push_str(&format!("{b:02x}"));
        }
        out.push('\n');
        out.push_str(&format!("cipher_id     {:02x}\n", self.cipher_id));
        for (format, schema_version) in &self.layouts {
            out.push_str(&format!("layout        {format:02x} {schema_version:02x}\n"));
        }
        out
    }

    /// Parse the text format. Rejects anything the format doesn't expect
    /// rather than silently defaulting it -- a bundle carries a secret, and
    /// guessing at a malformed field is the wrong failure mode here.
    pub fn parse(s: &str) -> Result<Bundle, ProvisionError> {
        let bad = |msg: &str| ProvisionError::Format(msg.to_string());

        let mut sender_id = None;
        let mut device_secret = None;
        let mut cipher_id = None;
        let mut layouts = Vec::new();

        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.splitn(2, char::is_whitespace);
            let key = it.next().unwrap();
            let rest = it.next().unwrap_or("").trim();
            match key {
                "sender_id" => {
                    sender_id = Some(
                        u32::from_str_radix(rest, 16)
                            .map_err(|_| bad("sender_id is not 8 hex digits"))?,
                    );
                }
                "device_secret" => {
                    let bytes = parse_hex_bytes(rest)
                        .map_err(|_| bad("device_secret is not valid hex"))?;
                    let arr: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| bad("device_secret must be exactly 32 bytes (64 hex digits)"))?;
                    device_secret = Some(arr);
                }
                "cipher_id" => {
                    cipher_id = Some(
                        u8::from_str_radix(rest, 16).map_err(|_| bad("cipher_id is not 2 hex digits"))?,
                    );
                }
                "layout" => {
                    let mut parts = rest.split_whitespace();
                    let format = parts
                        .next()
                        .ok_or_else(|| bad("layout line needs a format byte"))?;
                    let schema_version = parts
                        .next()
                        .ok_or_else(|| bad("layout line needs a schema_version byte"))?;
                    if parts.next().is_some() {
                        return Err(bad("layout line has more than two fields"));
                    }
                    let format = u8::from_str_radix(format, 16).map_err(|_| bad("layout format is not hex"))?;
                    let schema_version = u8::from_str_radix(schema_version, 16)
                        .map_err(|_| bad("layout schema_version is not hex"))?;
                    layouts.push((format, schema_version));
                }
                other => return Err(bad(&format!("unrecognized field '{other}'"))),
            }
        }

        Ok(Bundle {
            sender_id: sender_id.ok_or_else(|| bad("missing sender_id"))?,
            device_secret: device_secret.ok_or_else(|| bad("missing device_secret"))?,
            cipher_id: cipher_id.ok_or_else(|| bad("missing cipher_id"))?,
            layouts,
        })
    }

    /// Write the bundle to `path`. On Unix, sets file permissions to `0600`
    /// (owner read/write only) before writing the secret -- cheap hygiene
    /// against a shared umask leaving a device secret world-readable. Not a
    /// substitute for actual secure storage (PROTOCOL.md §15 leaves storage
    /// at rest out of scope, deliberately), just a floor.
    ///
    /// `mode(0o600)` on `OpenOptions` only sets permissions at *creation*
    /// time (`O_CREAT`) -- if `path` already exists (e.g. `reissue`
    /// overwriting an older bundle, or a directory shared with a tool that
    /// used a looser umask), opening it with `truncate(true)` keeps
    /// whatever permissions it already had. This explicitly `chmod`s the
    /// open file descriptor to `0600` before writing, so an existing
    /// world-readable bundle is tightened rather than silently left as is.
    pub fn write_file(&self, path: &Path) -> Result<(), ProvisionError> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut f =
                fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(self.to_text().as_bytes())?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            fs::write(path, self.to_text())?;
            Ok(())
        }
    }

    pub fn read_file(path: &Path) -> Result<Bundle, ProvisionError> {
        let text = fs::read_to_string(path)?;
        Bundle::parse(&text)
    }

    /// Build the [`PeerConfig`] a collector loads this bundle into.
    ///
    /// `inbound_rate_limit` is supplied by the caller rather than carried on
    /// the bundle -- see the struct documentation for why. Fails with
    /// [`Error::CipherUnimplemented`] if `cipher_id` isn't a registered
    /// suite; fails with [`Error::CipherRequiresRateLimit`] if the suite
    /// requires a limit (PROTOCOL.md 8.1.1) and `inbound_rate_limit` is
    /// `None`, exactly as [`crate::peer::PeerState::new`] would.
    pub fn into_peer_config(&self, inbound_rate_limit: Option<RateLimit>) -> Result<PeerConfig, Error> {
        let cipher =
            CipherId::from_u8(self.cipher_id).ok_or(Error::CipherUnimplemented(self.cipher_id))?;
        if cipher.requires_inbound_rate_limit() && inbound_rate_limit.is_none() {
            return Err(Error::CipherRequiresRateLimit(self.cipher_id));
        }
        Ok(PeerConfig {
            sender_id: self.sender_id,
            secret: DeviceSecret::new(self.device_secret),
            cipher,
            layouts: self.layouts.clone(),
            inbound_rate_limit,
        })
    }
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// Load every `*.bundle` file in `dir`, in directory-listing order.
///
/// Bulk collector provisioning: `for b in load_bundles_dir(dir)? { collector
/// .provision(b.into_peer_config(rate_limit)?)?; }`. Stops at the first
/// unreadable or malformed file rather than silently skipping it -- a
/// provisioning error should block startup, not produce a collector quietly
/// missing a peer.
pub fn load_bundles_dir(dir: &Path) -> Result<Vec<Bundle>, ProvisionError> {
    let mut paths: Vec<_> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "bundle"))
        .collect();
    paths.sort();
    paths.iter().map(|p| Bundle::read_file(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Bundle {
        Bundle {
            sender_id: 0x1234_5678,
            device_secret: [0x42; 32],
            cipher_id: 0x04,
            layouts: vec![(0x01, 0x01), (0x02, 0x03)],
        }
    }

    #[test]
    fn round_trips_through_text() {
        let b = sample();
        let parsed = Bundle::parse(&b.to_text()).unwrap();
        assert_eq!(parsed, b);
    }

    #[test]
    fn to_text_matches_documented_format() {
        let b = Bundle { layouts: vec![(1, 1)], ..sample() };
        let text = b.to_text();
        assert!(text.starts_with("# CATP provisioning bundle v1\n"));
        assert!(text.contains("sender_id     12345678\n"));
        assert!(text.contains(
            "device_secret 4242424242424242424242424242424242424242424242424242424242424242\n"
        ));
        assert!(text.contains("cipher_id     04\n"));
        assert!(text.contains("layout        01 01\n"));
    }

    #[test]
    fn empty_layouts_round_trip() {
        let b = Bundle { layouts: vec![], ..sample() };
        assert_eq!(Bundle::parse(&b.to_text()).unwrap(), b);
    }

    #[test]
    fn missing_field_is_rejected() {
        let text = "sender_id 12345678\ncipher_id 04\n";
        assert!(matches!(Bundle::parse(text), Err(ProvisionError::Format(_))));
    }

    #[test]
    fn short_secret_is_rejected_not_zero_padded() {
        let text = "sender_id 12345678\ndevice_secret 4242\ncipher_id 04\n";
        assert!(matches!(Bundle::parse(text), Err(ProvisionError::Format(_))));
    }

    #[test]
    fn unrecognized_field_is_rejected() {
        let text = "sender_id 12345678\ndevice_secret 4242424242424242424242424242424242424242424242424242424242424242\ncipher_id 04\nnotes hello\n";
        assert!(matches!(Bundle::parse(text), Err(ProvisionError::Format(_))));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let text = format!("\n{}\n\n{}", HEADER_COMMENT, sample().to_text());
        // Doubling the header comment and adding blank lines must not change
        // the parse.
        assert_eq!(Bundle::parse(&text).unwrap(), sample());
    }

    #[test]
    fn into_peer_config_carries_every_field() {
        let b = sample();
        let cfg = b.into_peer_config(Some(RateLimit::RECOMMENDED_DEFAULT)).unwrap();
        assert_eq!(cfg.sender_id, b.sender_id);
        assert_eq!(cfg.secret.expose_secret(), &b.device_secret);
        assert_eq!(cfg.cipher as u8, b.cipher_id);
        assert_eq!(cfg.layouts, b.layouts);
    }

    #[test]
    fn into_peer_config_rejects_unimplemented_cipher() {
        let b = Bundle { cipher_id: 0xFE, ..sample() };
        assert!(matches!(b.into_peer_config(None), Err(Error::CipherUnimplemented(0xFE))));
    }

    #[test]
    fn into_peer_config_requires_rate_limit_for_0x04() {
        let b = Bundle { cipher_id: 0x04, ..sample() };
        assert!(matches!(b.into_peer_config(None), Err(Error::CipherRequiresRateLimit(0x04))));
        assert!(b.into_peer_config(Some(RateLimit::RECOMMENDED_DEFAULT)).is_ok());
    }

    #[test]
    fn file_round_trip() {
        let dir = std::env::temp_dir().join(format!("catp-provisioning-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.bundle");
        let b = sample();
        b.write_file(&path).unwrap();
        assert_eq!(Bundle::read_file(&path).unwrap(), b);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_file_tightens_an_existing_worlds_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("catp-provisioning-test-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.bundle");
        // Simulate a file that pre-existed with looser permissions -- e.g.
        // left over from a different tool, or from before this hardening
        // existed. `OpenOptions::mode()` only sets permissions at creation,
        // so overwriting it must not leave them as they were.
        std::fs::write(&path, "stale").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        sample().write_file(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "existing file's permissions were not tightened");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_bundles_dir_reads_only_dot_bundle_files_in_sorted_order() {
        let dir = std::env::temp_dir().join(format!("catp-provisioning-test-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let b1 = Bundle { sender_id: 1, ..sample() };
        let b2 = Bundle { sender_id: 2, ..sample() };
        b2.write_file(&dir.join("b-second.bundle")).unwrap();
        b1.write_file(&dir.join("a-first.bundle")).unwrap();
        std::fs::write(dir.join("readme.txt"), "not a bundle").unwrap();

        let loaded = load_bundles_dir(&dir).unwrap();
        assert_eq!(loaded, vec![b1, b2]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
