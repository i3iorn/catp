//! Control message payloads (PROTOCOL.md 6.7, 9.4, 11.3).
//!
//! Control messages are not record-framed: each has one fixed layout,
//! identified by `msg_type` alone.

use crate::*;

/// A parsed control payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Control {
    /// `EPOCH_ANNOUNCE` (`0x10`) — asserts an absolute epoch (PROTOCOL.md 9.4).
    EpochAnnounce { target_epoch: u32 },
    /// `TIME_ANNOUNCE` (`0x11`) — cold-start time (PROTOCOL.md 11.3).
    ///
    /// Never reached through [`crate::wire::decode`]: it is keyed on `time_key`
    /// rather than an epoch key, so it has its own entry point
    /// ([`crate::wire::decode_time_announce`]).
    TimeAnnounce { asserted_time: i64 },
    /// `HEARTBEAT` (`0x12`) — empty payload.
    Heartbeat,
    /// `CAPABILITY_ADVERTISE` (`0x13`) — advisory (PROTOCOL.md 6.7.1).
    Capability(Capability),
}

/// Body of a `CAPABILITY_ADVERTISE`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Capability {
    pub max_version: u8,
    pub ciphers: Vec<u8>,
    /// `(format, schema_version)` pairs the sender can produce.
    pub layouts: Vec<(u8, u8)>,
}

impl Capability {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.ciphers.len() > 255 || self.layouts.len() > 255 {
            return Err(Error::Framing("capability list longer than 255"));
        }
        let mut v = Vec::with_capacity(3 + self.ciphers.len() + self.layouts.len() * 2);
        v.push(self.max_version);
        v.push(self.ciphers.len() as u8);
        v.extend_from_slice(&self.ciphers);
        v.push(self.layouts.len() as u8);
        for (f, s) in &self.layouts {
            v.push(*f);
            v.push(*s);
        }
        Ok(v)
    }

    pub fn parse(p: &[u8]) -> Result<Self, Error> {
        if p.len() < 3 {
            return Err(Error::Framing("CAPABILITY_ADVERTISE shorter than 3 bytes"));
        }
        let max_version = p[0];
        let nc = p[1] as usize;
        if p.len() < 2 + nc + 1 {
            return Err(Error::Framing("cipher list overruns payload"));
        }
        let ciphers = p[2..2 + nc].to_vec();
        let nl = p[2 + nc] as usize;
        // PROTOCOL.md 6.7.1: length MUST equal 3 + cipher_count + layout_count*2
        if p.len() != 3 + nc + nl * 2 {
            return Err(Error::Framing("CAPABILITY_ADVERTISE length mismatch"));
        }
        // Exact by construction: the length check above requires
        // `p.len() == 3 + nc + nl * 2`, so this slice is exactly `nl` pairs.
        let (layout_pairs, remainder) = p[3 + nc..].as_chunks::<2>();
        debug_assert!(remainder.is_empty());
        let layouts = layout_pairs.iter().map(|c| (c[0], c[1])).collect();
        Ok(Self { max_version, ciphers, layouts })
    }
}

impl Control {
    /// Parse a verified control payload according to `msg_type`.
    pub fn parse(mt: MsgType, p: &[u8]) -> Result<Self, Error> {
        match mt {
            MsgType::EpochAnnounce => {
                if p.len() != 4 {
                    return Err(Error::Framing("EPOCH_ANNOUNCE payload is not 4 bytes"));
                }
                Ok(Control::EpochAnnounce {
                    target_epoch: u32::from_be_bytes([p[0], p[1], p[2], p[3]]),
                })
            }
            MsgType::TimeAnnounce => {
                if p.len() != 8 {
                    return Err(Error::Framing("TIME_ANNOUNCE payload is not 8 bytes"));
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(p);
                Ok(Control::TimeAnnounce { asserted_time: i64::from_be_bytes(b) })
            }
            MsgType::Heartbeat => {
                if !p.is_empty() {
                    return Err(Error::Framing("HEARTBEAT payload is not empty"));
                }
                Ok(Control::Heartbeat)
            }
            MsgType::CapabilityAdvertise => Ok(Control::Capability(Capability::parse(p)?)),
            _ => Err(Error::Framing("not a control message type")),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(match self {
            Control::EpochAnnounce { target_epoch } => target_epoch.to_be_bytes().to_vec(),
            Control::TimeAnnounce { asserted_time } => asserted_time.to_be_bytes().to_vec(),
            Control::Heartbeat => Vec::new(),
            Control::Capability(c) => c.encode()?,
        })
    }

    pub fn msg_type(&self) -> MsgType {
        match self {
            Control::EpochAnnounce { .. } => MsgType::EpochAnnounce,
            Control::TimeAnnounce { .. } => MsgType::TimeAnnounce,
            Control::Heartbeat => MsgType::Heartbeat,
            Control::Capability(_) => MsgType::CapabilityAdvertise,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_announce_roundtrip() {
        let c = Control::EpochAnnounce { target_epoch: 0xDEAD_BEEF };
        let p = c.encode().unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(Control::parse(MsgType::EpochAnnounce, &p).unwrap(), c);
        // Wrong length rejected.
        assert!(Control::parse(MsgType::EpochAnnounce, &p[..3]).is_err());
        assert!(Control::parse(MsgType::EpochAnnounce, b"\0\0\0\0\0").is_err());
    }

    #[test]
    fn heartbeat_must_be_empty() {
        assert_eq!(Control::parse(MsgType::Heartbeat, &[]).unwrap(), Control::Heartbeat);
        assert!(Control::parse(MsgType::Heartbeat, b"x").is_err());
    }

    #[test]
    fn capability_roundtrip_and_length_check() {
        let c = Capability {
            max_version: 1,
            ciphers: vec![0x01, 0x04],
            layouts: vec![(0x01, 1), (0x02, 7)],
        };
        let p = c.encode().unwrap();
        // PROTOCOL.md 6.7.1: 3 + cipher_count + layout_count*2
        assert_eq!(p.len(), 3 + 2 + 2 * 2);
        assert_eq!(Capability::parse(&p).unwrap(), c);

        // Truncated and over-long payloads both fail the length equality.
        assert!(Capability::parse(&p[..p.len() - 1]).is_err());
        let mut long = p.clone();
        long.push(0);
        assert!(Capability::parse(&long).is_err());
        // A cipher_count that overruns the buffer.
        assert!(Capability::parse(&[1, 200, 0]).is_err());
    }

    #[test]
    fn empty_capability_is_legal() {
        let c = Capability { max_version: 1, ciphers: vec![], layouts: vec![] };
        let p = c.encode().unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(Capability::parse(&p).unwrap(), c);
    }
}
