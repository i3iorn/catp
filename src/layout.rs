//! Record layout description (PROTOCOL.md 6.4.4).

/// A record layout the sender may produce and the receiver understands.
///
/// PROTOCOL.md 6.7.1 advertises only the `(format, schema_version)` pair on
/// the wire; a fixed body width, when the layout has one, lives in the
/// receiver's configuration so `decode` can enforce the per-record size check
/// of Section 6.4.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub format: u8,
    pub schema_version: u8,
    /// Fixed body width in bytes, if the layout has one.
    pub fixed_width: Option<u16>,
}

impl Layout {
    /// A layout without a fixed body width.
    pub const fn new(format: u8, schema_version: u8) -> Self {
        Self {
            format,
            schema_version,
            fixed_width: None,
        }
    }

    /// A layout whose record bodies must always be exactly `fixed_width`
    /// bytes (PROTOCOL.md 6.4.4).
    pub const fn with_fixed_width(format: u8, schema_version: u8, fixed_width: u16) -> Self {
        Self {
            format,
            schema_version,
            fixed_width: Some(fixed_width),
        }
    }

    /// The `(format, schema_version)` pair advertised on the wire
    /// (PROTOCOL.md 6.7.1).
    pub const fn pair(self) -> (u8, u8) {
        (self.format, self.schema_version)
    }
}
