use std::fmt;

use super::RecordType;

/// A received message that isn't valid DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The message ends in the middle of a field.
    UnexpectedEof,
    /// A label length byte starting with the reserved bits `01` or `10`.
    InvalidLabelType(u8),
    /// A compression pointer that doesn't point strictly backwards.
    BadPointer,
    /// A name longer than 255 bytes once decompressed.
    NameTooLong,
    /// Record data that doesn't match its declared length or type.
    BadRdata(RecordType),
    /// An OPT record outside the additional section, or more than one.
    InvalidOpt,
    /// The datagram didn't fit the receive buffer and was cut by the kernel.
    /// Not the TC bit: that marks a complete message the server shortened.
    TruncatedDatagram,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("message ends unexpectedly"),
            Self::InvalidLabelType(b) => write!(f, "invalid label type byte {b:#04x}"),
            Self::BadPointer => f.write_str("compression pointer does not point backwards"),
            Self::NameTooLong => f.write_str("name longer than 255 bytes"),
            Self::BadRdata(rtype) => write!(f, "malformed {rtype:?} record data"),
            Self::InvalidOpt => f.write_str("misplaced or duplicate OPT record"),
            Self::TruncatedDatagram => f.write_str("datagram larger than the receive buffer"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// An invalid domain name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// An empty label, as in `a..b`.
    EmptyLabel,
    /// A label longer than 63 bytes.
    LabelTooLong,
    /// A name longer than 255 bytes on the wire.
    NameTooLong,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLabel => f.write_str("empty label"),
            Self::LabelTooLong => f.write_str("label longer than 63 bytes"),
            Self::NameTooLong => f.write_str("name longer than 255 bytes"),
        }
    }
}

impl std::error::Error for NameError {}
