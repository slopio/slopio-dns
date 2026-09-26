use std::fmt;

use super::wire::{Reader, put_u16};
use super::{DecodeError, RecordType};

/// Recommended EDNS UDP payload size: fits in an IPv6 minimum MTU without fragmenting.
const DEFAULT_UDP_PAYLOAD_SIZE: u16 = 1232;

const DNSSEC_OK: u8 = 0x80;

/// EDNS(0) parameters. On the wire they form an OPT pseudo-record in the
/// additional section, which reuses CLASS and TTL for its own fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edns<'a> {
    /// Largest UDP response the sender can receive (the OPT CLASS field).
    pub udp_payload_size: u16,
    /// Upper 8 bits of the 12-bit response code.
    pub extended_rcode: u8,
    pub version: u8,
    /// DO bit: ask for DNSSEC records.
    pub dnssec_ok: bool,
    pub options: EdnsOptions<'a>,
}

/// The OPT record's RDATA: a validated run of options, borrowed.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct EdnsOptions<'a>(&'a [u8]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdnsOption<'a> {
    pub code: u16,
    pub data: &'a [u8],
}

impl Default for Edns<'_> {
    fn default() -> Self {
        Self {
            udp_payload_size: DEFAULT_UDP_PAYLOAD_SIZE,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            options: EdnsOptions::default(),
        }
    }
}

impl<'a> Edns<'a> {
    /// Writes the whole OPT record.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.push(0); // root owner name
        put_u16(out, RecordType::Opt.into());
        put_u16(out, self.udp_payload_size);
        let flags = if self.dnssec_ok { DNSSEC_OK } else { 0 };
        out.extend_from_slice(&[self.extended_rcode, self.version, flags, 0]);
        // Fits: `EdnsOptions::parse` checked the length.
        put_u16(out, self.options.0.len() as u16);
        out.extend_from_slice(self.options.0);
    }

    /// Builds from the OPT record's CLASS, TTL and RDATA.
    pub(crate) fn decode(class: u16, ttl: u32, rdata: &'a [u8]) -> Result<Self, DecodeError> {
        let [extended_rcode, version, flags, _] = ttl.to_be_bytes();
        Ok(Self {
            udp_payload_size: class,
            extended_rcode,
            version,
            dnssec_ok: flags & DNSSEC_OK != 0,
            options: EdnsOptions::parse(rdata)?,
        })
    }
}

impl<'a> EdnsOptions<'a> {
    /// Validates encoded options, e.g. built with [`EdnsOption::encode`].
    pub fn parse(raw: &'a [u8]) -> Result<Self, DecodeError> {
        let bad = DecodeError::BadRdata(RecordType::Opt);
        if raw.len() > usize::from(u16::MAX) {
            return Err(bad);
        }
        let mut r = Reader::new(raw);
        while r.remaining() > 0 {
            r.read_u16().map_err(|_| bad)?;
            let len = r.read_u16().map_err(|_| bad)?;
            r.read_bytes(usize::from(len)).map_err(|_| bad)?;
        }
        Ok(Self(raw))
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    pub fn iter(&self) -> impl Iterator<Item = EdnsOption<'a>> + use<'a> {
        let mut r = Reader::new(self.0);
        std::iter::from_fn(move || {
            Some(EdnsOption {
                code: r.read_u16().ok()?,
                data: {
                    let len = r.read_u16().ok()?;
                    r.read_bytes(usize::from(len)).ok()?
                },
            })
        })
    }
}

impl EdnsOption<'_> {
    /// Appends the option in wire form. The data must fit in 65535 bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.code);
        put_u16(out, self.data.len() as u16);
        out.extend_from_slice(self.data);
    }
}

impl fmt::Debug for EdnsOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}
