use super::wire::{Reader, put_u16};
use super::{DecodeError, Opcode, Rcode};

pub const HEADER_LEN: usize = 12;

/// The fixed 12-byte header, minus the section counts, which [`super::Message`]
/// derives from its sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    /// Set in responses, clear in queries.
    pub qr: bool,
    /// 4 bits on the wire; higher bits are dropped when encoding.
    pub opcode: Opcode,
    /// Authoritative answer.
    pub aa: bool,
    /// Truncated: retry over TCP to get the full response.
    pub tc: bool,
    /// Recursion desired.
    pub rd: bool,
    /// Recursion available.
    pub ra: bool,
    /// Authentic data (DNSSEC).
    pub ad: bool,
    /// Checking disabled (DNSSEC).
    pub cd: bool,
    /// Only the low 4 bits live here; see [`super::Message::rcode`].
    pub rcode: Rcode,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            id: 0,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
        }
    }
}

/// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
pub(crate) type Counts = [u16; 4];

impl Header {
    pub(crate) fn encode(&self, counts: Counts, out: &mut Vec<u8>) {
        put_u16(out, self.id);

        let mut b2 = (u8::from(self.opcode) & 0x0F) << 3;
        b2 |= u8::from(self.qr) << 7;
        b2 |= u8::from(self.aa) << 2;
        b2 |= u8::from(self.tc) << 1;
        b2 |= u8::from(self.rd);

        let mut b3 = (u16::from(self.rcode) & 0x0F) as u8;
        b3 |= u8::from(self.ra) << 7;
        b3 |= u8::from(self.ad) << 5;
        b3 |= u8::from(self.cd) << 4;

        out.extend_from_slice(&[b2, b3]);
        for count in counts {
            put_u16(out, count);
        }
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<(Self, Counts), DecodeError> {
        let id = r.read_u16()?;
        let [b2, b3] = r.read_array()?;
        let header = Self {
            id,
            qr: b2 & 0x80 != 0,
            opcode: Opcode::from((b2 >> 3) & 0x0F),
            aa: b2 & 0x04 != 0,
            tc: b2 & 0x02 != 0,
            rd: b2 & 0x01 != 0,
            ra: b3 & 0x80 != 0,
            ad: b3 & 0x20 != 0,
            cd: b3 & 0x10 != 0,
            rcode: Rcode::from(u16::from(b3 & 0x0F)),
        };
        let counts = [r.read_u16()?, r.read_u16()?, r.read_u16()?, r.read_u16()?];
        Ok((header, counts))
    }
}
