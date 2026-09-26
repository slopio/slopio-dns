use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::wire::Reader;
use super::{Class, DecodeError, Edns, NameRef, RecordType};

/// A resource record inside a received message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    pub name: NameRef<'a>,
    pub class: Class,
    pub ttl: u32,
    pub data: RData<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RData<'a> {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(NameRef<'a>),
    Cname(NameRef<'a>),
    Ptr(NameRef<'a>),
    Mx {
        preference: u16,
        exchange: NameRef<'a>,
    },
    Txt(CharacterStrings<'a>),
    Soa(Soa<'a>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: NameRef<'a>,
    },
    /// Any type without a variant above, as raw bytes.
    Unknown {
        rtype: RecordType,
        data: &'a [u8],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Soa<'a> {
    pub mname: NameRef<'a>,
    pub rname: NameRef<'a>,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/// TXT data: a run of length-prefixed strings of up to 255 bytes each.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CharacterStrings<'a>(&'a [u8]);

/// What an entry in a record section decodes to: OPT is not a real record.
pub(crate) enum Entry<'a> {
    Record(Record<'a>),
    Opt(Edns<'a>),
}

impl<'a> Record<'a> {
    pub fn rtype(&self) -> RecordType {
        self.data.rtype()
    }

    pub(crate) fn read_entry(r: &mut Reader<'a>) -> Result<Entry<'a>, DecodeError> {
        let name = NameRef::read(r)?;
        let rtype = RecordType::from(r.read_u16()?);
        let class = r.read_u16()?;
        let ttl = r.read_u32()?;
        let rdlen = usize::from(r.read_u16()?);

        if rtype == RecordType::Opt {
            return Edns::decode(class, ttl, r.read_bytes(rdlen)?).map(Entry::Opt);
        }
        Ok(Entry::Record(Self {
            name,
            class: class.into(),
            ttl,
            data: RData::read(r, rtype, rdlen)?,
        }))
    }
}

impl<'a> RData<'a> {
    pub fn rtype(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::Aaaa,
            Self::Ns(_) => RecordType::Ns,
            Self::Cname(_) => RecordType::Cname,
            Self::Ptr(_) => RecordType::Ptr,
            Self::Mx { .. } => RecordType::Mx,
            Self::Txt(_) => RecordType::Txt,
            Self::Soa(_) => RecordType::Soa,
            Self::Srv { .. } => RecordType::Srv,
            Self::Unknown { rtype, .. } => *rtype,
        }
    }

    fn read(r: &mut Reader<'a>, rtype: RecordType, rdlen: usize) -> Result<Self, DecodeError> {
        if rdlen > r.remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let start = r.pos();
        let end = start + rdlen;
        // Cut the buffer at the end of RDATA so no field can read past it.
        // Compression pointers only go backwards, so names still resolve.
        let mut rd = Reader::at(&r.buf()[..end], start);
        let data = Self::read_fields(&mut rd, rtype, rdlen).map_err(|e| match e {
            DecodeError::UnexpectedEof => DecodeError::BadRdata(rtype),
            e => e,
        })?;
        if rd.pos() != end {
            return Err(DecodeError::BadRdata(rtype));
        }
        r.set_pos(end);
        Ok(data)
    }

    fn read_fields(
        r: &mut Reader<'a>,
        rtype: RecordType,
        rdlen: usize,
    ) -> Result<Self, DecodeError> {
        let start = r.pos();
        let data = match rtype {
            RecordType::A => Self::A(Ipv4Addr::from(r.read_array::<4>()?)),
            RecordType::Aaaa => Self::Aaaa(Ipv6Addr::from(r.read_array::<16>()?)),
            RecordType::Ns => Self::Ns(NameRef::read(r)?),
            RecordType::Cname => Self::Cname(NameRef::read(r)?),
            RecordType::Ptr => Self::Ptr(NameRef::read(r)?),
            RecordType::Mx => Self::Mx {
                preference: r.read_u16()?,
                exchange: NameRef::read(r)?,
            },
            RecordType::Txt => {
                while r.remaining() > 0 {
                    let len = usize::from(r.read_u8()?);
                    r.read_bytes(len)?;
                }
                Self::Txt(CharacterStrings(&r.buf()[start..r.pos()]))
            }
            RecordType::Soa => Self::Soa(Soa {
                mname: NameRef::read(r)?,
                rname: NameRef::read(r)?,
                serial: r.read_u32()?,
                refresh: r.read_u32()?,
                retry: r.read_u32()?,
                expire: r.read_u32()?,
                minimum: r.read_u32()?,
            }),
            RecordType::Srv => Self::Srv {
                priority: r.read_u16()?,
                weight: r.read_u16()?,
                port: r.read_u16()?,
                target: NameRef::read(r)?,
            },
            _ => Self::Unknown {
                rtype,
                data: r.read_bytes(rdlen)?,
            },
        };
        Ok(data)
    }
}

impl<'a> CharacterStrings<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        let mut rest = self.0;
        std::iter::from_fn(move || {
            let (&len, tail) = rest.split_first()?;
            let s = tail.get(..usize::from(len))?;
            rest = &tail[s.len()..];
            Some(s)
        })
    }
}

impl fmt::Debug for CharacterStrings<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.iter().map(|s| s.escape_ascii().to_string()))
            .finish()
    }
}
