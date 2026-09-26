//! From a response to an address: what [`super::DnsClient::resolve`] keeps of it.

use std::fmt;
use std::net::IpAddr;

use super::QueryError;
use crate::protocol::{Class, Message, RData, Rcode, RecordType};

/// Longest CNAME chain followed; also stops alias loops.
const MAX_CNAME_HOPS: usize = 8;

/// Which kind of address to resolve a name to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    /// IPv4, from A records.
    V4,
    /// IPv6, from AAAA records.
    V6,
}

impl IpVersion {
    /// The record type holding this kind of address.
    pub fn record_type(self) -> RecordType {
        match self {
            Self::V4 => RecordType::A,
            Self::V6 => RecordType::Aaaa,
        }
    }

    /// The address in `data`, if it holds one of this kind.
    fn address(self, data: &RData<'_>) -> Option<IpAddr> {
        match (self, data) {
            (Self::V4, RData::A(addr)) => Some(IpAddr::V4(*addr)),
            (Self::V6, RData::Aaaa(addr)) => Some(IpAddr::V6(*addr)),
            _ => None,
        }
    }
}

/// Why a name gave no address.
#[derive(Debug)]
pub enum ResolveError {
    /// No usable response: timeout, I/O error, client stopped…
    Query(QueryError),
    /// NXDOMAIN: the name doesn't exist.
    NotFound,
    /// The name exists but has no address of the type asked.
    NoAddress,
    /// The server couldn't answer (SERVFAIL, REFUSED…). SERVFAIL is often
    /// transient, so retrying can help.
    ServerFailure(Rcode),
    /// The server cut the response short (TC bit) before any address.
    Truncated,
}

/// The first address of the `version` asked for the question's name in
/// `message`, following CNAMEs from it. Addresses of any other name are ignored.
pub(super) fn first_address(
    message: &Message<'_>,
    version: IpVersion,
) -> Result<IpAddr, ResolveError> {
    match message.rcode() {
        Rcode::NoError => {}
        Rcode::NxDomain => return Err(ResolveError::NotFound),
        rcode => return Err(ResolveError::ServerFailure(rcode)),
    }
    let Some(question) = message.questions().next() else {
        return Err(ResolveError::NoAddress);
    };

    let mut name = question.name;
    for _ in 0..=MAX_CNAME_HOPS {
        let mut alias_of = None;
        for record in message.answers() {
            if record.class != Class::In || record.name != name {
                continue;
            }
            if let Some(addr) = version.address(&record.data) {
                return Ok(addr);
            }
            if let RData::Cname(target) = record.data {
                alias_of = alias_of.or(Some(target));
            }
        }
        let Some(target) = alias_of else { break };
        name = target;
    }

    // A truncated response may have dropped the address: say so.
    Err(if message.header.tc {
        ResolveError::Truncated
    } else {
        ResolveError::NoAddress
    })
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query(e) => e.fmt(f),
            Self::NotFound => f.write_str("name not found (NXDOMAIN)"),
            Self::NoAddress => f.write_str("name has no address"),
            Self::ServerFailure(rcode) => write!(f, "server failure ({rcode:?})"),
            Self::Truncated => f.write_str("response truncated before any address"),
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Query(e) => Some(e),
            _ => None,
        }
    }
}

impl From<QueryError> for ResolveError {
    fn from(e: QueryError) -> Self {
        Self::Query(e)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// Question name `www.example.com`, at offset 12.
    const QNAME: &[u8] = b"\x03www\x07example\x03com\x00";
    /// Pointers to `www.example.com` and to its suffix `example.com`.
    const WWW: &[u8] = &[0xC0, 12];
    const APEX: &[u8] = &[0xC0, 16];

    const A: u16 = 1;
    const CNAME: u16 = 5;
    const AAAA: u16 = 28;

    /// A response to `www.example.com A IN` with the given answers.
    fn response(rcode: u8, tc: bool, answers: &[(&[u8], u16, &[u8])]) -> Vec<u8> {
        let flags = 0x81 | if tc { 0x02 } else { 0 };
        let mut buf = vec![
            0x12,
            0x34,
            flags,
            0x80 | rcode,
            0,
            1,
            0,
            answers.len() as u8,
            0,
            0,
            0,
            0,
        ];
        buf.extend_from_slice(QNAME);
        buf.extend_from_slice(&[0, 1, 0, 1]);
        for (owner, rtype, rdata) in answers {
            buf.extend_from_slice(owner);
            buf.extend_from_slice(&rtype.to_be_bytes());
            buf.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            buf.extend_from_slice(rdata);
        }
        buf
    }

    fn resolve(buf: &[u8]) -> Result<IpAddr, ResolveError> {
        resolve_as(buf, IpVersion::V4)
    }

    fn resolve_as(buf: &[u8], version: IpVersion) -> Result<IpAddr, ResolveError> {
        first_address(&Message::parse(buf).unwrap(), version)
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn takes_the_first_address() {
        let buf = response(
            0,
            false,
            &[(WWW, A, &[10, 0, 0, 1]), (WWW, A, &[10, 0, 0, 2])],
        );
        assert_eq!(resolve(&buf).unwrap(), v4(10, 0, 0, 1));
    }

    #[test]
    fn follows_cnames() {
        let buf = response(0, false, &[(WWW, CNAME, APEX), (APEX, A, &[10, 0, 0, 1])]);
        assert_eq!(resolve(&buf).unwrap(), v4(10, 0, 0, 1));
    }

    #[test]
    fn ignores_addresses_of_other_names() {
        let buf = response(0, false, &[(APEX, A, &[6, 6, 6, 6])]);
        assert!(matches!(resolve(&buf), Err(ResolveError::NoAddress)));
    }

    #[test]
    fn stops_on_cname_loops() {
        let buf = response(0, false, &[(WWW, CNAME, APEX), (APEX, CNAME, WWW)]);
        assert!(matches!(resolve(&buf), Err(ResolveError::NoAddress)));
    }

    #[test]
    fn a_cname_to_nowhere_has_no_address() {
        let buf = response(0, false, &[(WWW, CNAME, APEX)]);
        assert!(matches!(resolve(&buf), Err(ResolveError::NoAddress)));
    }

    #[test]
    fn takes_the_version_asked() {
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let buf = response(
            0,
            false,
            &[(WWW, A, &[10, 0, 0, 1]), (WWW, AAAA, &v6.octets())],
        );
        assert_eq!(resolve_as(&buf, IpVersion::V4).unwrap(), v4(10, 0, 0, 1));
        assert_eq!(resolve_as(&buf, IpVersion::V6).unwrap(), IpAddr::V6(v6));
    }

    #[test]
    fn follows_cnames_to_ipv6() {
        let v6 = Ipv6Addr::LOCALHOST;
        let buf = response(0, false, &[(WWW, CNAME, APEX), (APEX, AAAA, &v6.octets())]);
        assert_eq!(resolve_as(&buf, IpVersion::V6).unwrap(), IpAddr::V6(v6));
    }

    #[test]
    fn no_address_of_the_version_asked_is_no_address() {
        let buf = response(0, false, &[(WWW, AAAA, &[0; 16])]);
        assert!(matches!(resolve(&buf), Err(ResolveError::NoAddress)));
        let buf = response(0, false, &[(WWW, A, &[10, 0, 0, 1])]);
        assert!(matches!(
            resolve_as(&buf, IpVersion::V6),
            Err(ResolveError::NoAddress)
        ));
        assert!(matches!(
            resolve(&response(0, false, &[])),
            Err(ResolveError::NoAddress)
        ));
    }

    #[test]
    fn maps_response_codes() {
        assert!(matches!(
            resolve(&response(3, false, &[])),
            Err(ResolveError::NotFound)
        ));
        assert!(matches!(
            resolve(&response(2, false, &[])),
            Err(ResolveError::ServerFailure(Rcode::ServFail))
        ));
        assert!(matches!(
            resolve(&response(5, false, &[])),
            Err(ResolveError::ServerFailure(Rcode::Refused))
        ));
    }

    #[test]
    fn a_truncated_response_still_gives_what_it_holds() {
        let buf = response(0, true, &[(WWW, A, &[10, 0, 0, 1])]);
        assert_eq!(resolve(&buf).unwrap(), v4(10, 0, 0, 1));
        assert!(matches!(
            resolve(&response(0, true, &[])),
            Err(ResolveError::Truncated)
        ));
    }
}
