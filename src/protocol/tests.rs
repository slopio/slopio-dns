use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

fn example_query() -> Query<'static> {
    Query::new(0xBEEF, Question::new(name("example.com"), RecordType::A))
}

/// Header (QR, RD, RA) + `example.com A IN` question, as a server would echo it.
const RESPONSE_PREFIX: [u8; 29] = [
    0xBE, 0xEF, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, //
    7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, //
    0, 1, 0, 1,
];

/// A response whose answers are all owned by `example.com` (pointer to offset 12).
fn response(answers: &[(u16, &[u8])]) -> Vec<u8> {
    let mut buf = RESPONSE_PREFIX.to_vec();
    buf[7] = answers.len() as u8;
    for (rtype, rdata) in answers {
        buf.extend_from_slice(&[0xC0, 12]);
        buf.extend_from_slice(&rtype.to_be_bytes());
        buf.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(rdata);
    }
    buf
}

#[test]
fn encodes_query() {
    let mut query = example_query();
    query.edns = None;
    let mut out = Vec::new();
    query.encode(&mut out);
    let expected = [
        0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, //
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, //
        0, 1, 0, 1,
    ];
    assert_eq!(out, expected);
}

#[test]
fn encodes_query_with_edns_options() {
    let mut raw = Vec::new();
    EdnsOption {
        code: 10,
        data: &[0xAA; 8],
    }
    .encode(&mut raw);
    let mut query = example_query();
    query.edns.as_mut().unwrap().options = EdnsOptions::parse(&raw).unwrap();

    let mut out = Vec::new();
    query.encode(&mut out);
    assert_eq!(&out[10..12], [0, 1], "ARCOUNT includes OPT");
    let mut opt = vec![0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 12];
    opt.extend_from_slice(&raw);
    assert!(out.ends_with(&opt));

    let parsed = Message::parse(&out).unwrap();
    let options: Vec<_> = parsed.edns.unwrap().options.iter().collect();
    assert_eq!(
        options,
        [EdnsOption {
            code: 10,
            data: &[0xAA; 8]
        }]
    );
}

#[test]
fn parses_compressed_response() {
    let buf = response(&[(1, &[93, 184, 215, 14])]);
    let msg = Message::parse(&buf).unwrap();
    assert!(msg.header.qr && msg.header.rd && msg.header.ra);
    assert_eq!(msg.rcode(), Rcode::NoError);

    let answers: Vec<_> = msg.answers().collect();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].name, name("example.com"));
    assert_eq!(answers[0].ttl, 60);
    assert_eq!(answers[0].data, RData::A(Ipv4Addr::new(93, 184, 215, 14)));
    assert!(msg.is_response_to(&example_query()));
}

#[test]
fn parses_record_types() {
    let aaaa = Ipv6Addr::LOCALHOST.octets();
    // Names in RDATA may point back into the message too.
    let cname = [3, b'w', b'w', b'w', 0xC0, 12];
    let mx = [0, 10, 4, b'm', b'a', b'i', b'l', 0xC0, 12];
    let txt = [3, b'a', b'b', b'c', 0];
    let mut soa = vec![0xC0, 12, 0xC0, 12];
    for v in 1u32..=5 {
        soa.extend_from_slice(&v.to_be_bytes());
    }
    let srv = [0, 1, 0, 2, 1, 187, 0];
    let buf = response(&[
        (28, &aaaa),
        (5, &cname),
        (15, &mx),
        (16, &txt),
        (6, &soa),
        (33, &srv),
        (65, &[1, 2, 3]),
    ]);

    let msg = Message::parse(&buf).unwrap();
    let data: Vec<_> = msg.answers().map(|r| r.data).collect();

    assert_eq!(data[0], RData::Aaaa(Ipv6Addr::LOCALHOST));
    assert!(matches!(data[1], RData::Cname(n) if n == name("www.example.com")));
    assert!(
        matches!(data[2], RData::Mx { preference: 10, exchange } if exchange == name("mail.example.com"))
    );
    let RData::Txt(strings) = data[3] else {
        panic!("{:?}", data[3])
    };
    assert_eq!(strings.iter().collect::<Vec<_>>(), [&b"abc"[..], b""]);
    let RData::Soa(soa) = data[4] else {
        panic!("{:?}", data[4])
    };
    assert_eq!(
        (soa.mname.to_name(), soa.serial, soa.minimum),
        (name("example.com"), 1, 5)
    );
    assert!(
        matches!(data[5], RData::Srv { priority: 1, weight: 2, port: 443, target } if target.is_root())
    );
    assert_eq!(
        data[6],
        RData::Unknown {
            rtype: RecordType::from(65),
            data: &[1, 2, 3]
        }
    );
}

#[test]
fn edns_extends_rcode() {
    let mut buf = RESPONSE_PREFIX.to_vec();
    buf[11] = 1; // ARCOUNT
    buf.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 1, 0, 0x80, 0, 0, 0]);
    let msg = Message::parse(&buf).unwrap();
    let edns = msg.edns.unwrap();
    assert_eq!((edns.udp_payload_size, edns.dnssec_ok), (4096, true));
    assert_eq!(msg.rcode(), Rcode::BadVers);
    assert_eq!(
        msg.additionals().count(),
        0,
        "OPT is not listed as a record"
    );
}

#[test]
fn rejects_pointer_loop() {
    let mut buf = RESPONSE_PREFIX[..12].to_vec();
    buf.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
    assert_eq!(Message::parse(&buf).unwrap_err(), DecodeError::BadPointer);
}

#[test]
fn rejects_forward_pointer() {
    let mut buf = RESPONSE_PREFIX.to_vec();
    buf[7] = 1;
    buf.extend_from_slice(&[0xC0, 100, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4]);
    assert_eq!(Message::parse(&buf).unwrap_err(), DecodeError::BadPointer);
}

#[test]
fn rejects_rdata_length_mismatch() {
    let buf = response(&[(1, &[1, 2, 3])]);
    assert_eq!(
        Message::parse(&buf).unwrap_err(),
        DecodeError::BadRdata(RecordType::A)
    );
    let buf = response(&[(16, &[5, b'a'])]);
    assert_eq!(
        Message::parse(&buf).unwrap_err(),
        DecodeError::BadRdata(RecordType::Txt)
    );
    // A name running past RDLENGTH, even though the message continues.
    let mut buf = response(&[(5, &[3, b'w', b'w'])]);
    buf.extend_from_slice(&[b'w', 0]);
    assert_eq!(
        Message::parse(&buf).unwrap_err(),
        DecodeError::BadRdata(RecordType::Cname)
    );
}

#[test]
fn rejects_truncated_message() {
    let mut buf = Vec::new();
    example_query().encode(&mut buf);
    for len in 0..buf.len() {
        assert_eq!(
            Message::parse(&buf[..len]).unwrap_err(),
            DecodeError::UnexpectedEof,
            "len {len}"
        );
    }
}

#[test]
fn rejects_misplaced_or_duplicate_opt() {
    let mut buf = Vec::new();
    example_query().encode(&mut buf);
    buf[11] = 2; // ARCOUNT
    buf.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(Message::parse(&buf).unwrap_err(), DecodeError::InvalidOpt);

    let buf = response(&[(41, &[])]);
    assert_eq!(Message::parse(&buf).unwrap_err(), DecodeError::InvalidOpt);
}

#[test]
fn response_matching() {
    let query = example_query();
    let mut buf = RESPONSE_PREFIX.to_vec();
    buf[13..20].copy_from_slice(b"EXAMPLE");
    assert!(
        Message::parse(&buf).unwrap().is_response_to(&query),
        "case-insensitive"
    );

    let mut other = buf.clone();
    other[1] ^= 1; // ID
    assert!(!Message::parse(&other).unwrap().is_response_to(&query));

    let mut other = buf.clone();
    other[26] = 28; // QTYPE AAAA
    assert!(!Message::parse(&other).unwrap().is_response_to(&query));

    let mut other = buf.clone();
    other[2] &= !0x80; // QR
    assert!(!Message::parse(&other).unwrap().is_response_to(&query));
}

runtime::define_buf_ring!(Ring, bgid = 0, buffer_size = 4096, ring_size = 4);
runtime::define_buf_ring!(TinyRing, bgid = 1, buffer_size = 128, ring_size = 4);

/// Sends `payload` to a multishot receiver on `port` and hands over the datagram.
async fn receive<S: runtime::BufRingSpec>(
    port: u16,
    payload: &[u8],
) -> runtime::io_driver::operations::sockets::udp::UdpDatagram<S> {
    use runtime_streams::StreamExt;

    let socket = runtime::net::UdpSocket::bind_addr((Ipv4Addr::LOCALHOST, port).into()).unwrap();
    let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    peer.send_to(payload, (Ipv4Addr::LOCALHOST, port)).unwrap();
    let mut stream = runtime::net::UdpMultiRecv::<S>::new(socket);
    stream.next().await.unwrap().unwrap()
}

#[test]
fn parses_from_datagram() {
    runtime::main_thread_with::<(Ring, TinyRing), _>(async {
        let buf = response(&[(1, &[93, 184, 215, 14])]);
        let datagram = receive::<Ring>(19501, &buf).await;
        let msg = Message::from_datagram(&datagram).unwrap();
        assert!(msg.is_response_to(&example_query()));
        assert_eq!(msg.answers().count(), 1);

        // Bigger than the ring's buffers: cut by the kernel, so rejected.
        let mut big = RESPONSE_PREFIX.to_vec();
        big.resize(4096, 0);
        let datagram = receive::<TinyRing>(19502, &big).await;
        assert_eq!(
            Message::from_datagram(&datagram).unwrap_err(),
            DecodeError::TruncatedDatagram
        );
    });
}

#[test]
fn parses_and_displays_names() {
    assert_eq!(name("Example.COM."), name("example.com"));
    assert!(name(".").is_root());
    assert_eq!(name(".").to_string(), ".");
    assert_eq!(name("example.com").as_wire(), &RESPONSE_PREFIX[12..25]);
    assert_eq!(
        Name::from_labels([&b"a.b"[..], b"c\x01"])
            .unwrap()
            .to_string(),
        "a\\.b.c\\001"
    );

    assert_eq!("a..b".parse::<Name>(), Err(NameError::EmptyLabel));
    assert_eq!("a".repeat(64).parse::<Name>(), Err(NameError::LabelTooLong));
    let longest = [
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(61),
    ]
    .join(".");
    assert_eq!(longest.parse::<Name>().unwrap().as_wire().len(), 255);
    assert_eq!(
        format!("{longest}a").parse::<Name>(),
        Err(NameError::NameTooLong)
    );
}

#[test]
fn rebuilds_from_layout_without_parsing() {
    let mut buf = response(&[
        (1, &[93, 184, 215, 14]),
        (5, &[3, b'w', b'w', b'w', 0xC0, 12]),
    ]);
    buf[11] = 1; // ARCOUNT: an OPT record with an option
    buf.extend_from_slice(&[
        0, 0, 41, 0x04, 0xD0, 1, 0, 0x80, 0, 0, 6, 0, 10, 0, 2, 0xAB, 0xCD,
    ]);

    let parsed = Message::parse(&buf).unwrap();
    let rebuilt = Message::with_layout(&buf, parsed.layout());
    assert_eq!(format!("{rebuilt:?}"), format!("{parsed:?}"));
    assert_eq!(rebuilt.edns, parsed.edns);
    assert_eq!(rebuilt.rcode(), Rcode::BadVers);
    assert!(rebuilt.is_response_to(&example_query()));
}

#[test]
fn randomizes_only_the_case_of_letters() {
    let mut n = name("a-1.Example.com");
    n.randomize_case(|| true);
    assert_eq!(n.as_wire(), b"\x03A-1\x07EXAMPLE\x03COM\x00");
    n.randomize_case(|| false);
    assert_eq!(n.to_string(), "a-1.example.com");
}

#[test]
fn exact_name_equality_checks_the_case() {
    let msg = Message::parse(&RESPONSE_PREFIX).unwrap();
    let sent = msg.questions().next().unwrap().name;
    assert!(sent == name("EXAMPLE.com"));
    assert!(!sent.eq_exact(&name("EXAMPLE.com")));
    assert!(sent.eq_exact(&name("example.com")));
    assert!(!sent.eq_exact(&name("example.org")));
}
