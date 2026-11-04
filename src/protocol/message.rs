use std::fmt;

use slopio::BufRingSpec;
use slopio::io_driver::operations::sockets::udp::UdpDatagram;

use super::header::HEADER_LEN;
use super::record::Entry;
use super::wire::{Reader, VALIDATED};
use super::{DecodeError, Edns, Header, Question, QuestionRef, Rcode, Record};

/// A query to send: one question, optionally with EDNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query<'a> {
    pub header: Header,
    pub question: Question,
    pub edns: Option<Edns<'a>>,
}

/// A received message, parsed in place: everything borrows the buffer.
///
/// [`Message::parse`] validates the whole message up front, so the section
/// iterators can't fail.
#[derive(Clone, Copy)]
pub struct Message<'a> {
    pub header: Header,
    pub edns: Option<Edns<'a>>,
    buf: &'a [u8],
    layout: Layout,
}

/// Where everything is in a validated message, without borrowing it: kept
/// next to the buffer, it rebuilds the [`Message`] without validating again.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Layout {
    header: Header,
    questions: Section,
    answers: Section,
    authorities: Section,
    additionals: Section,
    /// Start of the OPT record, if any.
    opt: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
struct Section {
    start: usize,
    count: u16,
}

pub struct Questions<'a> {
    r: Reader<'a>,
    remaining: u16,
}

/// Iterates a record section. The OPT record is skipped: see [`Message::edns`].
pub struct Records<'a> {
    r: Reader<'a>,
    remaining: u16,
}

impl Query<'_> {
    /// A recursive query advertising EDNS(0).
    pub fn new(id: u16, question: Question) -> Self {
        Self {
            header: Header {
                id,
                rd: true,
                ..Header::default()
            },
            question,
            edns: Some(Edns::default()),
        }
    }

    /// Appends the query to `out`, which can be reused across queries.
    pub fn encode(&self, out: &mut Vec<u8>) {
        self.header
            .encode([1, 0, 0, u16::from(self.edns.is_some())], out);
        self.question.encode(out);
        if let Some(edns) = &self.edns {
            edns.encode(out);
        }
    }
}

impl<'a> Message<'a> {
    /// Parses a datagram's payload in place. The message borrows the datagram,
    /// so its buf-ring buffer is held until the message is dropped.
    ///
    /// Callers must still check [`UdpDatagram::addr`] against the server.
    pub fn from_datagram<S: BufRingSpec>(
        datagram: &'a UdpDatagram<S>,
    ) -> Result<Self, DecodeError> {
        if datagram.is_truncated() {
            return Err(DecodeError::TruncatedDatagram);
        }
        Self::parse(datagram.payload())
    }

    /// Validates a message. Bytes after the last counted record are ignored.
    pub fn parse(buf: &'a [u8]) -> Result<Self, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::UnexpectedEof);
        }
        let mut r = Reader::new(buf);
        let (header, [qd, an, ns, ar]) = Header::decode(&mut r)?;

        let questions = Section {
            start: r.pos(),
            count: qd,
        };
        for _ in 0..qd {
            QuestionRef::read(&mut r)?;
        }

        let answers = Section {
            start: r.pos(),
            count: an,
        };
        skip_records(&mut r, an)?;
        let authorities = Section {
            start: r.pos(),
            count: ns,
        };
        skip_records(&mut r, ns)?;

        let additionals = Section {
            start: r.pos(),
            count: ar,
        };
        let mut opt = None;
        let mut edns = None;
        for _ in 0..ar {
            let start = r.pos();
            match Record::read_entry(&mut r)? {
                Entry::Record(_) => {}
                Entry::Opt(_) if edns.is_some() => return Err(DecodeError::InvalidOpt),
                Entry::Opt(found) => (opt, edns) = (Some(start), Some(found)),
            }
        }

        let layout = Layout {
            header,
            questions,
            answers,
            authorities,
            additionals,
            opt,
        };
        Ok(Self {
            header,
            edns,
            buf,
            layout,
        })
    }

    /// Where everything is in this message, to rebuild it later with
    /// [`Message::with_layout`].
    pub(crate) fn layout(&self) -> Layout {
        self.layout
    }

    /// Rebuilds a message from the layout [`Message::parse`] found for the
    /// same `buf`, without validating again. With another buffer, the
    /// iterators may panic.
    pub(crate) fn with_layout(buf: &'a [u8], layout: Layout) -> Self {
        let edns = layout.opt.map(|start| {
            match Record::read_entry(&mut Reader::at(buf, start)).expect(VALIDATED) {
                Entry::Opt(edns) => edns,
                Entry::Record(_) => unreachable!("the layout points at the OPT record"),
            }
        });
        Self {
            header: layout.header,
            edns,
            buf,
            layout,
        }
    }

    pub fn questions(&self) -> Questions<'a> {
        Questions {
            r: Reader::at(self.buf, self.layout.questions.start),
            remaining: self.layout.questions.count,
        }
    }

    pub fn answers(&self) -> Records<'a> {
        self.records(self.layout.answers)
    }

    pub fn authorities(&self) -> Records<'a> {
        self.records(self.layout.authorities)
    }

    pub fn additionals(&self) -> Records<'a> {
        self.records(self.layout.additionals)
    }

    fn records(&self, section: Section) -> Records<'a> {
        Records {
            r: Reader::at(self.buf, section.start),
            remaining: section.count,
        }
    }

    /// Full response code, combining the header bits with the EDNS extension.
    pub fn rcode(&self) -> Rcode {
        let low = u16::from(self.header.rcode) & 0x0F;
        let high = self
            .edns
            .as_ref()
            .map_or(0, |e| u16::from(e.extended_rcode));
        Rcode::from(high << 4 | low)
    }

    /// Whether `self` answers `query` (RFC 5452 §9.1): it is a response
    /// with the same ID, opcode and question.
    ///
    /// Callers must also check the source address and port.
    pub fn is_response_to(&self, query: &Query<'_>) -> bool {
        self.header.qr
            && !query.header.qr
            && self.header.id == query.header.id
            && self.header.opcode == query.header.opcode
            && self.layout.questions.count == 1
            && self.questions().next().is_some_and(|q| q == query.question)
    }
}

/// Answer and authority sections, where OPT is not allowed.
fn skip_records(r: &mut Reader<'_>, count: u16) -> Result<(), DecodeError> {
    for _ in 0..count {
        if let Entry::Opt(_) = Record::read_entry(r)? {
            return Err(DecodeError::InvalidOpt);
        }
    }
    Ok(())
}

impl<'a> Iterator for Questions<'a> {
    type Item = QuestionRef<'a>;

    fn next(&mut self) -> Option<QuestionRef<'a>> {
        self.remaining = self.remaining.checked_sub(1)?;
        Some(QuestionRef::read(&mut self.r).expect(VALIDATED))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (
            usize::from(self.remaining),
            Some(usize::from(self.remaining)),
        )
    }
}

impl ExactSizeIterator for Questions<'_> {}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Record<'a>> {
        loop {
            self.remaining = self.remaining.checked_sub(1)?;
            if let Entry::Record(record) = Record::read_entry(&mut self.r).expect(VALIDATED) {
                return Some(record);
            }
        }
    }
}

impl fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("header", &self.header)
            .field("questions", &DebugIter(|| self.questions()))
            .field("answers", &DebugIter(|| self.answers()))
            .field("authorities", &DebugIter(|| self.authorities()))
            .field("additionals", &DebugIter(|| self.additionals()))
            .field("edns", &self.edns)
            .finish()
    }
}

struct DebugIter<F>(F);

impl<F, I> fmt::Debug for DebugIter<F>
where
    F: Fn() -> I,
    I: Iterator<Item: fmt::Debug>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries((self.0)()).finish()
    }
}
