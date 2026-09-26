use super::wire::{Reader, put_u16};
use super::{Class, DecodeError, Name, NameRef, RecordType};

/// A question to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: Class,
}

/// A question inside a received message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuestionRef<'a> {
    pub name: NameRef<'a>,
    pub qtype: RecordType,
    pub qclass: Class,
}

impl Question {
    /// A question in the `IN` class.
    pub fn new(name: Name, qtype: RecordType) -> Self {
        Self {
            name,
            qtype,
            qclass: Class::In,
        }
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        self.name.encode(out);
        put_u16(out, self.qtype.into());
        put_u16(out, self.qclass.into());
    }
}

impl<'a> QuestionRef<'a> {
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(Self {
            name: NameRef::read(r)?,
            qtype: r.read_u16()?.into(),
            qclass: r.read_u16()?.into(),
        })
    }
}

impl PartialEq<Question> for QuestionRef<'_> {
    fn eq(&self, other: &Question) -> bool {
        self.name == other.name && self.qtype == other.qtype && self.qclass == other.qclass
    }
}
