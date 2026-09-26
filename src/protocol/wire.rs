use super::DecodeError;

/// Cursor over a whole message. Names need the whole buffer, not just the
/// remaining bytes, to follow compression pointers.
#[derive(Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self::at(buf, 0)
    }

    pub(crate) fn at(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    pub(crate) fn buf(&self) -> &'a [u8] {
        self.buf
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(bytes)
    }

    pub(crate) fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.read_bytes(N)?.try_into().expect("length checked"))
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_array::<1>()?[0])
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, DecodeError> {
        self.read_array().map(u16::from_be_bytes)
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, DecodeError> {
        self.read_array().map(u32::from_be_bytes)
    }
}

pub(crate) fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Message used when re-reading data that [`super::Message::parse`] already validated.
pub(crate) const VALIDATED: &str = "validated by Message::parse";
