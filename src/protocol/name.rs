use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use super::wire::Reader;
use super::{DecodeError, NameError};

const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255;

/// An owned domain name, stored inline in uncompressed wire form (length-prefixed
/// labels ending with the empty root label), so it never allocates.
///
/// Equality and hashing ignore ASCII case, as DNS requires.
#[derive(Clone)]
pub struct Name {
    wire: [u8; MAX_NAME_LEN],
    len: u8,
}

/// A name inside a received message, possibly compressed. Borrows the message.
#[derive(Clone, Copy)]
pub struct NameRef<'a> {
    msg: &'a [u8],
    start: usize,
}

/// Iterator over a name's labels, excluding the root label.
#[derive(Clone)]
pub struct Labels<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Name {
    pub fn root() -> Self {
        Self {
            wire: [0; MAX_NAME_LEN],
            len: 1,
        }
    }

    pub fn from_labels<I>(labels: I) -> Result<Self, NameError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut name = Self::root();
        let mut len = 0;
        for label in labels {
            let label = label.as_ref();
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(NameError::LabelTooLong);
            }
            // Length byte, label, and the root label still to come.
            if len + 1 + label.len() + 1 > MAX_NAME_LEN {
                return Err(NameError::NameTooLong);
            }
            name.wire[len] = label.len() as u8;
            name.wire[len + 1..len + 1 + label.len()].copy_from_slice(label);
            len += 1 + label.len();
        }
        name.len = (len + 1) as u8;
        Ok(name)
    }

    /// Uncompressed wire form, including the root label.
    pub fn as_wire(&self) -> &[u8] {
        &self.wire[..usize::from(self.len)]
    }

    pub fn labels(&self) -> Labels<'_> {
        Labels {
            buf: self.as_wire(),
            pos: 0,
        }
    }

    pub fn is_root(&self) -> bool {
        self.len == 1
    }

    /// Sets the case of every ASCII letter from `upper`, called once per
    /// letter. With random bits, this is 0x20 encoding: servers echo the
    /// question as sent, so a forged response must also guess the case.
    pub fn randomize_case(&mut self, mut upper: impl FnMut() -> bool) {
        let len = usize::from(self.len);
        let mut pos = 0;
        // The last byte is the root label.
        while pos + 1 < len {
            let label_len = usize::from(self.wire[pos]);
            for b in &mut self.wire[pos + 1..pos + 1 + label_len] {
                if b.is_ascii_alphabetic() {
                    *b = if upper() {
                        b.to_ascii_uppercase()
                    } else {
                        b.to_ascii_lowercase()
                    };
                }
            }
            pos += 1 + label_len;
        }
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_wire());
    }
}

impl<'a> NameRef<'a> {
    /// Validates the name at the reader's position and moves the reader past it.
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let buf = r.buf();
        let start = r.pos();
        let mut pos = start;
        // Where the reader resumes: after the first pointer, or after the root label.
        let mut resume = None;
        // Each pointer must land before the start of the segment containing
        // it, so every jump goes strictly backwards and loops are impossible.
        let mut segment_start = start;
        let mut wire_len = 1;

        loop {
            let len = *buf.get(pos).ok_or(DecodeError::UnexpectedEof)?;
            match len & 0xC0 {
                0x00 => {
                    pos += 1;
                    if len == 0 {
                        break;
                    }
                    let len = usize::from(len);
                    if pos + len > buf.len() {
                        return Err(DecodeError::UnexpectedEof);
                    }
                    wire_len += len + 1;
                    if wire_len > MAX_NAME_LEN {
                        return Err(DecodeError::NameTooLong);
                    }
                    pos += len;
                }
                0xC0 => {
                    let low = *buf.get(pos + 1).ok_or(DecodeError::UnexpectedEof)?;
                    let target = usize::from(len & 0x3F) << 8 | usize::from(low);
                    if target >= segment_start {
                        return Err(DecodeError::BadPointer);
                    }
                    resume.get_or_insert(pos + 2);
                    segment_start = target;
                    pos = target;
                }
                _ => return Err(DecodeError::InvalidLabelType(len)),
            }
        }

        r.set_pos(resume.unwrap_or(pos));
        Ok(Self { msg: buf, start })
    }

    pub fn labels(&self) -> Labels<'a> {
        Labels {
            buf: self.msg,
            pos: self.start,
        }
    }

    pub fn is_root(&self) -> bool {
        self.labels().next().is_none()
    }

    /// Copies the name out of the message, decompressed. Does not allocate.
    pub fn to_name(&self) -> Name {
        Name::from_labels(self.labels()).expect("validated when read")
    }

    /// Byte-for-byte equality, case included, unlike `==`. Checks that a
    /// server echoed a 0x20-encoded name as sent.
    pub fn eq_exact(&self, other: &Name) -> bool {
        labels_eq_by(self.labels(), other.labels(), |a, b| a == b)
    }
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    /// Only ever walks validated names; malformed input just ends the iteration.
    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            let len = *self.buf.get(self.pos)?;
            if len & 0xC0 == 0xC0 {
                let low = *self.buf.get(self.pos + 1)?;
                self.pos = usize::from(len & 0x3F) << 8 | usize::from(low);
                continue;
            }
            if len == 0 {
                return None;
            }
            let label = self
                .buf
                .get(self.pos + 1..self.pos + 1 + usize::from(len))?;
            self.pos += 1 + usize::from(len);
            return Some(label);
        }
    }
}

fn labels_eq(a: Labels<'_>, b: Labels<'_>) -> bool {
    labels_eq_by(a, b, <[u8]>::eq_ignore_ascii_case)
}

fn labels_eq_by(mut a: Labels<'_>, mut b: Labels<'_>, eq: impl Fn(&[u8], &[u8]) -> bool) -> bool {
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) if eq(x, y) => {}
            _ => return false,
        }
    }
}

/// Dotted form without the trailing dot; the root prints as `.`.
/// Dots and backslashes inside labels are escaped, as are non-printable bytes (`\DDD`).
fn fmt_labels(mut labels: Labels<'_>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let Some(first) = labels.next() else {
        return f.write_str(".");
    };
    for (i, label) in std::iter::once(first).chain(labels).enumerate() {
        if i > 0 {
            f.write_str(".")?;
        }
        for &b in label {
            match b {
                b'.' | b'\\' => write!(f, "\\{}", b as char)?,
                0x21..=0x7E => write!(f, "{}", b as char)?,
                _ => write!(f, "\\{b:03}")?,
            }
        }
    }
    Ok(())
}

impl FromStr for Name {
    type Err = NameError;

    /// Parses dotted form; a trailing dot is optional and `.` or `""` is the root.
    /// Escapes like `\.` are not supported.
    fn from_str(s: &str) -> Result<Self, NameError> {
        let s = s.strip_suffix('.').unwrap_or(s);
        if s.is_empty() {
            return Ok(Self::root());
        }
        Self::from_labels(s.split('.'))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_labels(self.labels(), f)
    }
}

impl fmt::Display for NameRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_labels(self.labels(), f)
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

impl fmt::Debug for NameRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NameRef({self})")
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        // Length bytes are at most 63, below 'A', so lowercasing leaves them alone.
        self.as_wire().eq_ignore_ascii_case(other.as_wire())
    }
}

impl Eq for Name {}

impl PartialEq for NameRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        labels_eq(self.labels(), other.labels())
    }
}

impl Eq for NameRef<'_> {}

impl PartialEq<Name> for NameRef<'_> {
    fn eq(&self, other: &Name) -> bool {
        labels_eq(self.labels(), other.labels())
    }
}

impl PartialEq<NameRef<'_>> for Name {
    fn eq(&self, other: &NameRef<'_>) -> bool {
        other == self
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self.as_wire() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}
