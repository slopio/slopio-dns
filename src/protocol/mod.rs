//! DNS wire format (RFC 1035), with EDNS(0) (RFC 6891).
//!
//! Nothing here allocates. Received messages are parsed in place and borrow
//! the receive buffer; queries are appended to a caller-provided buffer.
//! Encoding never compresses: queries hold a single name.

mod edns;
mod error;
mod header;
mod message;
mod name;
mod question;
mod record;
mod types;
mod wire;

#[cfg(test)]
mod tests;

pub use edns::{Edns, EdnsOption, EdnsOptions};
pub use error::{DecodeError, NameError};
pub use header::{HEADER_LEN, Header};
pub(crate) use message::Layout;
pub use message::{Message, Query, Questions, Records};
pub use name::{Labels, Name, NameRef};
pub use question::{Question, QuestionRef};
pub use record::{CharacterStrings, RData, Record, Soa};
pub use types::{Class, Opcode, Rcode, RecordType};
