//! The client's logic as a state machine, with no I/O: no socket, no clock.
//! The I/O layer feeds it events (queries, datagrams, send errors) and carries
//! out what it asks for (datagrams to send, waiters to wake). Each query keeps
//! its waiter, opaque to the core: a `Waker` in the client, anything in tests.

use std::collections::VecDeque;
use std::collections::hash_map::Entry;
use std::fmt;
use std::io;
use std::net::SocketAddr;

use rustc_hash::FxHashMap;

use crate::protocol::{Layout, Message, Query};

#[derive(Debug)]
pub enum QueryError {
    Io(io::Error),
    /// No matching response before the client's timeout.
    Timeout,
    /// The client task stopped; the client can't send or receive anymore.
    Closed,
    /// All 65536 transaction IDs are in use.
    TooManyInFlight,
}

/// Where a query is in its life. Cancelling removes it altogether.
#[derive(Debug)]
enum QueryState<D> {
    /// Registered, waiting for its turn to be sent.
    Queued,
    /// On the wire, waiting for its response.
    Sent,
    /// A response matched; its layout saves parsing it again.
    Answered(D, Layout),
    /// The send failed.
    Failed(io::Error),
}

impl<D> QueryState<D> {
    /// Queued → Sent.
    fn send(self) -> Result<Self, Self> {
        match self {
            Self::Queued => Ok(Self::Sent),
            other => Err(other),
        }
    }

    /// Sent → Answered. A response can't answer a query before it's sent,
    /// nor one already settled; the datagram is dropped then.
    fn answer(self, datagram: D, layout: Layout) -> Result<Self, Self> {
        match self {
            Self::Sent => Ok(Self::Answered(datagram, layout)),
            other => Err(other),
        }
    }

    /// Sent → Failed.
    fn fail(self, error: io::Error) -> Result<Self, Self> {
        match self {
            Self::Sent => Ok(Self::Failed(error)),
            other => Err(other),
        }
    }

    fn is_settled(&self) -> bool {
        matches!(self, Self::Answered(..) | Self::Failed(_))
    }

    /// Answered or Failed → the query's outcome; anything else is still going.
    fn settle(self) -> Result<Result<(D, Layout), QueryError>, Self> {
        match self {
            Self::Answered(datagram, layout) => Ok(Ok((datagram, layout))),
            Self::Failed(error) => Ok(Err(QueryError::Io(error))),
            other => Err(other),
        }
    }
}

struct InFlight<D, W> {
    query: Query<'static>,
    /// Sent with 0x20 encoding: the response must echo the case exactly.
    exact_case: bool,
    state: QueryState<D>,
    /// To wake once the query settles, if it registered.
    waiter: Option<W>,
}

/// A query that just settled, and its waiter to wake, if it registered one.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Settled<W> {
    pub(super) id: u16,
    pub(super) waiter: Option<W>,
}

impl<D, W> InFlight<D, W> {
    /// Runs a transition. Returns whether it applied; if rejected, the state
    /// is left as it was.
    fn apply(
        &mut self,
        transition: impl FnOnce(QueryState<D>) -> Result<QueryState<D>, QueryState<D>>,
    ) -> bool {
        // `Queued` holds nothing, so it's a free placeholder meanwhile.
        let state = std::mem::replace(&mut self.state, QueryState::Queued);
        let (state, applied) = match transition(state) {
            Ok(next) => (next, true),
            Err(unchanged) => (unchanged, false),
        };
        self.state = state;
        applied
    }

    /// Settles the query with `transition`, handing back its waiter; `None`
    /// if the transition was rejected.
    fn settle_with(
        &mut self,
        id: u16,
        transition: impl FnOnce(QueryState<D>) -> Result<QueryState<D>, QueryState<D>>,
    ) -> Option<Settled<W>> {
        self.apply(transition).then(|| Settled {
            id,
            waiter: self.waiter.take(),
        })
    }
}

/// Every query in flight against one server. `D` is a received datagram:
/// `UdpDatagram` in the client, plain bytes in tests. `W` is what to wake
/// when a query settles.
pub(super) struct ClientCore<D, W> {
    server: SocketAddr,
    queries: FxHashMap<u16, InFlight<D, W>>,
    /// IDs waiting to be sent, in submission order. May hold IDs cancelled
    /// since; they're skipped.
    outbox: VecDeque<u16>,
    /// 0x20 encoding: send names in random case, and only accept responses
    /// echoing it exactly.
    case_randomization: bool,
}

impl<D: AsRef<[u8]>, W> ClientCore<D, W> {
    /// A core with 0x20 encoding on.
    pub(super) fn new(server: SocketAddr) -> Self {
        Self {
            server,
            queries: FxHashMap::default(),
            outbox: VecDeque::new(),
            case_randomization: true,
        }
    }

    pub(super) fn server(&self) -> SocketAddr {
        self.server
    }

    /// Turns 0x20 encoding on or off, for queries submitted from now on
    /// (and responses to them). Off for servers that don't echo the case.
    pub(super) fn set_case_randomization(&mut self, enabled: bool) {
        self.case_randomization = enabled;
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    /// Registers `query` under a random unused ID and, with 0x20 encoding,
    /// a random case (RFC 5452: both make responses hard to spoof), and
    /// queues it for sending.
    pub(super) fn submit(&mut self, mut query: Query<'static>) -> Result<u16, QueryError> {
        if self.queries.len() > usize::from(u16::MAX) {
            return Err(QueryError::TooManyInFlight);
        }
        let id = std::iter::repeat_with(rand::random::<u16>)
            .find(|id| !self.queries.contains_key(id))
            .expect("a free ID exists");
        query.header.id = id;
        if self.case_randomization {
            query.question.name.randomize_case(random_bits());
        }
        self.queries.insert(
            id,
            InFlight {
                query,
                exact_case: self.case_randomization,
                state: QueryState::Queued,
                waiter: None,
            },
        );
        self.outbox.push_back(id);
        Ok(id)
    }

    /// Forgets a query, whatever its state. A response arriving later is
    /// then unknown and dropped.
    pub(super) fn cancel(&mut self, id: u16) {
        self.queries.remove(&id);
    }

    /// Encodes the next query to send into `buf` and marks it sent.
    pub(super) fn poll_transmit(&mut self, buf: &mut Vec<u8>) -> Option<u16> {
        while let Some(id) = self.outbox.pop_front() {
            let Some(entry) = self.queries.get_mut(&id) else {
                continue; // cancelled
            };
            // Rejected when already sent: the ID was queued twice (cancelled, then reused).
            if entry.apply(QueryState::send) {
                buf.clear();
                entry.query.encode(buf);
                return Some(id);
            }
        }
        None
    }

    /// Settles the query `datagram` answers. Anything that answers nothing in
    /// flight is dropped.
    pub(super) fn on_datagram(&mut self, from: SocketAddr, datagram: D) -> Option<Settled<W>> {
        let id = transaction_id(datagram.as_ref())?;
        let entry = self.queries.get_mut(&id)?;
        let layout = answer_layout(
            self.server,
            &entry.query,
            entry.exact_case,
            from,
            datagram.as_ref(),
        )?;
        entry.settle_with(id, |s| s.answer(datagram, layout))
    }

    /// Settles a query whose send failed.
    pub(super) fn on_send_error(&mut self, id: u16, error: io::Error) -> Option<Settled<W>> {
        self.queries
            .get_mut(&id)?
            .settle_with(id, |s| s.fail(error))
    }

    /// Takes a settled query's outcome, which also forgets the query. If it
    /// hasn't settled, `register` sets (or keeps) the waiter to wake once it does.
    pub(super) fn poll_outcome(
        &mut self,
        id: u16,
        register: impl FnOnce(&mut Option<W>),
    ) -> Option<Result<(D, Layout), QueryError>> {
        let Entry::Occupied(mut query) = self.queries.entry(id) else {
            return None;
        };
        if !query.get().state.is_settled() {
            register(&mut query.get_mut().waiter);
            return None;
        }
        query.remove().state.settle().ok()
    }

    /// Takes every registered waiter, to wake them all when the client stops.
    pub(super) fn take_waiters(&mut self) -> impl Iterator<Item = W> + '_ {
        self.queries
            .values_mut()
            .filter_map(|query| query.waiter.take())
    }
}

/// If `payload`, received from `from`, answers `query` sent to `server` (right
/// sender, and a response with the query's ID, opcode and question, in the
/// exact case sent if `exact_case`), the layout its validation found.
fn answer_layout(
    server: SocketAddr,
    query: &Query<'_>,
    exact_case: bool,
    from: SocketAddr,
    payload: &[u8],
) -> Option<Layout> {
    if from != server {
        return None;
    }
    let message = Message::parse(payload).ok()?;
    let answers = message.is_response_to(query)
        && (!exact_case
            || message
                .questions()
                .next()
                .is_some_and(|q| q.name.eq_exact(&query.question.name)));
    answers.then(|| message.layout())
}

/// Random bits, drawn 64 at a time.
fn random_bits() -> impl FnMut() -> bool {
    let (mut bits, mut left) = (0u64, 0u32);
    move || {
        if left == 0 {
            (bits, left) = (rand::random(), u64::BITS);
        }
        let bit = bits & 1 == 1;
        (bits, left) = (bits >> 1, left - 1);
        bit
    }
}

/// The first two bytes of a DNS header are the transaction ID.
fn transaction_id(message: &[u8]) -> Option<u16> {
    message.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Timeout => f.write_str("DNS query timed out"),
            Self::Closed => f.write_str("DNS client task has stopped"),
            Self::TooManyInFlight => f.write_str("all transaction IDs are in use"),
        }
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for QueryError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::protocol::{Name, Question, RecordType};

    const SERVER: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53);
    const STRANGER: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 66)), 53);

    fn query(name: &str) -> Query<'static> {
        Query::new(
            0,
            Question::new(name.parse::<Name>().unwrap(), RecordType::A),
        )
    }

    /// What the server would send back: the query itself, flagged as a response.
    fn respond(wire: &[u8]) -> Vec<u8> {
        let mut response = wire.to_vec();
        response[2] |= 0x80;
        response
    }

    fn core() -> ClientCore<Vec<u8>, u32> {
        ClientCore::new(SERVER)
    }

    /// The ID of the query `datagram` settles, if any.
    fn answered(
        core: &mut ClientCore<Vec<u8>, u32>,
        from: SocketAddr,
        datagram: Vec<u8>,
    ) -> Option<u16> {
        core.on_datagram(from, datagram).map(|settled| settled.id)
    }

    /// Submits and sends one query, returning its ID and wire form.
    fn sent(core: &mut ClientCore<Vec<u8>, u32>, name: &str) -> (u16, Vec<u8>) {
        let id = core.submit(query(name)).unwrap();
        let mut wire = Vec::new();
        assert_eq!(core.poll_transmit(&mut wire), Some(id));
        (id, wire)
    }

    #[test]
    fn a_query_goes_queued_sent_answered() {
        let mut core = core();
        let id = core.submit(query("example.com")).unwrap();
        assert!(
            core.poll_outcome(id, |_| {}).is_none(),
            "queued: nothing yet"
        );

        let mut wire = Vec::new();
        assert_eq!(core.poll_transmit(&mut wire), Some(id));
        assert_eq!(&wire[..2], id.to_be_bytes(), "sent under its ID");
        assert_eq!(core.poll_transmit(&mut wire), None, "sent only once");
        assert!(core.poll_outcome(id, |_| {}).is_none(), "sent: nothing yet");

        let response = respond(&wire);
        assert_eq!(answered(&mut core, SERVER, response.clone()), Some(id));
        assert_eq!(core.poll_outcome(id, |_| {}).unwrap().unwrap().0, response);
        assert!(core.is_empty(), "taking the result forgets the query");
    }

    #[test]
    fn sends_in_submission_order() {
        let mut core = core();
        let ids: Vec<_> = ["a.test", "b.test", "c.test"]
            .map(|n| core.submit(query(n)).unwrap())
            .into();
        let mut buf = Vec::new();
        let sent: Vec<_> = std::iter::from_fn(|| core.poll_transmit(&mut buf)).collect();
        assert_eq!(sent, ids);
    }

    #[test]
    fn drops_what_answers_nothing() {
        let mut core = core();
        let (id, wire) = sent(&mut core, "example.com");
        let response = respond(&wire);

        assert_eq!(
            answered(&mut core, STRANGER, response.clone()),
            None,
            "wrong sender"
        );

        let mut other_id = response.clone();
        other_id[0] ^= 0xFF;
        assert_eq!(answered(&mut core, SERVER, other_id), None, "unknown ID");

        let mut wrong_question = response.clone();
        wrong_question[14] = b'z';
        assert_eq!(
            answered(&mut core, SERVER, wrong_question),
            None,
            "wrong question"
        );

        assert_eq!(
            answered(&mut core, SERVER, wire.clone()),
            None,
            "not a response"
        );
        assert_eq!(
            answered(&mut core, SERVER, response[..20].to_vec()),
            None,
            "malformed"
        );
        assert_eq!(answered(&mut core, SERVER, vec![]), None, "empty");

        assert!(core.poll_outcome(id, |_| {}).is_none(), "still waiting");
        assert_eq!(answered(&mut core, SERVER, response), Some(id));
    }

    /// The question's name in `wire`, as sent.
    fn sent_name(wire: &[u8]) -> Name {
        let message = Message::parse(wire).unwrap();
        message.questions().next().unwrap().name.to_name()
    }

    #[test]
    fn sends_names_in_random_case() {
        let mut core = core();
        let names: Vec<_> = (0..20)
            .map(|_| sent_name(&sent(&mut core, "example.com").1))
            .collect();
        let example: Name = "example.com".parse().unwrap();
        assert!(names.iter().all(|n| *n == example), "same name, case aside");
        let spellings: HashSet<_> = names.iter().map(Name::to_string).collect();
        assert!(spellings.len() > 1, "the case varies: {spellings:?}");
    }

    #[test]
    fn rejects_a_response_in_another_case() {
        let mut core = core();
        let (id, wire) = sent(&mut core, "example.com");
        let mut recased = respond(&wire);
        recased[13] ^= 0x20; // the first letter's case
        assert_eq!(answered(&mut core, SERVER, recased), None);
        assert_eq!(answered(&mut core, SERVER, respond(&wire)), Some(id));
    }

    #[test]
    fn without_case_randomization_the_case_is_kept_and_ignored() {
        let mut core = core();
        core.set_case_randomization(false);
        let (id, wire) = sent(&mut core, "Example.COM");
        assert_eq!(sent_name(&wire).to_string(), "Example.COM");

        let mut lowered = respond(&wire);
        lowered[13..24].make_ascii_lowercase(); // length bytes are below 'A'
        assert_eq!(answered(&mut core, SERVER, lowered), Some(id));
    }

    #[test]
    fn switching_case_randomization_leaves_queries_in_flight_alone() {
        let mut core = core();
        let (id, wire) = sent(&mut core, "example.com");
        core.set_case_randomization(false);
        let mut recased = respond(&wire);
        recased[13] ^= 0x20;
        assert_eq!(answered(&mut core, SERVER, recased), None, "still exact");
        assert_eq!(answered(&mut core, SERVER, respond(&wire)), Some(id));
    }

    #[test]
    fn hands_back_the_waiter_when_a_query_settles() {
        let mut core = core();
        let (id, wire) = sent(&mut core, "example.com");
        assert!(core.poll_outcome(id, |w| *w = Some(7)).is_none());
        let settled = core.on_datagram(SERVER, respond(&wire));
        assert_eq!(
            settled,
            Some(Settled {
                id,
                waiter: Some(7)
            })
        );

        let (id, _) = sent(&mut core, "failed.test");
        assert!(core.poll_outcome(id, |w| *w = Some(8)).is_none());
        let settled = core.on_send_error(id, io::Error::other("unreachable"));
        assert_eq!(
            settled,
            Some(Settled {
                id,
                waiter: Some(8)
            })
        );
    }

    #[test]
    fn cancelling_drops_the_waiter_with_the_query() {
        let mut core = core();
        let (id, wire) = sent(&mut core, "example.com");
        core.poll_outcome(id, |w| *w = Some(7));
        core.cancel(id);
        assert_eq!(core.take_waiters().count(), 0);
        assert_eq!(core.on_datagram(SERVER, respond(&wire)), None);
    }

    #[test]
    fn takes_every_waiter_on_close() {
        let mut core = core();
        for (waiter, name) in [(1, "a.test"), (2, "b.test")] {
            let (id, _) = sent(&mut core, name);
            core.poll_outcome(id, |w| *w = Some(waiter));
        }
        let mut waiters: Vec<_> = core.take_waiters().collect();
        waiters.sort();
        assert_eq!(waiters, [1, 2]);
        assert_eq!(core.take_waiters().count(), 0, "taken once");
    }

    #[test]
    fn takes_only_the_first_response() {
        let mut core = core();
        let (id, wire) = sent(&mut core, "example.com");
        assert_eq!(answered(&mut core, SERVER, respond(&wire)), Some(id));
        assert_eq!(
            answered(&mut core, SERVER, respond(&wire)),
            None,
            "duplicate"
        );
    }

    #[test]
    fn a_response_cannot_answer_a_query_not_yet_sent() {
        let mut core = core();
        // So the forged response below has the right case.
        core.set_case_randomization(false);
        let id = core.submit(query("example.com")).unwrap();
        // Forge the response the server would give once it's sent.
        let mut expected = Vec::new();
        query("example.com").encode(&mut expected);
        expected[..2].copy_from_slice(&id.to_be_bytes());
        assert_eq!(answered(&mut core, SERVER, respond(&expected)), None);
    }

    #[test]
    fn a_cancelled_query_is_not_sent_nor_answered() {
        let mut core = core();
        let id = core.submit(query("cancelled.test")).unwrap();
        core.cancel(id);
        assert_eq!(core.poll_transmit(&mut Vec::new()), None);

        let (id, wire) = sent(&mut core, "late.test");
        core.cancel(id);
        assert_eq!(answered(&mut core, SERVER, respond(&wire)), None);
        assert!(core.is_empty());
    }

    #[test]
    fn a_failed_send_settles_the_query() {
        let mut core = core();
        let (id, _) = sent(&mut core, "example.com");
        assert!(
            core.on_send_error(id, io::Error::other("unreachable"))
                .is_some()
        );
        assert!(matches!(
            core.poll_outcome(id, |_| {}),
            Some(Err(QueryError::Io(_)))
        ));
    }

    #[test]
    fn a_send_error_cannot_fail_a_settled_query() {
        let mut core = core();
        let (id, wire) = sent(&mut core, "example.com");
        answered(&mut core, SERVER, respond(&wire));
        assert!(core.on_send_error(id, io::Error::other("late")).is_none());
        assert!(core.poll_outcome(id, |_| {}).unwrap().is_ok());
    }

    #[test]
    fn ids_are_unique_among_queries_in_flight() {
        let mut core = core();
        let ids: HashSet<_> = (0..10_000)
            .map(|_| core.submit(query("example.com")).unwrap())
            .collect();
        assert_eq!(ids.len(), 10_000);
    }
}
