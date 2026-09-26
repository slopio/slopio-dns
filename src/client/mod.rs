//! The DNS client: a task doing the I/O around [`core::ClientCore`], which
//! holds all the logic.

mod core;
mod resolve;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use runtime::io_driver::operations::sockets::udp::{UdpDatagram, UdpSendTo};
use runtime::net::{UdpMultiRecv, UdpRecvHalf, UdpSendHalf, UdpSocket};
use runtime::runtime::time::timeout;
use runtime::task::Handle;
use runtime::{BufRingSpec, spawn};
use runtime_streams::Stream;

use self::core::ClientCore;
pub use self::core::QueryError;
pub use self::resolve::{IpVersion, ResolveError};
use crate::protocol::{Layout, Message, Name, Query, Question, RecordType};

/// Standard DNS port, for both UDP and TCP.
pub const DNS_PORT: u16 = 53;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Bytes of each buf-ring buffer not available to the payload: the
/// `io_uring_recvmsg_out` header (16) and room for a `sockaddr_in6` (28).
const RECVMSG_OVERHEAD: u32 = 16 + 28;

/// Initial capacity of send buffers: a query with a long name and EDNS fits.
const SEND_BUF_CAPACITY: usize = 512;

/// A DNS client that sends queries to a single upstream server over UDP.
///
/// The socket lives in a dedicated task. Queries only register with the
/// [`ClientCore`] and wake the task; each time the task wakes, whether for new
/// queries, finished sends or received datagrams, it sends everything queued
/// and settles the queries their responses answer. Any number of queries can
/// be in flight at once.
///
/// Datagrams land in the buf ring `S`, which must be installed on the runtime
/// (`main_thread_with::<S, _>`); its buffers bound the size of the responses
/// the client can take.
pub struct DnsClient<S: BufRingSpec> {
    shared: Rc<Shared<S>>,
    task: Option<Handle<()>>,
    timeout: Duration,
}

/// A response that matched its query. Holds its buf-ring buffer until dropped.
pub struct Response<S: BufRingSpec> {
    datagram: UdpDatagram<S>,
    /// Found when the response was validated on receipt.
    layout: Layout,
}

/// A received datagram as the core sees it: its payload.
struct Payload<S: BufRingSpec>(UdpDatagram<S>);

impl<S: BufRingSpec> AsRef<[u8]> for Payload<S> {
    fn as_ref(&self) -> &[u8] {
        self.0.payload()
    }
}

/// What the queries and the client task share.
struct Shared<S: BufRingSpec> {
    core: RefCell<ClientCore<Payload<S>>>,
    /// Queries waiting for their outcome, by ID.
    waiters: RefCell<HashMap<u16, Waker>>,
    task_waker: Cell<Option<Waker>>,
    closed: Cell<bool>,
}

/// Everything only the client task touches.
struct Task<S: BufRingSpec> {
    shared: Rc<Shared<S>>,
    server: SocketAddr,
    stream: UdpMultiRecv<S, UdpRecvHalf>,
    socket: UdpSendHalf,
    /// Sends the kernel hasn't finished. Dropping one would cancel it, so
    /// they're kept until they complete.
    sending: Vec<(u16, UdpSendTo<Vec<u8>>)>,
    /// Encoding buffers, back from completed sends.
    free_bufs: Vec<Vec<u8>>,
}

impl<S: BufRingSpec> DnsClient<S> {
    /// Binds an ephemeral local port in the same address family as `server`
    /// and starts the client task. Must be called on the runtime.
    pub fn new(server: SocketAddr) -> io::Result<Self> {
        let local = match server {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let (recv, send) = UdpSocket::bind_addr(local)?.into_split();
        let shared = Rc::new(Shared {
            core: RefCell::new(ClientCore::new(server)),
            waiters: RefCell::default(),
            task_waker: Cell::new(None),
            closed: Cell::new(false),
        });
        let task = Task {
            shared: shared.clone(),
            server,
            stream: UdpMultiRecv::new(recv),
            socket: send,
            sending: Vec::new(),
            free_bufs: Vec::new(),
        };
        Ok(Self {
            shared,
            task: Some(spawn(task.run())),
            timeout: DEFAULT_TIMEOUT,
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 0x20 encoding, on by default: names are sent in random case, and only
    /// responses echoing it exactly are accepted, which makes them much
    /// harder to forge. Turn it off for servers that don't echo the case.
    pub fn with_case_randomization(self, enabled: bool) -> Self {
        self.shared
            .core
            .borrow_mut()
            .set_case_randomization(enabled);
        self
    }

    pub fn server(&self) -> SocketAddr {
        self.shared.core.borrow().server()
    }

    /// An address of the `version` asked for `name`: the first one the
    /// server gives, after following CNAMEs. Any response without one is an
    /// error, including a truncated one.
    pub async fn resolve(&self, name: Name, version: IpVersion) -> Result<IpAddr, ResolveError> {
        let response = self.query(name, version.record_type()).await?;
        resolve::first_address(&response.message(), version)
    }

    /// Sends a recursive query. It advertises EDNS with a UDP payload size
    /// no larger than what fits in the buf ring's buffers.
    pub async fn query(&self, name: Name, qtype: RecordType) -> Result<Response<S>, QueryError> {
        let mut query = Query::new(0, Question::new(name, qtype));
        if let Some(edns) = &mut query.edns {
            let fits = S::BUFFER_SIZE.saturating_sub(RECVMSG_OVERHEAD);
            edns.udp_payload_size = edns
                .udp_payload_size
                .min(fits.try_into().unwrap_or(u16::MAX));
        }
        self.send(query).await
    }

    /// Queues `query` under a fresh random ID (overwriting `header.id`) and
    /// waits for the matching response.
    ///
    /// Dropping the returned future cancels the query: it's forgotten, and not
    /// sent if the task hasn't got to it yet.
    pub async fn send(&self, query: Query<'static>) -> Result<Response<S>, QueryError> {
        if self.shared.closed.get() {
            return Err(QueryError::Closed);
        }
        let id = self.shared.core.borrow_mut().submit(query)?;
        let _registration = Registration {
            shared: &self.shared,
            id,
        };
        self.shared.wake_task();

        let outcome = poll_fn(|cx| self.shared.poll_outcome(id, cx));
        let (datagram, layout) = timeout(self.timeout, outcome)
            .await
            .map_err(|()| QueryError::Timeout)??;
        Ok(Response { datagram, layout })
    }
}

impl<S: BufRingSpec> Drop for DnsClient<S> {
    fn drop(&mut self) {
        // The task owns the socket: stop it, or it would outlive us.
        if let Some(task) = self.task.take() {
            task.kill();
        }
    }
}

impl<S: BufRingSpec> Shared<S> {
    fn poll_outcome(
        &self,
        id: u16,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(UdpDatagram<S>, Layout), QueryError>> {
        let outcome = self.core.borrow_mut().take_result(id);
        if let Some(outcome) = outcome {
            return Poll::Ready(outcome.map(|(Payload(datagram), layout)| (datagram, layout)));
        }
        if self.closed.get() {
            return Poll::Ready(Err(QueryError::Closed));
        }
        self.waiters.borrow_mut().insert(id, cx.waker().clone());
        Poll::Pending
    }

    fn wake_query(&self, id: u16) {
        let waker = self.waiters.borrow_mut().remove(&id);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn wake_task(&self) {
        if let Some(waker) = self.task_waker.take() {
            waker.wake();
        }
    }

    fn close(&self) {
        self.closed.set(true);
        let waiters = std::mem::take(&mut *self.waiters.borrow_mut());
        waiters.into_values().for_each(Waker::wake);
    }
}

impl<S: BufRingSpec> Task<S> {
    async fn run(mut self) {
        poll_fn(|cx| self.poll(cx)).await;
        self.shared.close();
    }

    /// One pass over everything the task handles. Ready only when the
    /// receive stream has ended for good.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.shared.task_waker.set(Some(cx.waker().clone()));
        self.transmit();
        self.advance_sends(cx);
        self.receive(cx)
    }

    /// Starts a send for every query the core has queued.
    fn transmit(&mut self) {
        loop {
            let mut buf = self
                .free_bufs
                .pop()
                .unwrap_or_else(|| Vec::with_capacity(SEND_BUF_CAPACITY));
            let next = self.shared.core.borrow_mut().poll_transmit(&mut buf);
            let Some(id) = next else {
                self.free_bufs.push(buf);
                return;
            };
            let send = self.socket.socket().send_to(buf, self.server);
            self.sending.push((id, send));
        }
    }

    /// Polls the sends: new ones get submitted, finished ones give their
    /// buffer back, failed ones settle their query.
    fn advance_sends(&mut self, cx: &mut Context<'_>) {
        let (shared, free_bufs) = (&self.shared, &mut self.free_bufs);
        self.sending.retain_mut(|(id, send)| {
            let Poll::Ready((result, buf)) = Pin::new(send).poll(cx) else {
                return true;
            };
            free_bufs.push(buf);
            if let Err(error) = result {
                let settled = shared.core.borrow_mut().on_send_error(*id, error);
                if settled {
                    shared.wake_query(*id);
                }
            }
            false
        });
    }

    /// Feeds every datagram received so far to the core.
    fn receive(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(datagram))) => self.deliver(datagram),
                // Either clears up on a later poll (like ENOBUFS, until
                // buffers come back) or ends the stream, which then yields `None`.
                Poll::Ready(Some(Err(_))) => {}
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn deliver(&self, datagram: UdpDatagram<S>) {
        // Cut by the kernel: can't be a whole response.
        if datagram.is_truncated() {
            return;
        }
        let from = datagram.addr();
        let answered = self
            .shared
            .core
            .borrow_mut()
            .on_datagram(from, Payload(datagram));
        if let Some(id) = answered {
            self.shared.wake_query(id);
        }
    }
}

/// Forgets a query however it ends, including by timeout or drop,
/// releasing any buffer it still holds.
struct Registration<'a, S: BufRingSpec> {
    shared: &'a Shared<S>,
    id: u16,
}

impl<S: BufRingSpec> Drop for Registration<'_, S> {
    fn drop(&mut self) {
        self.shared.core.borrow_mut().cancel(self.id);
        self.shared.waiters.borrow_mut().remove(&self.id);
    }
}

impl<S: BufRingSpec> Response<S> {
    /// The parsed response, rebuilt from where its validation on receipt
    /// found each part: nothing is parsed again.
    pub fn message(&self) -> Message<'_> {
        Message::with_layout(self.datagram.payload(), self.layout)
    }

    pub fn datagram(&self) -> &UdpDatagram<S> {
        &self.datagram
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket as StdUdpSocket;

    use runtime::runtime::join::join;
    use runtime::runtime::select::{SelectResult, select};

    use super::*;
    use crate::protocol::RData;

    runtime::define_buf_ring!(TestRing, bgid = 2, buffer_size = 2048, ring_size = 16);

    /// Runs `script` on a thread with a blocking socket, standing in for the server.
    fn fake_server(script: impl FnOnce(StdUdpSocket) + Send + 'static) -> SocketAddr {
        let socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || script(socket));
        addr
    }

    fn recv_query(socket: &StdUdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = vec![0; 512];
        let (len, from) = socket.recv_from(&mut buf).unwrap();
        buf.truncate(len);
        (buf, from)
    }

    /// Answers `query` with one A record, echoing its header and question.
    fn answer(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
        let mut end = 12;
        while query[end] != 0 {
            end += 1 + usize::from(query[end]);
        }
        let mut response = query[..end + 5].to_vec();
        response[2] |= 0x80; // QR
        response[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        response.extend_from_slice(&ip);
        response
    }

    fn a_record<S: BufRingSpec>(response: &Response<S>) -> Ipv4Addr {
        match response.message().answers().next().map(|r| r.data) {
            Some(RData::A(ip)) => ip,
            other => panic!("expected an A record, got {other:?}"),
        }
    }

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn resolves_a_name_to_an_address() {
        let server = fake_server(|s| {
            let (query, from) = recv_query(&s);
            s.send_to(&answer(&query, [192, 0, 2, 7]), from).unwrap();
        });
        runtime::main_thread_with::<TestRing, _>(async {
            let client = DnsClient::<TestRing>::new(server).unwrap();
            let addr = client
                .resolve(name("api.test"), IpVersion::V4)
                .await
                .unwrap();
            assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
        });
    }

    #[test]
    fn answers_a_query() {
        let server = fake_server(|s| {
            let (query, from) = recv_query(&s);
            s.send_to(&answer(&query, [192, 0, 2, 1]), from).unwrap();
        });
        runtime::main_thread_with::<TestRing, _>(async {
            let client = DnsClient::<TestRing>::new(server).unwrap();
            let response = client
                .query(name("example.com"), RecordType::A)
                .await
                .unwrap();
            assert_eq!(a_record(&response), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(response.message().edns, None, "the fake server drops EDNS");
        });
    }

    #[test]
    fn matches_concurrent_responses_out_of_order() {
        let server = fake_server(|s| {
            let first = recv_query(&s);
            let second = recv_query(&s);
            for (query, from) in [second, first] {
                let ip = if query[13].eq_ignore_ascii_case(&b'a') {
                    [10, 0, 0, 1]
                } else {
                    [10, 0, 0, 2]
                };
                s.send_to(&answer(&query, ip), from).unwrap();
            }
        });
        runtime::main_thread_with::<TestRing, _>(async {
            let client = DnsClient::<TestRing>::new(server).unwrap();
            let (a, b) = join(
                client.query(name("a.test"), RecordType::A),
                client.query(name("b.test"), RecordType::A),
            )
            .await;
            assert_eq!(a_record(&a.unwrap()), Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(a_record(&b.unwrap()), Ipv4Addr::new(10, 0, 0, 2));
        });
    }

    #[test]
    fn ignores_spoofed_responses() {
        let server = fake_server(|s| {
            let (query, from) = recv_query(&s);
            // Right ID and question, but from another port.
            let other = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            other.send_to(&answer(&query, [6, 6, 6, 6]), from).unwrap();
            // Right sender and ID, wrong question.
            let mut wrong = answer(&query, [6, 6, 6, 7]);
            wrong[14] = b'z'; // ezample.com
            s.send_to(&wrong, from).unwrap();
            s.send_to(&answer(&query, [192, 0, 2, 1]), from).unwrap();
        });
        runtime::main_thread_with::<TestRing, _>(async {
            let client = DnsClient::<TestRing>::new(server).unwrap();
            let response = client
                .query(name("example.com"), RecordType::A)
                .await
                .unwrap();
            assert_eq!(a_record(&response), Ipv4Addr::new(192, 0, 2, 1));
        });
    }

    #[test]
    fn times_out_then_keeps_working() {
        let server = fake_server(|s| {
            recv_query(&s); // never answered
            let (query, from) = recv_query(&s);
            s.send_to(&answer(&query, [192, 0, 2, 1]), from).unwrap();
        });
        runtime::main_thread_with::<TestRing, _>(async {
            let client = DnsClient::<TestRing>::new(server)
                .unwrap()
                .with_timeout(Duration::from_millis(100));
            let err = client.query(name("example.com"), RecordType::A).await.err();
            assert!(matches!(err, Some(QueryError::Timeout)), "{err:?}");
            assert!(
                client.shared.core.borrow().is_empty(),
                "timed-out query unregistered"
            );

            let response = client
                .query(name("example.com"), RecordType::A)
                .await
                .unwrap();
            assert_eq!(a_record(&response), Ipv4Addr::new(192, 0, 2, 1));
        });
    }

    #[test]
    fn a_query_cancelled_before_the_task_runs_is_never_sent() {
        let server = fake_server(|s| {
            // Only answers the first query it sees.
            let (query, from) = recv_query(&s);
            s.send_to(&answer(&query, [192, 0, 2, 1]), from).unwrap();
        });
        runtime::main_thread_with::<TestRing, _>(async {
            let client = DnsClient::<TestRing>::new(server)
                .unwrap()
                .with_timeout(Duration::from_millis(500));
            // `select` polls the query once, which queues it, then completes
            // on the ready future and drops it before the task gets to run.
            let cancelled = select(
                client.query(name("cancelled.test"), RecordType::A),
                std::future::ready(()),
            )
            .await;
            assert!(matches!(cancelled, SelectResult::Second(())));
            assert!(client.shared.core.borrow().is_empty());

            let response = client
                .query(name("kept.test"), RecordType::A)
                .await
                .unwrap();
            let question = response.message().questions().next().unwrap();
            assert_eq!(question.name, name("kept.test"));
        });
    }
}
