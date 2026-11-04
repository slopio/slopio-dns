//! A DNS client over UDP for the io_uring runtime [`slopio`].
//!
//! [`DnsClient`] resolves a name to an IPv4 or IPv6 address, with many queries
//! in flight on one socket, no allocations in the protocol, and protection
//! against forged responses (random IDs and ports, 0x20 case randomization).
//! [`protocol`] holds the wire format, usable on its own.
//!
//! ```no_run
//! use slopio_dns::{DnsClient, IpVersion};
//!
//! // Responses land in a buf ring, which must be installed on the runtime.
//! slopio::define_buf_ring!(DnsRing, bgid = 0, buffer_size = 2048, ring_size = 16);
//!
//! slopio::main_thread_with::<DnsRing, _>(async {
//!     let client = DnsClient::<DnsRing>::new("1.1.1.1:53".parse().unwrap()).unwrap();
//!     let addr = client
//!         .resolve("example.com".parse().unwrap(), IpVersion::V4)
//!         .await
//!         .unwrap();
//!     println!("{addr}");
//! });
//! ```
//!
//! Linux only. There is no retransmission, cache, TCP fallback or
//! `/etc/resolv.conf` support yet; see the README for the full list.

pub mod client;
pub mod protocol;

pub use client::{DnsClient, IpVersion, ResolveError};
