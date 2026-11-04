# popple-dns

A DNS client over UDP for the io_uring [`slopio`](https://crates.io/crates/slopio):
resolves a name to an IPv4 or IPv6 address, with many queries in flight on one socket,
no allocations in the protocol, and protection against forged responses.

## Limits

- No retransmission: a lost packet means a timeout.
- A single server; `/etc/resolv.conf` isn't read, so no `search` or `ndots`.
- UDP only: a truncated response with no address is an error.
- No cache.
- Linux only.
