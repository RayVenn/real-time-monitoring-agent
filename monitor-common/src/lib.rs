//! Shared types between the capture agent and any downstream consumers.

/// A TCP retransmission detected on an outgoing connection.
#[derive(Clone, Copy, Debug)]
pub struct RetransmitEvent {
    /// Source IPv4 address (local machine) in network byte order.
    pub src_addr: u32,
    /// Destination IPv4 address (remote) in network byte order.
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    /// Time since the original packet was sent (≈ RTO), in microseconds.
    pub rto_us: u32,
    /// How many times this sequence number has been retransmitted so far.
    pub retransmit_count: u32,
    /// Capture timestamp of this retransmit in nanoseconds.
    pub timestamp_ns: u64,
}

/// A network event captured from a live TCP packet stream.
///
/// # IP Address Byte Order
///
/// `src_addr` and `dst_addr` are stored in **network byte order** (big-endian),
/// matching the convention of `u32::from(std::net::Ipv4Addr)`.
///
/// Convert to a displayable address with:
/// ```rust
/// let ip = std::net::Ipv4Addr::from(event.src_addr);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct NetworkEvent {
    /// Source IPv4 address in network byte order (big-endian).
    pub src_addr: u32,

    /// Destination IPv4 address in network byte order (big-endian).
    pub dst_addr: u32,

    /// Source TCP port.
    pub src_port: u16,

    /// Destination TCP port.
    pub dst_port: u16,

    /// TCP payload size in bytes of the data packet that triggered this RTT measurement.
    /// `0` for handshake (SYN/SYN-ACK) RTT events which carry no payload.
    pub payload_bytes: u32,

    /// Round-trip time in microseconds.
    pub rtt_us: u32,

    /// Packet capture timestamp in nanoseconds (from the pcap packet header).
    pub timestamp_ns: u64,
}
