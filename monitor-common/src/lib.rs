//! Shared types between the capture agent and any downstream consumers.

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

    /// Round-trip time in microseconds measured from TCP handshake timing.
    ///
    /// Computed as: `SYN-ACK capture timestamp − SYN capture timestamp`.
    /// `0` for packets where RTT has not been measured (e.g., mid-connection
    /// data packets).
    pub rtt_us: u32,

    /// Packet capture timestamp in nanoseconds (from the pcap packet header).
    ///
    /// This is wall-clock time (from the kernel's packet capture clock),
    /// unlike the eBPF monotonic clock. Suitable for absolute timestamping.
    pub timestamp_ns: u64,
}
