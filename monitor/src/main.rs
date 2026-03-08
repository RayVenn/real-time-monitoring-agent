//! Userspace agent for the network latency monitor (pcap edition).
//!
//! This binary:
//!   1. Opens a live pcap capture on a network interface
//!   2. Parses Ethernet → IPv4 → TCP headers using `pnet`
//!   3. Tracks outgoing TCP packets (SYN, DATA) and measures RTT when the
//!      remote sends an ACK back
//!   4. Sends each RTT event as a JSON message to a Kafka topic
//!
//! # Running
//!
//! Root (or `CAP_NET_RAW`) is required to open a raw packet capture:
//! ```bash
//! sudo ./target/debug/monitor --interface eth0 --kafka-brokers localhost:9092
//! ```

mod kafka;

use anyhow::{Context, Result};
use clap::Parser;
use log::{info, warn};
use monitor_common::{NetworkEvent, RetransmitEvent};
use pnet::datalink;
use pnet::packet::{
    ethernet::{EthernetPacket, EtherTypes},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet,
};
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr}};
use tokio::sync::mpsc;

use kafka::KafkaProducer;

// Events sent from the capture thread to the async Kafka sender.
enum CaptureEvent {
    Rtt(NetworkEvent),
    Retransmit(RetransmitEvent),
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name    = "monitor",
    version = env!("CARGO_PKG_VERSION"),
    about   = "Real-time network latency monitoring agent (pcap + Kafka)"
)]
struct Args {
    /// Network interface to capture on (e.g. "eth0", "en0")
    #[arg(short = 'i', long, default_value = "eth0")]
    interface: String,

    /// Kafka broker addresses (comma-separated, e.g. "localhost:9092,broker2:9092")
    #[arg(short = 'b', long, default_value = "localhost:9092")]
    kafka_brokers: String,

    /// Kafka topic to produce latency events to
    #[arg(short = 't', long, default_value = "net-latency")]
    kafka_topic: String,

    /// Kafka topic to produce retransmission events to
    #[arg(short = 'r', long, default_value = "net-retransmit")]
    retransmit_topic: String,

    /// Log verbosity level: error | warn | info | debug | trace
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&args.log_level),
    )
    .init();

    info!("Network latency monitor starting up (pcap mode)");
    info!("Interface        : {}", args.interface);
    info!("Kafka brokers    : {}", args.kafka_brokers);
    info!("RTT topic        : {}", args.kafka_topic);
    info!("Retransmit topic : {}", args.retransmit_topic);

    let kafka = KafkaProducer::new(&args.kafka_brokers, &args.kafka_topic, &args.retransmit_topic)
        .context("Failed to create Kafka producer")?;

    // ── Channel: capture thread → async Kafka sender ─────────────────────────
    //
    // `mpsc` = multi-producer, single-consumer channel.
    // Capacity 1024: if Kafka is slow, we buffer up to 1024 events in memory
    // before the capture thread blocks on `blocking_send`.
    let (tx, mut rx) = mpsc::channel::<CaptureEvent>(1024);

    // ── Resolve local IP of the capture interface ────────────────────────────
    //
    // Used to distinguish our outgoing data (src == local) from incoming
    // packets (src == remote). We only track local→remote data and measure
    // RTT when the remote sends an ACK back.
    let local_ip: Option<u32> = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == args.interface)
        .and_then(|iface| {
            iface.ips.into_iter().find_map(|net| {
                if let IpAddr::V4(v4) = net.ip() {
                    Some(u32::from(v4))
                } else {
                    None
                }
            })
        });

    if let Some(ip) = local_ip {
        info!("Local IP     : {}", Ipv4Addr::from(ip));
    } else {
        warn!("Could not detect local IP — all ACK events will be shown");
    }

    // ── Spawn the pcap capture in a blocking thread ───────────────────────────
    //
    // pcap's API is synchronous. `spawn_blocking` moves it off the tokio
    // async thread pool into a dedicated OS thread so it can block freely.
    let interface = args.interface.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = capture_loop(&interface, local_ip, tx) {
            // Use eprintln here — the logger may be torn down at shutdown.
            eprintln!("Capture loop exited: {e}");
        }
    });

    // ── Main event loop ───────────────────────────────────────────────────────
    //
    // `tokio::select!` races two futures. Whichever completes first wins;
    // the other is cancelled.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down gracefully");
        }
        _ = async {
            // Drain the channel. `rx.recv()` returns None when all senders
            // (the capture thread) have been dropped — i.e., on shutdown.
            while let Some(event) = rx.recv().await {
                let result = match event {
                    CaptureEvent::Rtt(e)         => kafka.send_event(&e).await,
                    CaptureEvent::Retransmit(e)  => kafka.send_retransmit(&e).await,
                };
                if let Err(e) = result {
                    warn!("Failed to send event to Kafka: {e}");
                }
            }
        } => {}
    }

    Ok(())
}

// ─── Packet Capture Loop ─────────────────────────────────────────────────────

/// 4-tuple that uniquely identifies one direction of a TCP connection.
/// All values are in network byte order (big-endian).
type ConnKey = (u32, u16, u32, u16); // (src_ip, src_port, dst_ip, dst_port)

/// 5-tuple used to match a data packet to its ACK for RTT measurement.
/// The 5th element is the TCP sequence number + payload length (i.e. the
/// next sequence number the receiver will ACK).
type SeqKey = (u32, u16, u32, u16, u32); // ConnKey + next_seq

/// Compute the TCP payload length from IP/TCP header fields.
///
/// We derive this from header fields rather than from `tcp.payload().len()`
/// because `snaplen(96)` may truncate the actual packet bytes before they
/// reach us. The header fields are always present in the first 96 bytes.
///
/// Formula:  IP total length
///         − IP header length  (get_header_length() is in 32-bit words → × 4)
///         − TCP header length (get_data_offset()   is in 32-bit words → × 4)
fn tcp_payload_len(ipv4: &Ipv4Packet, tcp: &TcpPacket) -> u32 {
    let ip_total  = ipv4.get_total_length()   as u32;
    let ip_hdr    = ipv4.get_header_length()  as u32 * 4;
    let tcp_hdr   = tcp.get_data_offset()     as u32 * 4;
    ip_total.saturating_sub(ip_hdr + tcp_hdr)
}

/// Blocking pcap capture loop. Intended to run in `spawn_blocking`.
///
/// For each outgoing packet (SYN or DATA), records the timestamp.
/// When the remote sends an ACK back, computes RTT and emits a `NetworkEvent`.
fn capture_loop(interface: &str, local_ip: Option<u32>, tx: mpsc::Sender<CaptureEvent>) -> Result<()> {
    let mut cap = pcap::Capture::from_device(interface)
        .context("Network interface not found — check `--interface`")?
        .promisc(true)
        .snaplen(96)   // headers only; payload length is read from IP header field
        .timeout(100)  // deliver packets within 100ms even if buffer isn't full
        .open()
        .context("Failed to open pcap capture (are you root / CAP_NET_RAW?)")?;

    cap.filter("tcp", true).context("Failed to apply pcap BPF filter")?;

    // Pending SYN packets: key = ConnKey, value = capture timestamp (µs)
    let mut pending_syns: HashMap<ConnKey, u64> = HashMap::new();

    // Pending data packets awaiting ACK: key = SeqKey, value = capture timestamp (µs)
    //
    // SeqKey = (src_ip, src_port, dst_ip, dst_port, next_seq)
    // where next_seq = seq + payload_len (the ACK number we expect back).
    // value = (capture timestamp µs, TCP payload bytes)
    let mut pending_seqs: HashMap<SeqKey, (u64, u32)> = HashMap::new();

    // Retransmission counters: how many times each seq has been retransmitted.
    let mut seq_retransmit_counts:  HashMap<SeqKey,    u32> = HashMap::new();
    let mut syn_retransmit_counts:  HashMap<ConnKey,   u32> = HashMap::new();

    let mut event_count: u64 = 0;

    loop {
        // `next_packet()` returns `Err(TimeoutExpired)` when the 100ms timeout
        // fires with no packets — that's normal, just keep looping.
        // Any other error (interface down, permission lost) is fatal → propagate.
        let packet = match cap.next_packet() {
            Ok(p)                               => p,
            Err(pcap::Error::TimeoutExpired)    => continue,
            Err(e)                              => return Err(e.into()),
        };

        // ── Timestamp ────────────────────────────────────────────────────────
        let ts_us      = packet.header.ts.tv_sec as u64 * 1_000_000
                       + packet.header.ts.tv_usec as u64;
        let timestamp_ns = ts_us * 1_000;

        // ── Parse layers ─────────────────────────────────────────────────────
        let Some(eth)  = EthernetPacket::new(packet.data)  else { continue };
        if eth.get_ethertype() != EtherTypes::Ipv4          { continue }

        let Some(ipv4) = Ipv4Packet::new(eth.payload())    else { continue };
        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp { continue }

        let Some(tcp)  = TcpPacket::new(ipv4.payload())    else { continue };

        // ── Connection fields ─────────────────────────────────────────────────
        let src_addr = u32::from(ipv4.get_source());
        let dst_addr = u32::from(ipv4.get_destination());
        let src_port = tcp.get_source();
        let dst_port = tcp.get_destination();

        let flags  = tcp.get_flags();
        let is_syn = flags & TcpFlags::SYN != 0;
        let is_ack = flags & TcpFlags::ACK != 0;
        let is_fin = flags & TcpFlags::FIN != 0;
        let is_rst = flags & TcpFlags::RST != 0;

        // ── SYN (no ACK): record handshake start time, skip event ───────────
        // Only record SYNs from our local machine. RTT will be measured when
        // the remote sends the SYN-ACK back.
        if is_syn && !is_ack {
            if local_ip.map_or(true, |lip| src_addr == lip) {
                let syn_key = (src_addr, src_port, dst_addr, dst_port);
                if let Some(original_ts) = pending_syns.insert(syn_key, ts_us) {
                    // Key already existed → SYN retransmit (no SYN-ACK received yet)
                    let count = syn_retransmit_counts.entry(syn_key).or_insert(0);
                    *count += 1;
                    let event = RetransmitEvent {
                        src_addr,
                        dst_addr,
                        src_port,
                        dst_port,
                        rto_us:           ts_us.saturating_sub(original_ts) as u32,
                        retransmit_count: *count,
                        timestamp_ns,
                    };
                    info!("retransmit SYN {}:{} → {}:{} rto={}µs count={}",
                        Ipv4Addr::from(src_addr), src_port,
                        Ipv4Addr::from(dst_addr), dst_port,
                        event.rto_us, event.retransmit_count);
                    let _ = tx.blocking_send(CaptureEvent::Retransmit(event));
                }
            }
            continue;
        }

        // ── Compute RTT ───────────────────────────────────────────────────────
        let (rtt_us, payload_bytes): (u32, u32) = if is_syn && is_ack {
            // SYN-ACK from remote: measures TCP handshake RTT.
            // SYN-ACK reverses src/dst vs. the SYN, so look up with reversed key.
            let syn_key = (dst_addr, dst_port, src_addr, src_port);
            let rtt = pending_syns
                .remove(&syn_key)
                .map(|syn_ts| ts_us.saturating_sub(syn_ts) as u32)
                .unwrap_or(0);
            (rtt, 0) // handshake carries no payload

        } else if is_ack && !is_rst && local_ip.map_or(true, |lip| src_addr != lip) {
            // ACK from remote: measures round-trip time for our outgoing data.
            // ack_number is the next seq the remote expects — matches the
            // next_seq we stored when we sent the data packet.
            let seq_key = (dst_addr, dst_port, src_addr, src_port,
                           tcp.get_acknowledgement());
            pending_seqs
                .remove(&seq_key)
                .map(|(data_ts, plen)| (ts_us.saturating_sub(data_ts) as u32, plen))
                .unwrap_or((0, 0))

        } else {
            (0, 0)
        };

        // ── Emit RTT event if measured ────────────────────────────────────────
        if rtt_us > 0 {
            // The current packet is an ACK from remote (src=remote, dst=local).
            // Swap src/dst so the event always reads "local → remote".
            let event = NetworkEvent {
                src_addr: dst_addr,  // local IP
                dst_addr: src_addr,  // remote IP
                src_port: dst_port,  // local port
                dst_port: src_port,  // remote port
                payload_bytes,
                rtt_us,
                timestamp_ns,
            };

            // ACK arrived — clear retransmit counter for this connection if any.
            if is_syn {
                // SYN-ACK: clear SYN retransmit counter
                syn_retransmit_counts.remove(&(event.src_addr, event.src_port,
                                               event.dst_addr, event.dst_port));
            } else {
                // Data ACK: clear seq retransmit counter
                let seq_key = (event.src_addr, event.src_port,
                               event.dst_addr, event.dst_port,
                               tcp.get_acknowledgement());
                seq_retransmit_counts.remove(&seq_key);
            }

            info!(
                "[{}] {}:{} → {}:{} | rtt={}µs bytes={}",
                event_count,
                Ipv4Addr::from(event.src_addr), event.src_port,
                Ipv4Addr::from(event.dst_addr), event.dst_port,
                rtt_us,
                payload_bytes,
            );

            if tx.blocking_send(CaptureEvent::Rtt(event)).is_err() {
                break;
            }

            event_count += 1;
        }

        // ── Record outgoing packet seq for future ACK matching ────────────────
        // Only record packets from our local machine. When the remote ACKs them,
        // we compute the RTT. RST packets expect no ACK, so skip those.
        let is_local_sender = local_ip.map_or(true, |lip| src_addr == lip);
        if !is_rst && is_local_sender {
            let payload_len = tcp_payload_len(&ipv4, &tcp);

            // SYN and FIN each consume one sequence number even with no payload.
            let seq_advance = if payload_len > 0 {
                payload_len
            } else if is_syn || is_fin {
                1
            } else {
                0 // pure ACK — no seq space consumed, nothing to track
            };

            if seq_advance > 0 {
                let next_seq = tcp.get_sequence().wrapping_add(seq_advance);
                let seq_key  = (src_addr, src_port, dst_addr, dst_port, next_seq);
                if let Some((original_ts, _)) = pending_seqs.insert(seq_key, (ts_us, payload_len)) {
                    // Key already existed → DATA retransmit (no ACK received yet)
                    let count = seq_retransmit_counts.entry(seq_key).or_insert(0);
                    *count += 1;
                    let event = RetransmitEvent {
                        src_addr,
                        dst_addr,
                        src_port,
                        dst_port,
                        rto_us:           ts_us.saturating_sub(original_ts) as u32,
                        retransmit_count: *count,
                        timestamp_ns,
                    };
                    info!("retransmit DATA {}:{} → {}:{} rto={}µs count={}",
                        Ipv4Addr::from(src_addr), src_port,
                        Ipv4Addr::from(dst_addr), dst_port,
                        event.rto_us, event.retransmit_count);
                    let _ = tx.blocking_send(CaptureEvent::Retransmit(event));
                }
            }
        }

    }

    Ok(())
}
