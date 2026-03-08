//! Kafka producer wrapper.
//!
//! Wraps `rdkafka`'s `FutureProducer` with a simple async interface for
//! sending `NetworkEvent` structs as JSON messages to a Kafka topic.
//!
//! # Message Format
//!
//! Key:   `<src_ip>:<src_port>-><dst_ip>:<dst_port>`
//! Value: JSON-encoded `KafkaPayload`
//!
//! Example:
//! ```json
//! {
//!   "src_ip": "10.0.0.1",
//!   "src_port": 54321,
//!   "dst_ip": "93.184.216.34",
//!   "dst_port": 443,
//!   "rtt_us": 1250,
//!   "timestamp_ns": 1709123456789012345
//! }
//! ```

use anyhow::{Context, Result};
use monitor_common::{NetworkEvent, RetransmitEvent};
use rdkafka::{
    producer::{FutureProducer, FutureRecord},
    ClientConfig,
};
use serde::Serialize;
use std::{net::Ipv4Addr, time::Duration};

// ─── Kafka Payload ────────────────────────────────────────────────────────────

/// JSON representation of a `NetworkEvent` as it appears in Kafka.
///
/// Uses human-readable string IPs rather than raw `u32` values so that
/// downstream consumers don't need to handle byte-order conversion.
#[derive(Serialize)]
struct KafkaPayload<'a> {
    src_ip:        &'a str,
    src_port:      u16,
    dst_ip:        &'a str,
    dst_port:      u16,
    payload_bytes: u32,
    rtt_us:        u32,
    timestamp_ns:  u64,
}

// ─── Producer ─────────────────────────────────────────────────────────────────

pub struct KafkaProducer {
    producer:          FutureProducer,
    topic:             String,
    retransmit_topic:  String,
}

impl KafkaProducer {
    /// Create a new Kafka producer connected to the given brokers.
    pub fn new(brokers: &str, topic: &str, retransmit_topic: &str) -> Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "5000")
            .set("queue.buffering.max.messages", "100000")
            .set("queue.buffering.max.ms", "50")
            .set("compression.type", "lz4")
            .create()
            .context("Failed to create rdkafka FutureProducer")?;

        Ok(Self {
            producer,
            topic: topic.to_string(),
            retransmit_topic: retransmit_topic.to_string(),
        })
    }

    /// Serialize and send a `NetworkEvent` to Kafka.
    pub async fn send_event(&self, event: &NetworkEvent) -> Result<()> {
        // `event.src_addr` is in network byte order (big-endian u32).
        // `Ipv4Addr::from(u32)` interprets the u32 as big-endian, so this
        // round-trips correctly without any extra byte-swapping.
        let src_ip = Ipv4Addr::from(event.src_addr).to_string();
        let dst_ip = Ipv4Addr::from(event.dst_addr).to_string();

        let key = format!("{}:{}->{}", src_ip, event.src_port, dst_ip);

        let payload = serde_json::to_string(&KafkaPayload {
            src_ip:        &src_ip,
            src_port:      event.src_port,
            dst_ip:        &dst_ip,
            dst_port:      event.dst_port,
            payload_bytes: event.payload_bytes,
            rtt_us:        event.rtt_us,
            timestamp_ns:  event.timestamp_ns,
        })
        .context("Failed to serialize NetworkEvent to JSON")?;

        self.producer
            .send(
                FutureRecord::to(&self.topic)
                    .key(&key)
                    .payload(&payload),
                Duration::from_secs(5),
            )
            .await
            .map_err(|(err, _msg)| anyhow::anyhow!("Kafka send failed: {err}"))?;

        Ok(())
    }

    /// Serialize and send a `RetransmitEvent` to the retransmit Kafka topic.
    pub async fn send_retransmit(&self, event: &RetransmitEvent) -> Result<()> {
        let src_ip = Ipv4Addr::from(event.src_addr).to_string();
        let dst_ip = Ipv4Addr::from(event.dst_addr).to_string();

        let key = format!("{}:{}->{}", src_ip, event.src_port, dst_ip);

        #[derive(Serialize)]
        struct RetransmitPayload<'a> {
            src_ip:            &'a str,
            src_port:          u16,
            dst_ip:            &'a str,
            dst_port:          u16,
            rto_us:            u32,
            retransmit_count:  u32,
            timestamp_ns:      u64,
        }

        let payload = serde_json::to_string(&RetransmitPayload {
            src_ip:           &src_ip,
            src_port:         event.src_port,
            dst_ip:           &dst_ip,
            dst_port:         event.dst_port,
            rto_us:           event.rto_us,
            retransmit_count: event.retransmit_count,
            timestamp_ns:     event.timestamp_ns,
        })
        .context("Failed to serialize RetransmitEvent to JSON")?;

        self.producer
            .send(
                FutureRecord::to(&self.retransmit_topic)
                    .key(&key)
                    .payload(&payload),
                Duration::from_secs(5),
            )
            .await
            .map_err(|(err, _msg)| anyhow::anyhow!("Kafka send failed: {err}"))?;

        Ok(())
    }
}
