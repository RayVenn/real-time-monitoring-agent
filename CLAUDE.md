# Real-Time Network Latency Monitoring Agent

## Project Overview

A real-time network latency monitoring agent built with **pcap** and **Rust**. It captures live TCP packets on a network interface, measures round-trip time (RTT) for outgoing connections, and streams structured events to **Apache Kafka**.

**Primary goals:** Learn Rust, build production-quality observability tooling.

---

## Architecture

```
┌──────────────────────────────────────────┐
│          Network Interface (en0)         │
│  Live TCP packet capture via libpcap     │
└─────────────────────┬────────────────────┘
                      │  raw packets
┌─────────────────────▼────────────────────┐
│         Userspace Agent (monitor)        │
│  - Parses Ethernet → IPv4 → TCP          │
│  - Tracks outgoing SYN + DATA packets    │
│  - Computes RTT when remote sends ACK    │
│  - Sends NetworkEvent via mpsc channel   │
└─────────────────────┬────────────────────┘
                      │  async channel
┌─────────────────────▼────────────────────┐
│           Kafka Producer                 │
│  - Serializes NetworkEvent to JSON       │
│  - Produces to topic: net-latency        │
└─────────────────────┬────────────────────┘
                      │
          ┌───────────▼───────────┐
          │    Apache Kafka       │
          │  Topic: net-latency   │
          └───────────────────────┘
```

---

## Workspace Structure

```
real-time-monitoring-agent/
├── CLAUDE.md                    # This file
├── Cargo.toml                   # Workspace manifest
├── rust-toolchain.toml          # Pins stable toolchain
│
├── monitor-common/              # Shared types
│   ├── Cargo.toml
│   └── src/lib.rs               # NetworkEvent struct
│
└── monitor/                     # Userspace agent binary
    ├── Cargo.toml
    └── src/
        ├── main.rs              # pcap capture loop + RTT logic
        └── kafka.rs             # Kafka producer wrapper (rdkafka)
```

---

## Tech Stack

| Component      | Crate           | Purpose                                      |
|----------------|-----------------|----------------------------------------------|
| Packet capture | `pcap`          | Live capture via libpcap                     |
| Packet parsing | `pnet`          | Ethernet/IPv4/TCP header parsing             |
| Kafka producer | `rdkafka`       | Produce events to Kafka (dynamic-linking)    |
| Async runtime  | `tokio`         | Async event loop + spawn_blocking            |
| Serialization  | `serde_json`    | Serialize NetworkEvent to JSON               |
| CLI            | `clap`          | Argument parsing                             |
| Error handling | `anyhow`        | Ergonomic error propagation                  |

---

## How RTT Is Measured

We only measure RTT for **outgoing** connections (local machine as client):

1. **Local sends SYN** → timestamp recorded in `pending_syns`
2. **Remote sends SYN-ACK** → handshake RTT = now − SYN timestamp
3. **Local sends DATA** → `next_seq = seq + payload_len` recorded in `pending_seqs`
4. **Remote sends ACK** → data RTT = now − DATA timestamp

All emitted events have `src = local machine`, `dst = remote`. RTT always represents a full network round-trip.

Packets where local sends the ACK (measuring local kernel time, not network) are ignored.

---

## NetworkEvent (Kafka Message Format)

**Topic:** `net-latency`

**Key:** `<src_ip>:<src_port>-><dst_ip>`

**Value (JSON):**
```json
{
  "src_ip": "192.168.0.166",
  "src_port": 55495,
  "dst_ip": "140.82.112.26",
  "dst_port": 443,
  "rtt_us": 31279,
  "timestamp_ns": 1772952115698113000
}
```

`src_ip` is always the local machine. `rtt_us` is always > 0 (events with no RTT are dropped).

---

## Building & Running

### Prerequisites

```bash
# macOS
brew install libpcap librdkafka

# Kafka (Docker)
docker run -d -p 9092:9092 apache/kafka:latest
```

### Build

```bash
cd real-time-monitoring-agent
cargo build
```

### Run

```bash
# Requires root for raw packet capture
sudo ./target/debug/monitor \
  --interface en0 \
  --kafka-brokers localhost:9092 \
  --kafka-topic net-latency
```

### CLI Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--interface` | `-i` | `eth0` | Network interface to capture on |
| `--kafka-brokers` | `-b` | `localhost:9092` | Kafka broker addresses |
| `--kafka-topic` | `-t` | `net-latency` | Kafka topic to produce to |
| `--log-level` | `-l` | `info` | Log verbosity (error/warn/info/debug/trace) |

### Inspect Kafka messages

```bash
docker exec <container> /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic net-latency \
  --from-beginning
```

---

## Key Implementation Notes

- **`snaplen(96)`** — captures headers only (no payload bytes). Payload *length* is computed from IP/TCP header fields, which are always in the first 96 bytes.
- **`.timeout(100)`** — pcap delivers packets within 100ms even if the buffer isn't full, preventing output delays.
- **`spawn_blocking`** — pcap's API is synchronous. It runs in a dedicated OS thread so it doesn't block the tokio async runtime.
- **`mpsc` channel** — bridges the blocking pcap thread to the async Kafka sender.
- **`wrapping_add`** — TCP sequence numbers wrap at u32::MAX; wrapping arithmetic handles this correctly.
- **`saturating_sub`** — safe subtraction for RTT; prevents underflow if timestamps are out of order.
