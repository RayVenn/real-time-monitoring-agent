# Real-Time Network Latency Monitoring Agent

## Project Overview

A real-time network latency monitoring agent built with **Go** and **gopacket/libpcap**. It captures live TCP packets on a network interface, measures round-trip time (RTT) for outgoing connections, and streams structured events to **Amazon MSK (Managed Kafka)**.

**Primary goals:** Build production-quality observability tooling; strong AWS interview material.

---

## Architecture

```
┌──────────────────────────────────────────┐
│          Network Interface (en0)         │
│  Live TCP packet capture via libpcap     │
└─────────────────────┬────────────────────┘
                      │  raw packets
┌─────────────────────▼────────────────────┐
│         Go Agent (monitor-go)            │
│  - Parses Ethernet → IPv4 → TCP          │
│  - Tracks outgoing SYN + DATA packets    │
│  - Computes RTT when remote sends ACK    │
│  - Sends events via Go channel           │
└─────────────────────┬────────────────────┘
                      │  channel
┌─────────────────────▼────────────────────┐
│         MSK Producer (sarama)            │
│  - Serializes events to JSON             │
│  - Produces to two Kafka topics          │
│  - IAM auth via SASL/OAUTHBEARER + TLS   │
└──────────┬──────────────────┬────────────┘
           │                  │
  ┌────────▼──────┐  ┌────────▼──────────┐
  │ net-latency   │  │  net-retransmit   │
  │ (RTT events)  │  │ (retransmit events│
  └───────────────┘  └───────────────────┘
           │                  │
  ┌────────▼──────────────────▼────────────┐
  │     Amazon MSK (Managed Kafka)         │
  │     → AWS Flink / CloudWatch           │
  └────────────────────────────────────────┘
```

---

## Workspace Structure

```
real-time-monitoring-agent/
├── CLAUDE.md                    # This file
│
├── monitor-go/                  # Go agent binary
│   ├── go.mod
│   ├── go.sum
│   ├── main.go                  # CLI args, signal handling, main drain loop
│   ├── capture.go               # pcap capture loop + RTT state machine
│   ├── msk.go                   # MSK producer (sarama + aws-msk-iam-sasl-signer-go)
│   └── events.go                # NetworkEvent, RetransmitEvent types
│
└── infra/                       # CDK TypeScript — MSK stack only
    ├── cdk.json
    ├── package.json
    ├── tsconfig.json
    ├── bin/infra.ts             # App entry point → RtmMskStack
    └── lib/msk-stack.ts        # MSK cluster + security groups + SSM exports
```

---

## Tech Stack

| Component      | Package                                    | Purpose                              |
|----------------|--------------------------------------------|--------------------------------------|
| Packet capture | `gopacket/pcap`                            | Live capture via libpcap             |
| Packet parsing | `gopacket/layers`                          | Ethernet/IPv4/TCP decoding           |
| Kafka client   | `github.com/IBM/sarama`                    | Produce to MSK topics                |
| MSK IAM auth   | `aws-msk-iam-sasl-signer-go/signer`        | SASL/OAUTHBEARER token for MSK IAM   |
| AWS auth       | `aws-sdk-go-v2/config`                     | Default credential chain (IAM roles) |
| Serialization  | `encoding/json`                            | Serialize events to JSON             |
| CLI            | `flag`                                     | Argument parsing                     |

**Auth:** MSK IAM auth via SASL/OAUTHBEARER over TLS. `aws-msk-iam-sasl-signer-go` generates a short-lived token from the default credential chain (env vars → `~/.aws/credentials` → EC2 instance profile → ECS task role). No passwords, no hardcoded SASL config. Attach an IAM role with `kafka-cluster:*` on the target cluster and topics.

MSK bootstrap endpoints use port **9098** (TLS + IAM auth).

---

## How RTT Is Measured

We only measure RTT for **outgoing** connections (local machine as client):

1. **Local sends SYN** → timestamp recorded in `pendingSYNs`
2. **Remote sends SYN-ACK** → handshake RTT = now − SYN timestamp
3. **Local sends DATA** → `nextSeq = seq + payloadLen` recorded in `pendingSEQs`
4. **Remote sends ACK** → data RTT = now − DATA timestamp

All emitted events have `src = local machine`, `dst = remote`. RTT is always > 0 (zero-RTT events are dropped).

Retransmissions are detected when the same key arrives before its ACK. Each retransmit emits a `RetransmitEvent` with cumulative count and time-since-original.

---

## Event Schemas

### NetworkEvent → topic `net-latency`

**Partition key:** `<src_ip>:<src_port>-><dst_ip>`

```json
{
  "src_ip":        "192.168.0.166",
  "src_port":      55495,
  "dst_ip":        "140.82.112.26",
  "dst_port":      443,
  "payload_bytes": 1448,
  "rtt_us":        31279,
  "timestamp_ns":  1772952115698113000
}
```

### RetransmitEvent → topic `net-retransmit`

**Partition key:** `<src_ip>:<src_port>-><dst_ip>`

```json
{
  "src_ip":           "192.168.0.166",
  "src_port":         55495,
  "dst_ip":           "140.82.112.26",
  "dst_port":         443,
  "rto_us":           201000,
  "retransmit_count": 1,
  "timestamp_ns":     1772952115698113000
}
```

---

## Building & Running

### Prerequisites

```bash
brew install libpcap   # macOS
# or: apt install libpcap-dev  (Linux)
```

AWS credentials must be configured (env vars, `~/.aws/credentials`, or instance role).

### Deploy MSK infra

```bash
cd infra
npm install
npx cdk deploy          # deploys RtmMskStack
# After deploy, note the BrokersIamPublic output (port 9198)
```

### Build agent

```bash
cd monitor-go
go build -o monitor .
```

### Run agent

```bash
# Requires root for raw packet capture.
# Use the BrokersIamPublic output from cdk deploy (port 9198).
sudo ./monitor \
  --interface en0 \
  --brokers <BrokersIamPublic output> \
  --rtt-topic net-latency \
  --retransmit-topic net-retransmit \
  --region us-east-1
```

### CLI Options

| Flag                  | Default           | Description                                      |
|-----------------------|-------------------|--------------------------------------------------|
| `--interface`         | `eth0`            | Network interface to capture on                  |
| `--brokers`           | *(required)*      | Comma-separated MSK bootstrap servers (port 9198)|
| `--rtt-topic`         | `net-latency`     | Kafka topic for RTT events                       |
| `--retransmit-topic`  | `net-retransmit`  | Kafka topic for retransmit events                |
| `--region`            | `us-east-1`       | AWS region                                       |

---

## Key Implementation Notes

- **`snaplen=96`** — captures headers only. Payload *length* is computed from `ip.Length - ip.IHL*4 - tcp.DataOffset*4`, which is always in the first 96 bytes.
- **goroutine + channel** — capture runs in a dedicated goroutine (pcap is blocking); the main goroutine drains the channel and produces to Kafka.
- **struct map keys** — `connKey` and `seqKey` are plain structs; Go uses them as map keys directly with no custom hash needed.
- **`nextSeq` wrapping** — `tcp.Seq + payloadLen` wraps naturally at uint32 max, matching TCP semantics.
- **`saturatingSub`** — guards against underflow if pcap timestamps arrive out of order.
- **MSK IAM auth** — `mskTokenProvider` implements sarama's `AccessTokenProvider` interface; `signer.GenerateAuthToken` fetches a short-lived IAM token on each SASL handshake.
