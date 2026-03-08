# Real-Time Network Latency Monitoring Agent

## Project Overview

A real-time network latency monitoring agent built with **eBPF** and **Rust**. It hooks into the Linux kernel's TCP stack using eBPF programs to measure TCP RTT (Round-Trip Time) with minimal overhead and streams structured events to **Apache Kafka**.

**Primary goals:** Learn Rust + eBPF, build production-quality observability tooling.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Linux Kernel                   │
│  ┌───────────┐   tracepoint/tcp/tcp_probe   │
│  │ TCP Stack │──────────────────┐           │
│  └───────────┘                  │           │
└─────────────────────────────────┼───────────┘
                                  │
┌─────────────────────────────────▼───────────┐
│           eBPF Program (monitor-ebpf)        │
│  - Tracepoint hook: tcp/tcp_probe            │
│  - Extracts: src/dst IP, ports, srtt (RTT)  │
│  - Writes NetworkEvent to Ring Buffer        │
└─────────────────────────────────┬───────────┘
                  Ring Buffer (kernel → userspace)
┌─────────────────────────────────▼───────────┐
│         Userspace Agent (monitor)            │
│  - Loads eBPF via aya                        │
│  - Reads NetworkEvent from ring buffer       │
│  - Serializes to JSON                        │
│  - Produces to Kafka topic                   │
└─────────────────────────────────┬───────────┘
                                  │
                     ┌────────────▼────────────┐
                     │  Apache Kafka           │
                     │  Topic: net-latency     │
                     └─────────────────────────┘
```

---

## Workspace Structure

```
real-time-monitoring-agent/
├── CLAUDE.md                    # This file - persistent project context
├── Cargo.toml                   # Workspace manifest
├── rust-toolchain.toml          # Pins nightly toolchain (required for eBPF)
├── .cargo/config.toml           # Workspace build config + aliases
├── .gitignore
│
├── monitor-common/              # Shared types (no_std compatible)
│   ├── Cargo.toml
│   └── src/lib.rs               # NetworkEvent struct (shared kernel↔userspace)
│
├── monitor-ebpf/                # eBPF kernel program (compiled to BPF ELF)
│   ├── Cargo.toml
│   ├── .cargo/config.toml       # Forces bpfel-unknown-none target
│   └── src/main.rs              # tcp_probe tracepoint handler
│
├── monitor/                     # Userspace agent binary
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs              # Entry point: load eBPF, event loop
│       └── kafka.rs             # Kafka producer wrapper (rdkafka)
│
└── xtask/                       # Build helper (builds eBPF programs)
    ├── Cargo.toml
    └── src/main.rs
```

---

## Tech Stack

| Component     | Crate                          | Purpose                                     |
|---------------|--------------------------------|---------------------------------------------|
| eBPF userspace| `aya`                          | Load/manage eBPF programs from userspace    |
| eBPF kernel   | `aya-ebpf`                     | Write eBPF programs in Rust (no_std)        |
| eBPF logging  | `aya-log` + `aya-log-ebpf`     | Debug logging bridging kernel↔userspace     |
| Kafka         | `rdkafka`                      | Produce events to Kafka (librdkafka binding)|
| Async runtime | `tokio`                        | Async I/O for userspace agent               |
| Serialization | `serde` + `serde_json`         | Serialize NetworkEvent to JSON for Kafka    |
| CLI           | `clap`                         | Argument parsing                            |
| Error handling| `anyhow` + `thiserror`         | Ergonomic error handling                    |

---

## Key Concepts

### eBPF Tracepoint: `tcp/tcp_probe`

The `tcp_probe` tracepoint fires when the kernel TCP stack probes a connection. It gives us the **smoothed RTT (srtt)** directly from kernel TCP state — no packet capture needed.

**Verify available tracepoints on your system:**
```bash
sudo ls /sys/kernel/debug/tracing/events/tcp/
sudo cat /sys/kernel/debug/tracing/events/tcp/tcp_probe/format
```

### tcp_probe Tracepoint Field Offsets

**IMPORTANT:** These offsets may vary by kernel version. Always verify with the format file above.

| Field       | Offset | Size | Notes                              |
|-------------|--------|------|------------------------------------|
| common hdr  | 0      | 8    | type(2)+flags(1)+preempt(1)+pid(4) |
| saddr       | 8      | 28   | sockaddr_in6 bytes (IPv4: [4..8])  |
| daddr       | 36     | 28   | sockaddr_in6 bytes (IPv4: [4..8])  |
| sport       | 64     | 2    | source port                        |
| dport       | 66     | 2    | destination port                   |
| family      | 68     | 2    | AF_INET=2, AF_INET6=10             |
| mark        | 72     | 4    | (2 bytes padding after family)     |
| data_len    | 76     | 4    |                                    |
| snd_nxt     | 80     | 4    |                                    |
| snd_una     | 84     | 4    |                                    |
| snd_cwnd    | 88     | 4    |                                    |
| ssthresh    | 92     | 4    |                                    |
| snd_wnd     | 96     | 4    |                                    |
| srtt        | 100    | 4    | Smoothed RTT in microseconds       |
| rcv_wnd     | 104    | 4    |                                    |
| sock_cookie | 108    | 8    |                                    |

### Data Flow

1. Kernel fires `tcp_probe` tracepoint on TCP activity
2. eBPF program reads connection info (IPs, ports, srtt)
3. `NetworkEvent` written to **Ring Buffer** (kernel→userspace IPC)
4. Userspace polls ring buffer, deserializes `NetworkEvent`
5. Event serialized to JSON, sent to Kafka topic `net-latency`

### Ring Buffer (modern approach)

The Ring Buffer (`BPF_MAP_TYPE_RINGBUF`) is preferred over the legacy `PerfEventArray`:
- Single shared buffer (not per-CPU)
- Lower memory overhead, in-order delivery
- Requires Linux 5.8+

### monitor-common: no_std Compatibility

`monitor-common` is shared between the eBPF program (no_std) and userspace (std).
The `user` feature gates std-only code like `impl aya::Pod for NetworkEvent`.

---

## Building

### Prerequisites

```bash
# Install Rust nightly (required for eBPF no_std + build-std)
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Add eBPF target (little-endian BPF)
rustup target add bpfel-unknown-none --toolchain nightly

# Install bpf-linker (needed to link BPF ELF objects)
cargo install bpf-linker

# Linux kernel headers (Ubuntu/Debian)
sudo apt-get install linux-headers-$(uname -r) linux-tools-$(uname -r)

# Kafka (for testing - optional, can use docker)
docker run -d -p 9092:9092 apache/kafka:latest
```

### Build Commands

```bash
# Step 1: Build eBPF programs (must run before building monitor)
cargo xtask build-ebpf

# Step 2: Build userspace agent
cargo build --package monitor

# Or build everything at once:
cargo xtask build

# Release builds:
cargo xtask build --release

# Run (requires root for eBPF program loading):
sudo ./target/debug/monitor \
  --kafka-brokers localhost:9092 \
  --kafka-topic net-latency
```

### Cargo Aliases (from .cargo/config.toml)

```bash
cargo xtask build-ebpf    # Build only eBPF programs
cargo xtask build          # Build eBPF + userspace
```

### Development Tips

- **macOS / non-Linux**: Code compiles but cannot run (eBPF is Linux-only). Use a Linux VM or Docker.
- **Minimum kernel**: 5.8+ for Ring Buffer support
- **View eBPF logs**: `sudo cat /sys/kernel/debug/tracing/trace_pipe`
- **Debugging offsets**: If srtt readings look wrong, verify field offsets against your kernel's format file
- **Root required**: `sudo` is needed to load eBPF programs into the kernel

---

## NetworkEvent (Kafka Message Format)

**Key:** `<src_ip>:<src_port>-><dst_ip>:<dst_port>`

**Value (JSON):**
```json
{
  "src_ip": "10.0.0.1",
  "src_port": 54321,
  "dst_ip": "93.184.216.34",
  "dst_port": 443,
  "srtt_us": 1250,
  "timestamp_ns": 1709123456789012345
}
```

---

## Development Status

### Phase 1 (Current): Foundation
- [x] Workspace scaffold with all 4 crates
- [x] `NetworkEvent` shared struct (no_std compatible)
- [x] eBPF tracepoint program for `tcp_probe`
- [x] Ring buffer event passing (kernel → userspace)
- [x] Kafka producer with JSON serialization
- [x] CLI argument parsing
- [ ] Test end-to-end on Linux (needs Linux environment)
- [ ] Verify/calibrate tracepoint field offsets on target kernel

### Phase 2: Enhancements
- [ ] IPv6 support (saddr/daddr parsing for AF_INET6)
- [ ] Async ring buffer polling (tokio AsyncFd instead of busy-poll)
- [ ] Per-connection latency histograms
- [ ] Configurable port/IP filtering in eBPF
- [ ] Prometheus metrics endpoint

### Phase 3: Production
- [ ] Dockerized deployment
- [ ] Kubernetes DaemonSet manifest
- [ ] Performance benchmarking vs. alternatives
- [ ] CI/CD pipeline (GitHub Actions)

---

## Platform Notes

- **eBPF programs only run on Linux** (not macOS, not Windows)
- Development on macOS: the Rust code compiles, but you cannot attach to tracepoints
- For development without Linux: use a VM (UTM, VMware, VirtualBox) or `docker run --privileged`
- Tested on: *(add kernel version and distro when first tested)*

---

## References

- [aya book](https://aya-rs.dev/book/) — the definitive Rust eBPF guide
- [eBPF.io](https://ebpf.io) — eBPF concepts and ecosystem
- [Linux TCP tracepoints source](https://elixir.bootlin.com/linux/latest/source/include/trace/events/tcp.h)
- [rdkafka docs](https://docs.rs/rdkafka)
- [Aya API docs](https://docs.rs/aya)

---

## Contributors

- *(Add names here)*
