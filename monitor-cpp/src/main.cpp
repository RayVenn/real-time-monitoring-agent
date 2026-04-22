#include <pcap/pcap.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <variant>

#include "network_event.h"
#include "kafka_producer.h"

// ═════════════════════════════════════════════════════════════════════════════
// Connection tracking key types
// ═════════════════════════════════════════════════════════════════════════════

// 4-tuple that identifies a TCP connection direction (used for SYN tracking)
struct ConnKey {
    uint32_t src_addr;  // network byte order
    uint16_t src_port;  // network byte order
    uint32_t dst_addr;
    uint16_t dst_port;

    bool operator==(const ConnKey& o) const noexcept {
        return src_addr == o.src_addr && src_port == o.src_port &&
               dst_addr == o.dst_addr && dst_port == o.dst_port;
    }
};

// 5-tuple: 4-tuple + the next sequence number the remote will ACK
// (used to correlate outgoing data with incoming ACKs)
struct SeqKey {
    uint32_t src_addr;
    uint16_t src_port;
    uint32_t dst_addr;
    uint16_t dst_port;
    uint32_t next_seq;  // host byte order: seq + payload_len (wraps on overflow)

    bool operator==(const SeqKey& o) const noexcept {
        return src_addr == o.src_addr && src_port == o.src_port &&
               dst_addr == o.dst_addr && dst_port == o.dst_port &&
               next_seq == o.next_seq;
    }
};

// Simple hash combining via the boost/Abseil pattern (works well in practice)
static size_t hash_combine(size_t h, size_t v) {
    return h ^ (v + 0x9e3779b9 + (h << 6) + (h >> 2));
}

struct ConnKeyHash {
    size_t operator()(const ConnKey& k) const noexcept {
        size_t h = std::hash<uint32_t>{}(k.src_addr);
        h = hash_combine(h, std::hash<uint16_t>{}(k.src_port));
        h = hash_combine(h, std::hash<uint32_t>{}(k.dst_addr));
        h = hash_combine(h, std::hash<uint16_t>{}(k.dst_port));
        return h;
    }
};

struct SeqKeyHash {
    size_t operator()(const SeqKey& k) const noexcept {
        size_t h = std::hash<uint32_t>{}(k.src_addr);
        h = hash_combine(h, std::hash<uint16_t>{}(k.src_port));
        h = hash_combine(h, std::hash<uint32_t>{}(k.dst_addr));
        h = hash_combine(h, std::hash<uint16_t>{}(k.dst_port));
        h = hash_combine(h, std::hash<uint32_t>{}(k.next_seq));
        return h;
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// Thread-safe event queue — bridges the blocking pcap thread to the Kafka
// sender running on the main thread.
// ═════════════════════════════════════════════════════════════════════════════

using Event = std::variant<NetworkEvent, RetransmitEvent>;

class EventQueue {
public:
    // Template push: explicitly constructs the variant alternative T, which
    // avoids an IntelliSense false-positive on std::variant's converting ctor.
    template<typename T>
    void push(T e) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            q_.emplace(std::in_place_type<T>, std::move(e));
        }
        cv_.notify_one();
    }

    // Returns true and fills `out` if an event was available within `timeout`.
    // Returns false on timeout or if the queue is closed and empty.
    bool pop(Event& out, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait_for(lk, timeout, [this] { return !q_.empty() || closed_; });
        if (q_.empty()) return false;
        out = std::move(q_.front());
        q_.pop();
        return true;
    }

    // Signals the queue is permanently closed (no more pushes).
    void close() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            closed_ = true;
        }
        cv_.notify_all();
    }

    bool is_done() const {
        std::lock_guard<std::mutex> lk(mu_);
        return closed_ && q_.empty();
    }

private:
    mutable std::mutex      mu_;
    std::condition_variable cv_;
    std::queue<Event>       q_;
    bool                    closed_ = false;
};

// ═════════════════════════════════════════════════════════════════════════════
// Signal handling
// ═════════════════════════════════════════════════════════════════════════════

static std::atomic<bool> g_running{true};

static void on_signal(int) {
    g_running = false;
}

// ═════════════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════════════

// Returns the primary IPv4 address bound to `iface`, in network byte order.
// Returns 0 if the interface is not found or has no IPv4 address.
static uint32_t get_local_ip(const std::string& iface) {
    struct ifaddrs* head = nullptr;
    if (getifaddrs(&head) != 0) return 0;

    uint32_t result = 0;
    for (auto* p = head; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (iface != p->ifa_name) continue;
        result = reinterpret_cast<const struct sockaddr_in*>(p->ifa_addr)->sin_addr.s_addr;
        break;
    }
    freeifaddrs(head);
    return result;
}

// Computes TCP payload length using header-field arithmetic.
// snaplen=96 may have truncated the actual payload, but the IP total-length
// field (always within the first 96 bytes) gives us the real payload size.
static uint32_t tcp_payload_len(const IpHeader* iph, const TcpHeader* tcph) {
    uint16_t ip_total  = ntohs(iph->total_len);
    uint8_t  ip_hlen   = iph->ihl_bytes();
    uint8_t  tcp_hlen  = tcph->hdr_bytes();
    if (ip_total < ip_hlen + tcp_hlen) return 0;
    return ip_total - ip_hlen - tcp_hlen;
}

// ═════════════════════════════════════════════════════════════════════════════
// Capture loop — runs in a dedicated OS thread (pcap is synchronous).
//
// RTT measurement strategy (local machine as client):
//   SYN outgoing    → record timestamp in pending_syns
//   SYN-ACK incoming → emit NetworkEvent(rtt = now - SYN ts, payload=0)
//   DATA outgoing   → record timestamp in pending_seqs keyed by next_seq
//   ACK incoming    → emit NetworkEvent(rtt = now - DATA ts, payload=size)
//
// Retransmissions are detected when the same key appears before the ACK
// arrives. Each retransmit increments the counter and emits RetransmitEvent.
// ═════════════════════════════════════════════════════════════════════════════

static void capture_loop(const std::string& iface,
                         uint32_t local_ip,
                         EventQueue& queue)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    // snaplen=96 captures full headers without storing payload bytes,
    // saving memory and bandwidth. timeout=100ms prevents output stalls
    // when traffic is sparse.
    pcap_t* handle = pcap_open_live(iface.c_str(), 96, /*promisc=*/1, /*timeout_ms=*/100, errbuf);
    if (!handle) {
        std::cerr << "[pcap] failed to open " << iface << ": " << errbuf << "\n";
        return;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "[pcap] unsupported datalink type (expected Ethernet/DLT_EN10MB)\n";
        pcap_close(handle);
        return;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp", /*optimize=*/0, PCAP_NETMASK_UNKNOWN) != 0 ||
        pcap_setfilter(handle, &fp) != 0)
    {
        std::cerr << "[pcap] filter error: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return;
    }
    pcap_freecode(&fp);

    // ── RTT state ────────────────────────────────────────────────────────────
    // pending_syns[conn]      = SYN send timestamp (µs)
    // pending_seqs[seq]       = {DATA send timestamp (µs), payload_bytes}
    // *_retransmit_counts[k]  = how many extra transmissions of that segment
    using ConnMap = std::unordered_map<ConnKey, uint64_t,                    ConnKeyHash>;
    using SeqMap  = std::unordered_map<SeqKey,  std::pair<uint64_t,uint32_t>, SeqKeyHash>;
    using ConnCnt = std::unordered_map<ConnKey, uint32_t, ConnKeyHash>;
    using SeqCnt  = std::unordered_map<SeqKey,  uint32_t, SeqKeyHash>;

    ConnMap pending_syns;
    SeqMap  pending_seqs;
    ConnCnt syn_retransmit_counts;
    SeqCnt  seq_retransmit_counts;

    struct pcap_pkthdr* pkt_hdr;
    const uint8_t*      pkt_data;

    while (g_running) {
        int rc = pcap_next_ex(handle, &pkt_hdr, &pkt_data);
        if (rc == 0)  continue;   // read timeout — loop and check g_running
        if (rc < 0) {
            if (g_running)
                std::cerr << "[pcap] error: " << pcap_geterr(handle) << "\n";
            break;
        }

        // Minimum viable frame: Ethernet(14) + IP_min(20) + TCP_min(20) = 54
        if (pkt_hdr->caplen < 54) continue;

        const auto* iph  = reinterpret_cast<const IpHeader*>(pkt_data + ETH_HDR_LEN);
        if (iph->protocol != IPPROTO_TCP) continue;

        uint8_t ip_hlen = iph->ihl_bytes();
        if (pkt_hdr->caplen < ETH_HDR_LEN + ip_hlen + 20u) continue;

        const auto* tcph = reinterpret_cast<const TcpHeader*>(pkt_data + ETH_HDR_LEN + ip_hlen);

        // Convert pcap timeval to nanoseconds; µs used for RTT arithmetic
        uint64_t ts_ns = static_cast<uint64_t>(pkt_hdr->ts.tv_sec)  * 1'000'000'000ULL
                       + static_cast<uint64_t>(pkt_hdr->ts.tv_usec) * 1'000ULL;
        uint64_t ts_us = ts_ns / 1000;

        uint32_t src_addr = iph->src_addr;
        uint32_t dst_addr = iph->dst_addr;
        uint16_t src_port = tcph->src_port;
        uint16_t dst_port = tcph->dst_port;

        uint8_t flags        = tcph->flags;
        bool    is_syn       = flags & TCP_SYN;
        bool    is_ack       = flags & TCP_ACK;
        bool    local_is_src = (src_addr == local_ip);

        // Skip FIN/RST — they carry no latency signal
        if (flags & (TCP_FIN | TCP_RST)) continue;

        uint32_t payload = tcp_payload_len(iph, tcph);

        // ── Case 1: Outgoing SYN (start of handshake) ──────────────────────
        if (is_syn && !is_ack && local_is_src) {
            ConnKey key{src_addr, src_port, dst_addr, dst_port};
            auto it = pending_syns.find(key);
            if (it != pending_syns.end()) {
                // Retransmitted SYN
                uint32_t& count = syn_retransmit_counts[key];
                ++count;
                uint64_t rto = ts_us > it->second ? ts_us - it->second : 0;
                RetransmitEvent re1{src_addr, dst_addr, src_port, dst_port,
                                    static_cast<uint32_t>(rto), count, ts_ns};
                queue.push(re1);
            } else {
                pending_syns[key] = ts_us;
            }

        // ── Case 2: Incoming SYN-ACK (handshake complete) ──────────────────
        } else if (is_syn && is_ack && !local_is_src) {
            // Packet direction is remote→local, so look up the reversed key
            ConnKey key{dst_addr, dst_port, src_addr, src_port};
            auto it = pending_syns.find(key);
            if (it != pending_syns.end()) {
                uint64_t rtt = ts_us > it->second ? ts_us - it->second : 0;
                if (rtt > 0) {
                    NetworkEvent ne1{dst_addr, src_addr, dst_port, src_port,
                                     /*payload_bytes=*/0, static_cast<uint32_t>(rtt), ts_ns};
                    queue.push(ne1);
                }
                pending_syns.erase(it);
                syn_retransmit_counts.erase(key);
            }

        // ── Case 3: Outgoing data segment ──────────────────────────────────
        } else if (!is_syn && local_is_src && payload > 0) {
            // Key uses next_seq in host byte order so it can be matched against
            // the ACK number from the remote (which is also in host byte order
            // after ntohl).
            uint32_t next_seq = ntohl(tcph->seq) + payload;  // wraps naturally
            SeqKey key{src_addr, src_port, dst_addr, dst_port, next_seq};

            auto it = pending_seqs.find(key);
            if (it != pending_seqs.end()) {
                // Retransmitted data segment
                uint32_t& count = seq_retransmit_counts[key];
                ++count;
                uint64_t rto = ts_us > it->second.first ? ts_us - it->second.first : 0;
                RetransmitEvent re2{src_addr, dst_addr, src_port, dst_port,
                                    static_cast<uint32_t>(rto), count, ts_ns};
                queue.push(re2);
            } else {
                pending_seqs[key] = {ts_us, payload};
            }

        // ── Case 4: Incoming ACK (data RTT completion) ─────────────────────
        } else if (is_ack && !is_syn && !local_is_src) {
            // ack field in the header = next_seq we recorded (host byte order)
            uint32_t ack_seq = ntohl(tcph->ack);
            SeqKey key{dst_addr, dst_port, src_addr, src_port, ack_seq};

            auto it = pending_seqs.find(key);
            if (it != pending_seqs.end()) {
                uint64_t rtt = ts_us > it->second.first ? ts_us - it->second.first : 0;
                if (rtt > 0) {
                    NetworkEvent ne2{dst_addr, src_addr, dst_port, src_port,
                                     it->second.second, static_cast<uint32_t>(rtt), ts_ns};
                    queue.push(ne2);
                }
                pending_seqs.erase(it);
                seq_retransmit_counts.erase(key);
            }
        }
    }

    pcap_close(handle);
}

// ═════════════════════════════════════════════════════════════════════════════
// CLI argument parsing
// ═════════════════════════════════════════════════════════════════════════════

struct Args {
    std::string interface        = "eth0";
    std::string kafka_brokers    = "localhost:9092";
    std::string kafka_topic      = "net-latency";
    std::string retransmit_topic = "net-retransmit";
};

static void print_usage(const char* prog) {
    std::cout
        << "Usage: " << prog << " [options]\n"
        << "  -i, --interface        Network interface to capture on (default: eth0)\n"
        << "  -b, --kafka-brokers    Kafka broker addresses   (default: localhost:9092)\n"
        << "  -t, --kafka-topic      RTT events topic         (default: net-latency)\n"
        << "  -r, --retransmit-topic Retransmit events topic  (default: net-retransmit)\n"
        << "  -h, --help             Show this message\n";
}

static Args parse_args(int argc, char* argv[]) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "missing value for " << a << "\n";
                std::exit(1);
            }
            return argv[++i];
        };
        if      (a == "-i" || a == "--interface")        args.interface        = next();
        else if (a == "-b" || a == "--kafka-brokers")    args.kafka_brokers    = next();
        else if (a == "-t" || a == "--kafka-topic")      args.kafka_topic      = next();
        else if (a == "-r" || a == "--retransmit-topic") args.retransmit_topic = next();
        else if (a == "-h" || a == "--help") { print_usage(argv[0]); std::exit(0); }
        else { std::cerr << "unknown option: " << a << "\n"; std::exit(1); }
    }
    return args;
}

// ═════════════════════════════════════════════════════════════════════════════
// Main
// ═════════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    auto args = parse_args(argc, argv);

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    // Resolve the local IP so we can tell apart outgoing from incoming packets
    uint32_t local_ip = get_local_ip(args.interface);
    if (local_ip == 0) {
        std::cerr << "[warn] could not resolve local IP for interface "
                  << args.interface << " — direction detection may fail\n";
    } else {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_ip, buf, sizeof(buf));
        std::cout << "[info] interface=" << args.interface << " local_ip=" << buf << "\n";
    }

    std::cout << "[info] kafka_brokers="    << args.kafka_brokers    << "\n"
              << "[info] kafka_topic="      << args.kafka_topic      << "\n"
              << "[info] retransmit_topic=" << args.retransmit_topic << "\n";

    KafkaProducer kafka(args.kafka_brokers, args.kafka_topic, args.retransmit_topic);
    EventQueue    queue;

    // pcap's API is synchronous, so it runs in a dedicated thread to avoid
    // blocking the main thread's Kafka I/O.
    std::thread capture_thread([&] {
        capture_loop(args.interface, local_ip, queue);
        queue.close();  // signal main thread that no more events are coming
    });

    // Drain the queue and forward events to Kafka
    Event event;
    while (!queue.is_done()) {
        if (!queue.pop(event, std::chrono::milliseconds(100))) continue;

        std::visit([&](auto& e) {
            using T = std::decay_t<decltype(e)>;

            if constexpr (std::is_same_v<T, NetworkEvent>) {
                std::cout << "[rtt] "
                          << e.src_ip_str() << ":" << ntohs(e.src_port)
                          << " -> "
                          << e.dst_ip_str() << ":" << ntohs(e.dst_port)
                          << "  rtt=" << e.rtt_us << "us"
                          << "  payload=" << e.payload_bytes << "B\n";
                kafka.send_event(e);

            } else if constexpr (std::is_same_v<T, RetransmitEvent>) {
                std::cout << "[retransmit] "
                          << e.src_ip_str() << ":" << ntohs(e.src_port)
                          << " -> "
                          << e.dst_ip_str() << ":" << ntohs(e.dst_port)
                          << "  rto=" << e.rto_us << "us"
                          << "  count=" << e.retransmit_count << "\n";
                kafka.send_retransmit(e);
            }
        }, event);
    }

    capture_thread.join();
    std::cout << "[info] shutdown complete\n";
    return 0;
}
