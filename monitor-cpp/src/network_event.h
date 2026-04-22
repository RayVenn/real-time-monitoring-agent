#pragma once

#include <cstdint>
#include <string>
#include <arpa/inet.h>

// Packed TCP/IP header structs — avoids platform differences between macOS
// (<netinet/tcp.h> BSD field names) and Linux (POSIX field names).
#pragma pack(push, 1)

struct IpHeader {
    uint8_t  ihl_version;   // high nibble = version (4), low nibble = IHL (in 32-bit words)
    uint8_t  tos;
    uint16_t total_len;     // network byte order
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;      // network byte order
    uint32_t dst_addr;      // network byte order

    uint8_t ihl_bytes() const { return (ihl_version & 0x0F) * 4; }
};

struct TcpHeader {
    uint16_t src_port;  // network byte order
    uint16_t dst_port;  // network byte order
    uint32_t seq;       // network byte order
    uint32_t ack;       // network byte order
    uint8_t  data_off;  // high 4 bits = header length in 32-bit words
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;

    uint8_t hdr_bytes() const { return ((data_off >> 4) & 0x0F) * 4; }
};

#pragma pack(pop)

// TCP flag bits
constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_ACK = 0x10;

// Ethernet frame header size (IEEE 802.3)
constexpr size_t ETH_HDR_LEN = 14;

// ─────────────────────────────────────────────────────────────────────────────
// NetworkEvent — emitted for every measured TCP round-trip
// src_* is always the local machine; dst_* is always the remote.
// ─────────────────────────────────────────────────────────────────────────────
struct NetworkEvent {
    uint32_t src_addr;      // local IPv4, network byte order
    uint32_t dst_addr;      // remote IPv4, network byte order
    uint16_t src_port;      // network byte order
    uint16_t dst_port;      // network byte order
    uint32_t payload_bytes; // data bytes that triggered this RTT (0 for SYN/SYN-ACK)
    uint32_t rtt_us;        // round-trip time in microseconds
    uint64_t timestamp_ns;  // packet capture timestamp in nanoseconds

    std::string src_ip_str() const {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, buf, sizeof(buf));
        return buf;
    }

    std::string dst_ip_str() const {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dst_addr, buf, sizeof(buf));
        return buf;
    }

    // Kafka message key: "src_ip:src_port->dst_ip"
    std::string kafka_key() const {
        return src_ip_str() + ":" + std::to_string(ntohs(src_port)) + "->" + dst_ip_str();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// RetransmitEvent — emitted each time a SYN or data segment is retransmitted
// ─────────────────────────────────────────────────────────────────────────────
struct RetransmitEvent {
    uint32_t src_addr;         // local IPv4, network byte order
    uint32_t dst_addr;         // remote IPv4, network byte order
    uint16_t src_port;         // network byte order
    uint16_t dst_port;         // network byte order
    uint32_t rto_us;           // time since original transmission (microseconds)
    uint32_t retransmit_count; // how many times this segment has been retransmitted
    uint64_t timestamp_ns;

    std::string src_ip_str() const {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, buf, sizeof(buf));
        return buf;
    }

    std::string dst_ip_str() const {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dst_addr, buf, sizeof(buf));
        return buf;
    }

    std::string kafka_key() const {
        return src_ip_str() + ":" + std::to_string(ntohs(src_port)) + "->" + dst_ip_str();
    }
};
