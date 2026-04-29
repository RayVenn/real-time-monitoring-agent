package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// connKey identifies a TCP connection direction (src→dst).
type connKey struct {
	srcAddr [4]byte
	srcPort uint16
	dstAddr [4]byte
	dstPort uint16
}

// seqKey extends connKey with the next sequence number the remote will ACK,
// used to correlate outgoing data segments with their incoming ACKs.
type seqKey struct {
	connKey
	nextSeq uint32
}

type seqEntry struct {
	tsUS    uint64
	payload uint32
}

// capture runs the pcap loop, computing RTTs and detecting retransmissions.
// It sends events to the channel and returns when ctx is cancelled.
//
// RTT strategy (local machine as client):
//   - Outgoing SYN      → record timestamp in pendingSYNs
//   - Incoming SYN-ACK  → emit NetworkEvent(rtt, payload=0), delete entry
//   - Outgoing DATA     → record timestamp keyed by nextSeq
//   - Incoming ACK      → emit NetworkEvent(rtt, payload), delete entry
//
// Retransmissions are detected when the same key arrives before the ACK.
func capture(ctx context.Context, iface string, events chan<- Event) error {
	localIP, err := getLocalIP(iface)
	if err != nil {
		log.Printf("[warn] could not resolve local IP for %s: %v", iface, err)
	}

	// snaplen=96 captures full headers without storing payload bytes.
	// timeout=100ms prevents output stalls when traffic is sparse.
	handle, err := pcap.OpenLive(iface, 96, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open: %w", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp"); err != nil {
		return fmt.Errorf("bpf filter: %w", err)
	}

	var localAddr [4]byte
	if localIP != nil {
		copy(localAddr[:], localIP.To4())
		log.Printf("[info] interface=%s local_ip=%s", iface, localIP)
	}

	// RTT state — all maps are keyed by connection tuples so lookups are O(1).
	pendingSYNs    := make(map[connKey]uint64)
	pendingSEQs    := make(map[seqKey]seqEntry)
	synRetransmits := make(map[connKey]uint32)
	seqRetransmits := make(map[seqKey]uint32)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		packet, err := src.NextPacket()
		if err != nil {
			continue // timeout or transient read error
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if ipLayer == nil || tcpLayer == nil {
			continue
		}

		ip := ipLayer.(*layers.IPv4)
		tcp := tcpLayer.(*layers.TCP)

		if tcp.FIN || tcp.RST {
			continue
		}

		ci := packet.Metadata().CaptureInfo
		tsNS := ci.Timestamp.UnixNano()
		tsUS := uint64(tsNS / 1000)

		srcAddr := to4(ip.SrcIP)
		dstAddr := to4(ip.DstIP)
		localIsSrc := srcAddr == localAddr

		// Compute payload length from IP header fields — snaplen may have
		// truncated the actual bytes, but ip.Length is always intact.
		payloadLen := int(ip.Length) - int(ip.IHL)*4 - int(tcp.DataOffset)*4
		if payloadLen < 0 {
			payloadLen = 0
		}
		payload := uint32(payloadLen)

		switch {
		// ── Case 1: Outgoing SYN (start of handshake) ───────────────────────
		case tcp.SYN && !tcp.ACK && localIsSrc:
			key := connKey{srcAddr, uint16(tcp.SrcPort), dstAddr, uint16(tcp.DstPort)}
			if ts, ok := pendingSYNs[key]; ok {
				synRetransmits[key]++
				rto := saturatingSub(tsUS, ts)
				events <- RetransmitEvent{
					SrcIP: ip.SrcIP.String(), SrcPort: uint16(tcp.SrcPort),
					DstIP: ip.DstIP.String(), DstPort: uint16(tcp.DstPort),
					RTOUS: uint32(rto), RetransmitCount: synRetransmits[key],
					TimestampNS: tsNS,
				}
			} else {
				pendingSYNs[key] = tsUS
			}

		// ── Case 2: Incoming SYN-ACK (handshake complete) ───────────────────
		case tcp.SYN && tcp.ACK && !localIsSrc:
			// Packet direction is remote→local, so look up the reversed key.
			key := connKey{dstAddr, uint16(tcp.DstPort), srcAddr, uint16(tcp.SrcPort)}
			if ts, ok := pendingSYNs[key]; ok {
				if rtt := saturatingSub(tsUS, ts); rtt > 0 {
					events <- NetworkEvent{
						SrcIP: ip.DstIP.String(), SrcPort: uint16(tcp.DstPort),
						DstIP: ip.SrcIP.String(), DstPort: uint16(tcp.SrcPort),
						PayloadBytes: 0, RTTUS: uint32(rtt), TimestampNS: tsNS,
					}
				}
				delete(pendingSYNs, key)
				delete(synRetransmits, key)
			}

		// ── Case 3: Outgoing data segment ───────────────────────────────────
		case !tcp.SYN && localIsSrc && payload > 0:
			// nextSeq wraps naturally at uint32 max, matching TCP semantics.
			nextSeq := tcp.Seq + payload
			key := seqKey{connKey{srcAddr, uint16(tcp.SrcPort), dstAddr, uint16(tcp.DstPort)}, nextSeq}
			if entry, ok := pendingSEQs[key]; ok {
				seqRetransmits[key]++
				rto := saturatingSub(tsUS, entry.tsUS)
				events <- RetransmitEvent{
					SrcIP: ip.SrcIP.String(), SrcPort: uint16(tcp.SrcPort),
					DstIP: ip.DstIP.String(), DstPort: uint16(tcp.DstPort),
					RTOUS: uint32(rto), RetransmitCount: seqRetransmits[key],
					TimestampNS: tsNS,
				}
			} else {
				pendingSEQs[key] = seqEntry{tsUS, payload}
			}

		// ── Case 4: Incoming ACK (data RTT completion) ──────────────────────
		case tcp.ACK && !tcp.SYN && !localIsSrc:
			key := seqKey{connKey{dstAddr, uint16(tcp.DstPort), srcAddr, uint16(tcp.SrcPort)}, tcp.Ack}
			if entry, ok := pendingSEQs[key]; ok {
				if rtt := saturatingSub(tsUS, entry.tsUS); rtt > 0 {
					events <- NetworkEvent{
						SrcIP: ip.DstIP.String(), SrcPort: uint16(tcp.DstPort),
						DstIP: ip.SrcIP.String(), DstPort: uint16(tcp.SrcPort),
						PayloadBytes: entry.payload, RTTUS: uint32(rtt), TimestampNS: tsNS,
					}
				}
				delete(pendingSEQs, key)
				delete(seqRetransmits, key)
			}
		}
	}
}

func getLocalIP(iface string) (net.IP, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 address on %s", iface)
}

func to4(ip net.IP) [4]byte {
	var arr [4]byte
	if ip4 := ip.To4(); ip4 != nil {
		copy(arr[:], ip4)
	}
	return arr
}

// saturatingSub returns a - b, or 0 if b > a (guards against out-of-order timestamps).
func saturatingSub(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return 0
}
