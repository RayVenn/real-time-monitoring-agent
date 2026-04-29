package main

import "fmt"

// NetworkEvent is emitted for every measured TCP round-trip.
// SrcIP is always the local machine; DstIP is always the remote.
type NetworkEvent struct {
	SrcIP        string `json:"src_ip"`
	SrcPort      uint16 `json:"src_port"`
	DstIP        string `json:"dst_ip"`
	DstPort      uint16 `json:"dst_port"`
	PayloadBytes uint32 `json:"payload_bytes"`
	RTTUS        uint32 `json:"rtt_us"`
	TimestampNS  int64  `json:"timestamp_ns"`
}

func (e NetworkEvent) PartitionKey() string {
	return fmt.Sprintf("%s:%d->%s", e.SrcIP, e.SrcPort, e.DstIP)
}

// RetransmitEvent is emitted each time a SYN or data segment is retransmitted.
type RetransmitEvent struct {
	SrcIP           string `json:"src_ip"`
	SrcPort         uint16 `json:"src_port"`
	DstIP           string `json:"dst_ip"`
	DstPort         uint16 `json:"dst_port"`
	RTOUS           uint32 `json:"rto_us"`
	RetransmitCount uint32 `json:"retransmit_count"`
	TimestampNS     int64  `json:"timestamp_ns"`
}

func (e RetransmitEvent) PartitionKey() string {
	return fmt.Sprintf("%s:%d->%s", e.SrcIP, e.SrcPort, e.DstIP)
}

type Event interface {
	PartitionKey() string
}
