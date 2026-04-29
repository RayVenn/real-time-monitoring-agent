package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	iface           := flag.String("interface",         "eth0",          "network interface to capture on")
	brokersFlag     := flag.String("brokers",           "",              "comma-separated MSK bootstrap servers (port 9098 for IAM auth)")
	rttTopic        := flag.String("rtt-topic",         "net-latency",   "Kafka topic for RTT events")
	retransmitTopic := flag.String("retransmit-topic",  "net-retransmit","Kafka topic for retransmit events")
	region          := flag.String("region",            "us-east-1",     "AWS region")
	flag.Parse()

	if *brokersFlag == "" {
		log.Fatal("[fatal] --brokers is required")
	}
	brokers := strings.Split(*brokersFlag, ",")

	log.Printf("[info] interface=%s brokers=%v rtt-topic=%s retransmit-topic=%s region=%s",
		*iface, brokers, *rttTopic, *retransmitTopic, *region)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	producer, err := NewMSKProducer(brokers, *region, *rttTopic, *retransmitTopic)
	if err != nil {
		log.Fatalf("[fatal] msk producer: %v", err)
	}
	defer producer.Close()

	events := make(chan Event, 1000)

	go func() {
		if err := capture(ctx, *iface, events); err != nil {
			log.Printf("[error] capture: %v", err)
		}
		close(events)
	}()

	for event := range events {
		switch e := event.(type) {
		case NetworkEvent:
			fmt.Printf("[rtt] %s:%d -> %s:%d  rtt=%dus  payload=%dB\n",
				e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.RTTUS, e.PayloadBytes)
			producer.SendEvent(ctx, e)

		case RetransmitEvent:
			fmt.Printf("[retransmit] %s:%d -> %s:%d  rto=%dus  count=%d\n",
				e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.RTOUS, e.RetransmitCount)
			producer.SendRetransmit(ctx, e)
		}
	}

	log.Println("[info] shutdown complete")
}
