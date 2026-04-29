package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"

	"github.com/IBM/sarama"
	"github.com/aws/aws-msk-iam-sasl-signer-go/signer"
)

type MSKProducer struct {
	producer        sarama.SyncProducer
	rttTopic        string
	retransmitTopic string
}

// mskTokenProvider satisfies sarama's OAUTHBEARER token provider interface
// using the AWS MSK IAM SASL signer — no passwords, no SASL config in code.
type mskTokenProvider struct {
	region string
}

func (p *mskTokenProvider) Token() (*sarama.AccessToken, error) {
	token, _, err := signer.GenerateAuthToken(context.Background(), p.region)
	if err != nil {
		return nil, fmt.Errorf("msk iam token: %w", err)
	}
	return &sarama.AccessToken{Token: token}, nil
}

// NewMSKProducer connects to an MSK cluster via IAM auth (SASL/OAUTHBEARER over TLS).
// brokers should be the IAM-auth bootstrap endpoints, e.g. b-1.cluster.region.kafka.amazonaws.com:9098
func NewMSKProducer(brokers []string, region, rttTopic, retransmitTopic string) (*MSKProducer, error) {
	cfg := sarama.NewConfig()
	cfg.Producer.Return.Successes = true
	cfg.Producer.RequiredAcks = sarama.WaitForLocal

	cfg.Net.SASL.Enable = true
	cfg.Net.SASL.Mechanism = sarama.SASLTypeOAuth
	cfg.Net.SASL.TokenProvider = &mskTokenProvider{region: region}
	cfg.Net.TLS.Enable = true
	cfg.Net.TLS.Config = &tls.Config{}

	producer, err := sarama.NewSyncProducer(brokers, cfg)
	if err != nil {
		return nil, fmt.Errorf("new msk producer: %w", err)
	}
	return &MSKProducer{
		producer:        producer,
		rttTopic:        rttTopic,
		retransmitTopic: retransmitTopic,
	}, nil
}

func (p *MSKProducer) SendEvent(_ context.Context, e NetworkEvent) {
	data, _ := json.Marshal(e)
	p.send(p.rttTopic, e.PartitionKey(), data)
}

func (p *MSKProducer) SendRetransmit(_ context.Context, e RetransmitEvent) {
	data, _ := json.Marshal(e)
	p.send(p.retransmitTopic, e.PartitionKey(), data)
}

func (p *MSKProducer) send(topic, key string, data []byte) {
	msg := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(data),
	}
	if _, _, err := p.producer.SendMessage(msg); err != nil {
		log.Printf("[msk] send error topic=%s: %v", topic, err)
	}
}

func (p *MSKProducer) Close() {
	if err := p.producer.Close(); err != nil {
		log.Printf("[msk] close error: %v", err)
	}
}
