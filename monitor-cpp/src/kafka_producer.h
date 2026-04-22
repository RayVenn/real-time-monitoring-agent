#pragma once

#include <string>
#include <memory>
#include <librdkafka/rdkafkacpp.h>
#include "network_event.h"

class KafkaProducer {
public:
    KafkaProducer(const std::string& brokers,
                  const std::string& rtt_topic,
                  const std::string& retransmit_topic);
    ~KafkaProducer();

    void send_event(const NetworkEvent& event);
    void send_retransmit(const RetransmitEvent& event);

    // Block until all queued messages are delivered (call before shutdown)
    void flush(int timeout_ms = 3000);

private:
    std::unique_ptr<RdKafka::Producer> producer_;
    std::string rtt_topic_;
    std::string retransmit_topic_;

    void produce(const std::string& topic,
                 const std::string& key,
                 const std::string& value);
};
