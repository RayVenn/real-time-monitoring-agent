#include "kafka_producer.h"

#include <iostream>
#include <stdexcept>
#include <nlohmann/json.hpp>

static std::string to_json(const NetworkEvent& e) {
    return nlohmann::json{
        {"src_ip",        e.src_ip_str()},
        {"src_port",      ntohs(e.src_port)},
        {"dst_ip",        e.dst_ip_str()},
        {"dst_port",      ntohs(e.dst_port)},
        {"payload_bytes", e.payload_bytes},
        {"rtt_us",        e.rtt_us},
        {"timestamp_ns",  e.timestamp_ns},
    }.dump();
}

static std::string to_json(const RetransmitEvent& e) {
    return nlohmann::json{
        {"src_ip",           e.src_ip_str()},
        {"src_port",         ntohs(e.src_port)},
        {"dst_ip",           e.dst_ip_str()},
        {"dst_port",         ntohs(e.dst_port)},
        {"rto_us",           e.rto_us},
        {"retransmit_count", e.retransmit_count},
        {"timestamp_ns",     e.timestamp_ns},
    }.dump();
}

// ─────────────────────────────────────────────────────────────────────────────
// Delivery callback — called by rdkafka after each message is acknowledged (or
// failed). We only log errors; success is silent.
// ─────────────────────────────────────────────────────────────────────────────
class DeliveryReportCb : public RdKafka::DeliveryReportCb {
public:
    void dr_cb(RdKafka::Message& msg) override {
        if (msg.err() != RdKafka::ERR_NO_ERROR) {
            std::cerr << "[kafka] delivery error topic=" << msg.topic_name()
                      << " err=" << msg.errstr() << "\n";
        }
    }
};

static DeliveryReportCb g_dr_cb;

// ─────────────────────────────────────────────────────────────────────────────

static void set_conf(RdKafka::Conf* conf,
                     const std::string& key,
                     const std::string& val)
{
    std::string err;
    if (conf->set(key, val, err) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("kafka config [" + key + "]: " + err);
}

KafkaProducer::KafkaProducer(const std::string& brokers,
                              const std::string& rtt_topic,
                              const std::string& retransmit_topic)
    : rtt_topic_(rtt_topic), retransmit_topic_(retransmit_topic)
{
    std::string err;
    auto conf = std::unique_ptr<RdKafka::Conf>(
        RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));

    set_conf(conf.get(), "bootstrap.servers",              brokers);
    set_conf(conf.get(), "message.timeout.ms",             "5000");
    set_conf(conf.get(), "queue.buffering.max.messages",   "100000");
    set_conf(conf.get(), "queue.buffering.max.ms",         "50");
    set_conf(conf.get(), "compression.type",               "lz4");

    if (conf->set("dr_cb", &g_dr_cb, err) != RdKafka::Conf::CONF_OK)
        throw std::runtime_error("kafka config [dr_cb]: " + err);

    producer_.reset(RdKafka::Producer::create(conf.get(), err));
    if (!producer_)
        throw std::runtime_error("failed to create kafka producer: " + err);
}

KafkaProducer::~KafkaProducer() {
    flush();
}

void KafkaProducer::produce(const std::string& topic,
                             const std::string& key,
                             const std::string& value)
{
    auto err = producer_->produce(
        topic,
        RdKafka::Topic::PARTITION_UA,       // let Kafka choose the partition
        RdKafka::Producer::RK_MSG_COPY,     // copy payload — we don't own the buffer
        const_cast<char*>(value.data()), value.size(),
        key.data(), key.size(),
        0,       // timestamp (0 = use broker wall-clock)
        nullptr, // per-message opaque pointer (unused)
        nullptr  // headers (unused)
    );

    if (err != RdKafka::ERR_NO_ERROR)
        std::cerr << "[kafka] produce error: " << RdKafka::err2str(err) << "\n";

    // Poll delivery reports without blocking — prevents internal queue overflow
    producer_->poll(0);
}

void KafkaProducer::send_event(const NetworkEvent& event) {
    produce(rtt_topic_, event.kafka_key(), to_json(event));
}

void KafkaProducer::send_retransmit(const RetransmitEvent& event) {
    produce(retransmit_topic_, event.kafka_key(), to_json(event));
}

void KafkaProducer::flush(int timeout_ms) {
    producer_->flush(timeout_ms);
}
