

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "zeek/IntrusivePtr.h"


namespace zeek {

class TableVal;
using TableValPtr = zeek::IntrusivePtr<TableVal>;

namespace telemetry {
class Counter;
using CounterPtr = std::shared_ptr<Counter>;

class CounterFamily;
using CounterFamilyPtr = std::shared_ptr<CounterFamily>;

class HistogramFamily;
using HistogramFamilyPtr = std::shared_ptr<HistogramFamily>;

using LabelView = std::pair<std::string_view, std::string_view>;

}

namespace cluster {

class Backend;

namespace detail {

enum class TelemetryScope : uint8_t {
    Core,
    WebSocket,
};




class SerializationInfo {
public:
    explicit SerializationInfo(size_t size) : size(size) {}

    size_t Size() const { return size; }

private:
    size_t size;
};

using TopicNormalizer = std::function<std::string_view(std::string_view)>;
using LabelList = std::vector<std::pair<std::string, std::string>>;
using LabelViewList = std::vector<std::pair<std::string_view, std::string_view>>;




class TableTopicNormalizer {
public:
    TableTopicNormalizer();
    std::string_view operator()(std::string_view topic);

private:
    zeek::TableValPtr topic_normalizations;
};

class Telemetry {
public:
    virtual ~Telemetry() = default;

    virtual void OnOutgoingEvent(std::string_view topic, std::string_view handler_name,
                                 const SerializationInfo& info) = 0;
    virtual void OnIncomingEvent(std::string_view topic, std::string_view handler_name,
                                 const SerializationInfo& info) = 0;
};

using TelemetryPtr = std::unique_ptr<Telemetry>;


class NullTelemetry : public Telemetry {
    void OnOutgoingEvent(std::string_view topic, std::string_view handler_name,
                         const SerializationInfo& info) override {}
    void OnIncomingEvent(std::string_view topic, std::string_view handler_name,
                         const SerializationInfo& info) override {}
};



class CompositeTelemetry : public Telemetry {
public:
    void OnOutgoingEvent(std::string_view topic, std::string_view handler_name,
                         const SerializationInfo& info) override {
        for ( const auto& c : children )
            c->OnOutgoingEvent(topic, handler_name, info);
    }

    void OnIncomingEvent(std::string_view topic, std::string_view handler_name,
                         const SerializationInfo& info) override {
        for ( const auto& c : children )
            c->OnIncomingEvent(topic, handler_name, info);
    }

    void Add(TelemetryPtr child) { children.push_back(std::move(child)); }

private:
    std::vector<TelemetryPtr> children;
};




class InfoTelemetry : public Telemetry {
public:






    InfoTelemetry(std::string_view name, const LabelList& static_labels, std::string_view prefix = "zeek");

    void OnOutgoingEvent(std::string_view topic, std::string_view handler_name, const SerializationInfo& info) override;
    void OnIncomingEvent(std::string_view topic, std::string_view handler_name, const SerializationInfo& info) override;

private:
    telemetry::CounterPtr in, out;
};








class VerboseTelemetry : public Telemetry {
public:
    VerboseTelemetry(TopicNormalizer topic_normalizer, std::string_view name, LabelList static_labels,
                     std::string_view prefix = "zeek");

    void OnOutgoingEvent(std::string_view topic, std::string_view handler_name, const SerializationInfo& info) override;
    void OnIncomingEvent(std::string_view topic, std::string_view handler_name, const SerializationInfo& info) override;

private:
    TopicNormalizer topic_normalizer;
    LabelList labels;
    LabelViewList labels_view;
    size_t topic_idx, handler_idx;
    telemetry::CounterFamilyPtr in, out;
};





class DebugTelemetry : public Telemetry {
public:
    DebugTelemetry(TopicNormalizer topic_normalizer, std::string_view name, LabelList static_labels,
                   std::vector<double> size_bounds, std::string_view prefix = "zeek");

    void OnOutgoingEvent(std::string_view topic, std::string_view handler_name, const SerializationInfo& info) override;
    void OnIncomingEvent(std::string_view topic, std::string_view handler_name, const SerializationInfo& info) override;

private:
    TopicNormalizer topic_normalizer;
    std::vector<double> size_bounds;
    LabelList labels;
    LabelViewList labels_view;
    std::span<telemetry::LabelView> labels_view_no_location;
    size_t topic_idx, handler_idx,
        script_location_idx;
    telemetry::HistogramFamilyPtr in, out;
};









void configure_backend_telemetry(Backend& backend, std::string_view name, const LabelList& static_labels = {});

}
}
}
