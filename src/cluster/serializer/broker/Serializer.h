

#pragma once

#include <memory>
#include <vector>

#include "zeek/cluster/Serializer.h"

namespace broker::zeek {
class Event;
}

namespace zeek {

namespace detail {
class MetadataEntry;

using EventMetadataVector = std::vector<MetadataEntry>;
using EventMetadataVectorPtr = std::unique_ptr<EventMetadataVector>;

}

namespace cluster::detail {












zeek::detail::EventMetadataVectorPtr metadata_vector_from_broker_event(const broker::zeek::Event& ev);









std::optional<cluster::Event> to_zeek_event(const broker::zeek::Event& ev);







std::optional<broker::zeek::Event> to_broker_event(const cluster::Event& ev);



class BrokerBinV1_Serializer : public EventSerializer {
public:
    BrokerBinV1_Serializer() : EventSerializer("broker-bin-v1") {}

    bool SerializeEvent(byte_buffer& buf, const cluster::Event& event) override;

    std::optional<cluster::Event> UnserializeEvent(byte_buffer_span buf) override;
};



class BrokerJsonV1_Serializer : public EventSerializer {
public:
    BrokerJsonV1_Serializer() : EventSerializer("broker-json-v1") {}

    bool SerializeEvent(byte_buffer& buf, const cluster::Event& event) override;

    std::optional<cluster::Event> UnserializeEvent(byte_buffer_span buf) override;
};

}
}
