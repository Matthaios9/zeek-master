

#pragma once

#include <optional>
#include <span>
#include <string>

#include "zeek/IntrusivePtr.h"
#include "zeek/net_util.h"



namespace zeek {

namespace detail {
class Frame;
}

class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;
class VectorVal;
using VectorValPtr = IntrusivePtr<VectorVal>;

class Val;
using ValPtr = IntrusivePtr<Val>;
using ArgsSpan = std::span<const ValPtr>;

namespace cluster::detail::bif {










zeek::RecordValPtr make_event(zeek::ArgsSpan args);










bool publish_event(const zeek::ValPtr& topic, zeek::ArgsSpan args);

bool is_cluster_pool(const zeek::Val* pool);











zeek::RecordValPtr make_endpoint_info(const std::string& id, const std::string& address, uint32_t port,
                                      TransportProto proto, std::optional<std::string> application_name);








zeek::VectorValPtr make_string_vec(std::span<const std::string> strings);

}

}
