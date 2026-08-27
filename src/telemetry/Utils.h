

#pragma once

#include <prometheus/family.h>
#include <prometheus/labels.h>
#include <span>
#include <string_view>

namespace zeek::telemetry {

using LabelView = std::pair<std::string_view, std::string_view>;

namespace detail {





prometheus::Labels BuildPrometheusLabels(std::span<const LabelView> labels);




std::string BuildFullPrometheusName(std::string_view prefix, std::string_view name, std::string_view unit,
                                    bool is_sum = false);

}
}
