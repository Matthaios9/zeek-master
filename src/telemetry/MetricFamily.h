

#pragma once

#include <span>
#include <string>
#include <vector>

#include "zeek/util-types.h"

namespace zeek::telemetry {





class MetricFamily {
public:
    virtual ~MetricFamily() = default;

    virtual zeek_int_t MetricType() const = 0;

    std::vector<std::string> LabelNames() const { return label_names; }

    virtual void RunCallbacks() = 0;

protected:
    MetricFamily(std::span<const std::string_view> labels) {
        for ( const auto& lbl : labels )
            label_names.emplace_back(lbl);
    }

    std::vector<std::string> label_names;
};

}
