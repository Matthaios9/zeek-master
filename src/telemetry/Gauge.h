

#pragma once

#include <prometheus/family.h>
#include <prometheus/gauge.h>
#include <initializer_list>
#include <memory>
#include <span>

#include "zeek/NetVar.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/Utils.h"

namespace zeek::telemetry {

namespace detail {
using CollectCallbackPtr = std::function<double()>;
}




class Gauge {
public:
    static inline const char* OpaqueName = "GaugeMetricVal";

    using Handle = prometheus::Gauge;
    using FamilyType = prometheus::Family<Handle>;

    explicit Gauge(FamilyType* family, const prometheus::Labels& labels,
                   detail::CollectCallbackPtr callback = nullptr) noexcept;




    void Inc() noexcept { Inc(1); }




    void Inc(double amount) noexcept { handle.Increment(amount); }





    double operator++() noexcept {
        Inc(1);
        return Value();
    }




    void Dec() noexcept { Dec(1); }




    void Dec(double amount) noexcept { handle.Decrement(amount); }




    void Set(double val) noexcept { handle.Set(val); }





    double operator--() noexcept {
        Dec(1);
        return Value();
    }

    double Value() const noexcept;

    bool operator==(const Gauge& rhs) const noexcept { return &handle == &rhs.handle; }
    bool operator!=(const Gauge& rhs) const noexcept { return &handle != &rhs.handle; }

    bool CompareLabels(const prometheus::Labels& lbls) const { return labels == lbls; }

    bool HasCallback() const noexcept { return callback != nullptr; }
    double RunCallback() const { return callback(); }
    void RemoveCallback() { callback = nullptr; }

private:
    FamilyType* family = nullptr;
    Handle& handle;
    prometheus::Labels labels;
    detail::CollectCallbackPtr callback;
};

using GaugePtr = std::shared_ptr<Gauge>;

class GaugeFamily : public MetricFamily {
public:
    static inline const char* OpaqueName = "GaugeMetricFamilyVal";





    GaugePtr GetOrAdd(std::span<const LabelView> labels, detail::CollectCallbackPtr callback = nullptr);




    GaugePtr GetOrAdd(std::initializer_list<LabelView> labels, detail::CollectCallbackPtr callback = nullptr);

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::GAUGE; }

    GaugeFamily(prometheus::Family<prometheus::Gauge>* family, std::span<const std::string_view> labels)
        : MetricFamily(labels), family(family) {}

    void RunCallbacks() override;

private:
    prometheus::Family<prometheus::Gauge>* family;
    std::vector<GaugePtr> gauges;
};

using GaugeFamilyPtr = std::shared_ptr<GaugeFamily>;

}
