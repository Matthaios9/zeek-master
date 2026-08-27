

#pragma once

#include <prometheus/counter.h>
#include <prometheus/family.h>
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

class CounterFamily;




class Counter {
public:
    static inline const char* OpaqueName = "CounterMetricVal";

    using Handle = prometheus::Counter;
    using FamilyType = prometheus::Family<Handle>;

    explicit Counter(FamilyType* family, const prometheus::Labels& labels,
                     detail::CollectCallbackPtr callback = nullptr) noexcept;




    void Inc() noexcept { Inc(1); }





    void Inc(double amount) noexcept { handle.Increment(amount); }





    double operator++() noexcept {
        Inc(1);
        return Value();
    }

    double Value() const noexcept;

    bool operator==(const Counter& rhs) const noexcept { return &handle == &rhs.handle; }
    bool operator!=(const Counter& rhs) const noexcept { return &handle != &rhs.handle; }

    bool CompareLabels(const prometheus::Labels& lbls) const { return labels == lbls; }

    bool HasCallback() const noexcept { return callback != nullptr; }
    double RunCallback() const { return callback(); }
    void RemoveCallback() { callback = nullptr; }

private:
    friend class CounterFamily;
    void Set(double val) {

        handle.Reset();
        handle.Increment(val);
    }

    FamilyType* family = nullptr;
    Handle& handle;
    prometheus::Labels labels;
    detail::CollectCallbackPtr callback;
};

using CounterPtr = std::shared_ptr<Counter>;

class CounterFamily : public MetricFamily {
public:
    static inline const char* OpaqueName = "CounterMetricFamilyVal";

    CounterFamily(prometheus::Family<prometheus::Counter>* family, std::span<const std::string_view> labels)
        : MetricFamily(labels), family(family) {}





    CounterPtr GetOrAdd(std::span<const LabelView> labels, detail::CollectCallbackPtr callback = nullptr);




    CounterPtr GetOrAdd(std::initializer_list<LabelView> labels, detail::CollectCallbackPtr callback = nullptr);

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::COUNTER; }

    void RunCallbacks() override;

private:
    prometheus::Family<prometheus::Counter>* family;
    std::vector<CounterPtr> counters;
};

using CounterFamilyPtr = std::shared_ptr<CounterFamily>;

}
