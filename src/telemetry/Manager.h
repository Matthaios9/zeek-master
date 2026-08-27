

#pragma once

#include "zeek/zeek-config.h"

#include <concepts>
#include <condition_variable>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "zeek/Flare.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/telemetry/Gauge.h"
#include "zeek/telemetry/Histogram.h"
#include "zeek/telemetry/ProcessStats.h"
#include "zeek/telemetry/Utils.h"

namespace zeek {
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;
}

namespace prometheus {
class Exposer;
class Registry;
}

namespace zeek::telemetry {

namespace detail {
using CollectCallbackPtr = std::function<double()>;
}

class ZeekCollectable;




class Manager final : public iosource::IOSource {
public:
    Manager();

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    ~Manager() override;





    void InitPostScript();









    void ListenPrometheus(std::string_view metrics_addr, int port, bool expose_services_json);

    void Terminate();






    ValPtr CollectMetrics(std::string_view prefix, std::string_view name);






    ValPtr CollectHistogramMetrics(std::string_view prefix, std::string_view name);









    CounterFamilyPtr CounterFamily(std::string_view prefix, std::string_view name,
                                   std::span<const std::string_view> labels, std::string_view helptext,
                                   std::string_view unit = "");


    CounterFamilyPtr CounterFamily(std::string_view prefix, std::string_view name,
                                   std::initializer_list<std::string_view> labels, std::string_view helptext,
                                   std::string_view unit = "");












    CounterPtr CounterInstance(std::string_view prefix, std::string_view name, std::span<const LabelView> labels,
                               std::string_view helptext, std::string_view unit = "",
                               detail::CollectCallbackPtr callback = nullptr);


    CounterPtr CounterInstance(std::string_view prefix, std::string_view name, std::initializer_list<LabelView> labels,
                               std::string_view helptext, std::string_view unit = "",
                               detail::CollectCallbackPtr callback = nullptr);









    GaugeFamilyPtr GaugeFamily(std::string_view prefix, std::string_view name, std::span<const std::string_view> labels,
                               std::string_view helptext, std::string_view unit = "");


    GaugeFamilyPtr GaugeFamily(std::string_view prefix, std::string_view name,
                               std::initializer_list<std::string_view> labels, std::string_view helptext,
                               std::string_view unit = "");












    GaugePtr GaugeInstance(std::string_view prefix, std::string_view name, std::span<const LabelView> labels,
                           std::string_view helptext, std::string_view unit = "",
                           detail::CollectCallbackPtr callback = nullptr);


    GaugePtr GaugeInstance(std::string_view prefix, std::string_view name, std::initializer_list<LabelView> labels,
                           std::string_view helptext, std::string_view unit = "",
                           detail::CollectCallbackPtr callback = nullptr);



















    HistogramFamilyPtr HistogramFamily(std::string_view prefix, std::string_view name,
                                       std::span<const std::string_view> labels, std::span<const double> bounds,
                                       std::string_view helptext, std::string_view unit = "");


    HistogramFamilyPtr HistogramFamily(std::string_view prefix, std::string_view name,
                                       std::initializer_list<std::string_view> labels, std::span<const double> bounds,
                                       std::string_view helptext, std::string_view unit = "");


















    HistogramPtr HistogramInstance(std::string_view prefix, std::string_view name, std::span<const LabelView> labels,
                                   std::span<const double> bounds, std::string_view helptext,
                                   std::string_view unit = "");


    HistogramPtr HistogramInstance(std::string_view prefix, std::string_view name,
                                   std::initializer_list<LabelView> labels, std::initializer_list<double> bounds,
                                   std::string_view helptext, std::string_view unit = "");





    std::string GetClusterJson() const { return cluster_json; }






    std::shared_ptr<prometheus::Registry> GetRegistry() const { return prometheus_registry; }


    double GetNextTimeout() override { return -1.0; }
    void Process() override {}
    const char* Tag() override { return "Telemetry::Manager"; }
    void ProcessFd(int fd, int flags) override;

protected:
    template<std::invocable<std::span<std::string_view>> F>
    static auto WithLabelNames(std::span<const LabelView> xs, F&& continuation) {
        if ( xs.size() <= 10 ) {
            std::string_view buf[10];
            for ( size_t index = 0; index < xs.size(); ++index )
                buf[index] = xs[index].first;

            return continuation(std::span{buf, xs.size()});
        }
        else {
            std::vector<std::string_view> buf;
            for ( auto x : xs )
                buf.emplace_back(x.first);

            return continuation(std::span{buf});
        }
    }

    friend class ZeekCollectable;






    void WaitForPrometheusCallbacks();

private:
    RecordValPtr GetMetricOptsRecord(const prometheus::MetricFamily& metric_family);
    void BuildClusterJson();




    void InvokeTelemetrySyncHook();




    void UpdateMetrics();

    bool in_sync_hook = false;

    std::map<std::string, std::shared_ptr<MetricFamily>> families;
    std::map<std::string, RecordValPtr> opts_records;

    detail::process_stats current_process_stats;
    double process_stats_last_updated = 0.0;

    GaugePtr rss_gauge;
    GaugePtr vms_gauge;
    CounterPtr cpu_user_counter;
    CounterPtr cpu_system_counter;
    GaugePtr fds_gauge;
    GaugePtr process_start_time;

    std::shared_ptr<prometheus::Registry> prometheus_registry;
    std::unique_ptr<prometheus::Exposer> prometheus_exposer;

    std::string cluster_json;

    std::shared_ptr<ZeekCollectable> zeek_collectable;
    zeek::detail::Flare collector_flare;
    std::condition_variable collector_cv;
    std::mutex collector_cv_mtx;

    uint64_t collector_request_idx = 0;
    uint64_t collector_response_idx = 0;
};

}

namespace zeek {
ZEEK_EXTERN_DATA telemetry::Manager* telemetry_mgr;

}
