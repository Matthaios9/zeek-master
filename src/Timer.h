

#pragma once

#include "zeek/zeek-config.h"

#include <cstdint>
#include <memory>

#include "zeek/PriorityQueue.h"
#include "zeek/iosource/IOSource.h"

namespace zeek {
class ODesc;

namespace telemetry {
class Gauge;
class Counter;
using GaugePtr = std::shared_ptr<Gauge>;
using CounterPtr = std::shared_ptr<Counter>;
}
}

namespace zeek::detail {


enum TimerType : uint8_t {
    TIMER_BACKDOOR,
    TIMER_BREAKPOINT,
    TIMER_CONN_DELETE,
    TIMER_CONN_EXPIRE,
    TIMER_CONN_INACTIVITY,
    TIMER_CONN_STATUS_UPDATE,
    TIMER_CONN_TUPLE_WEIRD_EXPIRE,
    TIMER_DNS_EXPIRE,
    TIMER_FILE_ANALYSIS_INACTIVITY,
    TIMER_FLOW_WEIRD_EXPIRE,
    TIMER_FRAG,
    TIMER_INTERCONN,
    TIMER_IP_TUNNEL_INACTIVITY,
    TIMER_NB_EXPIRE,
    TIMER_NET_WEIRD_EXPIRE,
    TIMER_NETWORK,
    TIMER_NTP_EXPIRE,
    TIMER_PROFILE,
    TIMER_ROTATE,
    TIMER_REMOVE_CONNECTION,
    TIMER_RPC_EXPIRE,
    TIMER_SCHEDULE,
    TIMER_TABLE_VAL,
    TIMER_TCP_ATTEMPT,
    TIMER_TCP_DELETE,
    TIMER_TCP_EXPIRE,
    TIMER_TCP_PARTIAL_CLOSE,
    TIMER_TCP_RESET,
    TIMER_TRIGGER,
    TIMER_PPID_CHECK,
    TIMER_TIMERMGR_EXPIRE,
    TIMER_THREAD_HEARTBEAT,
    TIMER_UNKNOWN_PROTOCOL_EXPIRE,
    TIMER_LOG_DELAY_EXPIRE,
    TIMER_LOG_FLUSH_WRITE_BUFFER,
    TIMER_STORAGE_EXPIRE,
    TIMER_TABLE_PUBLISH_QUEUED_CHANGES,
};
constexpr int NUM_TIMER_TYPES = static_cast<int>(TIMER_TABLE_PUBLISH_QUEUED_CHANGES) + 1;

extern const char* timer_type_to_string(TimerType type);

class Timer : public PQ_Element {
public:
    Timer(double t, TimerType arg_type) : PQ_Element(t), type(arg_type) {}

    TimerType Type() const { return type; }




    virtual void Dispatch(double t, bool is_expire) = 0;

    void Describe(ODesc* d) const;

protected:
    TimerType type{};
};

class TimerMgr final : public iosource::IOSource {
public:
    TimerMgr();

    void Add(Timer* timer);









    int Advance(double t, int max_expire);





    int NumExpiredDuringCurrentAdvance() { return num_expired; }




    void Expire();










    void Cancel(Timer* timer) { Remove(timer); }

    double Time() const { return t ? t : 1; }

    size_t Size() const { return q->Size(); }
    size_t PeakSize() const { return q->PeakSize(); }
    size_t CumulativeNum() const { return q->CumulativeNum(); }

    double LastTimestamp() const { return last_timestamp; }




    double LastAdvance() const { return last_advance; }

    static unsigned int* CurrentTimers() { return current_timers; }


    double GetNextTimeout() override;
    void Process() override;
    const char* Tag() override { return "TimerMgr"; }





    void InitPostScript();

private:
    int DoAdvance(double t, int max_expire);
    void Remove(Timer* timer);

    Timer* Remove();
    Timer* Top();

    double t;
    double last_timestamp;
    double last_advance;

    int num_expired;


    bool dispatch_all_expired = false;

    static unsigned int current_timers[NUM_TIMER_TYPES];

    telemetry::CounterPtr cumulative_num_metric;
    telemetry::GaugePtr lag_time_metric;
    telemetry::GaugePtr current_timer_metrics[NUM_TIMER_TYPES];

    std::unique_ptr<PriorityQueue> q;
};

ZEEK_EXTERN_DATA TimerMgr* timer_mgr;

}
