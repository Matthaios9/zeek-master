

#pragma once

#include "zeek/zeek-config.h"

#include <list>
#include <map>
#include <utility>

#include "zeek/Timer.h"
#include "zeek/threading/MsgThread.h"

namespace zeek {

namespace telemetry {
class Gauge;
using GaugePtr = std::shared_ptr<Gauge>;
class GaugeFamily;
using GaugeFamilyPtr = std::shared_ptr<GaugeFamily>;
class Counter;
using CounterPtr = std::shared_ptr<Counter>;
}

namespace threading {
namespace detail {

class HeartbeatTimer final : public zeek::detail::Timer {
public:
    HeartbeatTimer(double t) : zeek::detail::Timer(t, zeek::detail::TIMER_THREAD_HEARTBEAT) {}

    void Dispatch(double t, bool is_expire) override;

protected:
    void Init();
};

}











class Manager {
public:




    Manager();




    ~Manager();





    void InitPostScript();







    void Terminate();





    bool Terminating() const { return terminating; }

    using msg_stats_list = std::list<std::pair<std::string, MsgThread::Stats>>;









    const msg_stats_list& GetMsgThreadStats();






    size_t NumThreads() const { return all_threads.size(); }




    void KillThread(BasicThread* thread);




    void KillThreads();











    bool SendEvent(MsgThread* thread, const std::string& name, const int num_vals, Value** vals) const;

protected:
    friend class BasicThread;
    friend class MsgThread;
    friend class detail::HeartbeatTimer;







    void AddThread(BasicThread* thread);









    void AddMsgThread(MsgThread* thread);

    void Flush();




    void SendHeartbeats();




    void StartHeartbeatTimer();




    void MessageIn();




    void MessageOut();

private:
    using all_thread_list = std::list<BasicThread*>;
    all_thread_list all_threads;

    using msg_thread_list = std::list<MsgThread*>;
    msg_thread_list msg_threads;

    bool did_process;
    double next_beat;
    bool terminating;
    bool terminated;

    msg_stats_list stats;

    bool heartbeat_timer_running = false;
    telemetry::GaugePtr num_threads_metric;
    telemetry::CounterPtr total_threads_metric;
    telemetry::CounterPtr total_messages_in_metric;
    telemetry::CounterPtr total_messages_out_metric;
    telemetry::GaugePtr pending_messages_in_metric;
    telemetry::GaugePtr pending_messages_out_metric;

    telemetry::GaugeFamilyPtr pending_message_in_buckets_fam;
    telemetry::GaugeFamilyPtr pending_message_out_buckets_fam;
    std::map<uint64_t, telemetry::GaugePtr> pending_message_in_buckets;
    std::map<uint64_t, telemetry::GaugePtr> pending_message_out_buckets;

    struct BucketedMessages {
        uint64_t pending_in_total;
        uint64_t pending_out_total;
        std::map<uint64_t, uint64_t> pending_in;
        std::map<uint64_t, uint64_t> pending_out;
    };

    BucketedMessages current_bucketed_messages;
    double bucketed_messages_last_updated = 0.0;
};

}





ZEEK_EXTERN_DATA threading::Manager* thread_mgr;

}
