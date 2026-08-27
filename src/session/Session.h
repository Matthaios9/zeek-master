

#pragma once

#include <map>

#include "zeek/EventHandler.h"
#include "zeek/Hash.h"
#include "zeek/Obj.h"
#include "zeek/Tag.h"
#include "zeek/Timer.h"
#include "zeek/session/Key.h"

namespace zeek {

class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace analyzer {
class Analyzer;
}

namespace session {
namespace detail {
class Timer;

constexpr uint32_t HIST_UNKNOWN_PKT = 0x400;
}

class Session;
using timer_func = void (Session::*)(double t);

enum class AnalyzerConfirmationState : uint8_t { UNKNOWN, VIOLATED, CONFIRMED };

class Session : public Obj {
public:













    Session(double t, EventHandlerPtr timeout_event, EventHandlerPtr status_update_event = nullptr,
            double status_update_interval = 0);






    virtual void Done() = 0;








    virtual detail::Key SessionKey(bool copy) const = 0;




    void SetInSessionTable(bool in_table) { in_session_table = in_table; }




    bool IsInSessionTable() const { return in_session_table; }

    double StartTime() const { return start_time; }
    void SetStartTime(double t) { start_time = t; }
    double LastTime() const { return last_time; }
    void SetLastTime(double t) { last_time = t; }




    bool RecordPackets() const { return record_packets; }
    void SetRecordPackets(bool do_record) { record_packets = do_record ? 1 : 0; }



    bool RecordContents() const { return record_contents; }
    void SetRecordContents(bool do_record) { record_contents = do_record ? 1 : 0; }


    void SetRecordCurrentPacket(bool do_record) { record_current_packet = do_record ? 1 : 0; }
    void SetRecordCurrentContent(bool do_record) { record_current_content = do_record ? 1 : 0; }




    virtual const RecordValPtr& GetVal() = 0;





    virtual void RemovalEvent() = 0;











    void Event(EventHandlerPtr f, analyzer::Analyzer* analyzer = nullptr, const char* name = nullptr);




    void EnqueueEvent(EventHandlerPtr f, analyzer::Analyzer* analyzer, Args args);




    template<class... Args>
        requires std::is_convertible_v<std::tuple_element_t<0, std::tuple<Args...>>, ValPtr>
    void EnqueueEvent(EventHandlerPtr h, analyzer::Analyzer* analyzer, Args&&... args) {
        return EnqueueEvent(h, analyzer, zeek::Args{std::forward<Args>(args)...});
    }

    void Describe(ODesc* d) const override;






    void SetLifetime(double lifetime);







    void SetInactivityTimeout(double timeout);




    double InactivityTimeout() const { return inactivity_timeout; }




    void EnableStatusUpdateTimer();




    void CancelTimers();









    void DeleteTimer(double t);





    virtual std::string TransportIdentifier() const = 0;

    AnalyzerConfirmationState AnalyzerState(const zeek::Tag& tag) const;
    void SetAnalyzerState(const zeek::Tag& tag, AnalyzerConfirmationState);










    bool CheckHistory(uint32_t mask, char code) {
        if ( (hist_seen & mask) == 0 ) {
            hist_seen |= mask;
            AddHistory(code);
            return false;
        }

        return true;
    }













    bool ScaledHistoryEntry(char code, uint32_t& counter, uint32_t& scaling_threshold, uint32_t scaling_base = 10);








    void HistoryThresholdEvent(EventHandlerPtr e, bool is_orig, uint32_t threshold);






    void AddHistory(char code) { history += code; }




    const std::string& GetHistory() const { return history; }






    void ReplaceHistory(std::string new_h) { history = std::move(new_h); }

protected:
    friend class detail::Timer;











    void AddTimer(timer_func timer, double t, bool do_expire, zeek::detail::TimerType type);




    void RemoveTimer(zeek::detail::Timer* t);




    void InactivityTimer(double t);




    void StatusUpdateTimer(double t);


    void RemoveConnectionTimer(double t);

    double start_time, last_time;
    TimerPList timers;
    double inactivity_timeout;

    EventHandlerPtr session_timeout_event;
    EventHandlerPtr session_status_update_event;
    double session_status_update_interval;

    unsigned int installed_status_timer : 1;
    unsigned int timers_canceled : 1;
    unsigned int is_active : 1;
    unsigned int record_packets : 1, record_contents : 1;
    unsigned int record_current_packet : 1, record_current_content : 1;
    bool in_session_table;

    std::map<zeek::Tag, AnalyzerConfirmationState> analyzer_confirmations;

    uint32_t hist_seen;
    std::string history;
};

namespace detail {

class Timer final : public zeek::detail::Timer {
public:
    Timer(Session* arg_session, timer_func arg_timer, double arg_t, bool arg_do_expire,
          zeek::detail::TimerType arg_type)
        : zeek::detail::Timer(arg_t, arg_type) {
        Init(arg_session, arg_timer, arg_do_expire);
    }
    ~Timer() override;

    void Dispatch(double t, bool is_expire) override;

protected:
    void Init(Session* session, timer_func timer, bool do_expire);

    Session* session;
    timer_func timer;
    bool do_expire;
};

}
}
}


#define ADD_TIMER(timer, t, do_expire, type) AddTimer(timer_func(timer), (t), (do_expire), (type))
