



#pragma once

#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

#include "zeek/EventHandler.h"
#include "zeek/Tag.h"
#include "zeek/Val.h"
#include "zeek/ZeekArgs.h"
#include "zeek/cluster/BifSupport.h"
#include "zeek/cluster/Event.h"
#include "zeek/cluster/OnLoop.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/Telemetry.h"
#include "zeek/logging/Types.h"

namespace zeek {

namespace detail {
template<class Proc, class Work>
class OnLoopProcess;
}

namespace cluster {

namespace detail {











class EventHandlingStrategy {
public:
    virtual ~EventHandlingStrategy() = default;











    bool ProcessEvent(std::string_view topic, cluster::Event e) { return DoProcessEvent(topic, std::move(e)); }













    void ProcessLocalEvent(EventHandlerPtr h, zeek::Args args) { DoProcessLocalEvent(h, std::move(args)); }







    void ProcessError(std::string_view tag, std::string_view message) { return DoProcessError(tag, message); };

private:








    virtual bool DoProcessEvent(std::string_view topic, cluster::Event e) = 0;







    virtual void DoProcessLocalEvent(EventHandlerPtr h, zeek::Args args) = 0;







    virtual void DoProcessError(std::string_view tag, std::string_view message) = 0;
};




class LocalEventHandlingStrategy : public EventHandlingStrategy {
private:
    bool DoProcessEvent(std::string_view topic, cluster::Event e) override;
    void DoProcessLocalEvent(EventHandlerPtr h, zeek::Args args) override;
    void DoProcessError(std::string_view tag, std::string_view message) override;
};









std::optional<zeek::Args> check_args(const zeek::FuncValPtr& handler, zeek::ArgsSpan args);
}






class Backend {
public:
    virtual ~Backend() = default;




    void InitPostScript() { DoInitPostScript(); }






    bool Init(std::string nid);




    void Terminate() { DoTerminate(); }








    std::optional<cluster::Event> MakeClusterEvent(FuncValPtr handler, ArgsSpan args) const;














    bool PublishEvent(const std::string& topic, cluster::Event& event) { return DoPublishEvent(topic, event); }




    enum class CallbackStatus : uint8_t {
        Success,
        Error,
        NotImplemented,
    };




    struct SubscriptionCallbackInfo {
        CallbackStatus status;
        std::optional<std::string> message;
    };

    using SubscribeCallback =
        std::function<void(const std::string& topic_prefix, const SubscriptionCallbackInfo& info)>;












    bool Subscribe(const std::string& topic_prefix, SubscribeCallback cb = SubscribeCallback());







    bool Unsubscribe(const std::string& topic_prefix);




    using ReadyCallbackInfo = SubscriptionCallbackInfo;

    using ReadyCallback = std::function<void(const ReadyCallbackInfo& info)>;

















    void ReadyToPublishCallback(ReadyCallback cb) { DoReadyToPublishCallback(std::move(cb)); }










    bool PublishLogWrites(const zeek::logging::detail::LogWriteHeader& header,
                          std::span<zeek::logging::detail::LogRecord> records) {
        return DoPublishLogWrites(header, records);
    }




    const std::string& Name() const { return name; }




    const zeek::Tag& Tag() const { return tag; }




    const std::string& NodeId() const { return node_id; }






    void SetTelemetry(detail::TelemetryPtr new_telemetry) { telemetry = std::move(new_telemetry); }

protected:








    Backend(std::string_view name, std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
            std::unique_ptr<detail::EventHandlingStrategy> ehs);










    void EnqueueEvent(EventHandlerPtr h, zeek::Args args);













    bool ProcessEvent(std::string_view topic, cluster::Event e);











    void ProcessError(std::string_view tag, std::string_view message);




    bool ProcessEventMessage(std::string_view topic, std::string_view format, byte_buffer_span payload);




    bool ProcessLogMessage(std::string_view format, byte_buffer_span payload);









    void SetNodeId(std::string nid);




    detail::Telemetry& Telemetry() {
        assert(telemetry);
        return *telemetry;
    }

private:







    virtual void DoInitPostScript() = 0;








    virtual bool DoInit() = 0;









    virtual void DoTerminate() = 0;










    virtual bool DoPublishEvent(const std::string& topic, cluster::Event& event);
















    virtual bool DoPublishEvent(const std::string& topic, const std::string& format, const byte_buffer& buf) = 0;

















    virtual bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) = 0;







    virtual bool DoUnsubscribe(const std::string& topic_prefix) = 0;






    virtual void DoReadyToPublishCallback(ReadyCallback cb);















    virtual bool DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header,
                                    std::span<zeek::logging::detail::LogRecord> records);





















    virtual bool DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header, const std::string& format,
                                    byte_buffer& buf) = 0;

    std::string name;
    zeek::Tag tag;
    std::unique_ptr<EventSerializer> event_serializer;
    std::unique_ptr<LogSerializer> log_serializer;
    std::unique_ptr<detail::EventHandlingStrategy> event_handling_strategy;




    std::string node_id;

    detail::TelemetryPtr telemetry;
};















struct EventMessage {
    std::string topic;
    std::string format;
    byte_buffer payload;

    auto payload_span() const { return std::span(payload.data(), payload.size()); };
};




struct LogMessage {
    std::string format;
    byte_buffer payload;

    auto payload_span() const { return std::span(payload.data(), payload.size()); };
};







struct BackendMessage {
    int tag;
    byte_buffer payload;

    auto payload_span() const { return std::span(payload.data(), payload.size()); };
};

using QueueMessage = std::variant<EventMessage, LogMessage, BackendMessage>;





class ThreadedBackend : public Backend {
protected:



    ThreadedBackend(std::string_view name, std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                    std::unique_ptr<detail::EventHandlingStrategy> ehs,
                    zeek::detail::OnLoopProcess<ThreadedBackend, QueueMessage>* onloop);




    ThreadedBackend(std::string_view name, std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                    std::unique_ptr<detail::EventHandlingStrategy> ehs);











    bool DoInit() override;












    void DoTerminate() override;




    zeek::detail::OnLoopProcess<ThreadedBackend, QueueMessage>* OnLoop() { return onloop; }

private:



    bool ProcessBackendMessage(int tag, byte_buffer_span payload);





    virtual bool DoProcessBackendMessage(int tag, byte_buffer_span payload) { return false; };




    void Process(QueueMessage&& messages);


    friend class zeek::detail::OnLoopProcess<ThreadedBackend, QueueMessage>;


    zeek::detail::OnLoopProcess<ThreadedBackend, QueueMessage>* onloop = nullptr;
};



extern Backend* backend;

}
}
