

#pragma once

#include <memory>
#include <thread>
#include <zmq.hpp>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/backend/zeromq/ZeroMQ-ZAP.h"

namespace zeek {

namespace telemetry {
class Counter;
using CounterPtr = std::shared_ptr<Counter>;
}

namespace cluster::zeromq {











class ZeekProxyTelemetry {
public:
    ZeekProxyTelemetry(zmq::socket_t&& arg_req);
    ~ZeekProxyTelemetry() { Shutdown(); }


    ZeekProxyTelemetry(const ZeekProxyTelemetry&) = delete;
    ZeekProxyTelemetry(ZeekProxyTelemetry&&) = delete;
    ZeekProxyTelemetry operator=(ZeekProxyTelemetry&) = delete;









    void Shutdown() { req.close(); }

private:



    void RefreshStatistics();
    void RefreshStatisticsIfNeeded();

    zmq::socket_t req;
    double last_updated = 0.0;
    std::array<double, 8> proxy_stats = {0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0};
};



















struct CurveConfig {



    std::string client_publickey;
    std::string client_secretkey;
    std::string server_publickey;
    std::string server_secretkey;




    bool IsClientEnabled() const {
        return ! server_publickey.empty() && ! client_secretkey.empty() && ! client_publickey.empty();
    };




    bool IsServerEnabled() const { return ! server_secretkey.empty() && ! client_publickey.empty(); };






    void ConfigureClientCurveSockOpts(zmq::socket_t& sock) const;






    void ConfigureServerCurveSockOpts(zmq::socket_t& sock) const;




    void InitZap(zmq::context_t& ctx, ZapArgs& args) const;
};






struct CurveConfig load_curve_config();

class ProxyThread;

class ZeroMQBackend : public cluster::ThreadedBackend {
public:



    ZeroMQBackend(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                  std::unique_ptr<detail::EventHandlingStrategy> ehs, zeek_uint_t onloop_max_queue_size);




    ~ZeroMQBackend() override;





    bool SpawnZmqProxyThread();




    void Run();




    static std::unique_ptr<Backend> Instantiate(std::unique_ptr<EventSerializer> event_serializer,
                                                std::unique_ptr<LogSerializer> log_serializer,
                                                std::unique_ptr<detail::EventHandlingStrategy> ehs);

private:
    void DoInitPostScript() override;

    bool DoInit() override;

    void DoTerminate() override;

    bool DoPublishEvent(const std::string& topic, const std::string& format, const byte_buffer& buf) override;

    bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) override;

    bool DoUnsubscribe(const std::string& topic_prefix) override;

    bool DoPublishLogWrites(const logging::detail::LogWriteHeader& header, const std::string& format,
                            byte_buffer& buf) override;

    bool DoProcessBackendMessage(int tag, byte_buffer_span payload) override;

    void DoReadyToPublishCallback(ReadyCallback cb) override;


    using MultipartMessage = std::vector<zmq::message_t>;
    void HandleInprocMessages(std::vector<MultipartMessage>& msgs);
    void HandleLogMessages(const std::vector<MultipartMessage>& msgs);
    void HandleXPubMessages(const std::vector<MultipartMessage>& msgs);
    void HandleXSubMessages(const std::vector<MultipartMessage>& msgs);
    void HandleMonitoringMessages(const std::vector<MultipartMessage>& msgs);


    std::string connect_xsub_endpoint;
    std::string connect_xpub_endpoint;
    int connect_xpub_nodrop = 1;
    std::string listen_xsub_endpoint;
    std::string listen_xpub_endpoint;
    std::string listen_log_endpoint;
    int ipv6 = 1;
    int listen_xpub_nodrop = 1;

    int linger_ms = 0;
    zeek_uint_t poll_max_messages = 0;
    zeek_uint_t debug_flags = 0;

    std::string internal_topic_prefix;

    EventHandlerPtr event_subscription;
    EventHandlerPtr event_unsubscription;
    EventHandlerPtr event_monitoring_event;


    int xpub_sndhwm = 1000;
    int xpub_sndbuf = -1;
    int xsub_rcvhwm = 1000;
    int xsub_rcvbuf = -1;


    int log_immediate = false;
    int log_sndhwm = 1000;
    int log_sndbuf = -1;
    int log_rcvhwm = 1000;
    int log_rcvbuf = -1;

    zmq::context_t ctx;
    zmq::socket_t xsub;
    zmq::socket_t xpub;




    zmq::socket_t main_inproc;
    zmq::socket_t child_inproc;




    std::vector<std::string> connect_log_endpoints;
    zmq::socket_t log_push;
    zmq::socket_t log_pull;


    std::array<zmq::socket_t, 3> monitoring_sockets;

    std::thread self_thread;
    bool self_thread_shutdown_requested = false;
    bool self_thread_stop = false;



    std::thread zap_thread;
    ZapArgs zap_args;

    int proxy_io_threads = 2;
    std::unique_ptr<ProxyThread> proxy_thread;
    std::unique_ptr<ZeekProxyTelemetry> proxy_telemetry;

    CurveConfig curve_config;


    std::map<std::string, SubscribeCallback> subscription_callbacks;
    std::set<std::string> xpub_subscriptions;

    zeek::telemetry::CounterPtr total_xpub_drops;
    zeek::telemetry::CounterPtr total_onloop_drops;
    zeek::telemetry::CounterPtr total_msg_errors;


    double xpub_drop_last_warn_at = 0.0;
    double onloop_drop_last_warn_at = 0.0;
};

}
}
