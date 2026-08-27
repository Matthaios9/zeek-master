

#pragma once

#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace zeek {

namespace detail {

template<class Proc, class Work>
class OnLoopProcess;
}

namespace cluster {

class Backend;

namespace websocket::detail {









class WebSocketClient {
public:
    virtual ~WebSocketClient() = default;




    virtual bool IsTerminated() const = 0;




    virtual void Close(uint16_t code = 1000, const std::string& reason = "Normal closure") = 0;




    struct SendInfo {
        bool success;
    };










    virtual SendInfo SendText(std::string_view sv) = 0;




    SendInfo SendError(std::string_view code, std::string_view ctx);




    SendInfo SendAck(std::string_view endpoint, std::string_view version);




    bool IsAcked() const { return acked; }




    virtual const std::string& getId() = 0;




    virtual const std::string& getRemoteIp() = 0;




    virtual int getRemotePort() = 0;




    void SetSubscriptions(const std::vector<std::string>& topic_prefixes);




    std::vector<std::string> GetSubscriptions() const;




    void SetSubscriptionActive(const std::string& topic_prefix);




    bool AllSubscriptionsActive() const;

private:
    bool acked = false;
    std::map<std::string, bool> subscriptions_state;
};


struct WebSocketOpen {
    std::string id;
    std::string uri;
    std::string protocol;
    std::optional<std::string> application_name;
    std::shared_ptr<WebSocketClient> wsc;
};


struct WebSocketClose {
    std::string id;
    uint16_t code;
    std::string reason;
};


struct WebSocketMessage {
    std::string id;
    std::string msg;
};



struct WebSocketSubscribeFinished {
    std::string id;
    std::string topic_prefix;
};


struct WebSocketBackendReadyToPublish {
    std::string id;
};

using WebSocketEvent = std::variant<WebSocketOpen, WebSocketSubscribeFinished, WebSocketClose, WebSocketMessage,
                                    WebSocketBackendReadyToPublish>;

struct WebSocketSendReply {
    std::shared_ptr<WebSocketClient> wsc;
    std::string msg;
};

struct WebSocketCloseReply {
    std::shared_ptr<WebSocketClient> wsc;
    uint16_t code = 1000;
    std::string reason = "Normal closure";
};

using WebSocketReply = std::variant<WebSocketSendReply, WebSocketCloseReply>;


class ReplyMsgThread;







class WebSocketEventDispatcher {
public:






    WebSocketEventDispatcher(const std::string& ident, size_t queue_size);

    ~WebSocketEventDispatcher();




    void Terminate();






    void QueueForProcessing(WebSocketEvent&& event);







    void QueueReply(WebSocketReply&& reply);

private:





    void Process(const WebSocketEvent& event);

    void Process(const WebSocketOpen& open);
    void Process(const WebSocketSubscribeFinished& fin);
    void Process(const WebSocketBackendReadyToPublish& ready);
    void Process(const WebSocketMessage& msg);
    void Process(const WebSocketClose& close);





    struct WebSocketClientEntry {
        std::string id;
        std::shared_ptr<WebSocketClient> wsc;
        std::shared_ptr<zeek::cluster::Backend> backend;
        std::optional<std::string> application_name;
        bool ready_to_publish = false;
        uint64_t msg_count = 0;
        std::list<WebSocketMessage> queue;
    };


    void HandleSubscriptions(WebSocketClientEntry& entry, std::string_view buf);


    void HandleSubscriptionsActive(const WebSocketClientEntry& entry);

    void HandleEvent(WebSocketClientEntry& entry, std::string_view buf);


    friend zeek::detail::OnLoopProcess<WebSocketEventDispatcher, WebSocketEvent>;


    std::map<std::string, WebSocketClientEntry> clients;


    zeek::detail::OnLoopProcess<WebSocketEventDispatcher, WebSocketEvent>* onloop = nullptr;


    ReplyMsgThread* reply_msg_thread = nullptr;
};




class WebSocketServer {
public:
    WebSocketServer(std::unique_ptr<WebSocketEventDispatcher> demux) : dispatcher(std::move(demux)) {}
    virtual ~WebSocketServer() = default;




    void Terminate() {
        dispatcher->Terminate();

        DoTerminate();
    }

    WebSocketEventDispatcher& Dispatcher() { return *dispatcher; }

private:



    virtual void DoTerminate() = 0;

    std::unique_ptr<WebSocketEventDispatcher> dispatcher;
};




struct TLSOptions {
    std::optional<std::string> cert_file;
    std::optional<std::string> key_file;
    bool enable_peer_verification = false;
    std::string ca_file;
    std::string ciphers;




    bool TlsEnabled() const { return cert_file.has_value() && key_file.has_value(); }

    bool operator==(const TLSOptions& o) const {
        return cert_file == o.cert_file && key_file == o.key_file &&
               enable_peer_verification == o.enable_peer_verification && ca_file == o.ca_file && ciphers == o.ciphers;
    }
};




struct ServerOptions {
    std::string host;
    uint16_t port = 0;
    int ping_interval_seconds = 5;
    int max_connections = 100;
    bool per_message_deflate = false;
    size_t max_event_queue_size = 32;
    struct TLSOptions tls_options;

    bool operator==(const ServerOptions& o) const {
        return host == o.host && port == o.port && ping_interval_seconds == o.ping_interval_seconds &&
               max_connections == o.max_connections && per_message_deflate == o.per_message_deflate &&
               max_event_queue_size == o.max_event_queue_size && tls_options == o.tls_options;
    }
};










std::unique_ptr<WebSocketServer> StartServer(std::unique_ptr<WebSocketEventDispatcher> dispatcher,
                                             const ServerOptions& options);

}
}
}
