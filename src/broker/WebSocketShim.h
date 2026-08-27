

#pragma once

#include <broker/endpoint.hh>
#include <broker/zeek.hh>
#include <memory>
#include <stdexcept>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"

namespace zeek::Broker {

class WebSocketState;









class WebSocketShim : public zeek::cluster::Backend {
public:
    WebSocketShim(std::unique_ptr<zeek::cluster::EventSerializer> es, std::unique_ptr<zeek::cluster::LogSerializer> ls,
                  std::unique_ptr<zeek::cluster::detail::EventHandlingStrategy> ehs);
    ~WebSocketShim() override;




    static std::unique_ptr<Backend> Instantiate(std::unique_ptr<zeek::cluster::EventSerializer> es,
                                                std::unique_ptr<zeek::cluster::LogSerializer> ls,
                                                std::unique_ptr<zeek::cluster::detail::EventHandlingStrategy> ehs) {
        return std::make_unique<WebSocketShim>(std::move(es), std::move(ls), std::move(ehs));
    }


    void Process();

private:

    void DoInitPostScript() override {}
    bool DoInit() override;
    void DoTerminate() override;
    bool DoPublishEvent(const std::string& topic, zeek::cluster::Event& event) override;
    bool DoPublishEvent(const std::string& topic, const std::string& format, const zeek::byte_buffer& buf) override {
        throw std::logic_error("not implemented");
    }
    bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) override;
    bool DoUnsubscribe(const std::string& topic_prefix) override;
    bool DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header, const std::string& format,
                            zeek::byte_buffer& buf) override {

        throw std::logic_error("not implemented");
    }


    void ProcessMessage(std::string_view topic, broker::zeek::Batch& batch);
    void ProcessMessage(std::string_view topic, broker::zeek::Event& ev);
    void ProcessMessage(std::string_view topic, broker::zeek::Invalid& invalid);
    void ProcessMessage(std::string_view topic, broker::zeek::LogCreate& lc) {



    }
    void ProcessMessage(std::string_view topic, broker::zeek::LogWrite& lw) {



    }
    void ProcessMessage(std::string_view topic, broker::zeek::IdentifierUpdate& iu) {



    }

    class IOSource;

    std::unique_ptr<WebSocketState> state;
    IOSource* iosrc = nullptr;
};

}
