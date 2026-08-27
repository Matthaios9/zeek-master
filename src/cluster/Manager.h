

#pragma once

#include "zeek/zeek-config.h"

#include <map>
#include <memory>

#include "zeek/cluster/Component.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/websocket/WebSocket.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek::cluster {

namespace detail {









void report_non_functional_broker_tables(const zeek::EnumValPtr& cluster_backend_val);

}







class Manager {
public:
    Manager();
    ~Manager();







    void Terminate();












    std::unique_ptr<Backend> InstantiateBackend(const EnumValPtr& tag,
                                                std::unique_ptr<EventSerializer> event_serializer,
                                                std::unique_ptr<LogSerializer> log_serializer,
                                                std::unique_ptr<detail::EventHandlingStrategy> event_handling_strategy);








    std::unique_ptr<EventSerializer> InstantiateEventSerializer(const EnumValPtr& tag);








    std::unique_ptr<LogSerializer> InstantiateLogSerializer(const EnumValPtr& tag);




    plugin::ComponentManager<BackendComponent>& Backends() { return backends; };




    plugin::ComponentManager<EventSerializerComponent>& EventSerializers() { return event_serializers; };




    plugin::ComponentManager<LogSerializerComponent>& LogSerializers() { return log_serializers; };








    bool ListenWebSocket(const websocket::detail::ServerOptions& options);

private:
    plugin::ComponentManager<BackendComponent> backends;
    plugin::ComponentManager<EventSerializerComponent> event_serializers;
    plugin::ComponentManager<LogSerializerComponent> log_serializers;

    using WebSocketServerKey = std::pair<std::string, uint16_t>;
    struct WebSocketServerEntry {
        websocket::detail::ServerOptions options;
        std::unique_ptr<websocket::detail::WebSocketServer> server;
    };
    std::map<WebSocketServerKey, WebSocketServerEntry> websocket_servers;
};



ZEEK_EXTERN_DATA Manager* manager;

}
