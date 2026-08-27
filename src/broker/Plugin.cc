

#include "zeek/broker/Plugin.h"

#include <memory>

#include "zeek/broker/WebSocketShim.h"
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Component.h"
#include "zeek/cluster/Serializer.h"

using namespace zeek::plugin::Zeek_Cluster_Backend_Broker;

zeek::plugin::Configuration Plugin::Configure() {




    auto fail_instantiate =
        [](std::unique_ptr<cluster::EventSerializer>, std::unique_ptr<cluster::LogSerializer>,
           std::unique_ptr<cluster::detail::EventHandlingStrategy>) -> std::unique_ptr<cluster::Backend> {
        zeek::reporter->FatalError("do not instantiate broker explicitly");
        return nullptr;
    };

    AddComponent(new cluster::BackendComponent("BROKER", fail_instantiate));

    AddComponent(new cluster::BackendComponent("BROKER_WEBSOCKET_SHIM", Broker::WebSocketShim::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Cluster_Backend_Broker";
    config.description = "Cluster backend using Broker";
    return config;
}
