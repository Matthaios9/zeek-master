

#include "zeek/cluster/websocket/Plugin.h"

namespace zeek::plugin::Cluster_WebSocket {

Plugin plugin;
};

namespace zeek::plugin::Cluster_WebSocket {

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Zeek::Cluster_WebSocket";
    config.description = "Provides WebSocket access to a Zeek cluster";
    return config;
}

}
