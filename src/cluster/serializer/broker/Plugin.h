

#pragma once

#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::Broker_Serializer {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override;
} plugin;

}
