

#pragma once

#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::Zeek_Binary_Serializer {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override;
};

}
