

#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::detail::Zeek_MIME {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        zeek::plugin::Configuration config;
        config.name = "Zeek::MIME";
        config.description = "MIME parsing";
        return config;
    }
} plugin;

}
