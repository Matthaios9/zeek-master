

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/sip/SIP.h"

namespace zeek::plugin::detail::Zeek_SIP {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::analyzer::Component("SIP", zeek::analyzer::sip::SIP_Analyzer::Instantiate));





        zeek::plugin::Configuration config;
        config.name = "Zeek::SIP";
        config.description = "SIP analyzer UDP-only";
        return config;
    }
} plugin;

}
