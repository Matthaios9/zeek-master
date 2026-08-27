

#pragma once

#include <cstdint>
#include <functional>
#include <span>

#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::Geneve {

namespace detail {




using Callback =
    std::function<void(uint16_t opt_class, bool opt_critical, uint8_t opt_type, std::span<const uint8_t> opt_data)>;









void parse_options(std::span<const uint8_t> data, const Callback& cb);

}

class GeneveAnalyzer : public zeek::packet_analysis::Analyzer {
public:
    GeneveAnalyzer();

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<GeneveAnalyzer>(); }
};

}
