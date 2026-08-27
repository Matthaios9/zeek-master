

#pragma once

#include <cstdint>

#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::LinuxSLL2 {

class LinuxSLL2Analyzer : public Analyzer {
public:
    LinuxSLL2Analyzer();

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<LinuxSLL2Analyzer>(); }

private:


#pragma pack(push, 1)
    struct SLL2Header {
        uint16_t protocol_type;
        uint16_t reserved;
        uint32_t interface_index;
        uint16_t arphrd_type;
        uint8_t packet_type;
        uint8_t addr_len;
        uint64_t addr;
    };
#pragma pack(pop)
};

}
