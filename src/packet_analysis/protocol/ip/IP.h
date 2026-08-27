

#pragma once

#include "zeek/Frag.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::detail {
class Discarder;
}

namespace zeek::packet_analysis::IP {

class IPAnalyzer : public Analyzer {
public:
    IPAnalyzer();
    ~IPAnalyzer() override;

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<IPAnalyzer>(); }

private:


    zeek::detail::FragReassembler* NextFragment(double t, const IP_Hdr* ip, const u_char* pkt);

    zeek::detail::Discarder* discarder = nullptr;
};

enum class ParseResult : int8_t {
    CAPLEN_TOO_SMALL = -1,
    BAD_PROTOCOL = -2,
    OK = 0,
    CAPLEN_TOO_LARGE = 1,
};

























ParseResult ParsePacket(int caplen, const u_char* const pkt, int proto, std::shared_ptr<IP_Hdr>& inner);

}
