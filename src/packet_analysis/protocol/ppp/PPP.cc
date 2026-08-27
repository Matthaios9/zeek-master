

#include "zeek/packet_analysis/protocol/ppp/PPP.h"

using namespace zeek::packet_analysis::PPP;

PPPAnalyzer::PPPAnalyzer() : zeek::packet_analysis::Analyzer("PPP") {}

bool PPPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {








    if ( 2 >= len ) {
        Weird("truncated_ppp_header", packet);
        return false;
    }

    if ( data[0] == 0xff && data[1] == 0x03 ) {

        if ( 4 >= len ) {
            Weird("truncated_ppp_hdlc_header", packet);
            return false;
        }

        uint32_t protocol = (data[2] << 8) + data[3];
        return ForwardPacket(len - 4, data + 4, packet, protocol);
    }

    uint32_t protocol = (data[0] << 8) + data[1];
    return ForwardPacket(len - 2, data + 2, packet, protocol);
}
