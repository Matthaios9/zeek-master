

#include "zeek/packet_analysis/protocol/mpls/MPLS.h"

using namespace zeek::packet_analysis::MPLS;

MPLSAnalyzer::MPLSAnalyzer() : zeek::packet_analysis::Analyzer("MPLS") {}

bool MPLSAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {

    bool end_of_stack = false;

    while ( ! end_of_stack ) {
        if ( 4 >= len ) {
            Weird("truncated_link_header", packet);
            return false;
        }

        end_of_stack = *(data + 2u) & 0x01;
        data += 4;
        len -= 4;
    }



    return ForwardPacket(len, data, packet);
}
