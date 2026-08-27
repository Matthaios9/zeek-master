

#include "zeek/packet_analysis/protocol/llc/LLC.h"

using namespace zeek::packet_analysis::LLC;

LLCAnalyzer::LLCAnalyzer() : zeek::packet_analysis::Analyzer("LLC") {}

bool LLCAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {

    if ( len < 3 ) {
        Weird("truncated_llc_header", packet);
        return false;
    }




    size_t llc_header_len = 3;
    if ( (data[2] & 0x03) != 0x03 )
        llc_header_len++;

    if ( len < llc_header_len ) {
        Weird("truncated_llc_header", packet);
        return false;
    }



    return ForwardPacket(len, data, packet, data[0]);
}
