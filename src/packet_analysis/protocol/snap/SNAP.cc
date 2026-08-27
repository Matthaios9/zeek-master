

#include "zeek/packet_analysis/protocol/snap/SNAP.h"

using namespace zeek::packet_analysis::SNAP;

SNAPAnalyzer::SNAPAnalyzer() : zeek::packet_analysis::Analyzer("SNAP") {}

bool SNAPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {


    if ( len < 3 ) {
        Weird("truncated_snap_llc_header", packet);
        return false;
    }




    size_t llc_header_len = 3;
    if ( (data[2] & 0x03) != 0x03 )
        llc_header_len++;


    if ( len < llc_header_len + 5 ) {
        Weird("truncated_snap_header", packet);
        return false;
    }

    data += llc_header_len;
    len -= llc_header_len;

    int oui = (static_cast<uint32_t>(data[0]) << 16u) | (static_cast<uint32_t>(data[1]) << 8u) | data[2];
    int protocol = (static_cast<uint32_t>(data[3]) << 8u) | data[4];

    data += 5;
    len -= 5;



    int64_t identifier = oui;
    identifier <<= 16;
    identifier |= protocol;

    return ForwardPacket(len, data, packet, identifier);
}
