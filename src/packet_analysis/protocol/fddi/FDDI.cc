

#include "zeek/packet_analysis/protocol/fddi/FDDI.h"

using namespace zeek::packet_analysis::FDDI;

FDDIAnalyzer::FDDIAnalyzer() : zeek::packet_analysis::Analyzer("FDDI") {}

bool FDDIAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    size_t hdr_size = 13 + 8;

    if ( hdr_size >= len ) {
        Weird("FDDI_analyzer_failed");
        return false;
    }


    return ForwardPacket(len - hdr_size, data + hdr_size, packet);
}
