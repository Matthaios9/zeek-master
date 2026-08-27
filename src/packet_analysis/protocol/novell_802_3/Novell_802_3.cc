

#include "zeek/packet_analysis/protocol/novell_802_3/Novell_802_3.h"

using namespace zeek::packet_analysis::Novell_802_3;

Novell_802_3Analyzer::Novell_802_3Analyzer() : zeek::packet_analysis::Analyzer("Novell_802_3") {}

bool Novell_802_3Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {


    return ForwardPacket(len, data, packet);
}
