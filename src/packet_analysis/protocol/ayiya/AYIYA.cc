

#include "zeek/packet_analysis/protocol/ayiya/AYIYA.h"

#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

using namespace zeek::packet_analysis::AYIYA;

AYIYAAnalyzer::AYIYAAnalyzer() : zeek::packet_analysis::Analyzer("AYIYA") {}

bool AYIYAAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {



    if ( ! packet->session ) {
        Analyzer::Weird("ayiya_missing_connection");
        return false;
    }
    else if ( AnalyzerViolated(packet->session) )
        return false;

    if ( packet->encap && packet->encap->Depth() >= BifConst::Tunnel::max_depth ) {
        packet->session->CheckHistory(zeek::session::detail::HIST_UNKNOWN_PKT, 'X');
        Weird("exceeded_tunnel_max_depth", packet);
        return false;
    }



    size_t hdr_size = 8;

    if ( hdr_size > len ) {
        AnalyzerViolation("Truncated AYIYA", packet->session);
        return false;
    }

    size_t identity_len = 1 << (data[0] >> 4);
    uint8_t signature_len = (data[1] >> 4) * 4;
    hdr_size += identity_len + signature_len;


    if ( hdr_size > len ) {
        AnalyzerViolation("Truncated AYIYA", packet->session);
        return false;
    }

    uint8_t op_code = data[2] & 0x0F;



    if ( op_code != 1 )
        return true;

    uint8_t next_header = data[3];

    len -= hdr_size;
    data += hdr_size;


    AnalyzerConfirmation(packet->session);

    if ( len == 0 ) {

        Weird("ayiya_empty_packet", packet);
        return false;
    }

    int encap_index = 0;
    auto inner_packet = packet_analysis::IPTunnel::build_inner_packet(packet, &encap_index, nullptr, len, data, DLT_RAW,
                                                                      BifEnum::Tunnel::AYIYA, GetAnalyzerTag());

    return ForwardPacket(len, data, inner_packet.get(), next_header);
}

bool AYIYAAnalyzer::DetectProtocol(size_t len, const uint8_t* data, Packet* packet) {

    return len >= 3 && data[1] == 0x52 && data[2] == 0x11;
}
