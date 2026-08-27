

#include "zeek/packet_analysis/protocol/geneve/Geneve.h"

#include <span>

#include "zeek/packet_analysis/protocol/geneve/events.bif.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

using namespace zeek::packet_analysis::Geneve;

void zeek::packet_analysis::Geneve::detail::parse_options(std::span<const uint8_t> data, const detail::Callback& cb) {
    size_t remaining = data.size();

    if ( remaining < 8 )
        return;

    remaining -= 8;

    uint8_t all_opt_len = (data[0] & 0x3F) * 4;

    if ( remaining < all_opt_len )
        return;

    const uint8_t* p = &data[8];
    const uint8_t* const end = &data[8] + all_opt_len;

    while ( p < end ) {
        auto remaining = end - p;
        if ( remaining < 4 )
            break;

        uint16_t opt_class = ntohs(reinterpret_cast<const uint16_t*>(p)[0]);
        bool opt_critical = (p[2] & 0x80) == 0x80;
        uint8_t opt_type = p[2] & 0x7F;
        uint8_t opt_len = (p[3] & 0x1F) * 4;

        remaining -= 4;
        p += 4;

        if ( remaining < opt_len )
            break;

        cb(opt_class, opt_critical, opt_type, std::span{p, opt_len});

        p += opt_len;
    }
}

GeneveAnalyzer::GeneveAnalyzer() : zeek::packet_analysis::Analyzer("Geneve") {}

bool GeneveAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {



    if ( ! packet->session ) {
        Analyzer::Weird("geneve_missing_connection");
        return false;
    }
    else if ( AnalyzerViolated(packet->session) )
        return false;

    if ( packet->encap && packet->encap->Depth() >= BifConst::Tunnel::max_depth ) {
        packet->session->CheckHistory(zeek::session::detail::HIST_UNKNOWN_PKT, 'X');
        Weird("exceeded_tunnel_max_depth", packet);
        return false;
    }



    uint16_t hdr_size = 8;

    if ( hdr_size > len ) {
        AnalyzerViolation("Geneve header truncation", packet->session, reinterpret_cast<const char*>(data), len);
        return false;
    }



    auto version = data[0] >> 6;
    if ( version != 0 ) {
        Weird("geneve_invalid_version", packet, util::fmt("%d", version));
        return false;
    }


    uint8_t opt_len = (data[0] & 0x3F) * 4;
    hdr_size += opt_len;


    if ( hdr_size > len ) {
        AnalyzerViolation("Geneve option header truncation", packet->session, reinterpret_cast<const char*>(data), len);
        return false;
    }



    auto next_header = (static_cast<uint32_t>(data[2]) << 8u) | data[3];


    auto vni = (static_cast<uint32_t>(data[4]) << 16u) | (static_cast<uint32_t>(data[5]) << 8u) | data[6];

    len -= hdr_size;
    data += hdr_size;


    AnalyzerConfirmation(packet->session);

    if ( len == 0 ) {

        Weird("geneve_empty_packet", packet);
        return false;
    }

    int encap_index = 0;
    auto inner_packet = packet_analysis::IPTunnel::build_inner_packet(packet, &encap_index, nullptr, len, data, DLT_RAW,
                                                                      BifEnum::Tunnel::GENEVE, GetAnalyzerTag());

    bool analysis_succeeded = ForwardPacket(len, data, inner_packet.get(), next_header);

    if ( analysis_succeeded && geneve_packet ) {
        EncapsulatingConn* ec = inner_packet->encap->At(encap_index);
        if ( ec && ec->ip_hdr )
            packet->session->EnqueueEvent(geneve_packet, nullptr, packet->session->GetVal(), ec->ip_hdr->ToPktHdrVal(),
                                          val_mgr->Count(vni));
    }

    return analysis_succeeded;
}
