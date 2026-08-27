

#include "zeek/packet_analysis/protocol/ethernet/Ethernet.h"

#include "zeek/packet_analysis/Manager.h"

using namespace zeek::packet_analysis::Ethernet;

EthernetAnalyzer::EthernetAnalyzer() : zeek::packet_analysis::Analyzer("Ethernet") {
    snap_forwarding_key = id::find_val("PacketAnalyzer::ETHERNET::SNAP_FORWARDING_KEY")->AsCount();
    novell_forwarding_key = id::find_val("PacketAnalyzer::ETHERNET::NOVELL_FORWARDING_KEY")->AsCount();
    llc_forwarding_key = id::find_val("PacketAnalyzer::ETHERNET::LLC_FORWARDING_KEY")->AsCount();
}

bool EthernetAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {


    if ( 16 >= len ) {
        Weird("truncated_ethernet_frame", packet);
        return false;
    }


    if ( data[12] == 0x89 && data[13] == 0x03 ) {
        auto constexpr cfplen = 16;

        if ( cfplen + 14 >= len ) {
            Weird("truncated_link_header_cfp", packet);
            return false;
        }

        data += cfplen;
        len -= cfplen;
    }


    uint32_t protocol = (data[12] << 8) + data[13];

    packet->eth_type = protocol;
    packet->l2_dst = data;
    packet->l2_src = data + 6;


    if ( protocol >= 1536 )
        return ForwardPacket(len - 14, data + 14, packet, protocol);


    if ( protocol <= 1500 ) {
        len -= 14;
        data += 14;


        if ( len < 2 ) {
            Weird("truncated_ethernet_frame", packet);
            return false;
        }
        if ( len > protocol )
            len = protocol;


        if ( data[0] == 0xAA && data[1] == 0xAA )

            return ForwardPacket(len, data, packet, snap_forwarding_key);
        else if ( data[0] == 0xFF && data[1] == 0xFF )

            return ForwardPacket(len, data, packet, novell_forwarding_key);
        else

            return ForwardPacket(len, data, packet, llc_forwarding_key);
    }


    Weird("undefined_ether_type", packet);
    return false;
}
