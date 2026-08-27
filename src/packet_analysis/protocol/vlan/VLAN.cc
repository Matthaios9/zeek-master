

#include "zeek/packet_analysis/protocol/vlan/VLAN.h"

using namespace zeek::packet_analysis::VLAN;

VLANAnalyzer::VLANAnalyzer() : zeek::packet_analysis::Analyzer("VLAN") {
    snap_forwarding_key = id::find_val("PacketAnalyzer::VLAN::SNAP_FORWARDING_KEY")->AsCount();
    novell_forwarding_key = id::find_val("PacketAnalyzer::VLAN::NOVELL_FORWARDING_KEY")->AsCount();
    llc_forwarding_key = id::find_val("PacketAnalyzer::VLAN::LLC_FORWARDING_KEY")->AsCount();
}

bool VLANAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( 4 >= len ) {
        Weird("truncated_VLAN_header", packet);
        return false;
    }

    uint16_t tci = (data[0] << 8u) + data[1];
    uint16_t vlan_id = tci & 0xfff;
    uint8_t vlan_pcp = (tci & 0xe000) >> 13;
    bool vlan_dei = (tci & 0x1000) != 0;
    if ( ! packet->vlan )
        packet->vlan = {.id = vlan_id, .pcp = vlan_pcp, .dei = vlan_dei};
    else {
        if ( packet->inner_vlan )
            Weird("triple_tagged_vlan_unsupported", packet, "inner VLAN tag overwritten");

        packet->inner_vlan = {.id = vlan_id, .pcp = vlan_pcp, .dei = vlan_dei};
    }


    uint32_t protocol = ((data[2] << 8u) + data[3]);

    if ( protocol >= 1536 ) {
        packet->eth_type = protocol;

        return ForwardPacket(len - 4, data + 4, packet, protocol);
    }

    if ( protocol <= 1500 ) {

        len -= 4;
        data += 4;


        if ( len < 2 ) {
            Weird("truncated_VLAN_header", packet);
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

    Weird("undefined_vlan_protocol", packet);
    return false;
}
