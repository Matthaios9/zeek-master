

#include "zeek/packet_analysis/protocol/gre/GRE.h"

#include <pcap.h>

#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::GRE;

static unsigned int gre_header_len(uint16_t flags = 0) {
    unsigned int len = 4;

    if ( flags & 0x8000 )

        len += 4;



    if ( flags & 0x2000 )

        len += 4;

    if ( flags & 0x1000 )

        len += 4;

    if ( flags & 0x0080 )

        len += 4;

    return len;
}

GREAnalyzer::GREAnalyzer() : zeek::packet_analysis::Analyzer("GRE") {}

bool GREAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( ! packet->ip_hdr ) {
        reporter->InternalError("GREAnalyzer: ip_hdr not provided from earlier analyzer");
        return false;
    }

    if ( len < gre_header_len() ) {
        Weird("truncated_GRE", packet);
        return false;
    }

    int proto = packet->proto;
    int gre_link_type = DLT_RAW;

    uint16_t flags_ver = ntohs(*reinterpret_cast<const uint16_t*>(data + 0));
    uint16_t proto_typ = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    int gre_version = flags_ver & 0x0007;

    unsigned int eth_len = 0;
    unsigned int gre_len = gre_header_len(flags_ver);
    unsigned int pptp_len = gre_version == 1 ? 4 : 0;
    unsigned int erspan_len = 0;

    if ( gre_version != 0 && gre_version != 1 ) {
        Weird("unknown_gre_version", packet, util::fmt("version=%d", gre_version));
        return false;
    }

    if ( gre_version == 0 ) {
        if ( proto_typ == 0x6558 ) {

            if ( len > gre_len + 14 ) {
                eth_len = 14;
                gre_link_type = DLT_EN10MB;
            }
            else {
                Weird("truncated_GRE", packet);
                return false;
            }
        }

        else if ( proto_typ == 0x88be ) {
            if ( len > gre_len + 14 ) {

                erspan_len = 0;
                eth_len = 14;
                gre_link_type = DLT_EN10MB;
                bool have_sequence_header = ((flags_ver & 0x1000) == 0x1000);
                if ( have_sequence_header ) {

                    erspan_len += 8;
                    if ( len < gre_len + eth_len + erspan_len ) {
                        Weird("truncated_GRE", packet);
                        return false;
                    }
                }
            }
            else {
                Weird("truncated_GRE", packet);
                return false;
            }
        }

        else if ( proto_typ == 0x22eb ) {

            if ( len > gre_len + 14 + 12 ) {
                erspan_len = 12;
                eth_len = 14;
                gre_link_type = DLT_EN10MB;

                auto flags = data + gre_len + erspan_len - 1;
                bool have_opt_header = ((*flags & 0x01) == 0x01);

                if ( have_opt_header ) {
                    if ( len > gre_len + erspan_len + 8 + eth_len )
                        erspan_len += 8;
                    else {
                        Weird("truncated_GRE", packet);
                        return false;
                    }
                }
            }
            else {
                Weird("truncated_GRE", packet);
                return false;
            }
        }
        else if ( ((proto_typ & 0x8200) == 0x8200 && (proto_typ & 0x0F) == 0) ||
                  ((proto_typ & 0x8300) == 0x8300 && (proto_typ & 0x0F) == 0 && (proto_typ <= 0x8370)) ||
                  (proto_typ == 0x9000) ) {



            if ( len <= gre_len ) {
                Weird("truncated_GRE", packet);
                return false;
            }

            gre_link_type = DLT_IEEE802_11;
            proto = proto_typ;
        }
        else {

            proto = proto_typ;
        }
    }

    else
    {
        if ( proto_typ != 0x880b ) {

            Weird("egre_protocol_type", packet, util::fmt("proto=%d", proto_typ));
            return false;
        }
    }

    if ( flags_ver & 0x4000 ) {


        Weird("gre_routing", packet);
        return false;
    }

    if ( flags_ver & 0x0078 ) {

        Weird("unknown_gre_flags", packet);
        return false;
    }

    if ( len < gre_len + pptp_len + eth_len + erspan_len ) {
        Weird("truncated_GRE", packet);
        return false;
    }



    if ( gre_version == 1 ) {
        uint16_t pptp_proto = ntohs(*reinterpret_cast<const uint16_t*>(data + gre_len + 2));

        if ( pptp_proto != 0x0021 && pptp_proto != 0x0057 ) {
            Weird("non_ip_packet_in_encap", packet);
            return false;
        }

        proto = (pptp_proto == 0x0021) ? IPPROTO_IPV4 : IPPROTO_IPV6;
    }

    data += gre_len + pptp_len + erspan_len;
    len -= gre_len + pptp_len + erspan_len;




    packet->tunnel_type = BifEnum::Tunnel::GRE;
    packet->gre_version = gre_version;
    packet->gre_link_type = gre_link_type;
    packet->proto = proto;


    ForwardPacket(len, data, packet, proto);

    return true;
}
