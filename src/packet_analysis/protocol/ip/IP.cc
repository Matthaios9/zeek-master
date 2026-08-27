

#include "zeek/packet_analysis/protocol/ip/IP.h"

#include <netinet/in.h>
#include <algorithm>

#include "zeek/Discard.h"
#include "zeek/Event.h"
#include "zeek/Frag.h"
#include "zeek/IP.h"
#include "zeek/NetVar.h"
#include "zeek/PacketFilter.h"
#include "zeek/RunState.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::IP;

IPAnalyzer::IPAnalyzer() : zeek::packet_analysis::Analyzer("IP") {
    discarder = new zeek::detail::Discarder();
    if ( ! discarder->IsActive() ) {
        delete discarder;
        discarder = nullptr;
    }
}

IPAnalyzer::~IPAnalyzer() { delete discarder; }

bool IPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {


    if ( len < sizeof(struct ip) ) {
        Weird("truncated_IP", packet);
        return false;
    }

    int32_t hdr_size = static_cast<int32_t>(data - packet->data);



    auto ip = reinterpret_cast<const struct ip*>(data);
    uint32_t protocol = ip->ip_v;
    std::shared_ptr<IP_Hdr> ip_hdr;

    if ( protocol == 4 ) {
        ip_hdr = std::make_shared<IP_Hdr>(ip, false, false, len);
        packet->l3_proto = L3_IPV4;
    }
    else if ( protocol == 6 ) {
        if ( len < sizeof(struct ip6_hdr) ) {
            Weird("truncated_IP", packet);
            return false;
        }

        ip_hdr = std::make_shared<IP_Hdr>(reinterpret_cast<const ip6_hdr*>(data), false, len, nullptr, false);
        packet->l3_proto = L3_IPV6;
    }
    else {
        Weird("unknown_ip_version", packet);
        return false;
    }



    uint32_t total_len = ip_hdr->TotalLen();
    if ( total_len == 0 ) {

        Weird("ip_hdr_len_zero", packet);

        if ( zeek::detail::ignore_checksums )

            total_len = packet->cap_len - hdr_size;
        else


            return false;
    }

    if ( packet->len < total_len + hdr_size ) {
        Weird("truncated_IP_len", packet);
        return false;
    }



    uint16_t ip_hdr_len = ip_hdr->HdrLen();
    if ( ip_hdr_len > total_len ) {
        Weird("invalid_IP_header_size", packet);
        return false;
    }

    if ( ip_hdr_len > len ) {
        Weird("internally_truncated_header", packet);
        return false;
    }

    const struct ip* ip4 = ip_hdr->IP4_Hdr();

    if ( ip4 ) {
        if ( ip_hdr_len < sizeof(struct ip) ) {
            Weird("IPv4_min_header_size", packet);
            return false;
        }
    }
    else {
        if ( ip_hdr_len < sizeof(struct ip6_hdr) ) {
            Weird("IPv6_min_header_size", packet);
            return false;
        }
    }


    packet->ip_hdr = std::move(ip_hdr);




    if ( packet->encap ) {
        if ( auto* ec = packet->encap->Last() )
            ec->ip_hdr = packet->ip_hdr;
    }


    zeek::detail::PacketFilter* packet_filter = packet_mgr->GetPacketFilter(false);
    if ( packet_filter && packet_filter->Match(packet->ip_hdr, total_len, len) )
        return false;

    if ( ! packet->l3_checksummed && ! zeek::detail::ignore_checksums && ip4 &&
         ! IPBasedAnalyzer::GetIgnoreChecksumsNets()->Contains(packet->ip_hdr->IPHeaderSrcAddr()) &&
         zeek::detail::in_cksum(reinterpret_cast<const uint8_t*>(ip4), ip_hdr_len) != 0xffff ) {
        Weird("bad_IP_checksum", packet);
        return false;
    }

    if ( discarder && discarder->NextPacket(packet->ip_hdr, total_len, len) )
        return false;

    zeek::detail::FragReassembler* f = nullptr;



    size_t orig_cap_len = packet->cap_len;

    if ( packet->ip_hdr->IsFragment() ) {
        packet->dump_packet = true;

        if ( len < total_len ) {
            Weird("incompletely_captured_fragment", packet);




            if ( packet->ip_hdr->FragOffset() != 0 )
                return false;
        }
        else {
            f = zeek::detail::fragment_mgr->NextFragment(run_state::processing_start_time, packet->ip_hdr,
                                                         packet->data + hdr_size);
            std::shared_ptr<IP_Hdr> ih = f->ReassembledPkt();

            if ( ! ih )

                return true;

            ip4 = ih->IP4_Hdr();



            packet->ip_hdr = std::move(ih);

            len = total_len = packet->ip_hdr->TotalLen();
            ip_hdr_len = packet->ip_hdr->HdrLen();

            if ( ip_hdr_len > total_len ) {
                Weird("invalid_IP_header_size", packet);
                return false;
            }

            packet->cap_len = total_len + hdr_size;

            packet->len = packet->cap_len;
        }
    }

    zeek::detail::FragReassemblerTracker frt(f);



    if ( packet->ip_hdr->LastHeader() == IPPROTO_ESP ) {
        packet->dump_packet = true;
        if ( esp_packet )
            event_mgr.Enqueue(esp_packet, packet->ip_hdr->ToPktHdrVal());


        packet->cap_len = orig_cap_len;
        return true;
    }



    if ( packet->ip_hdr->LastHeader() == IPPROTO_MOBILITY ) {
        packet->dump_packet = true;

        if ( ! zeek::detail::ignore_checksums && mobility_header_checksum(packet->ip_hdr.get()) != 0xffff ) {
            Weird("bad_MH_checksum", packet);
            packet->cap_len = orig_cap_len;
            return false;
        }

        if ( mobile_ipv6_message )
            event_mgr.Enqueue(mobile_ipv6_message, packet->ip_hdr->ToPktHdrVal());

        if ( packet->ip_hdr->NextProto() != IPPROTO_NONE )
            Weird("mobility_piggyback", packet);

        packet->cap_len = orig_cap_len;
        return true;
    }



    data = packet->ip_hdr->Payload();
    len -= ip_hdr_len;

    if ( packet->ip_hdr->PayloadLen() != 0 )
        len = std::min<size_t>(len, packet->ip_hdr->PayloadLen());







    bool return_val = true;
    int proto = packet->ip_hdr->NextProto();

    packet->proto = proto;


    if ( total_len < packet->ip_hdr->HdrLen() ) {
        Weird("bogus_IP_header_lengths", packet);
        packet->cap_len = orig_cap_len;
        return false;
    }



    if ( proto == IPPROTO_IPV4 || proto == IPPROTO_IPV6 )
        packet->tunnel_type = BifEnum::Tunnel::IP;

    if ( proto == IPPROTO_NONE ) {



        if ( ! (packet->encap && packet->encap->LastType() == BifEnum::Tunnel::TEREDO) ) {
            Weird("ipv6_no_next", packet);
            return_val = false;
        }
    }
    else {
        packet->proto = proto;



        return_val = ForwardPacket(len, data, packet, proto);
    }

    if ( f )
        f->DeleteTimer();

    packet->cap_len = orig_cap_len;
    return return_val;
}

ParseResult zeek::packet_analysis::IP::ParsePacket(int caplen, const u_char* const pkt, int proto,
                                                   std::shared_ptr<zeek::IP_Hdr>& inner) {
    if ( proto == IPPROTO_IPV6 ) {
        if ( caplen < static_cast<int>(sizeof(struct ip6_hdr)) )
            return ParseResult::CAPLEN_TOO_SMALL;

        const struct ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(pkt);
        inner = std::make_shared<zeek::IP_Hdr>(ip6, false, caplen);
        if ( (ip6->ip6_ctlun.ip6_un2_vfc & 0xF0) != 0x60 )
            return ParseResult::BAD_PROTOCOL;
    }

    else if ( proto == IPPROTO_IPV4 ) {
        if ( caplen < static_cast<int>(sizeof(struct ip)) )
            return ParseResult::BAD_PROTOCOL;

        const struct ip* ip4 = reinterpret_cast<const struct ip*>(pkt);
        inner = std::make_shared<zeek::IP_Hdr>(ip4, false);
        if ( ip4->ip_v != 4 )
            return ParseResult::BAD_PROTOCOL;
    }
    else {
        return ParseResult::BAD_PROTOCOL;
    }

    if ( static_cast<uint32_t>(caplen) != inner->TotalLen() )
        return static_cast<uint32_t>(caplen) < inner->TotalLen() ? ParseResult::CAPLEN_TOO_SMALL :
                                                                   ParseResult::CAPLEN_TOO_LARGE;

    return ParseResult::OK;
}
