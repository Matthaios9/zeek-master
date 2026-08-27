

#include "zeek/packet_analysis/protocol/arp/ARP.h"

#include "zeek/zeek-config.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#elif defined(HAVE_SYS_ETHERNET_H)
#include <sys/ethernet.h>
#elif defined(HAVE_NETINET_IF_ETHER_H)
#include <netinet/if_ether.h>
#elif defined(HAVE_NET_ETHERTYPES_H)
#include <net/ethertypes.h>
#endif

#include "zeek/Event.h"
#include "zeek/packet_analysis/protocol/arp/events.bif.h"

using namespace zeek::packet_analysis::ARP;

ARPAnalyzer::ARPAnalyzer() : zeek::packet_analysis::Analyzer("ARP") {}







#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY 2
#endif
#ifndef ARPOP_PREQUEST
#define ARPOP_RREQUEST 3
#endif
#ifndef ARPOP_RREPLY
#define ARPOP_RREPLY 4
#endif
#ifndef ARPOP_InREQUEST
#define ARPOP_InREQUEST 8
#endif
#ifndef ARPOP_InREPLY
#define ARPOP_InREPLY 9
#endif
#ifndef ARPOP_NAK
#define ARPOP_NAK 10
#endif

#ifndef ar_sha
#define ar_sha(ap) ((caddr_t((ap) + 1)) + 0)
#endif

#ifndef ar_spa
#define ar_spa(ap) ((caddr_t((ap) + 1)) + (ap)->ar_hln)
#endif

#ifndef ar_tha
#define ar_tha(ap) ((caddr_t((ap) + 1)) + (ap)->ar_hln + (ap)->ar_pln)
#endif

#ifndef ar_tpa
#define ar_tpa(ap) ((caddr_t((ap) + 1)) + 2 * static_cast<size_t>((ap)->ar_hln) + (ap)->ar_pln)
#endif

#ifndef ARPOP_REVREQUEST
#define ARPOP_REVREQUEST ARPOP_RREQUEST
#endif

#ifndef ARPOP_REVREPLY
#define ARPOP_REVREPLY ARPOP_RREPLY
#endif

#ifndef ARPOP_INVREQUEST
#define ARPOP_INVREQUEST ARPOP_InREQUEST
#endif

#ifndef ARPOP_INVREPLY
#define ARPOP_INVREPLY ARPOP_InREPLY
#endif


#ifndef ARPHRD_IEEE802
#define ARPHRD_IEEE802 6
#endif



bool ARPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    packet->l3_proto = L3_ARP;


    if ( sizeof(struct arp_pkthdr) > len ) {
        Weird("truncated_ARP", packet);
        return false;
    }


    auto ah = reinterpret_cast<const arp_pkthdr*>(data);


    size_t min_length = (ar_tpa(ah) - reinterpret_cast<caddr_t>(const_cast<uint8_t*>(data))) + ah->ar_pln;
    if ( min_length > len ) {
        Weird("truncated_ARP", packet);
        return false;
    }




    packet->processed = true;


    switch ( ntohs(ah->ar_hrd) ) {
        case ARPHRD_ETHER:
        case ARPHRD_IEEE802:
            if ( ah->ar_hln != 6 ) {

                BadARPEvent(ah, "corrupt-arp-header (hrd=%i, hln=%i)", ntohs(ah->ar_hrd), ah->ar_hln);
                return false;
            }
            break;

        default: {

            BadARPEvent(ah, "unknown-arp-hw-address (hrd=%i)", ntohs(ah->ar_hrd));
            return false;
        }
    }


    switch ( ntohs(ah->ar_pro) ) {
        case ETHERTYPE_IP:
            if ( ah->ar_pln != 4 ) {

                BadARPEvent(ah, "corrupt-arp-header (pro=%i, pln=%i)", ntohs(ah->ar_pro), ah->ar_pln);
                return false;
            }
            break;

        default: {

            BadARPEvent(ah, "unknown-arp-proto-address (pro=%i)", ntohs(ah->ar_pro));
            return false;
        }
    }


    if ( memcmp(packet->l2_src, ar_sha(ah), ah->ar_hln) != 0 ) {
        BadARPEvent(ah, "weird-arp-sha");
        return false;
    }


    switch ( ntohs(ah->ar_op) ) {
        case ARPOP_REQUEST: RequestReplyEvent(arp_request, packet->l2_src, packet->l2_dst, ah); break;

        case ARPOP_REPLY: RequestReplyEvent(arp_reply, packet->l2_src, packet->l2_dst, ah); break;

        case ARPOP_REVREQUEST:
        case ARPOP_REVREPLY:
        case ARPOP_INVREQUEST:
        case ARPOP_INVREPLY: {

            BadARPEvent(ah, "unimplemented-arp-opcode (%i)", ntohs(ah->ar_op));
            return false;
        }

        default: {

            BadARPEvent(ah, "invalid-arp-opcode (opcode=%i)", ntohs(ah->ar_op));
            return false;
        }
    }


    return true;
}

zeek::AddrValPtr ARPAnalyzer::ToAddrVal(const void* addr, size_t len) {
    if ( len < 4 )
        return zeek::make_intrusive<zeek::AddrVal>(static_cast<uint32_t>(0));


    return zeek::make_intrusive<zeek::AddrVal>(*reinterpret_cast<const uint32_t*>(addr));
}

zeek::StringValPtr ARPAnalyzer::ToEthAddrStr(const u_char* addr, size_t len) {
    if ( len < 6 )
        return zeek::make_intrusive<zeek::StringVal>("");

    char buf[1024];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return zeek::make_intrusive<zeek::StringVal>(buf);
}

void ARPAnalyzer::BadARPEvent(const struct arp_pkthdr* hdr, const char* fmt, ...) {
    if ( ! bad_arp )
        return;

    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    event_mgr.Enqueue(bad_arp, ToAddrVal(reinterpret_cast<const u_char*>(ar_spa(hdr)), hdr->ar_pln),
                      ToEthAddrStr(reinterpret_cast<const u_char*>(ar_sha(hdr)), hdr->ar_hln),
                      ToAddrVal(reinterpret_cast<const u_char*>(ar_tpa(hdr)), hdr->ar_pln),
                      ToEthAddrStr(reinterpret_cast<const u_char*>(ar_tha(hdr)), hdr->ar_hln),
                      zeek::make_intrusive<zeek::StringVal>(msg));
}

void ARPAnalyzer::RequestReplyEvent(EventHandlerPtr e, const u_char* src, const u_char* dst,
                                    const struct arp_pkthdr* hdr) {
    if ( ! e )
        return;



    event_mgr.Enqueue(e, ToEthAddrStr(src, 6), ToEthAddrStr(dst, 6), ToAddrVal(ar_spa(hdr), hdr->ar_pln),
                      ToEthAddrStr(reinterpret_cast<const u_char*>(ar_sha(hdr)), hdr->ar_hln),
                      ToAddrVal(ar_tpa(hdr), hdr->ar_pln),
                      ToEthAddrStr(reinterpret_cast<const u_char*>(ar_tha(hdr)), hdr->ar_hln));
}
