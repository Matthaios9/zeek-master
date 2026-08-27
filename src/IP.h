

#pragma once

#include "zeek/zeek-config.h"


#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>


#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#else
#include "net_util.h"
#endif

#include <vector>

#include "zeek/IntrusivePtr.h"

namespace zeek {

class IPAddr;
class RecordVal;
class VectorVal;
using RecordValPtr = IntrusivePtr<RecordVal>;
using VectorValPtr = IntrusivePtr<VectorVal>;

namespace detail {
class FragReassembler;
}

#ifndef IPPROTO_MOBILITY

#define IPPROTO_MOBILITY 135
#endif

constexpr uint16_t UNKNOWN_IP_PROTO = 65535;

struct ip6_mobility {
    uint8_t ip6mob_payload;
    uint8_t ip6mob_len;
    uint8_t ip6mob_type;
    uint8_t ip6mob_rsv;
    uint16_t ip6mob_chksum;
};




class IPv6_Hdr {
public:



    IPv6_Hdr(uint8_t t, const u_char* d) : type(t), data(d) {}




    void ChangeNext(uint8_t next_type) {
        switch ( type ) {
            data;
            case IPPROTO_IPV6: const_cast<ip6_hdr*>(reinterpret_cast<const ip6_hdr*>(data))->ip6_nxt = next_type; break;
            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_FRAGMENT:
            case IPPROTO_AH:
            case IPPROTO_MOBILITY:
                const_cast<ip6_ext*>(reinterpret_cast<const ip6_ext*>(data))->ip6e_nxt = next_type;
                break;
            case IPPROTO_ESP:
            default: break;
        }
    }

    ~IPv6_Hdr() = default;





    uint8_t NextHdr() const {
        switch ( type ) {
            case IPPROTO_IPV6: return (reinterpret_cast<const ip6_hdr*>(data))->ip6_nxt;
            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_FRAGMENT:
            case IPPROTO_AH:
            case IPPROTO_MOBILITY: return (reinterpret_cast<const ip6_ext*>(data))->ip6e_nxt;
            case IPPROTO_ESP:
            default: return IPPROTO_NONE;
        }
    }




    uint16_t Length() const {
        switch ( type ) {
            case IPPROTO_IPV6: return 40;
            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_MOBILITY: return 8 + 8 * (reinterpret_cast<const ip6_ext*>(data))->ip6e_len;
            case IPPROTO_FRAGMENT: return 8;
            case IPPROTO_AH: return 8 + 4 * (reinterpret_cast<const ip6_ext*>(data))->ip6e_len;
            case IPPROTO_ESP: return 8;
            default: return 0;
        }
    }




    uint8_t Type() const { return type; }




    const u_char* Data() const { return data; }




    RecordValPtr ToVal(VectorValPtr chain) const;
    RecordValPtr ToVal() const;

protected:
    uint8_t type;
    const u_char* data;

private:
    bool IsOptionTruncated(uint16_t off) const;
};

class IPv6_Hdr_Chain {
public:



    IPv6_Hdr_Chain(const struct ip6_hdr* ip6, uint64_t len) { Init(ip6, len, false); }

    ~IPv6_Hdr_Chain();





    IPv6_Hdr_Chain* Copy(const struct ip6_hdr* new_hdr) const;




    size_t Size() const { return chain.size(); }




    uint16_t TotalLength() const { return length; }




    const IPv6_Hdr* operator[](const size_t i) const { return &chain[i]; }




    bool IsFragment() const;




    const struct ip6_frag* GetFragHdr() const {
        return IsFragment() ? reinterpret_cast<const ip6_frag*>(chain[chain.size() - 1].Data()) : nullptr;
    }





    uint16_t FragOffset() const { return IsFragment() ? (ntohs(GetFragHdr()->ip6f_offlg) & 0xfff8) : 0; }




    uint32_t ID() const { return IsFragment() ? ntohl(GetFragHdr()->ip6f_ident) : 0; }




    int MF() const { return IsFragment() ? (ntohs(GetFragHdr()->ip6f_offlg) & 0x0001) != 0 : 0; }






    IPAddr SrcAddr() const;






    IPAddr DstAddr() const;





    VectorValPtr ToVal() const;

protected:


    friend class detail::FragReassembler;

    IPv6_Hdr_Chain() = default;





    IPv6_Hdr_Chain(const struct ip6_hdr* ip6, uint16_t next, uint64_t len) { Init(ip6, len, true, next); }






    void Init(const struct ip6_hdr* ip6, uint64_t total_len, bool set_next, uint16_t next = 0);





    void ProcessRoutingHeader(const struct ip6_rthdr* r, uint16_t len);





    void ProcessDstOpts(const struct ip6_dest* d, uint16_t len);

    std::vector<IPv6_Hdr> chain;




    uint16_t length = 0;




    IPAddr* homeAddr = nullptr;





    IPAddr* finalDst = nullptr;
};





class IP_Hdr {
public:








    IP_Hdr(const ip* arg_ip4, bool arg_del, bool reassembled = false, uint64_t len = 0)
        : ip4(arg_ip4), len(len), del(arg_del), reassembled(reassembled) {}













    IP_Hdr(const ip6_hdr* arg_ip6, bool arg_del, uint64_t len, const IPv6_Hdr_Chain* c = nullptr,
           bool reassembled = false)
        : ip6(arg_ip6),
          ip6_hdrs(c ? c : new IPv6_Hdr_Chain(ip6, len)),
          len(len),
          del(arg_del),
          reassembled(reassembled) {}






    IP_Hdr* Copy() const;




    ~IP_Hdr() {
        delete ip6_hdrs;

        if ( del ) {
            delete[] ip4;
            delete[] ip6;
        }
    }




    const struct ip* IP4_Hdr() const { return ip4; }




    const struct ip6_hdr* IP6_Hdr() const { return ip6; }




    IPAddr IPHeaderSrcAddr() const;




    IPAddr IPHeaderDstAddr() const;






    IPAddr SrcAddr() const;







    IPAddr DstAddr() const;





    const u_char* Payload() const {
        if ( ip4 )
            return (reinterpret_cast<const u_char*>(ip4)) + (ip4->ip_hl * static_cast<std::ptrdiff_t>(4));

        return (reinterpret_cast<const u_char*>(ip6)) + ip6_hdrs->TotalLength();
    }





    const ip6_mobility* MobilityHeader() const {
        if ( ip4 )
            return nullptr;
        else if ( (*ip6_hdrs)[ip6_hdrs->Size() - 1]->Type() != IPPROTO_MOBILITY )
            return nullptr;
        else
            return reinterpret_cast<const ip6_mobility*>((*ip6_hdrs)[ip6_hdrs->Size() - 1]->Data());
    }








    uint16_t PayloadLen() const {
        if ( ip4 ) {

            auto total_len = ntohs(ip4->ip_len);
            return total_len ? total_len - ip4->ip_hl * 4 : 0;
        }

        return ntohs(ip6->ip6_plen) + 40 - ip6_hdrs->TotalLength();
    }




    uint32_t TotalLen() const {
        if ( ip4 )
            return ntohs(ip4->ip_len);

        return ntohs(ip6->ip6_plen) + 40;
    }




    uint16_t HdrLen() const { return ip4 ? ip4->ip_hl * 4 : ip6_hdrs->TotalLength(); }




    uint8_t LastHeader() const {
        if ( ip4 )
            return IPPROTO_RAW;

        size_t i = ip6_hdrs->Size();
        if ( i > 0 )
            return (*ip6_hdrs)[i - 1]->Type();

        return IPPROTO_NONE;
    }






    unsigned char NextProto() const {
        if ( ip4 )
            return ip4->ip_p;

        size_t i = ip6_hdrs->Size();
        if ( i > 0 )
            return (*ip6_hdrs)[i - 1]->NextHdr();

        return IPPROTO_NONE;
    }




    unsigned char TTL() const { return ip4 ? ip4->ip_ttl : ip6->ip6_hlim; }




    bool IsFragment() const { return ip4 ? (ntohs(ip4->ip_off) & 0x3fff) != 0 : ip6_hdrs->IsFragment(); }





    uint16_t FragOffset() const { return ip4 ? (ntohs(ip4->ip_off) & 0x1fff) * 8 : ip6_hdrs->FragOffset(); }




    uint32_t ID() const { return ip4 ? ntohs(ip4->ip_id) : ip6_hdrs->ID(); }




    int MF() const { return ip4 ? (ntohs(ip4->ip_off) & 0x2000) != 0 : ip6_hdrs->MF(); }





    int DF() const { return ip4 ? ((ntohs(ip4->ip_off) & 0x4000) != 0) : 0; }




    uint32_t FlowLabel() const { return ip4 ? 0 : (ntohl(ip6->ip6_flow) & 0x000fffff); }




    size_t NumHeaders() const { return ip4 ? 1 : ip6_hdrs->Size(); }




    RecordValPtr ToIPHdrVal() const;





    RecordValPtr ToPktHdrVal() const;





    RecordValPtr ToPktHdrVal(RecordValPtr pkt_hdr, int sindex) const;

    bool Reassembled() const { return reassembled; }

private:
    const ip* ip4 = nullptr;
    const ip6_hdr* ip6 = nullptr;
    const IPv6_Hdr_Chain* ip6_hdrs = nullptr;
    uint64_t len = 0;
    bool del = false;
    bool reassembled = false;
};

}
