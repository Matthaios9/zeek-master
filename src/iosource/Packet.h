

#pragma once

#include <sys/types.h>
#include <cstdint>
#include <optional>
#include <string>

#if defined(__OpenBSD__)

#include <net/bpf.h>
using pkt_timeval = bpf_timeval;
#else
using pkt_timeval = struct timeval;
#include <sys/socket.h>
#include <sys/time.h>
#endif

#include "zeek/IP.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/session/Session.h"



#ifdef __OpenBSD__

#define DLT_RAW 14
#else

#define DLT_RAW 12
#endif

namespace zeek {

class ODesc;
class Val;
class RecordVal;

template<class T>
class IntrusivePtr;
using ValPtr = IntrusivePtr<Val>;
using RecordValPtr = IntrusivePtr<RecordVal>;






enum Layer3Proto : int8_t {
    L3_UNKNOWN = -1,
    L3_IPV4 = 1,
    L3_IPV6 = 2,
    L3_ARP = 3,
};




class Packet {
public:






















    Packet(int link_type, pkt_timeval* ts, uint32_t caplen, uint32_t len, const u_char* data, bool copy = false,
           std::string tag = "") {
        Init(link_type, ts, caplen, len, data, copy, std::move(tag));
    }




    Packet() {
        pkt_timeval ts = {0, 0};
        Init(0, &ts, 0, 0, nullptr);
    }




    ~Packet();























    void Init(int link_type, pkt_timeval* ts, uint32_t caplen, uint32_t len, const u_char* data, bool copy = false,
              std::string tag = "");





    RecordValPtr ToRawPktHdrVal() const;





    static RecordValPtr ToVal(const Packet* p);




    static const int L2_ADDR_LEN = 6;






    static constexpr const u_char L2_EMPTY_ADDR[L2_ADDR_LEN] = {0};

    struct VlanTag {
        uint16_t id = 0;

        uint8_t pcp = 0;

        bool dei = false;

        bool operator==(const VlanTag&) const = default;
    };


    std::string tag;
    double time;
    pkt_timeval ts;
    const u_char* data = nullptr;
    uint32_t len;
    uint32_t cap_len;
    uint32_t link_type;




    uint32_t eth_type;




    std::optional<VlanTag> vlan;




    std::optional<VlanTag> inner_vlan;




    Layer3Proto l3_proto;





    bool is_orig = false;









    bool l2_checksummed = false;





    bool l3_checksummed = false;





    bool l4_checksummed = false;




    const u_char* l2_src = nullptr;




    const u_char* l2_dst = nullptr;







    bool processed = false;




    mutable bool dump_packet = false;






    mutable int dump_size = 0;










    std::shared_ptr<EncapsulationStack> encap = nullptr;





    std::shared_ptr<IP_Hdr> ip_hdr = nullptr;





    int proto = -1;






    BifEnum::Tunnel::Type tunnel_type = BifEnum::Tunnel::NONE;






    int gre_version = -1;






    int gre_link_type = DLT_RAW;




    session::Session* session = nullptr;

private:

    ValPtr FmtEUI48(const u_char* mac) const;



    bool copy = false;
};

}
