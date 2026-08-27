



#pragma once

#include <memory>

#include "zeek/IPAddr.h"
#include "zeek/PrefixTable.h"

namespace zeek {

class IP_Hdr;
class Val;

namespace detail {

class PacketFilter {
public:
    explicit PacketFilter(bool arg_default);
    ~PacketFilter() = default;




    void AddSrc(const IPAddr& src, uint32_t tcp_flags, double probability);
    void AddSrc(Val* src, uint32_t tcp_flags, double probability);
    void AddDst(const IPAddr& src, uint32_t tcp_flags, double probability);
    void AddDst(Val* src, uint32_t tcp_flags, double probability);



    bool RemoveSrc(const IPAddr& src);
    bool RemoveSrc(Val* dst);
    bool RemoveDst(const IPAddr& dst);
    bool RemoveDst(Val* dst);


    bool Match(const std::shared_ptr<IP_Hdr>& ip, int len, int caplen);

private:
    struct Filter {
        uint32_t tcp_flags;
        double probability;
    };

    static void DeleteFilter(void* data);

    bool MatchFilter(const Filter& f, const IP_Hdr& ip, int len, int caplen);

    bool default_match;
    PrefixTable src_filter;
    PrefixTable dst_filter;
};

}
}
