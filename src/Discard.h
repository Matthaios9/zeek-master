

#pragma once

#include <sys/types.h>
#include <memory>

#include "zeek/IntrusivePtr.h"

namespace zeek {

class IP_Hdr;
class Val;
class Func;
using FuncPtr = IntrusivePtr<Func>;

namespace detail {

class Discarder final {
public:
    Discarder();
    ~Discarder();

    bool IsActive();

    bool NextPacket(const std::shared_ptr<IP_Hdr>& ip, int len, int caplen);

protected:
    Val* BuildData(const u_char* data, int hdrlen, int len, int caplen);

    FuncPtr check_ip;
    FuncPtr check_tcp;
    FuncPtr check_udp;
    FuncPtr check_icmp;


    int discarder_maxlen;
};

}
}
