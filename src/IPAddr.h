

#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <memory>
#include <string>

#include "zeek/threading/SerialTypes.h"

using in4_addr = in_addr;

namespace zeek {

class String;
struct ConnTuple;
class Val;

namespace detail {


constexpr uint16_t INVALID_CONN_KEY_IP_PROTO = 65534;

class HashKey;

}




class IPAddr {
public:



    using Family = IPFamily;




    enum ByteOrder : uint8_t { Host, Network };




    IPAddr() { memset(in6.s6_addr, 0, sizeof(in6.s6_addr)); }






    explicit IPAddr(const in4_addr& in4) {
        memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&in6.s6_addr[12], &in4.s_addr, sizeof(in4.s_addr));
    }






    explicit IPAddr(const in6_addr& arg_in6) : in6(arg_in6) {}







    IPAddr(const std::string& s) { Init(s.data()); }







    IPAddr(const char* s) { Init(s); }







    explicit IPAddr(const String& s);













    IPAddr(Family family, const uint32_t* bytes, ByteOrder order);




    IPAddr(const IPAddr& other) = default;




    ~IPAddr() = default;




    Family GetFamily() const {
        if ( memcmp(in6.s6_addr, v4_mapped_prefix, 12) == 0 )
            return IPv4;

        return IPv6;
    }




    bool IsLoopback() const;




    bool IsMulticast() const {
        if ( GetFamily() == IPv4 )
            return in6.s6_addr[12] == 224;

        return in6.s6_addr[0] == 0xff;
    }




    bool IsBroadcast() const {
        if ( GetFamily() == IPv4 )
            return ((in6.s6_addr[12] == 0xff) && (in6.s6_addr[13] == 0xff) && (in6.s6_addr[14] == 0xff) &&
                    (in6.s6_addr[15] == 0xff));

        return false;
    }













    int GetBytes(const uint32_t** bytes) const {
        if ( GetFamily() == IPv4 ) {
            *bytes = reinterpret_cast<const uint32_t*>(&in6.s6_addr[12]);
            return 1;
        }
        else {
            *bytes = reinterpret_cast<const uint32_t*>(in6.s6_addr);
            return 4;
        }
    }












    void CopyIPv6(uint32_t* bytes, ByteOrder order = Network) const {
        memcpy(bytes, in6.s6_addr, sizeof(in6.s6_addr));

        if ( order == Host ) {
            for ( unsigned int i = 0; i < 4; ++i )
                bytes[i] = ntohl(bytes[i]);
        }
    }





    void CopyIPv6(in6_addr* arg_in6) const { memcpy(arg_in6->s6_addr, in6.s6_addr, sizeof(in6.s6_addr)); }









    void CopyIPv4(in4_addr* in4) const { memcpy(&in4->s_addr, &in6.s6_addr[12], sizeof(in4->s_addr)); }




    std::unique_ptr<detail::HashKey> MakeHashKey() const;











    void Mask(int top_bits_to_keep);










    void ReverseMask(int top_bits_to_chop);




    IPAddr& operator=(const IPAddr& other) = default;





    IPAddr operator|(const IPAddr& other) {
        in6_addr result;
        for ( int i = 0; i < 16; ++i )
            result.s6_addr[i] = this->in6.s6_addr[i] | other.in6.s6_addr[i];

        return IPAddr(result);
    }






    std::string AsString() const;






    std::string AsURIString() const {
        if ( GetFamily() == IPv4 )
            return AsString();

        return std::string("[") + AsString() + "]";
    }




    std::string AsHexString() const;





    operator std::string() const { return AsString(); }





    std::string PtrName() const;




    friend bool operator==(const IPAddr& addr1, const IPAddr& addr2) {
        return memcmp(&addr1.in6, &addr2.in6, sizeof(in6_addr)) == 0;
    }

    friend bool operator!=(const IPAddr& addr1, const IPAddr& addr2) { return ! (addr1 == addr2); }






    friend bool operator<(const IPAddr& addr1, const IPAddr& addr2) {
        return memcmp(&addr1.in6, &addr2.in6, sizeof(in6_addr)) < 0;
    }

    friend bool operator<=(const IPAddr& addr1, const IPAddr& addr2) { return addr1 < addr2 || addr1 == addr2; }

    friend bool operator>=(const IPAddr& addr1, const IPAddr& addr2) { return ! (addr1 < addr2); }

    friend bool operator>(const IPAddr& addr1, const IPAddr& addr2) { return ! (addr1 <= addr2); }





    void ConvertToThreadingValue(threading::Value::addr_t* v) const;














    bool CheckPrefixLength(uint8_t length, bool len_is_v6_relative = false) const;











    static bool ConvertString(const char* s, in6_addr* result);






    static bool IsValid(const char* s) {
        in6_addr tmp;
        return ConvertString(s, &tmp);
    }




    static const IPAddr v4_unspecified;




    static const IPAddr v6_unspecified;

private:
    friend class IPPrefix;







    void Init(const char* s);

    in6_addr in6;


    static constexpr uint8_t v4_mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
};

inline IPAddr::IPAddr(Family family, const uint32_t* bytes, ByteOrder order) {
    if ( family == IPv4 ) {
        memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&in6.s6_addr[12], bytes, sizeof(uint32_t));

        if ( order == Host ) {
            uint32_t* p = reinterpret_cast<uint32_t*>(&in6.s6_addr[12]);
            *p = htonl(*p);
        }
    }

    else {
        memcpy(in6.s6_addr, bytes, sizeof(in6.s6_addr));

        if ( order == Host ) {
            for ( unsigned int i = 0; i < 4; ++i ) {
                uint32_t* p = reinterpret_cast<uint32_t*>(&in6.s6_addr[i * static_cast<ptrdiff_t>(4)]);
                *p = htonl(*p);
            }
        }
    }
}

inline bool IPAddr::IsLoopback() const {
    if ( GetFamily() == IPv4 )
        return in6.s6_addr[12] == 127;

    else
        return ((in6.s6_addr[0] == 0) && (in6.s6_addr[1] == 0) && (in6.s6_addr[2] == 0) && (in6.s6_addr[3] == 0) &&
                (in6.s6_addr[4] == 0) && (in6.s6_addr[5] == 0) && (in6.s6_addr[6] == 0) && (in6.s6_addr[7] == 0) &&
                (in6.s6_addr[8] == 0) && (in6.s6_addr[9] == 0) && (in6.s6_addr[10] == 0) && (in6.s6_addr[11] == 0) &&
                (in6.s6_addr[12] == 0) && (in6.s6_addr[13] == 0) && (in6.s6_addr[14] == 0) && (in6.s6_addr[15] == 1));
}

inline void IPAddr::ConvertToThreadingValue(threading::Value::addr_t* v) const {
    v->family = GetFamily();

    switch ( v->family ) {
        case IPv4: CopyIPv4(&v->in.in4); return;

        case IPv6: CopyIPv6(&v->in.in6); return;
    }
}





class IPPrefix {
public:



    IPPrefix() = default;









    IPPrefix(const in4_addr& in4, uint8_t length);









    IPPrefix(const in6_addr& in6, uint8_t length);














    IPPrefix(const IPAddr& addr, uint8_t length, bool len_is_v6_relative = false);




    IPPrefix(const IPPrefix& other) = default;




    ~IPPrefix() = default;





    const IPAddr& Prefix() const { return prefix; }





    uint8_t Length() const { return prefix.GetFamily() == IPv4 ? length - 96 : length; }





    uint8_t LengthIPv6() const { return length; }






    bool Contains(const IPAddr& addr) const {
        IPAddr p(addr);
        p.Mask(length);
        return p == prefix;
    }



    IPPrefix& operator=(const IPPrefix& other) = default;






    std::string AsString() const;

    operator std::string() const { return AsString(); }




    std::unique_ptr<detail::HashKey> MakeHashKey() const;





    void ConvertToThreadingValue(threading::Value::subnet_t* v) const {
        v->length = length;
        prefix.ConvertToThreadingValue(&v->prefix);
    }




    friend bool operator==(const IPPrefix& net1, const IPPrefix& net2) {
        return net1.Prefix() == net2.Prefix() && net1.Length() == net2.Length();
    }

    friend bool operator!=(const IPPrefix& net1, const IPPrefix& net2) { return ! (net1 == net2); }






    friend bool operator<(const IPPrefix& net1, const IPPrefix& net2) {
        if ( net1.Prefix() < net2.Prefix() )
            return true;

        else if ( net1.Prefix() == net2.Prefix() )
            return net1.Length() < net2.Length();

        else
            return false;
    }

    friend bool operator<=(const IPPrefix& net1, const IPPrefix& net2) { return net1 < net2 || net1 == net2; }

    friend bool operator>=(const IPPrefix& net1, const IPPrefix& net2) { return ! (net1 < net2); }

    friend bool operator>(const IPPrefix& net1, const IPPrefix& net2) { return ! (net1 <= net2); }










    static bool ConvertString(const char* s, IPPrefix* result);






    static bool IsValid(const char* s) {
        IPPrefix tmp;
        return ConvertString(s, &tmp);
    }

private:
    IPAddr prefix;
    uint8_t length = 0;
};

}
