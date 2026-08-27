

#pragma once

#include <netinet/in.h>

#include "zeek/Conn.h"
#include "zeek/ConnKey.h"
#include "zeek/IPAddr.h"
#include "zeek/net_util.h"

namespace zeek {

namespace detail {




struct PackedConnTuple {
    in6_addr ip1;
    in6_addr ip2;
    uint16_t port1 = 0;
    uint16_t port2 = 0;
    uint16_t proto = 0;
} __attribute__((packed, aligned));

}








class IPBasedConnKey : public zeek::ConnKey {
public:





    void InitTuple(const IPAddr& src_addr, uint32_t src_port, const IPAddr& dst_addr, uint32_t dst_port, uint16_t proto,
                   bool is_one_way = false);




    IPAddr SrcAddr() const { return flipped ? IPAddr(PackedTuple().ip2) : IPAddr(PackedTuple().ip1); }



    IPAddr DstAddr() const { return flipped ? IPAddr(PackedTuple().ip1) : IPAddr(PackedTuple().ip2); }



    uint16_t SrcPort() const { return flipped ? PackedTuple().port2 : PackedTuple().port1; }



    uint16_t DstPort() const { return flipped ? PackedTuple().port1 : PackedTuple().port2; }



    uint16_t Proto() const { return PackedTuple().proto; }




    TransportProto GetTransportProto() const {
        switch ( Proto() ) {
            case IPPROTO_TCP: return TRANSPORT_TCP;
            case IPPROTO_UDP: return TRANSPORT_UDP;
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6: return TRANSPORT_ICMP;
            default: return TRANSPORT_UNKNOWN;
        }
    }




    void FlipRoles() { flipped = ! flipped; }












    void FlipRoles(RecordVal& conn_id, RecordVal& ctx) {
        FlipRoles();

        DoFlipRoles(conn_id, ctx);
    }









    virtual detail::PackedConnTuple& PackedTuple() = 0;









    virtual const detail::PackedConnTuple& PackedTuple() const = 0;

protected:















    void DoPopulateConnIdVal(RecordVal& conn_id, RecordVal& ctx) override;









    virtual void DoFlipRoles(RecordVal& conn_id, RecordVal& ctx);




    bool flipped = false;
};

using IPBasedConnKeyPtr = std::unique_ptr<IPBasedConnKey>;




class IPConnKey : public IPBasedConnKey {
public:





    IPConnKey() { memset(static_cast<void*>(&key), 0, sizeof(key)); }




    detail::PackedConnTuple& PackedTuple() override { return key.tuple; }




    const detail::PackedConnTuple& PackedTuple() const override { return key.tuple; }

protected:



    zeek::session::detail::Key DoSessionKey() const override {
        return {reinterpret_cast<const void*>(&key), sizeof(key),

                session::detail::Key::CONNECTION_KEY_TYPE};
    }

private:
    struct {
        struct detail::PackedConnTuple tuple;
    } key;
};

}
