

#pragma once

#include <vector>

#include "zeek/IP.h"
#include "zeek/IPAddr.h"
#include "zeek/NetVar.h"
#include "zeek/UID.h"

namespace zeek {

class Connection;








class EncapsulatingConn {
public:



    EncapsulatingConn() = default;











    EncapsulatingConn(const IPAddr& s, const IPAddr& d, BifEnum::Tunnel::Type t = BifEnum::Tunnel::IP,
                      uint16_t ip_proto = UNKNOWN_IP_PROTO)
        : src_addr(s), dst_addr(d), ip_proto(ip_proto), type(t), uid(UID(detail::bits_per_uid)) {
        switch ( ip_proto ) {
            case IPPROTO_ICMP: proto = TRANSPORT_ICMP; break;
            case IPPROTO_UDP: proto = TRANSPORT_UDP; break;
            case IPPROTO_TCP: proto = TRANSPORT_TCP; break;
            default: proto = TRANSPORT_UNKNOWN; break;
        }
    }










    EncapsulatingConn(Connection* c, BifEnum::Tunnel::Type t);




    EncapsulatingConn(const EncapsulatingConn& other) = default;




    ~EncapsulatingConn() = default;

    EncapsulatingConn& operator=(const EncapsulatingConn& other) = default;

    BifEnum::Tunnel::Type Type() const { return type; }




    RecordValPtr ToVal() const;

    friend bool operator==(const EncapsulatingConn& ec1, const EncapsulatingConn& ec2) {
        if ( ec1.type != ec2.type )
            return false;

        if ( ec1.type == BifEnum::Tunnel::IP || ec1.type == BifEnum::Tunnel::GRE )

            return ec1.uid == ec2.uid && ec1.proto == ec2.proto && ec1.ip_proto == ec2.ip_proto &&
                   ((ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr) ||
                    (ec1.src_addr == ec2.dst_addr && ec1.dst_addr == ec2.src_addr));

        if ( ec1.type == BifEnum::Tunnel::VXLAN )


            return ec1.dst_port == ec2.dst_port && ec1.uid == ec2.uid && ec1.proto == ec2.proto &&
                   ec1.ip_proto == ec2.ip_proto &&
                   ((ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr) ||
                    (ec1.src_addr == ec2.dst_addr && ec1.dst_addr == ec2.src_addr));

        return ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr && ec1.src_port == ec2.src_port &&
               ec1.dst_port == ec2.dst_port && ec1.uid == ec2.uid && ec1.proto == ec2.proto &&
               ec1.ip_proto == ec2.ip_proto;
    }

    friend bool operator!=(const EncapsulatingConn& ec1, const EncapsulatingConn& ec2) { return ! (ec1 == ec2); }


    std::shared_ptr<IP_Hdr> ip_hdr;

protected:
    IPAddr src_addr;
    IPAddr dst_addr;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    TransportProto proto = TRANSPORT_UNKNOWN;
    uint16_t ip_proto = UNKNOWN_IP_PROTO;
    BifEnum::Tunnel::Type type = BifEnum::Tunnel::NONE;
    UID uid;
};




class EncapsulationStack {
public:
    EncapsulationStack() = default;

    EncapsulationStack(const EncapsulationStack& other) {
        if ( other.conns )
            conns = new std::vector<EncapsulatingConn>(*(other.conns));
        else
            conns = nullptr;
    }

    EncapsulationStack& operator=(const EncapsulationStack& other) {
        if ( this == &other )
            return *this;

        delete conns;

        if ( other.conns )
            conns = new std::vector<EncapsulatingConn>(*(other.conns));
        else
            conns = nullptr;

        return *this;
    }

    ~EncapsulationStack() { delete conns; }






    void Add(const EncapsulatingConn& c) {
        if ( ! conns )
            conns = new std::vector<EncapsulatingConn>();

        conns->push_back(c);
    }





    size_t Depth() const { return conns ? conns->size() : 0; }




    BifEnum::Tunnel::Type LastType() const {
        return conns ? (*conns)[conns->size() - 1].Type() : BifEnum::Tunnel::NONE;
    }





    VectorValPtr ToVal() const {
        auto vv = make_intrusive<VectorVal>(id::find_type<VectorType>("EncapsulatingConnVector"));

        if ( conns ) {
            for ( size_t i = 0; i < conns->size(); ++i )
                vv->Assign(i, (*conns)[i].ToVal());
        }

        return vv;
    }

    friend bool operator==(const EncapsulationStack& e1, const EncapsulationStack& e2);

    friend bool operator!=(const EncapsulationStack& e1, const EncapsulationStack& e2) { return ! (e1 == e2); }





    EncapsulatingConn* Last() { return Depth() > 0 ? &(conns->back()) : nullptr; }









    EncapsulatingConn* At(size_t index) {
        if ( index > 0 && index <= Depth() )
            return &(conns->at(index - 1));

        return nullptr;
    }




    void Pop();

protected:
    std::vector<EncapsulatingConn>* conns = nullptr;
};

}
