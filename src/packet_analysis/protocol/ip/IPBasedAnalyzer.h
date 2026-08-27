

#pragma once

#include <map>
#include <set>

#include "zeek/Tag.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"

namespace zeek::analyzer::pia {
class PIA;
}

namespace zeek::packet_analysis::IP {

class SessionAdapter;






class IPBasedAnalyzer : public Analyzer {
public:
    ~IPBasedAnalyzer() override;

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;








    virtual bool IsReuse(double t, const u_char* pkt) { return false; }










    bool RegisterAnalyzerForPort(const zeek::Tag& tag, uint32_t port);









    bool UnregisterAnalyzerForPort(const zeek::Tag& tag, uint32_t port);





    void DumpPortDebug();








    static void SetIgnoreChecksumsNets(TableValPtr t);








    static TableValPtr GetIgnoreChecksumsNets();

protected:













    IPBasedAnalyzer(const char* name, TransportProto proto, uint32_t mask, bool report_unknown_protocols);












    virtual bool InitConnKey(size_t len, const uint8_t* data, Packet* packet, IPBasedConnKey& key) = 0;












    virtual void DeliverPacket(Connection* conn, double t, bool is_orig, int remaining, Packet* pkt) {}













    virtual bool WantConnection(uint16_t src_port, uint16_t dst_port, const u_char* data, bool& flip_roles) const {
        flip_roles = false;
        return true;
    }






    virtual SessionAdapter* MakeSessionAdapter(Connection* conn) = 0;





    virtual analyzer::pia::PIA* MakePIA(Connection* conn) { return nullptr; }











    bool CheckHeaderTrunc(size_t min_hdr_len, size_t remaining, Packet* packet);








    bool IsLikelyServerPort(uint32_t port) const;

private:



    using tag_set = std::set<zeek::Tag>;
    using analyzer_map_by_port = std::map<uint32_t, tag_set*>;
    analyzer_map_by_port analyzers_by_port;

    tag_set* LookupPort(uint32_t port, bool add_if_not_found);







    zeek::Connection* NewConn(IPBasedConnKeyPtr key, const Packet* pkt);

    void BuildSessionAnalyzerTree(Connection* conn);

    TransportProto transport;
    uint32_t server_port_mask;
    static TableValPtr ignore_checksums_nets_table;
};

}
