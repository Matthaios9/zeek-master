

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/packet_analysis/protocol/tcp/Stats.h"

namespace zeek::analyzer::tcp {
class TCP_Endpoint;
}

namespace zeek::packet_analysis::TCP {

class TCPSessionAdapter;

class TCPAnalyzer final : public IP::IPBasedAnalyzer {
public:
    TCPAnalyzer();

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<TCPAnalyzer>(); }






    void Initialize() override;

    static TCPStateStats& GetStats() {
        static TCPStateStats stats;
        return stats;
    }

protected:
    bool InitConnKey(size_t len, const uint8_t* data, Packet* packet, IPBasedConnKey& key) override;

    void DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt) override;













    bool WantConnection(uint16_t src_port, uint16_t dst_port, const u_char* data, bool& flip_roles) const override;






    packet_analysis::IP::SessionAdapter* MakeSessionAdapter(Connection* conn) override;





    analyzer::pia::PIA* MakePIA(Connection* conn) override;

private:
    const struct tcphdr* ExtractTCP_Header(const u_char*& data, int& len, int& remaining, TCPSessionAdapter* adapter);



    bool ValidateChecksum(const IP_Hdr* ip, const struct tcphdr* tp, analyzer::tcp::TCP_Endpoint* endpoint, int len,
                          int caplen, TCPSessionAdapter* adapter);
};

}
