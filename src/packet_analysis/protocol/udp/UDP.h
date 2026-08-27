

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace zeek::packet_analysis::UDP {

class UDPAnalyzer final : public IP::IPBasedAnalyzer {
public:
    UDPAnalyzer();

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<UDPAnalyzer>(); }






    void Initialize() override;

protected:
    bool InitConnKey(size_t len, const uint8_t* data, Packet* packet, IPBasedConnKey& key) override;

    void DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt) override;













    bool WantConnection(uint16_t src_port, uint16_t dst_port, const u_char* data, bool& flip_roles) const override;

    packet_analysis::IP::SessionAdapter* MakeSessionAdapter(Connection* conn) override;
    analyzer::pia::PIA* MakePIA(Connection* conn) override;

private:

    static bool ValidateChecksum(const IP_Hdr* ip, const struct udphdr* up, int len);

    std::vector<uint16_t> vxlan_ports;
};

}
