

#pragma once

#include "zeek/IPAddr.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::packet_analysis::IPTunnel {

namespace detail {
class IPTunnelTimer;
}

class IPTunnelAnalyzer : public Analyzer {
public:
    IPTunnelAnalyzer();

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<IPTunnelAnalyzer>(); }
















    bool ProcessEncapsulatedPacket(double t, Packet* pkt, const std::shared_ptr<IP_Hdr>& inner,
                                   std::shared_ptr<EncapsulationStack> prev, const EncapsulatingConn& ec);

















    bool ProcessEncapsulatedPacket(double t, Packet* pkt, uint32_t caplen, uint32_t len, const u_char* data,
                                   int link_type, std::shared_ptr<EncapsulationStack> prev,
                                   const EncapsulatingConn& ec);

protected:
    friend class detail::IPTunnelTimer;

    using IPPair = std::pair<IPAddr, IPAddr>;
    using TunnelActivity = std::pair<EncapsulatingConn, double>;
    using IPTunnelMap = std::map<IPPair, TunnelActivity>;
    IPTunnelMap ip_tunnels;
};


























extern std::unique_ptr<Packet> build_inner_packet(Packet* outer_pkt, int* encap_index,
                                                  const std::shared_ptr<EncapsulationStack>& encap_stack,
                                                  uint32_t inner_cap_len, const u_char* data, int link_type,
                                                  BifEnum::Tunnel::Type tunnel_type, const Tag& analyzer_tag);

namespace detail {

class IPTunnelTimer final : public zeek::detail::Timer {
public:
    IPTunnelTimer(double t, IPTunnelAnalyzer::IPPair p, IPTunnelAnalyzer* analyzer);

    void Dispatch(double t, bool is_expire) override;

protected:
    IPTunnelAnalyzer::IPPair tunnel_idx;
    IPTunnelAnalyzer* analyzer;
};

}


extern IPTunnelAnalyzer* ip_tunnel_analyzer;

}
