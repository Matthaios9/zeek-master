

#pragma once

#include <sys/types.h>
#include <string>

#include "zeek/ConnKey.h"
#include "zeek/IPAddr.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Rule.h"
#include "zeek/Tag.h"
#include "zeek/Timer.h"
#include "zeek/UID.h"
#include "zeek/WeirdState.h"
#include "zeek/ZeekArgs.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/iosource/Packet.h"
#include "zeek/session/Session.h"

namespace zeek {

class Connection;
class EncapsulationStack;
class Val;
class RecordVal;

using ValPtr = IntrusivePtr<Val>;
using RecordValPtr = IntrusivePtr<RecordVal>;

class IPBasedConnKey;
using IPBasedConnKeyPtr = std::unique_ptr<IPBasedConnKey>;

namespace detail {

class Specific_RE_Matcher;
class RuleEndpointState;
class RuleHdrTest;

}

namespace analyzer {
class Analyzer;
}
namespace packet_analysis::IP {
class SessionAdapter;
}

enum ConnEventToFlag : uint8_t {
    NUL_IN_LINE,
    SINGULAR_CR,
    SINGULAR_LF,
    NUM_EVENTS_TO_FLAG,
};

static inline int addr_port_canon_lt(const IPAddr& addr1, uint32_t p1, const IPAddr& addr2, uint32_t p2) {
    return addr1 < addr2 || (addr1 == addr2 && p1 < p2);
}

class Connection final : public session::Session {
public:
    Connection(zeek::IPBasedConnKeyPtr k, double t, uint32_t flow, const Packet* pkt);

    ~Connection() override;









    void CheckEncapsulation(const std::shared_ptr<EncapsulationStack>& encap);






    void Done() override;










    void NextPacket(double t, bool is_orig, const IP_Hdr* ip, int len, int caplen, const u_char*& data,
                    int& record_packet, int& record_content,

                    const Packet* pkt);







    const ConnKey& Key() const;
    session::detail::Key SessionKey(bool copy) const override;
    uint8_t KeyProto() const;

    const IPAddr& OrigAddr() const { return orig_addr; }
    const IPAddr& RespAddr() const { return resp_addr; }

    uint32_t OrigPort() const { return orig_port; }
    uint32_t RespPort() const { return resp_port; }

    void FlipRoles();

    analyzer::Analyzer* FindAnalyzer(analyzer::ID id);
    analyzer::Analyzer* FindAnalyzer(const zeek::Tag& tag);
    analyzer::Analyzer* FindAnalyzer(const char* name);

    TransportProto ConnTransport() const { return proto; }
    std::string TransportIdentifier() const override {
        if ( proto == TRANSPORT_TCP )
            return "tcp";
        else if ( proto == TRANSPORT_UDP )
            return "udp";
        else if ( proto == TRANSPORT_ICMP )
            return "icmp";
        else
            return "unknown";
    }




    bool IsReuse(double t, const u_char* pkt);




    const RecordValPtr& GetVal() override;

    void Match(detail::Rule::PatternType type, const u_char* data, int len, bool is_orig, bool bol, bool eol,
               bool clear_state);




    void RemovalEvent() override;

    void Weird(const char* name, const char* addl = "", const char* source = "");
    bool DidWeird() const { return weird; }

    inline bool FlagEvent(ConnEventToFlag e) {
        if ( e >= 0 && e < NUM_EVENTS_TO_FLAG ) {
            if ( suppress_event & (1 << e) )
                return false;
            suppress_event |= 1 << e;
        }

        return true;
    }

    void Describe(ODesc* d) const override;
    void IDString(ODesc* d) const;



    static uint64_t TotalConnections() { return total_connections; }
    static uint64_t CurrentConnections() { return current_connections; }


    void SetSessionAdapter(packet_analysis::IP::SessionAdapter* aa, analyzer::pia::PIA* pia);
    packet_analysis::IP::SessionAdapter* GetSessionAdapter() { return adapter; }
    analyzer::pia::PIA* GetPrimaryPIA() { return primary_PIA; }


    void SetTransport(TransportProto arg_proto) { proto = arg_proto; }

    void SetUID(const UID& arg_uid) { uid = arg_uid; }

    UID GetUID() const { return uid; }

    std::shared_ptr<EncapsulationStack> GetEncapsulation() const { return encapsulation; }

    void CheckFlowLabel(bool is_orig, uint32_t flow_label);

    uint32_t GetOrigFlowLabel() { return orig_flow_label; }
    uint32_t GetRespFlowLabel() { return resp_flow_label; }

    bool PermitWeird(const char* name, uint64_t threshold, uint64_t rate, double duration);


    bool IsFinished() { return finished; }


    static void InitPostScript();

private:
    friend class session::detail::Timer;

    IPAddr orig_addr;
    IPAddr resp_addr;
    uint32_t orig_port, resp_port;
    uint32_t orig_flow_label, resp_flow_label;
    std::optional<uint16_t> vlan, inner_vlan;
    u_char orig_l2_addr[Packet::L2_ADDR_LEN];
    u_char resp_l2_addr[Packet::L2_ADDR_LEN];
    int suppress_event;
    RecordValPtr conn_val;
    std::shared_ptr<EncapsulationStack> encapsulation;

    IPBasedConnKeyPtr key;

    TransportProto proto;
    uint8_t tunnel_changes = 0;
    bool weird;
    bool finished;
    bool saw_first_orig_packet;
    bool saw_first_resp_packet;

    packet_analysis::IP::SessionAdapter* adapter;
    analyzer::pia::PIA* primary_PIA;

    UID uid;
    std::unique_ptr<detail::WeirdStateMap> weird_state;


    static uint64_t total_connections;
    static uint64_t current_connections;




    static RecordValPtr conn_id_ctx_singleton;
};


namespace detail {
extern RecordValPtr build_dummy_conn_record();
}

}
