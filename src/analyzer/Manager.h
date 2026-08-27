



















#pragma once

#include "zeek/zeek-config.h"

#include <queue>
#include <vector>

#include "zeek/IP.h"
#include "zeek/IPAddr.h"
#include "zeek/Tag.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Component.h"
#include "zeek/net_util.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek {

namespace packet_analysis::IP {

class IPBasedAnalyzer;
class SessionAdapter;

}

namespace analyzer {











class Manager : public plugin::ComponentManager<Component> {
public:



    Manager();




    ~Manager();





    void InitPostScript();




    void Done();






    void DumpDebug();









    bool EnableAnalyzer(const zeek::Tag& tag);










    bool EnableAnalyzer(EnumVal* tag);









    bool DisableAnalyzer(const zeek::Tag& tag);










    bool DisableAnalyzer(EnumVal* tag);




    void DisableAllAnalyzers();







    zeek::Tag GetAnalyzerTag(const char* name);






    bool IsEnabled(const zeek::Tag& tag);







    bool IsEnabled(EnumVal* tag);













    bool RegisterAnalyzerForPort(EnumVal* tag, PortVal* port);














    bool RegisterAnalyzerForPort(const zeek::Tag& tag, TransportProto proto, uint32_t port);













    bool UnregisterAnalyzerForPort(EnumVal* tag, PortVal* port);













    bool UnregisterAnalyzerForPort(const zeek::Tag& tag, TransportProto proto, uint32_t port);













    Analyzer* InstantiateAnalyzer(const zeek::Tag& tag, Connection* c);













    Analyzer* InstantiateAnalyzer(const char* name, Connection* c);





















    void ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp, uint16_t resp_p, TransportProto proto,
                          const zeek::Tag& analyzer, double timeout);






















    void ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp, uint16_t resp_p, TransportProto proto,
                          const char* analyzer, double timeout);
















    bool ApplyScheduledAnalyzers(Connection* conn, bool init_and_event = true,
                                 packet_analysis::IP::SessionAdapter* parent = nullptr);




















    void ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp, PortVal* resp_p, Val* analyzer, double timeout);




    const std::vector<uint16_t>& GetVxlanPorts() const { return vxlan_ports; }

private:

    bool RegisterAnalyzerForPort(const std::tuple<zeek::Tag, TransportProto, uint32_t>& p);

    friend class packet_analysis::IP::IPBasedAnalyzer;

    using tag_set = std::set<zeek::Tag>;

    tag_set GetScheduled(const Connection* conn);
    void ExpireScheduledAnalyzers();




    struct ConnIndex {
        IPAddr orig;
        IPAddr resp;
        uint16_t resp_p;
        uint16_t proto;

        ConnIndex(const IPAddr& _orig, const IPAddr& _resp, uint16_t _resp_p, uint16_t _proto);
        ConnIndex();

        bool operator<(const ConnIndex& other) const;
    };


    struct ScheduledAnalyzer {
        ConnIndex conn;
        zeek::Tag analyzer;
        double timeout;

        struct Comparator {
            bool operator()(ScheduledAnalyzer* a, ScheduledAnalyzer* b) { return a->timeout > b->timeout; }
        };
    };

    using protocol_analyzers = std::set<std::tuple<zeek::Tag, TransportProto, uint32_t>>;
    using conns_map = std::multimap<ConnIndex, ScheduledAnalyzer*>;
    using conns_queue =
        std::priority_queue<ScheduledAnalyzer*, std::vector<ScheduledAnalyzer*>, ScheduledAnalyzer::Comparator>;

    bool initialized = false;
    protocol_analyzers pending_analyzers_for_ports;

    conns_map conns;
    conns_queue conns_by_timeout;
    std::vector<uint16_t> vxlan_ports;
};

}

ZEEK_EXTERN_DATA analyzer::Manager* analyzer_mgr;

}




#ifdef DEBUG
#define DBG_ANALYZER(conn, txt)                                                                                        \
    DBG_LOG(zeek::DBG_ANALYZER, "%s " txt,                                                                             \
            fmt_conn_id((conn)->OrigAddr(), ntohs((conn)->OrigPort()), (conn)->RespAddr(),                             \
                        ntohs((conn)->RespPort())));
#define DBG_ANALYZER_ARGS(conn, fmt, ...)                                                                              \
    DBG_LOG(zeek::DBG_ANALYZER, "%s " fmt,                                                                             \
            fmt_conn_id((conn)->OrigAddr(), ntohs((conn)->OrigPort()), (conn)->RespAddr(), ntohs((conn)->RespPort())), \
            ##__VA_ARGS__);
#else
#define DBG_ANALYZER(conn, txt)
#define DBG_ANALYZER_ARGS(conn, fmt, ...)
#endif
