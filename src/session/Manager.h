

#pragma once

#include "zeek/zeek-config.h"

#include <sys/types.h>
#include <unordered_map>

#include "zeek/ConnKey.h"
#include "zeek/Frag.h"
#include "zeek/session/Session.h"

namespace zeek {

namespace telemetry {
class CounterFamily;
using CounterFamilyPtr = std::shared_ptr<CounterFamily>;
class Counter;
using CounterPtr = std::shared_ptr<Counter>;
}

namespace detail {
class PacketFilter;
}

class EncapsulationStack;
class Packet;
class Connection;
struct ConnTuple;
class StatBlocks;

namespace session {

namespace detail {
class ProtocolStats;
}

struct Stats {
    size_t num_TCP_conns;
    size_t max_TCP_conns;
    uint64_t cumulative_TCP_conns;

    size_t num_UDP_conns;
    size_t max_UDP_conns;
    uint64_t cumulative_UDP_conns;

    size_t num_ICMP_conns;
    size_t max_ICMP_conns;
    uint64_t cumulative_ICMP_conns;

    size_t num_fragments;
    size_t max_fragments;
    uint64_t num_packets;
    uint64_t num_packets_unprocessed;
};

class Manager final {
public:
    Manager();
    ~Manager();




    Connection* FindConnection(Val* v);







    Connection* FindConnection(const zeek::ConnKey& conn_key);

    void Remove(Session* s);
    void Insert(Session* c, bool remove_existing = true);



    void Drain();


    void Clear();

    void GetStats(Stats& s);

    void Weird(const char* name, const Packet* pkt, const char* addl = "", const char* source = "");
    void Weird(const char* name, const IP_Hdr* ip, const char* addl = "");

    size_t CurrentSessions() { return session_map.size(); }

private:
    using SessionMap = std::unordered_map<detail::Key, Session*, detail::KeyHash>;






    void InsertSession(detail::Key key, Session* session);

    SessionMap session_map;
    detail::ProtocolStats* stats;
    telemetry::CounterFamilyPtr ended_sessions_metric_family;
    telemetry::CounterPtr ended_by_inactivity_metric;
};

}


ZEEK_EXTERN_DATA session::Manager* session_mgr;

}
