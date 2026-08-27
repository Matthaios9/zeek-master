

#pragma once

#include "zeek/analyzer/Analyzer.h"

#include "analyzer/protocol/syslog/legacy/syslog_pac.h"

namespace zeek::analyzer::syslog {

class Syslog_Analyzer : public analyzer::Analyzer {
public:
    explicit Syslog_Analyzer(Connection* conn);
    ~Syslog_Analyzer() override;

    void Done() override;
    void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new Syslog_Analyzer(conn); }

protected:
    int did_session_done;

    binpac::Syslog::Syslog_Conn* interp;
};





















}
