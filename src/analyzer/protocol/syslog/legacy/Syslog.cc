

#include "zeek/analyzer/protocol/syslog/legacy/Syslog.h"

#include "zeek/analyzer/protocol/syslog/legacy/events.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::syslog {

Syslog_Analyzer::Syslog_Analyzer(Connection* conn) : Analyzer("SYSLOG", conn) {
    interp = new binpac::Syslog::Syslog_Conn(this);
    did_session_done = 0;


}

Syslog_Analyzer::~Syslog_Analyzer() { delete interp; }

void Syslog_Analyzer::Done() {
    Analyzer::Done();

    if ( ! did_session_done )
        Event(udp_session_done);
}

void Syslog_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip,
                                    int caplen) {
    Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
    interp->NewData(orig, data, data + len);
}


























































}
