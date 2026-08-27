

#include "zeek/analyzer/protocol/xmpp/XMPP.h"

#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::xmpp {

XMPP_Analyzer::XMPP_Analyzer(Connection* conn) : analyzer::tcp::TCP_ApplicationAnalyzer("XMPP", conn) {
    interp = std::make_unique<binpac::XMPP::XMPP_Conn>(this);
    had_gap = false;
    tls_active = false;
}

void XMPP_Analyzer::Done() {
    analyzer::tcp::TCP_ApplicationAnalyzer::Done();

    interp->FlowEOF(true);
    interp->FlowEOF(false);
}

void XMPP_Analyzer::EndpointEOF(bool is_orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    interp->FlowEOF(is_orig);
}

void XMPP_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

    if ( tls_active ) {


        ForwardStream(len, data, orig);
        return;
    }

    if ( TCP() && TCP()->IsPartial() )
        return;

    if ( had_gap )



        return;

    try {
        interp->NewData(orig, data, data + len);
    } catch ( const binpac::Exception& e ) {
        AnalyzerViolation(util::fmt("Binpac exception: %s", e.what()));
    }
}

void XMPP_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    had_gap = true;
    interp->NewGap(orig, len);
}

void XMPP_Analyzer::StartTLS() {




    tls_active = true;

    Analyzer* ssl = analyzer_mgr->InstantiateAnalyzer("SSL", Conn());
    if ( ssl )
        AddChildAnalyzer(ssl);
}

}
