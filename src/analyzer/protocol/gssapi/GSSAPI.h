

#pragma once

#include "zeek/analyzer/protocol/gssapi/gssapi_pac.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::gssapi {

class GSSAPI_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit GSSAPI_Analyzer(Connection* conn);
    ~GSSAPI_Analyzer() override;


    void Done() override;

    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;


    void EndpointEOF(bool is_orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new GSSAPI_Analyzer(conn); }

protected:
    binpac::GSSAPI::GSSAPI_Conn* interp;
};

}
