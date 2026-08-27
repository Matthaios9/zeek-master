

#pragma once

#include "zeek/analyzer/protocol/ntlm/ntlm_pac.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::ntlm {

class NTLM_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit NTLM_Analyzer(Connection* conn);
    ~NTLM_Analyzer() override;


    void Done() override;

    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;


    void EndpointEOF(bool is_orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new NTLM_Analyzer(conn); }

protected:
    binpac::NTLM::NTLM_Conn* interp;
};

}
