

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::login {
class NVT_Analyzer;
}

namespace zeek::analyzer::ftp {

class FTP_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit FTP_Analyzer(Connection* conn);

    void Done() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new FTP_Analyzer(conn); }

protected:
    analyzer::login::NVT_Analyzer* nvt_orig;
    analyzer::login::NVT_Analyzer* nvt_resp;
    uint32_t pending_reply = 0;
    std::string auth_requested;
    bool tls_active = false;
};








class FTP_ADAT_Analyzer final : public analyzer::SupportAnalyzer {
public:
    FTP_ADAT_Analyzer(Connection* conn, bool arg_orig) : SupportAnalyzer("FTP_ADAT", conn, arg_orig) {}

    void DeliverStream(int len, const u_char* data, bool orig) override;

protected:



    bool first_token = true;
};

}
