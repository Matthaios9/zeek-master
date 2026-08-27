

#pragma once

#include "zeek/analyzer/protocol/tcp/ContentLine.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::finger {

class Finger_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit Finger_Analyzer(Connection* conn);
    ~Finger_Analyzer() override {}

    void Done() override;

    void DeliverStream(int len, const u_char* data, bool orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new Finger_Analyzer(conn); }

protected:
    analyzer::tcp::ContentLine_Analyzer* content_line_orig;
    analyzer::tcp::ContentLine_Analyzer* content_line_resp;
    int did_deliver;
};

}
