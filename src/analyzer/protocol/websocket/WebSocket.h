

#pragma once

#include <memory>

#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/analyzer/protocol/websocket/websocket_pac.h"

namespace zeek::analyzer::websocket {




class WebSocket_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    WebSocket_Analyzer(zeek::Connection* conn);






    bool Configure(zeek::RecordValPtr config);

    void Init() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;

    static zeek::analyzer::Analyzer* Instantiate(Connection* conn) { return new WebSocket_Analyzer(conn); }

private:
    std::unique_ptr<binpac::WebSocket::WebSocket_Conn> interp;
    bool had_gap = false;
};

}
