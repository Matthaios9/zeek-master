

#pragma once

#include "zeek/analyzer/protocol/login/Login.h"
#include "zeek/analyzer/protocol/tcp/ContentLine.h"

namespace zeek::analyzer::login {

class Rlogin_Analyzer;

enum rlogin_state : uint8_t {
    RLOGIN_FIRST_NULL,
    RLOGIN_CLIENT_USER_NAME,
    RLOGIN_SERVER_USER_NAME,
    RLOGIN_TERMINAL_TYPE,

    RLOGIN_SERVER_ACK,

    RLOGIN_IN_BAND_CONTROL_FF2,

    RLOGIN_WINDOW_CHANGE_S1,
    RLOGIN_WINDOW_CHANGE_S2,
    RLOGIN_WINDOW_CHANGE_REMAINDER,

    RLOGIN_LINE_MODE,

    RLOGIN_PRESUMED_REJECTED,

    RLOGIN_UNKNOWN,
};

class Contents_Rlogin_Analyzer final : public analyzer::tcp::ContentLine_Analyzer {
public:
    Contents_Rlogin_Analyzer(Connection* conn, bool orig, Rlogin_Analyzer* analyzer);

    void SetPeer(Contents_Rlogin_Analyzer* arg_peer) { peer = arg_peer; }

    rlogin_state RloginState() const { return state; }

protected:
    void DoDeliver(int len, const u_char* data) override;
    void BadProlog();

    rlogin_state state, save_state;
    int num_bytes_to_scan;

    Contents_Rlogin_Analyzer* peer;
    Rlogin_Analyzer* analyzer;
};

class Rlogin_Analyzer final : public Login_Analyzer {
public:
    explicit Rlogin_Analyzer(Connection* conn);

    void ClientUserName(const char* s);
    void ServerUserName(const char* s);
    void TerminalType(const char* s);

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new Rlogin_Analyzer(conn); }
};

}
