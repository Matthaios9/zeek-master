

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::login {

enum login_state : uint8_t {
    LOGIN_STATE_AUTHENTICATE,
    LOGIN_STATE_LOGGED_IN,
    LOGIN_STATE_SKIP,
    LOGIN_STATE_CONFUSED,
};


constexpr int MAX_AUTHENTICATE_LINES = 50;


constexpr int MAX_LOGIN_LOOKAHEAD = 10;



constexpr int MAX_USER_TEXT = 12;

class Login_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    Login_Analyzer(const char* name, Connection* conn);
    ~Login_Analyzer() override;

    void DeliverStream(int len, const u_char* data, bool orig) override;

    void SetEnv(bool orig, char* name, char* val) override;

    login_state LoginState() const { return state; }
    void SetLoginState(login_state s) { state = s; }

    void EndpointEOF(bool is_orig) override;

protected:
    void NewLine(bool orig, char* line);
    void AuthenticationDialog(bool orig, char* line);

    void LoginEvent(EventHandlerPtr f, const char* line, bool no_user_okay = false);
    const char* GetUsername(const char* line) const;
    void LineEvent(EventHandlerPtr f, const char* line);
    void Confused(const char* msg, const char* addl);
    void ConfusionText(const char* line);

    bool IsPloy(const char* line);
    bool IsSkipAuthentication(const char* line) const;
    const char* IsLoginPrompt(const char* line) const;
    bool IsDirectLoginPrompt(const char* line) const;
    bool IsFailureMsg(const char* line) const;
    bool IsSuccessMsg(const char* line) const;
    bool IsTimeout(const char* line) const;
    bool IsEmpty(const char* line) const;

    void AddUserText(const char* line);
    char* PeekUserText();
    char* PopUserText();
    Val* PopUserTextVal();

    bool MatchesTypeahead(const char* line) const;
    bool HaveTypeahead() const { return num_user_text > 0; }
    void FlushEmptyTypeahead();

    char* user_text[MAX_USER_TEXT] = {nullptr};
    int user_text_first, user_text_last;
    int num_user_text;

    Val* username;
    Val* client_name;

    login_state state;
    int lines_scanned;
    int num_user_lines_seen;
    int last_failure_num_user_lines;
    int login_prompt_line;
    int failure_line;

    bool is_VMS;
    bool saw_ploy;
};

}
