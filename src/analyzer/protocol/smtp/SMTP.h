

#pragma once

#include <list>

#include "zeek/analyzer/protocol/mime/MIME.h"
#include "zeek/analyzer/protocol/tcp/ContentLine.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

#undef SMTP_CMD_DEF
#define SMTP_CMD_DEF(cmd) SMTP_CMD_##cmd,

namespace zeek::analyzer::smtp {
namespace detail {

class SMTP_BDAT_Analyzer;

enum SMTP_Cmd : uint8_t {
#include "SMTP_cmd.def"
};


enum SMTP_State : uint8_t {
    SMTP_CONNECTED,
    SMTP_INITIATED,
    SMTP_NOT_AVAILABLE,
    SMTP_READY,
    SMTP_MAIL_OK,
    SMTP_RCPT_OK,
    SMTP_IN_DATA,
    SMTP_AFTER_DATA,
    SMTP_IN_AUTH,
    SMTP_IN_TLS,
    SMTP_QUIT,
    SMTP_AFTER_GAP,
    SMTP_GAP_RECOVERY,
    SMTP_IN_BDAT,
};

}

class SMTP_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit SMTP_Analyzer(Connection* conn);
    ~SMTP_Analyzer() override;

    void Done() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void ConnectionFinished(bool half_finished) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;

    void SkipData() { skip_data = true; }

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new SMTP_Analyzer(conn); }

protected:
    void ProcessLine(int length, const char* line, bool orig);
    void NewCmd(int cmd_code);
    void NewReply(int reply_code, bool orig);
    void ProcessExtension(int ext_len, const char* ext);
    void ProcessData(int length, const char* line);
    bool ProcessBdatArg(int arg_len, const char* arg, bool orig);
    std::string Rfc822MsgDataIn(int len, const u_char* data);
    void Rfc822MsgGap(int len);

    void UpdateState(int cmd_code, int reply_code, bool orig);

    void BeginData(bool orig, detail::SMTP_State new_state = detail::SMTP_IN_DATA);
    void EndData();

    int ParseCmd(int cmd_len, const char* cmd);

    void RequestEvent(int cmd_len, const char* cmd, int arg_len, const char* arg);
    void Unexpected(bool is_sender, const char* msg, int detail_len, const char* detail);
    void UnexpectedCommand(int cmd_code, int reply_code);
    void UnexpectedReply(int cmd_code, int reply_code);
    void StartTLS();

    bool orig_is_sender;
    bool expect_sender, expect_recver;
    bool pipelining;
    int state;
    int last_replied_cmd;
    int first_cmd;
    int pending_reply;
    std::list<int> pending_cmd_q;
    bool skip_data;
    String* line_after_gap;


    std::unique_ptr<detail::SMTP_BDAT_Analyzer> bdat;

    analyzer::mime::MIME_Mail* mail;
    std::string rfc822_msg_fuid;
    uint64_t rfc822_msg_offset = 0;

private:
    analyzer::tcp::ContentLine_Analyzer* cl_orig;
    analyzer::tcp::ContentLine_Analyzer* cl_resp;
};

}
