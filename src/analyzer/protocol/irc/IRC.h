

#pragma once

#include "zeek/analyzer/protocol/file/File.h"
#include "zeek/analyzer/protocol/tcp/ContentLine.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer {

namespace irc {




class IRC_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
    enum : uint8_t {
        WAIT_FOR_REGISTRATION,
        REGISTERED,
    };
    enum : uint8_t {
        NO_ZIP,
        ACCEPT_ZIP,
        ZIP_LOADED,
    };

public:



    explicit IRC_Analyzer(Connection* conn);




    void Done() override;








    void DeliverStream(int len, const u_char* data, bool orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new IRC_Analyzer(conn); }

protected:
    int orig_status;
    int orig_zip_status;
    int resp_status;
    int resp_zip_status;

private:
    void StartTLS();

    inline void SkipLeadingWhitespace(std::string& str);


    int invalid_msg_count;


    int invalid_msg_max_count;









    std::vector<std::string> SplitWords(const std::string& input, char split);







    static bool IsValidClientCommand(const std::string& command);

    analyzer::tcp::ContentLine_Analyzer* cl_orig;
    analyzer::tcp::ContentLine_Analyzer* cl_resp;
    bool starttls;
};

}

namespace file {

class IRC_Data : public analyzer::file::File_Analyzer {
public:
    explicit IRC_Data(Connection* conn) : analyzer::file::File_Analyzer("IRC_Data", conn) {}

    void DeliverStream(int len, const u_char* data, bool orig) override;

    void Undelivered(uint64_t seq, int len, bool orig) override;

    static Analyzer* Instantiate(Connection* conn) { return new IRC_Data(conn); }
};
}

}
