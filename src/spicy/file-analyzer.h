

#pragma once

#include <optional>
#include <string>
#include <utility>

#include <hilti/rt/types/stream.h>

#include <spicy/rt/driver.h>
#include <spicy/rt/parser.h>

#include "zeek/spicy/cookie.h"

namespace zeek::spicy::rt {


class FileState : public ::spicy::rt::driver::ParsingState {
public:





    FileState(Cookie cookie) : ParsingState(::spicy::rt::driver::ParsingType::Stream), _cookie(std::move(cookie)) {}

    virtual ~FileState() = default;


    auto* cookie() { return &_cookie; }


    auto& file() {
        assert(_cookie.file);
        return *_cookie.file;
    }






    void DebugMsg(const std::string& msg) { debug(msg); }

protected:

    void debug(const std::string& msg) override;

private:
    Cookie _cookie;
};


class FileAnalyzer : public file_analysis::Analyzer {
public:
    FileAnalyzer(RecordValPtr arg_args, file_analysis::File* arg_file);

    static file_analysis::Analyzer* InstantiateAnalyzer(RecordValPtr args, file_analysis::File* file);

protected:

    void Init() override;
    void Done() override;
    bool DeliverStream(const u_char* data, uint64_t len) override;
    bool Undelivered(uint64_t offset, uint64_t len) override;
    bool EndOfFile() override;









    bool Process(int len, const u_char* data);





    void Finish();


    void DebugMsg(const std::string& msg) { _state.DebugMsg(msg); }

private:
    FileState _state;
};

}
