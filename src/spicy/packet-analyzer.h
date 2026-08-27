

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <hilti/rt/types/stream.h>

#include <spicy/rt/driver.h>
#include <spicy/rt/parser.h>

#include "zeek/spicy/cookie.h"

namespace zeek::spicy::rt {


class PacketState : public ::spicy::rt::driver::ParsingState {
public:





    PacketState(Cookie cookie) : ParsingState(::spicy::rt::driver::ParsingType::Block), _cookie(std::move(cookie)) {}

    virtual ~PacketState() = default;


    auto* cookie() { return &_cookie; }


    auto& packet() {
        assert(_cookie.packet);
        return *_cookie.packet;
    }






    void DebugMsg(const std::string& msg) { debug(msg); }

protected:

    void debug(const std::string& msg) override;

private:
    Cookie _cookie;
};


class PacketAnalyzer : public packet_analysis::Analyzer {
public:
    PacketAnalyzer(const std::string& name);
    ~PacketAnalyzer() override;


    void DebugMsg(const std::string& msg) { _state.DebugMsg(msg); }

    static packet_analysis::AnalyzerPtr Instantiate(std::string name) {
        name = util::canonify_name(name);
        return std::make_shared<PacketAnalyzer>(name);
    }

protected:

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

private:
    PacketState _state;
};

}
