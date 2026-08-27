

#pragma once

#include <optional>
#include <string>
#include <utility>

#include <hilti/rt/types/stream.h>

#include <spicy/rt/driver.h>
#include <spicy/rt/parser.h>

#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/spicy/cookie.h"

namespace zeek::spicy::rt {







class EndpointState : public ::spicy::rt::driver::ParsingState {
public:







    EndpointState(Cookie cookie, ::spicy::rt::driver::ParsingType type)
        : ParsingState(type), _cookie(std::move(cookie)) {}


    auto& protocol() {
        assert(_cookie.protocol);
        return *_cookie.protocol;
    }


    auto* cookie() { return &_cookie; }






    void DebugMsg(const std::string& msg) { debug(msg); }

protected:

    void debug(const std::string& msg) override;

private:
    Cookie _cookie;
};


class ProtocolAnalyzer {
public:
    ProtocolAnalyzer(analyzer::Analyzer* analyzer, ::spicy::rt::driver::ParsingType type);
    virtual ~ProtocolAnalyzer() = default;


    auto& originator() { return _originator; }


    auto& responder() { return _responder; }

protected:

    void Init();


    void Done();





    void FlipRoles();








    void Process(bool is_orig, int len, const u_char* data);







    void Finish(bool is_orig);








    cookie::ProtocolAnalyzer& cookie(bool is_orig);





    void DebugMsg(bool is_orig, const std::string& msg);

private:
    EndpointState _originator;
    EndpointState _responder;
    hilti::rt::Optional<::spicy::rt::UnitContext> _context;
};





class TCP_Analyzer : public ProtocolAnalyzer, public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    TCP_Analyzer(Connection* conn);


    void Init() override;
    void Done() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndOfData(bool is_orig) override;
    void FlipRoles() override;


    void EndpointEOF(bool is_orig) override;
    void ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
                          bool gen_event) override;
    void ConnectionFinished(bool half_finished) override;
    void ConnectionReset() override;
    void PacketWithRST() override;

    static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn);
};





class UDP_Analyzer : public ProtocolAnalyzer, public analyzer::Analyzer {
public:
    UDP_Analyzer(Connection* conn);


    void Init() override;
    void Done() override;
    void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndOfData(bool is_orig) override;
    void FlipRoles() override;

    static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn);
};

}
