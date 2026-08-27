



#pragma once

#include "zeek/RuleMatcher.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::detail {
class RuleEndpointState;
}

namespace zeek::analyzer::pia {








class PIA : public zeek::detail::RuleMatcherState {
public:
    explicit PIA(analyzer::Analyzer* as_analyzer);
    ~PIA() override;



    virtual void ActivateAnalyzer(zeek::Tag tag, const zeek::detail::Rule* rule = nullptr) = 0;


    virtual void DeactivateAnalyzer(zeek::Tag tag) = 0;

    void Match(zeek::detail::Rule::PatternType type, const u_char* data, int len, bool is_orig, bool bol, bool eol,
               bool clear_state) override;

    void ReplayPacketBuffer(analyzer::Analyzer* analyzer);











    void FirstPacket(bool is_orig, const IP_Hdr* ip);













    void FirstPacket(bool is_orig, TransportProto proto);



    analyzer::Analyzer* AsAnalyzer() { return as_analyzer; }

protected:
    void PIA_Done();
    void PIA_DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen,
                           bool clear_state);

    enum State : uint8_t { INIT, BUFFERING, MATCHING_ONLY, SKIPPING };
    State state = INIT;



    struct DataBlock {
        IP_Hdr* ip = nullptr;
        const u_char* data = nullptr;
        bool is_orig = false;
        size_t len = 0;
        size_t cap_len = 0;
        uint64_t seq = 0;
        DataBlock* next = nullptr;
    };

    struct Buffer {
        DataBlock* head = nullptr;
        DataBlock* tail = nullptr;
        int64_t size = 0;
        int64_t chunks = 0;
        State state = INIT;
    };

    void AddToBuffer(Buffer* buffer, uint64_t seq, int len, const u_char* data, bool is_orig,
                     const IP_Hdr* ip = nullptr);
    void AddToBuffer(Buffer* buffer, int len, const u_char* data, bool is_orig, const IP_Hdr* ip = nullptr);
    void ClearBuffer(Buffer* buffer);

    DataBlock* CurrentPacket() { return &current_packet; }

    void DoMatch(const u_char* data, int len, bool is_orig, bool bol, bool eol, bool clear_state,
                 const IP_Hdr* ip = nullptr);

    auto Conn() const { return conn; }
    void SetConn(Connection* c) { conn = c; }

    Buffer pkt_buffer;

private:

    void FirstPacket(bool is_orig, const std::optional<TransportProto>& proto, const IP_Hdr* ip);

    analyzer::Analyzer* as_analyzer = nullptr;
    Connection* conn = nullptr;
    DataBlock current_packet;
};


class PIA_UDP : public PIA, public analyzer::Analyzer {
public:
    explicit PIA_UDP(Connection* conn) : PIA(this), Analyzer("PIA_UDP", conn) { SetConn(conn); }

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new PIA_UDP(conn); }

protected:
    void Done() override {
        Analyzer::Done();
        PIA_Done();
    }

    void DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen) override {
        Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);
        PIA_DeliverPacket(len, data, is_orig, seq, ip, caplen, true);
    }

    void ActivateAnalyzer(zeek::Tag tag, const zeek::detail::Rule* rule) override;
    void DeactivateAnalyzer(zeek::Tag tag) override;
};



class PIA_TCP : public PIA, public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit PIA_TCP(Connection* conn) : PIA(this), analyzer::tcp::TCP_ApplicationAnalyzer("PIA_TCP", conn) {
        stream_mode = false;
        SetConn(conn);
    }

    ~PIA_TCP() override;

    void Init() override;

    void ReplayStreamBuffer(analyzer::Analyzer* analyzer);

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new PIA_TCP(conn); }

protected:
    void Done() override {
        Analyzer::Done();
        PIA_Done();
    }

    void DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen) override {
        TCP_ApplicationAnalyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);
        PIA_DeliverPacket(len, data, is_orig, seq, ip, caplen, false);
    }

    void DeliverStream(int len, const u_char* data, bool is_orig) override;
    void Undelivered(uint64_t seq, int len, bool is_orig) override;

    void ActivateAnalyzer(zeek::Tag tag, const zeek::detail::Rule* rule = nullptr) override;
    void DeactivateAnalyzer(zeek::Tag tag) override;

private:


    Buffer stream_buffer;

    bool stream_mode;
};

}
