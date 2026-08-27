










#include <binpac.h>

#include "zeek/Conn.h"
#include "zeek/RunState.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/conn_key/Manager.h"
#include "zeek/fuzzers/FuzzBuffer.h"
#include "zeek/fuzzers/fuzzer-setup.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"
#include "zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h"
#include "zeek/session/Manager.h"


#define VAL(str) #str
#define TOSTRING(str) VAL(str)

static const char* FUZZ_ANALYZER_NAME = TOSTRING(ZEEK_FUZZ_ANALYZER);
static const char* FUZZ_ANALYZER_TRANSPORT = TOSTRING(ZEEK_FUZZ_ANALYZER_TRANSPORT);

class Fuzzer {
public:
    Fuzzer(TransportProto proto, zeek::Tag analyzer_tag) : proto{proto}, analyzer_tag{std::move(analyzer_tag)} {}

    virtual ~Fuzzer() {};

    zeek::Connection* AddConnection() {
        static constexpr double network_time_start = 1439471031;
        zeek::run_state::detail::update_network_time(network_time_start);

        zeek::ConnKeyPtr ck = zeek::conn_key_mgr->GetFactory().NewConnKey();
        zeek::IPBasedConnKeyPtr key = zeek::IPBasedConnKeyPtr(static_cast<zeek::IPBasedConnKey*>(ck.release()));
        key->InitTuple(zeek::IPAddr("1.2.3.4"), htons(23132), zeek::IPAddr("5.6.7.8"), htons(80), proto, false);

        zeek::Packet p;
        zeek::Connection* conn = new zeek::Connection(std::move(key), network_time_start, 1, &p);
        conn->SetTransport(proto);
        zeek::session_mgr->Insert(conn);
        return conn;
    }

    std::tuple<zeek::analyzer::Analyzer*, zeek::packet_analysis::IP::SessionAdapter*, zeek::Connection*> Setup() {
        auto* conn = AddConnection();
        auto* analyzer = zeek::analyzer_mgr->InstantiateAnalyzer(analyzer_tag, conn);
        if ( ! analyzer ) {
            fprintf(stderr, "Unknown or unsupported analyzer %s\n", analyzer_tag.AsString().c_str());
            abort();
        }

        auto* adapter = BuildAnalyzerTree(conn, analyzer);

        return {analyzer, adapter, conn};
    }

    void Process(zeek::detail::FuzzBuffer& fb) {
        auto [analyzer, adapter, conn] = Setup();

        if ( new_connection )
            conn->Event(new_connection, nullptr);

        for ( ;; ) {
            auto chunk = fb.Next();

            if ( ! chunk )
                break;

            try {
                NextChunk(analyzer, *chunk);
            } catch ( const binpac::Exception& e ) {
            }

            chunk = {};
            zeek::event_mgr.Drain();


            if ( ! adapter->HasChildAnalyzer(analyzer_tag) )
                break;
        }
    }


    virtual zeek::packet_analysis::IP::SessionAdapter* BuildAnalyzerTree(zeek::Connection* conn,
                                                                         zeek::analyzer::Analyzer* analyzer) = 0;
    virtual void NextChunk(zeek::analyzer::Analyzer* analyzer, zeek::detail::FuzzBuffer::Chunk& chunk) = 0;

    void Cleanup() { zeek::detail::fuzzer_cleanup_one_input(); }


    static std::unique_ptr<Fuzzer> Create();

protected:
    TransportProto proto;
    zeek::Tag analyzer_tag;
};

class TCPFuzzer : public Fuzzer {
public:
    TCPFuzzer(const zeek::Tag& analyzer_tag) : Fuzzer(TRANSPORT_TCP, analyzer_tag) {}

    zeek::packet_analysis::IP::SessionAdapter* BuildAnalyzerTree(zeek::Connection* conn,
                                                                 zeek::analyzer::Analyzer* analyzer) override {
        auto* tcp = new zeek::packet_analysis::TCP::TCPSessionAdapter(conn);
        auto* pia = new zeek::analyzer::pia::PIA_TCP(conn);
        tcp->AddChildAnalyzer(analyzer);
        tcp->AddChildAnalyzer(pia->AsAnalyzer());
        conn->SetSessionAdapter(tcp, pia);
        return tcp;
    }

    void NextChunk(zeek::analyzer::Analyzer* analyzer, zeek::detail::FuzzBuffer::Chunk& chunk) override {
        analyzer->NextStream(chunk.size, chunk.data.get(), chunk.is_orig);
    }
};

class UDPFuzzer : public Fuzzer {
public:
    UDPFuzzer(const zeek::Tag& analyzer_tag) : Fuzzer(TRANSPORT_UDP, analyzer_tag) {}

    zeek::packet_analysis::IP::SessionAdapter* BuildAnalyzerTree(zeek::Connection* conn,
                                                                 zeek::analyzer::Analyzer* analyzer) override {
        auto* udp = new zeek::packet_analysis::UDP::UDPSessionAdapter(conn);
        auto* pia = new zeek::analyzer::pia::PIA_UDP(conn);
        udp->AddChildAnalyzer(analyzer);
        udp->AddChildAnalyzer(pia->AsAnalyzer());
        conn->SetSessionAdapter(udp, pia);
        return udp;
    }

    void NextChunk(zeek::analyzer::Analyzer* analyzer, zeek::detail::FuzzBuffer::Chunk& chunk) override {
        analyzer->NextPacket(chunk.size, chunk.data.get(), chunk.is_orig);
    }
};


std::unique_ptr<Fuzzer> Fuzzer::Create() {
    const auto& tag = zeek::analyzer_mgr->GetComponentTag(FUZZ_ANALYZER_NAME);
    if ( ! tag ) {
        std::fprintf(stderr, "Unable to find component tag for '%s'", FUZZ_ANALYZER_NAME);
        abort();
    }

    if ( strcmp(FUZZ_ANALYZER_TRANSPORT, "tcp") == 0 )
        return std::make_unique<TCPFuzzer>(tag);
    else if ( strcmp(FUZZ_ANALYZER_TRANSPORT, "udp") == 0 )
        return std::make_unique<UDPFuzzer>(tag);

    std::fprintf(stderr, "Unexpected FUZZ_ANALYZER_TRANSPORT '%s'", FUZZ_ANALYZER_TRANSPORT);
    abort();
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    zeek::detail::FuzzBuffer fb{data, size};

    if ( ! fb.Valid() )
        return 0;

    std::unique_ptr<Fuzzer> fuzzer = Fuzzer::Create();

    fuzzer->Process(fb);

    fuzzer->Cleanup();

    return 0;
}
