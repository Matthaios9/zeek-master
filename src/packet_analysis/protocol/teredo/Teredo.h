

#pragma once

#include <map>

#include "zeek/Conn.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/session/Key.h"

namespace zeek::packet_analysis::teredo {

class TeredoAnalyzer final : public packet_analysis::Analyzer {
public:
    TeredoAnalyzer();

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<TeredoAnalyzer>(); }








    void Weird(Connection* conn, const char* name, bool force = false) const {
        if ( AnalyzerConfirmed(conn) || force )
            reporter->Weird(conn, name, "", GetAnalyzerName());
    }





    void Confirm(Connection* conn, bool valid_orig, bool valid_resp) {
        if ( ! BifConst::Tunnel::delay_teredo_confirmation || (valid_orig && valid_resp) ) {
            AnalyzerConfirmation(conn);
        }
    }

    bool DetectProtocol(size_t len, const uint8_t* data, Packet* packet) override;

    void RemoveConnection(const zeek::session::detail::Key& conn_key) { orig_resp_map.erase(conn_key); }

protected:
    struct OrigResp {
        bool valid_orig = false;
        bool valid_resp = false;
        bool confirmed = false;
    };
    using OrigRespMap = std::map<zeek::session::detail::Key, OrigResp>;
    OrigRespMap orig_resp_map;

    std::unique_ptr<zeek::detail::Specific_RE_Matcher> pattern_re;
};

namespace detail {

class TeredoEncapsulation {
public:
    TeredoEncapsulation(const TeredoAnalyzer* ta, Connection* conn) : analyzer(ta), conn(conn) {}





    bool Parse(const u_char* data, size_t& len) { return DoParse(data, len, false, false); }

    const u_char* InnerIP() const { return inner_ip; }

    const u_char* OriginIndication() const { return origin_indication; }

    const u_char* Authentication() const { return auth; }

    RecordValPtr BuildVal(const std::shared_ptr<IP_Hdr>& inner) const;

private:
    bool DoParse(const u_char* data, size_t& len, bool found_orig, bool found_au);

    void Weird(const char* name) const { analyzer->Weird(conn, name); }

    const u_char* inner_ip = nullptr;
    const u_char* origin_indication = nullptr;
    const u_char* auth = nullptr;
    const TeredoAnalyzer* analyzer = nullptr;
    Connection* conn = nullptr;
};

}

}
