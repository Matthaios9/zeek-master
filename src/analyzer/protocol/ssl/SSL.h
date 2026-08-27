

#pragma once

#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace binpac {
namespace SSL {
class SSL_Conn;
}
}

namespace binpac {
namespace TLSHandshake {
class Handshake_Conn;
}
}

namespace zeek::analyzer::ssl {

class SSL_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {

    friend class binpac::SSL::SSL_Conn;

public:
    explicit SSL_Analyzer(Connection* conn);
    ~SSL_Analyzer() override;


    void Done() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;

    void SendHandshake(uint16_t raw_tls_version, const u_char* begin, const u_char* end, bool orig);


    void StartEncryption();

    uint16_t GetNegotiatedVersion() const;


    void EndpointEOF(bool is_orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new SSL_Analyzer(conn); }










    void SetSecret(const StringVal& secret);












    void SetSecret(size_t len, const u_char* data);











    void SetKeys(const StringVal& keys);











    void SetKeys(std::vector<u_char> newkeys);







    bool GetFlipped();

protected:


















    bool TryDecryptApplicationData(int len, const u_char* data, bool is_orig, uint8_t content_type,
                                   uint16_t raw_tls_version);






















    std::optional<std::vector<u_char>> TLS12_PRF(const std::string& secret, const std::string& label,
                                                 const std::string& rnd1, const std::string& rnd2,
                                                 size_t requested_len);








    void ForwardDecryptedData(const std::vector<u_char>& data, bool is_orig);

    binpac::SSL::SSL_Conn* interp;
    binpac::TLSHandshake::Handshake_Conn* handshake_interp;
    bool had_gap;


    int c_seq;
    int s_seq;

    std::string secret;

    std::vector<u_char> keys;

    zeek::analyzer::pia::PIA_TCP* pia;
};

}
