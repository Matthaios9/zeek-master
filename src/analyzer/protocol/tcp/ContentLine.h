



#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::tcp {

constexpr int CR_as_EOL = 1;
constexpr int LF_as_EOL = 2;


constexpr auto DEFAULT_MAX_LINE_LENGTH = 16 * 1024 * 1024 - 100;

class ContentLine_Analyzer : public TCP_SupportAnalyzer {
public:
    ContentLine_Analyzer(Connection* conn, bool orig, int max_line_length = DEFAULT_MAX_LINE_LENGTH);
    ~ContentLine_Analyzer() override;

    void SuppressWeirds(bool enable) { suppress_weirds = enable; };


    void SetIsNULSensitive(bool enable) { flag_NULs = enable; }


    bool SkipPartial() const { return skip_partial; }


    void SetSkipPartial(bool enable) { skip_partial = enable; }


    void SetCRLFAsEOL(int crlf = (CR_as_EOL | LF_as_EOL)) { CR_LF_as_EOL = crlf; }

    int CRLFAsEOL() { return CR_LF_as_EOL; }

    bool HasPartialLine() const;

    bool SkipDeliveries() const { return skip_deliveries; }

    void SetSkipDeliveries(bool should_skip) { skip_deliveries = should_skip; }







    void SetPlainDelivery(int64_t length);
    void SetDeliverySize(int64_t length);
    int64_t GetPlainDeliveryLength() const { return plain_delivery_length; }
    bool IsPlainDelivery() { return is_plain; }




    int GetDeliverStreamRemainingLength() const { return deliver_stream_remaining_length; }



    void SkipBytesAfterThisLine(int64_t length);
    void SkipBytes(int64_t length);

    bool IsSkippedContents(uint64_t seq, int64_t length) { return seq + length <= seq_to_skip; }

protected:
    ContentLine_Analyzer(const char* name, Connection* conn, bool orig, int max_line_length = DEFAULT_MAX_LINE_LENGTH);

    void DeliverStream(int len, const u_char* data, bool is_orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndpointEOF(bool is_orig) override;

    class State;
    void InitState();
    void InitBuffer(int size);


    bool InitBufferSafe(int size);
    virtual void DoDeliver(int len, const u_char* data);
    int DoDeliverOnce(int len, const u_char* data);
    void CheckNUL();


    uint64_t SeqDelivered() const { return seq_delivered_in_lines; }

    u_char* buf;
    int offset;
    int buf_len;
    unsigned int last_char;
    int max_line_length;

    uint64_t seq;
    uint64_t seq_to_skip;



    uint64_t seq_delivered_in_lines;



    int64_t skip_pending;


    int64_t plain_delivery_length;

    int64_t delivery_length;
    bool is_plain;


    bool skip_deliveries;

    bool suppress_weirds;


    bool flag_NULs;


    uint8_t CR_LF_as_EOL : 2;


    bool skip_partial;

    int deliver_stream_remaining_length;
};

}
