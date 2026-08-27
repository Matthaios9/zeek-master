

#include "zeek/analyzer/protocol/tcp/ContentLine.h"

#include "zeek/Reporter.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::tcp {

ContentLine_Analyzer::ContentLine_Analyzer(Connection* conn, bool orig, int max_line_length)
    : TCP_SupportAnalyzer("CONTENTLINE", conn, orig), max_line_length(max_line_length) {
    InitState();
}

ContentLine_Analyzer::ContentLine_Analyzer(const char* name, Connection* conn, bool orig, int max_line_length)
    : TCP_SupportAnalyzer(name, conn, orig), max_line_length(max_line_length) {
    InitState();
}

void ContentLine_Analyzer::InitState() {
    flag_NULs = false;
    CR_LF_as_EOL = (CR_as_EOL | LF_as_EOL);
    skip_deliveries = false;
    skip_partial = false;
    buf = nullptr;
    seq_delivered_in_lines = 0;
    skip_pending = 0;
    seq = 0;
    seq_to_skip = 0;
    plain_delivery_length = 0;
    delivery_length = -1;
    is_plain = false;
    suppress_weirds = false;
    deliver_stream_remaining_length = 0;

    InitBuffer(0);
}

void ContentLine_Analyzer::InitBuffer(int size) {
    if ( buf && buf_len >= size )


        return;

    if ( size < 128 )
        size = 128;

    u_char* b = new u_char[size];

    if ( buf ) {
        if ( offset > 0 )
            memcpy(b, buf, offset);
        delete[] buf;
    }
    else {
        offset = 0;
        last_char = 0;
    }

    buf = b;
    buf_len = size;
}

bool ContentLine_Analyzer::InitBufferSafe(int size) {
    if ( buf_len >= max_line_length )
        return false;

    InitBuffer(std::min(size, max_line_length));

    return true;
}

ContentLine_Analyzer::~ContentLine_Analyzer() { delete[] buf; }

bool ContentLine_Analyzer::HasPartialLine() const { return buf && offset > 0; }

void ContentLine_Analyzer::DeliverStream(int len, const u_char* data, bool is_orig) {
    TCP_SupportAnalyzer::DeliverStream(len, data, is_orig);

    if ( len <= 0 || SkipDeliveries() )
        return;

    if ( skip_partial ) {
        auto* tcp = static_cast<TCP_ApplicationAnalyzer*>(Parent())->TCP();

        if ( tcp && tcp->IsPartial() )
            return;
    }

    if ( delivery_length > 0 )
        delivery_length -= len;

    DoDeliver(len, data);



    if ( delivery_length == 0 ) {
        if ( HasPartialLine() ) {
            Weird("line_terminated_without_CRLF");
            DoDeliver(2, reinterpret_cast<const u_char*>("\r\n"));
        }
        delivery_length = -1;
    }

    seq += len;
}

void ContentLine_Analyzer::Undelivered(uint64_t seq, int len, bool orig) { ForwardUndelivered(seq, len, orig); }

void ContentLine_Analyzer::EndpointEOF(bool is_orig) {
    if ( offset > 0 )
        DeliverStream(1, reinterpret_cast<const u_char*>("\n"), is_orig);
}

void ContentLine_Analyzer::SetPlainDelivery(int64_t length) {
    if ( length < 0 ) {
        reporter->AnalyzerError(this, "negative length for plain delivery");
        return;
    }

    plain_delivery_length = length;
}

void ContentLine_Analyzer::SetDeliverySize(int64_t length) {

    if ( length < -1 ) {
        reporter->AnalyzerError(this, "negative length for delivery size");
        return;
    }

    delivery_length = length;
}

void ContentLine_Analyzer::DoDeliver(int len, const u_char* data) {
    seq_delivered_in_lines = seq;

    while ( len > 0 && ! SkipDeliveries() ) {
        if ( (CR_LF_as_EOL & CR_as_EOL) && last_char == '\r' && *data == '\n' ) {










            last_char = *data;
            --len;
            ++data;
            ++seq;
            ++seq_delivered_in_lines;
        }

        if ( plain_delivery_length > 0 ) {
            auto deliver_plain = static_cast<int>(std::min<int64_t>(plain_delivery_length, len));

            last_char = 0;
            plain_delivery_length -= deliver_plain;
            is_plain = true;

            deliver_stream_remaining_length = len - deliver_plain;
            ForwardStream(deliver_plain, data, IsOrig());

            is_plain = false;

            data += deliver_plain;
            len -= deliver_plain;
            if ( len == 0 )
                return;
        }

        if ( skip_pending > 0 )
            SkipBytes(skip_pending);




        if ( seq < seq_to_skip ) {

            int64_t skip_len = seq_to_skip - seq;
            if ( skip_len > len )
                skip_len = len;

            ForwardUndelivered(seq, skip_len, IsOrig());

            len -= skip_len;
            data += skip_len;
            seq += skip_len;
            seq_delivered_in_lines += skip_len;
        }

        if ( len <= 0 )
            break;

        int n = DoDeliverOnce(len, data);
        len -= n;
        data += n;
        seq += n;
    }
}

int ContentLine_Analyzer::DoDeliverOnce(int len, const u_char* data) {
    const u_char* data_start = data;

    if ( len <= 0 )
        return 0;

    for ( ; len > 0; --len, ++data ) {
#define EMIT_LINE                                                                                                      \
    {                                                                                                                  \
        buf[offset] = '\0';                                                                                            \
        int seq_len = data + 1 - data_start;                                                                           \
        seq_delivered_in_lines = seq + seq_len;                                                                        \
        last_char = c;                                                                                                 \
        deliver_stream_remaining_length = len - 1;                                                                     \
        ForwardStream(offset, buf, IsOrig());                                                                          \
        offset = 0;                                                                                                    \
        return seq_len;                                                                                                \
    }

        int c = data[0];

        if ( offset >= buf_len ) {
            if ( ! InitBufferSafe(buf_len * 2) ) {
                Weird("contentline_size_exceeded");
                offset = buf_len - 1;
                EMIT_LINE
            }
        }

        switch ( c ) {
            case '\r':

                if ( len > 1 && data[1] == '\n' ) {
                    --len;
                    ++data;
                    last_char = c;
                    c = data[0];
                    EMIT_LINE
                }

                else if ( CR_LF_as_EOL & CR_as_EOL )
                    EMIT_LINE

                else
                    buf[offset++] = c;
                break;

            case '\n':
                if ( last_char == '\r' ) {





                    if ( offset == 0 ) {
                        last_char = c;
                        break;
                    }
                    --offset;
                    EMIT_LINE
                }

                else if ( CR_LF_as_EOL & LF_as_EOL )
                    EMIT_LINE

                else {
                    if ( ! suppress_weirds && Conn()->FlagEvent(SINGULAR_LF) )
                        Weird("line_terminated_with_single_LF");
                    buf[offset++] = c;
                }
                break;

            case '\0':
                if ( flag_NULs )
                    CheckNUL();
                else
                    buf[offset++] = c;
                break;

            default: buf[offset++] = c; break;
        }

        if ( last_char == '\r' )
            if ( ! suppress_weirds && Conn()->FlagEvent(SINGULAR_CR) )
                Weird("line_terminated_with_single_CR");

        last_char = c;
    }

    return data - data_start;
}

void ContentLine_Analyzer::CheckNUL() {








    if ( auto* tcp = static_cast<TCP_ApplicationAnalyzer*>(Parent())->TCP() ) {
        TCP_Endpoint* endp = IsOrig() ? tcp->Orig() : tcp->Resp();
        if ( endp->state == TCP_ENDPOINT_PARTIAL && endp->LastSeq() - endp->StartSeq() <= 2 )
            ;
        else {
            if ( ! suppress_weirds && Conn()->FlagEvent(NUL_IN_LINE) )
                Weird("NUL_in_line");
            flag_NULs = false;
        }
    }
}

void ContentLine_Analyzer::SkipBytesAfterThisLine(int64_t length) {








    if ( last_char == '\r' )
        skip_pending = length;
    else
        SkipBytes(length);
}

void ContentLine_Analyzer::SkipBytes(int64_t length) {
    skip_pending = 0;
    seq_to_skip = SeqDelivered() + length;
}

}
