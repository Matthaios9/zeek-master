








































































































#include "zeek/analyzer/protocol/dnp3/DNP3.h"

#include "zeek/Reporter.h"

constexpr unsigned int PSEUDO_LENGTH_INDEX = 2;
constexpr unsigned int PSEUDO_CONTROL_FIELD_INDEX = 3;
constexpr unsigned int PSEUDO_TRANSPORT_INDEX = 10;
constexpr unsigned int PSEUDO_APP_LAYER_INDEX = 11;
constexpr unsigned int PSEUDO_TRANSPORT_LEN = 1;
constexpr unsigned int PSEUDO_LINK_LAYER_LEN = 8;

namespace zeek::analyzer::dnp3 {
namespace detail {

bool DNP3_Base::crc_table_initialized = false;
unsigned int DNP3_Base::crc_table[256];

DNP3_Base::DNP3_Base(analyzer::Analyzer* arg_analyzer) {
    analyzer = arg_analyzer;
    interp = new binpac::DNP3::DNP3_Conn(analyzer);

    ClearEndpointState(true);
    ClearEndpointState(false);

    if ( ! crc_table_initialized )
        PrecomputeCRCTable();
}

DNP3_Base::~DNP3_Base() { delete interp; }

bool DNP3_Base::ProcessData(int len, const u_char* data, bool orig) {
    Endpoint* endp = orig ? &orig_state : &resp_state;

    while ( len ) {
        if ( endp->in_hdr ) {

            int res = AddToBuffer(endp, PSEUDO_APP_LAYER_INDEX, &data, &len);

            if ( res == 0 )
                return true;

            if ( res < 0 )
                return false;


            if ( endp->buffer[0] != 0x05 || endp->buffer[1] != 0x64 ) {
                analyzer->Weird("dnp3_header_lacks_magic");
                return false;
            }


            if ( ! CheckCRC(PSEUDO_LINK_LAYER_LEN, endp->buffer, endp->buffer + PSEUDO_LINK_LAYER_LEN, "header") ) {
                analyzer->AnalyzerViolation("broken_checksum");
                return false;
            }


            analyzer->AnalyzerConfirmation();



            if ( (endp->buffer[PSEUDO_LENGTH_INDEX] + 3) == static_cast<char>(PSEUDO_LINK_LAYER_LEN) ) {
                ClearEndpointState(orig);
                return true;
            }



            u_char ctrl = endp->buffer[PSEUDO_CONTROL_FIELD_INDEX];

            if ( orig != static_cast<bool>(ctrl & 0x80) )
                analyzer->Weird("dnp3_unexpected_flow_direction");


            endp->pkt_length = endp->buffer[PSEUDO_LENGTH_INDEX];
            endp->tpflags = endp->buffer[PSEUDO_TRANSPORT_INDEX];
            endp->in_hdr = false;



            if ( ++endp->pkt_cnt == 1 )
                interp->NewData(orig, endp->buffer, endp->buffer + PSEUDO_LINK_LAYER_LEN);
        }

        if ( ! endp->in_hdr ) {
            if ( endp->pkt_length <= 0 ) {
                analyzer->Weird("dnp3_negative_or_zero_length_link_layer");
                return false;
            }







            int n = PSEUDO_APP_LAYER_INDEX + (endp->pkt_length - 5) + ((endp->pkt_length - 5) / 16) * 2 +
                    2 * (((endp->pkt_length - 5) % 16 == 0) ? 0 : 1) - 1;

            int res = AddToBuffer(endp, n, &data, &len);

            if ( res == 0 )
                return true;

            if ( res < 0 )
                return false;


            if ( ! ParseAppLayer(endp) )
                return false;


            endp->buffer_len = 0;
            endp->in_hdr = true;
        }
    }

    return true;
}

int DNP3_Base::AddToBuffer(Endpoint* endp, int target_len, const u_char** data, int* len) {
    if ( ! target_len )
        return 1;

    if ( *len < 0 ) {
        reporter->AnalyzerError(analyzer, "dnp3 negative input length: %d", *len);
        return -1;
    }

    if ( target_len < endp->buffer_len ) {
        reporter->AnalyzerError(analyzer, "dnp3 invalid target length: %d - %d", target_len, endp->buffer_len);
        return -1;
    }

    int to_copy = min(*len, target_len - endp->buffer_len);

    if ( endp->buffer_len + to_copy > MAX_BUFFER_SIZE ) {
        reporter->AnalyzerError(analyzer, "dnp3 buffer length exceeded: %d + %d", endp->buffer_len, to_copy);
        return -1;
    }

    memcpy(endp->buffer + endp->buffer_len, *data, to_copy);
    *data += to_copy;
    *len -= to_copy;
    endp->buffer_len += to_copy;

    if ( endp->buffer_len == target_len )
        return 1;

    return 0;
}

bool DNP3_Base::ParseAppLayer(Endpoint* endp) {
    bool orig = (endp == &orig_state);
    binpac::DNP3::DNP3_Flow* flow = orig ? interp->upflow() : interp->downflow();

    u_char* data = endp->buffer + PSEUDO_TRANSPORT_INDEX;
    int len = endp->pkt_length - 5;







    int is_first = (endp->tpflags & 0x40) >> 6;
    int is_last = (endp->tpflags & 0x80) >> 7;

    int transport = PSEUDO_TRANSPORT_LEN;

    int i = 0;
    while ( len > 0 ) {
        int n = min(len, 16);


        if ( ! CheckCRC(n, data, data + n, "app_chunk") )
            return false;

        if ( data + n >= endp->buffer + endp->buffer_len ) {
            reporter->AnalyzerError(analyzer, "dnp3 app layer parsing overflow %d - %d", endp->buffer_len, n);
            return false;
        }


        flow->flow_buffer()->BufferData(data + transport, data + n);
        transport = 0;

        data += n + 2;
        len -= n;
    }

    if ( is_first )
        endp->encountered_first_chunk = true;

    if ( ! is_first && ! endp->encountered_first_chunk ) {

        analyzer->Weird("dnp3_first_application_layer_chunk_missing");
        return false;
    }

    if ( is_last ) {
        flow->flow_buffer()->FinishBuffer();
        flow->FlowEOF();
        ClearEndpointState(orig);
    }

    return true;
}

void DNP3_Base::ClearEndpointState(bool orig) {
    Endpoint* endp = orig ? &orig_state : &resp_state;
    binpac::DNP3::DNP3_Flow* flow = orig ? interp->upflow() : interp->downflow();

    endp->in_hdr = true;
    endp->encountered_first_chunk = false;
    endp->buffer_len = 0;
    endp->pkt_length = 0;
    endp->tpflags = 0;
    endp->pkt_cnt = 0;
}

void DNP3_Base::DiscardFlowBuffer(bool orig) {
    auto* flow = orig ? Interpreter()->upflow() : Interpreter()->downflow();
    flow->flow_buffer()->DiscardData();
}

bool DNP3_Base::CheckCRC(int len, const u_char* data, const u_char* crc16, const char* where) {
    unsigned int crc = CalcCRC(len, data);

    if ( crc16[0] == (crc & 0xff) && crc16[1] == (crc & 0xff00) >> 8 )
        return true;

    analyzer->Weird(util::fmt("dnp3_corrupt_%s_checksum", where));
    return false;
}

void DNP3_Base::PrecomputeCRCTable() {
    for ( unsigned int i = 0; i < 256; i++ ) {
        unsigned int crc = i;

        for ( unsigned int j = 0; j < 8; ++j ) {
            if ( crc & 0x0001 )
                crc = (crc >> 1) ^ 0xA6BC;
            else
                crc >>= 1;
        }

        crc_table[i] = crc;
    }
}

unsigned int DNP3_Base::CalcCRC(int len, const u_char* data) {
    unsigned int crc = 0x0000;

    for ( int i = 0; i < len; i++ ) {
        unsigned int index = (crc ^ data[i]) & 0xFF;
        crc = crc_table[index] ^ (crc >> 8);
    }

    return ~crc & 0xFFFF;
}

}
DNP3_TCP_Analyzer::DNP3_TCP_Analyzer(Connection* c) : DNP3_Base(this), TCP_ApplicationAnalyzer("DNP3_TCP", c) {}

void DNP3_TCP_Analyzer::Done() {
    TCP_ApplicationAnalyzer::Done();

    Interpreter()->FlowEOF(true);
    Interpreter()->FlowEOF(false);
}

void DNP3_TCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

    try {
        if ( ! ProcessData(len, data, orig) )
            SetSkip(true);
    }

    catch ( const binpac::Exception& e ) {
        DiscardFlowBuffer(orig);
        SetSkip(true);
        throw;
    }
}

void DNP3_TCP_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    Interpreter()->NewGap(orig, len);
}

void DNP3_TCP_Analyzer::EndpointEOF(bool is_orig) {
    TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    Interpreter()->FlowEOF(is_orig);
}

DNP3_UDP_Analyzer::DNP3_UDP_Analyzer(Connection* c) : DNP3_Base(this), Analyzer("DNP3_UDP", c) {}

void DNP3_UDP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip,
                                      int caplen) {
    Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

    try {
        if ( ! ProcessData(len, data, orig) )
            SetSkip(true);
    }

    catch ( const binpac::Exception& e ) {
        DiscardFlowBuffer(orig);
        SetSkip(true);
        throw;
    }
}

}
