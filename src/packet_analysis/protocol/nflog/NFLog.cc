

#include "zeek/packet_analysis/protocol/nflog/NFLog.h"

using namespace zeek::packet_analysis::NFLog;

NFLogAnalyzer::NFLogAnalyzer() : zeek::packet_analysis::Analyzer("NFLog") {}

bool NFLogAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( 4 >= len ) {
        Weird("truncated_nflog_header", packet);
        return false;
    }


    uint32_t protocol = data[0];
    uint8_t version = data[1];

    if ( version != 0 ) {
        Weird("unknown_nflog_version", packet);
        return false;
    }


    data += 4;
    len -= 4;

    uint16_t tlv_len;
    uint16_t tlv_type;

    while ( true ) {
        if ( 4 >= len ) {
            Weird("nflog_no_pcap_payload", packet);
            return false;
        }




        tlv_len = *(reinterpret_cast<const uint16_t*>(data));
        tlv_type = *(reinterpret_cast<const uint16_t*>(data + 2));

        auto constexpr nflog_type_payload = 9;

        if ( tlv_type == nflog_type_payload ) {

            data += 4;
            len -= 4;
            break;
        }
        else {





            if ( tlv_len < 4 ) {
                Weird("nflog_bad_tlv_len", packet);
                return false;
            }





            size_t tlv_skip = tlv_len;
            auto rem = tlv_skip % 4;

            if ( rem != 0 )
                tlv_skip += 4 - rem;

            if ( tlv_skip > len ) {
                Weird("nflog_bad_tlv_len", packet, util::fmt("(%zu > %zu)", tlv_skip, len));
                return false;
            }

            data += tlv_skip;
            len -= tlv_skip;
        }
    }

    return ForwardPacket(len, data, packet, protocol);
}
