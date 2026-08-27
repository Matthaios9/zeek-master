

#include "zeek/packet_analysis/protocol/ieee802_11/IEEE802_11.h"

using namespace zeek::packet_analysis::IEEE802_11;

IEEE802_11Analyzer::IEEE802_11Analyzer() : zeek::packet_analysis::Analyzer("IEEE802_11") {}

bool IEEE802_11Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    u_char len_80211 = 24;

    if ( len_80211 >= len ) {
        Weird("truncated_802_11_header", packet);
        return false;
    }

    u_char fc_80211 = data[0];
    bool is_amsdu = false;


    if ( ! ((fc_80211 >> 2) & 0x02) )
        return false;


    if ( (fc_80211 >> 4) & 0x04 )
        return false;


    if ( (data[1] & 0x03) == 0x03 )
        len_80211 += packet->L2_ADDR_LEN;

    if ( len_80211 >= len ) {
        Weird("truncated_802_11_header", packet);
        return false;
    }


    if ( (fc_80211 >> 4) & 0x08 ) {


        is_amsdu = (data[len_80211] & 0x80) == 0x80;



        if ( data[1] & 0x40 )
            return true;

        len_80211 += 2;
    }

    if ( len_80211 >= len ) {
        Weird("truncated_802_11_header", packet);
        return false;
    }


    switch ( data[1] & 0x03 ) {
        case 0x00:
            packet->l2_src = data + 10;
            packet->l2_dst = data + 4;
            break;

        case 0x01:
            packet->l2_src = data + 10;
            packet->l2_dst = data + 16;
            break;

        case 0x02:
            packet->l2_src = data + 16;
            packet->l2_dst = data + 4;
            break;

        case 0x03:
            packet->l2_src = data + 24;
            packet->l2_dst = data + 16;
            break;
    }


    data += len_80211;
    len -= len_80211;

    if ( ! is_amsdu ) {
        return HandleInnerPacket(len, data, packet);
    }
    else {
        size_t amsdu_padding = 0;
        size_t encap_index = packet->encap ? packet->encap->Depth() : 0;

        while ( len > 0 ) {
            if ( len < 14 ) {
                Weird("truncated_802_11_amsdu_header", packet);
                return false;
            }


            size_t amsdu_len = (data[12] << 8) + data[13];
            if ( len < amsdu_len + 14 ) {
                Weird("truncated_802_11_amsdu_packet", packet);
                return false;
            }


            data += 14;
            len -= 14;

            if ( ! HandleInnerPacket(amsdu_len, data, packet) ) {
                Weird("invalid_802_11_amsdu_inner_packet", packet);
                return false;
            }

            data += amsdu_len;
            len -= amsdu_len;





            amsdu_padding = amsdu_len % 4;
            if ( len >= amsdu_padding ) {
                data += amsdu_padding;
                len -= amsdu_padding;
            }



            if ( packet->encap ) {
                while ( packet->encap->Depth() > encap_index )
                    packet->encap->Pop();
            }
        }

        return true;
    }
}

bool IEEE802_11Analyzer::HandleInnerPacket(size_t len, const uint8_t* data, Packet* packet) const {

    if ( len < 8 ) {
        Weird("truncated_802_11_llc_header", packet);
        return false;
    }




    if ( data[0] == 0xAA && data[1] == 0xAA && data[2] == 0x03 && data[3] == 0 && data[4] == 0 && data[5] == 0 ) {
        data += 6;
        len -= 6;
    }
    else {


        return false;
    }


    uint32_t protocol = (data[0] << 8) + data[1];
    data += 2;
    len -= 2;

    return ForwardPacket(len, data, packet, protocol);
}
