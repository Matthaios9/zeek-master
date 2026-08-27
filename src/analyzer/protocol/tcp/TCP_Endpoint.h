

#pragma once

#include "zeek/File.h"
#include "zeek/IPAddr.h"

namespace zeek {

class Connection;
class IP_Hdr;

namespace packet_analysis::TCP {
class TCPSessionAdapter;
}

namespace analyzer::tcp {

class TCP_Reassembler;

enum EndpointState : uint8_t {
    TCP_ENDPOINT_INACTIVE,
    TCP_ENDPOINT_SYN_SENT,
    TCP_ENDPOINT_SYN_ACK_SENT,
    TCP_ENDPOINT_PARTIAL,
    TCP_ENDPOINT_ESTABLISHED,

    TCP_ENDPOINT_CLOSED,
    TCP_ENDPOINT_RESET
};


class TCP_Endpoint {
public:
    TCP_Endpoint(packet_analysis::TCP::TCPSessionAdapter* analyzer, bool is_orig);
    ~TCP_Endpoint();

    void Done();

    packet_analysis::TCP::TCPSessionAdapter* TCP() { return tcp_analyzer; }

    void SetPeer(TCP_Endpoint* p);

    EndpointState State() const { return state; }
    void SetState(EndpointState new_state);
    uint64_t Size() const;
    bool IsActive() const { return state != TCP_ENDPOINT_INACTIVE && ! did_close; }

    double StartTime() const { return start_time; }
    double LastTime() const { return last_time; }




    uint32_t StartSeq() const { return static_cast<uint32_t>(start_seq); }






    int64_t StartSeqI64() const { return start_seq; }





    uint32_t LastSeq() const { return last_seq; }




    uint32_t AckSeq() const { return ack_seq; }





    uint32_t SeqWraps() const { return seq_wraps; }





    uint32_t AckWraps() const { return ack_wraps; }






    static uint64_t ToFullSeqSpace(uint32_t wraps) { return (static_cast<uint64_t>(wraps) << 32); }







    static uint64_t ToFullSeqSpace(uint32_t tcp_seq_num, uint32_t wraparounds) {
        return ToFullSeqSpace(wraparounds) + tcp_seq_num;
    }








    uint64_t ToRelativeSeqSpace(uint32_t tcp_seq_num, uint32_t wraparounds) const {
        return ToFullSeqSpace(tcp_seq_num, wraparounds) - StartSeqI64();
    }

    void InitStartSeq(int64_t seq) { start_seq = seq; }
    void InitLastSeq(uint32_t seq) { last_seq = seq; }
    void InitAckSeq(uint32_t seq) { ack_seq = seq; }

    void UpdateLastSeq(uint32_t seq) {
        if ( seq < last_seq )
            ++seq_wraps;

        last_seq = seq;
    }

    void UpdateAckSeq(uint32_t seq) {
        if ( seq < ack_seq )
            ++ack_wraps;

        ack_seq = seq;
    }




    bool NoDataAcked() const {
        uint64_t ack = ToFullSeqSpace(ack_seq, ack_wraps);
        uint64_t start = static_cast<uint64_t>(StartSeqI64());
        return ack == start || ack == start + 1;
    }

    Connection* Conn() const;

    bool HasContents() const { return contents_processor != nullptr; }
    bool HadGap() const;

    inline bool IsOrig() const { return is_orig; }

    bool HasDoneSomething() const { return last_time != 0.0; }

    void AddReassembler(TCP_Reassembler* contents_processor);

    bool DataPending() const;
    bool HasUndeliveredData() const;
    void CheckEOF();











    void SizeBufferedData(uint64_t& waiting_on_hole, uint64_t& waiting_on_ack);

    bool ValidChecksum(const struct tcphdr* tp, int len, bool ipv4) const;


    void ChecksumError();


    void DidRxmit();


    void ZeroWindow();


    void Gap(uint64_t seq, uint64_t len);



    bool DataSent(double t, uint64_t seq, int len, int caplen, const u_char* data, const IP_Hdr* ip,
                  const struct tcphdr* tp);

    void AckReceived(uint64_t seq);

    void SetContentsFile(FilePtr f);
    const FilePtr& GetContentsFile() const { return contents_file; }




    enum HistoryMasks : uint16_t {
        HIST_SYN_PKT = 0x1,
        HIST_FIN_PKT = 0x2,
        HIST_RST_PKT = 0x4,
        HIST_FIN_RST_PKT = 0x8,
        HIST_DATA_PKT = 0x10,
        HIST_ACK_PKT = 0x20,
        HIST_MULTI_FLAG_PKT = 0x40,
        HIST_CORRUPT_PKT = 0x80,
        HIST_RXMIT = 0x100,
        HIST_WIN0 = 0x200,
    };


    bool CheckHistory(uint32_t mask, char code);
    void AddHistory(char code);


    EndpointState state, prev_state;
    TCP_Endpoint* peer;
    TCP_Reassembler* contents_processor;
    packet_analysis::TCP::TCPSessionAdapter* tcp_analyzer;
    FilePtr contents_file;

    double start_time, last_time;
    IPAddr src_addr;
    IPAddr dst_addr;
    uint32_t window;
    int window_scale;
    uint32_t window_ack_seq;
    uint32_t window_seq;
    uint64_t contents_start_seq;
    uint64_t FIN_seq;
    int SYN_cnt, FIN_cnt, RST_cnt;
    bool did_close;
    bool is_orig;




    uint64_t hist_last_SYN, hist_last_FIN, hist_last_RST;

protected:
    int64_t start_seq;



    uint32_t last_seq, ack_seq;
    uint32_t seq_wraps, ack_wraps;



    uint32_t chk_cnt, chk_thresh;
    uint32_t rxmt_cnt, rxmt_thresh;
    uint32_t win0_cnt, win0_thresh;
    uint32_t gap_cnt, gap_thresh;
};

enum EndianTypes : uint8_t {
    ENDIAN_UNKNOWN = 0,
    ENDIAN_LITTLE = 1,
    ENDIAN_BIG = 2,
    ENDIAN_CONFUSED = 3,
};

}
}
