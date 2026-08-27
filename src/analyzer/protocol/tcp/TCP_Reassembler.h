

#pragma once

#include "zeek/File.h"
#include "zeek/Reassem.h"
#include "zeek/analyzer/protocol/tcp/TCP_Endpoint.h"
#include "zeek/analyzer/protocol/tcp/TCP_Flags.h"

namespace zeek {
namespace packet_analysis::TCP {
class TCPSessionAdapter;
}

class Connection;

namespace analyzer {

class Analyzer;

namespace tcp {

class TCP_Reassembler final : public Reassembler {
public:
    enum Type : uint8_t {
        Direct,
        Forward,
    };

    TCP_Reassembler(analyzer::Analyzer* arg_dst_analyzer, packet_analysis::TCP::TCPSessionAdapter* arg_tcp_analyzer,
                    Type arg_type, TCP_Endpoint* arg_endp);

    void Done();

    void SetDstAnalyzer(analyzer::Analyzer* analyzer) { dst_analyzer = analyzer; }
    void SetType(Type arg_type) { type = arg_type; }

    packet_analysis::TCP::TCPSessionAdapter* GetTCPAnalyzer() { return tcp_analyzer; }











    void SizeBufferedData(uint64_t& waiting_on_hole, uint64_t& waiting_on_ack) const;




    uint64_t NumUndeliveredBytes() const;

    void SetContentsFile(FilePtr f);
    const FilePtr& GetContentsFile() const { return record_contents_file; }

    void MatchUndelivered(uint64_t up_to_seq, bool use_last_upper);



    void SkipToSeq(uint64_t seq);

    bool DataSent(double t, uint64_t seq, int len, const u_char* data, analyzer::tcp::TCP_Flags flags,
                  bool replaying = true);
    void AckReceived(uint64_t seq);




    void CheckEOF();

    bool HasUndeliveredData() const { return HasBlocks(); }
    bool HadGap() const { return had_gap; }
    bool DataPending() const;
    uint64_t DataSeq() const { return LastReassemSeq(); }

    void DeliverBlock(uint64_t seq, int len, const u_char* data);
    void Deliver(uint64_t seq, int len, const u_char* data);

    TCP_Endpoint* Endpoint() { return endp; }
    const TCP_Endpoint* Endpoint() const { return endp; }

    bool IsOrig() const { return endp->IsOrig(); }

    bool IsSkippedContents(uint64_t seq, int length) const { return seq + length <= seq_to_skip; }

private:
    void Undelivered(uint64_t up_to_seq) override;
    void Gap(uint64_t seq, uint64_t len);

    void RecordToSeq(uint64_t start_seq, uint64_t stop_seq, const FilePtr& f);
    void RecordBlock(const DataBlock& b, const FilePtr& f);
    void RecordGap(uint64_t start_seq, uint64_t upper_seq, const FilePtr& f);

    void BlockInserted(DataBlockMap::const_iterator it) override;
    void Overlap(const u_char* b1, const u_char* b2, uint64_t n) override;

    TCP_Endpoint* endp;

    bool deliver_tcp_contents;
    bool had_gap;
    bool did_EOF;
    bool skip_deliveries;

    analyzer::tcp::TCP_Flags flags;
    bool in_delivery;

    uint64_t seq_to_skip;

    FilePtr record_contents_file;

    analyzer::Analyzer* dst_analyzer;
    packet_analysis::TCP::TCPSessionAdapter* tcp_analyzer;

    Type type;
};

}
}
}
