

#pragma once

#include <memory>

#include "zeek/analyzer/Analyzer.h"
#include "zeek/iosource/Packet.h"

namespace zeek::analyzer::pia {
class PIA;
}

namespace zeek::packet_analysis {




enum class PacketAction : uint8_t {
    Deliver,
    Skip,
};




enum class SkipReason : uint8_t {
    None,
    Unknown,
    BadChecksum,
    BadProtoHeader,
    SkipProcessing,
};













class TapAnalyzer {
public:
    virtual ~TapAnalyzer() = default;








    virtual void TapPacket(const Packet& pkt, PacketAction action, SkipReason skip_reason) = 0;










    virtual void UpdateConnVal(RecordVal* conn_val) {}






    virtual void Init() {};







    virtual void Done() {};
};

using TapAnalyzerPtr = std::unique_ptr<TapAnalyzer>;

namespace IP {

class IPBasedAnalyzer;






class SessionAdapter : public analyzer::Analyzer {
public:
    SessionAdapter(const char* name, Connection* conn) : analyzer::Analyzer(name, conn) {}




    void Done() override;







    void SetParent(IPBasedAnalyzer* p) { parent = p; }







    virtual bool IsReuse(double t, const u_char* pkt);






    virtual void AddExtraAnalyzers(Connection* conn) = 0;












    virtual void SetContentsFile(unsigned int direction, FilePtr f);









    virtual FilePtr GetContentsFile(unsigned int direction) const;






    void SetPIA(analyzer::pia::PIA* arg_PIA) { pia = arg_PIA; }





    analyzer::pia::PIA* GetPIA() const { return pia; }








    void PacketContents(const u_char* data, int len);






    void AddTapAnalyzer(TapAnalyzerPtr ta);











    bool RemoveTapAnalyzer(const TapAnalyzer* ta);








    void TapPacket(const Packet* pkt, PacketAction action = PacketAction::Deliver,
                   SkipReason skip_reason = SkipReason::None) const;




    void UpdateConnVal(RecordVal* conn_val) override;

protected:
    IPBasedAnalyzer* parent = nullptr;
    analyzer::pia::PIA* pia = nullptr;
    std::vector<TapAnalyzerPtr> tap_analyzers;
};

}
}
