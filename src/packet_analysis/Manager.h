

#pragma once

#include "zeek/zeek-config.h"

#include <span>

#include "zeek/PacketFilter.h"
#include "zeek/Tag.h"
#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/Dispatcher.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek {

namespace detail {
class PacketProfiler;
}

namespace iosource {
class PktDumper;
}

namespace packet_analysis {

class Analyzer;
using AnalyzerPtr = std::shared_ptr<Analyzer>;

class Manager : public plugin::ComponentManager<Component> {
public:



    Manager();




    ~Manager();









    void InitPostScript(const std::string& unprocessed_output_file);




    void Done();






    void DumpDebug();








    AnalyzerPtr GetAnalyzer(EnumVal* val);








    AnalyzerPtr GetAnalyzer(const std::string& name);









    bool EnableAnalyzer(zeek::EnumVal* tag);









    bool EnableAnalyzer(const zeek::Tag& tag) { return EnableAnalyzer(tag.AsVal().get()); }









    bool DisableAnalyzer(zeek::EnumVal* tag);









    bool DisableAnalyzer(const zeek::Tag& tag) { return DisableAnalyzer(tag.AsVal().get()); };






    void ProcessPacket(Packet* packet);









    bool ProcessInnerPacket(Packet* packet);

    uint64_t PacketsProcessed() const { return num_packets_processed; }








    void DumpPacket(const Packet* pkt, int len = 0);











    void ReportUnknownProtocol(const std::string& analyzer, uint32_t protocol, const uint8_t* data = nullptr,
                               size_t len = 0);





    void ResetUnknownProtocolTimer(const std::string& analyzer, uint32_t protocol);

    zeek::detail::PacketFilter* GetPacketFilter(bool init = true) {
        if ( ! pkt_filter && init )
            pkt_filter = new zeek::detail::PacketFilter(zeek::detail::packet_filter_default);
        return pkt_filter;
    }





    uint64_t PacketsUnprocessed() const { return total_not_processed; }










    void TrackAnalyzer(const Analyzer* analyzer, size_t len, const uint8_t* data) {
        analyzer_stack.push_back({analyzer, {data, len}});
    }








    std::vector<std::span<const uint8_t>> GetAnalyzerData(const AnalyzerPtr& analyzer);

private:








    AnalyzerPtr InstantiateAnalyzer(const zeek::Tag& tag);









    AnalyzerPtr InstantiateAnalyzer(const std::string& name);







    VectorValPtr BuildAnalyzerHistory() const;

    bool PermitUnknownProtocol(const std::string& analyzer, uint32_t protocol);

    std::map<std::string, AnalyzerPtr> analyzers;
    AnalyzerPtr root_analyzer = nullptr;

    uint64_t num_packets_processed = 0;
    zeek::detail::PacketProfiler* pkt_profiler = nullptr;
    zeek::detail::PacketFilter* pkt_filter = nullptr;

    using UnknownProtocolPair = std::pair<std::string, uint32_t>;
    std::map<UnknownProtocolPair, uint64_t> unknown_protocols;

    uint64_t unknown_sampling_threshold = 0;
    uint64_t unknown_sampling_rate = 0;
    double unknown_sampling_duration = 0;
    uint64_t unknown_first_bytes_count = 0;

    uint64_t total_not_processed = 0;
    iosource::PktDumper* unprocessed_dumper = nullptr;

    struct StackEntry {
        const Analyzer* analyzer;
        std::span<const uint8_t> data;
    };

    std::vector<StackEntry> analyzer_stack;
};

}

ZEEK_EXTERN_DATA zeek::packet_analysis::Manager* packet_mgr;

}
