

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

namespace zeek::packet_analysis {

class Analyzer;
using AnalyzerPtr = std::shared_ptr<zeek::packet_analysis::Analyzer>;

namespace detail {




class Dispatcher {
public:
    Dispatcher() : table(std::vector<AnalyzerPtr>(1, nullptr)) {};
    ~Dispatcher();







    void Register(uint64_t identifier, AnalyzerPtr analyzer);








    const AnalyzerPtr& Lookup(uint64_t identifier) const;





    size_t Count() const;




    void Clear();




    void DumpDebug() const;

private:
    uint64_t lowest_identifier = 0;
    std::vector<AnalyzerPtr> table;

    void FreeValues();

    inline uint64_t GetHighestIdentifier() const { return lowest_identifier + table.size() - 1; }
};

}
}
