






#pragma once

#include <string>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/threading/SerialTypes.h"

namespace zeek {
class EnumVal;
using EnumValPtr = IntrusivePtr<EnumVal>;

namespace logging::detail {








using LogRecord = std::vector<threading::Value>;









struct LogWriteHeader {



    LogWriteHeader() = default;









    LogWriteHeader(EnumValPtr stream_id, EnumValPtr writer_id, std::string filter_name, std::string path);




    LogWriteHeader& operator=(const LogWriteHeader& other) = default;




    ~LogWriteHeader() = default;




    LogWriteHeader(const LogWriteHeader& other) = default;




    LogWriteHeader(LogWriteHeader&& other) noexcept = default;







    bool PopulateEnumVals();

    EnumValPtr stream_id;
    std::string stream_name;
    EnumValPtr writer_id;
    std::string writer_name;
    std::string filter_name;
    std::string path;
    std::vector<threading::Field> fields;
    std::vector<const threading::Field*> field_pointers;
};












struct LogWriteBatch {
    LogWriteHeader header;
    std::vector<LogRecord> records;
};

}
}
