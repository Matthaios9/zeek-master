

#pragma once

#include <cstdio>
#include <string>

#include "zeek/Val.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/file_analysis/File.h"

namespace zeek::file_analysis::detail {




class Extract : public file_analysis::Analyzer {
public:



    ~Extract() override;








    bool DeliverStream(const u_char* data, uint64_t len) override;







    bool Undelivered(uint64_t offset, uint64_t len) override;








    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file);






    void SetLimit(uint64_t bytes) { limit = bytes; }

protected:









    Extract(RecordValPtr args, file_analysis::File* file, std::string arg_filename, uint64_t arg_limit,
            bool arg_limit_includes_missing);

private:
    std::string filename;
    FILE* file_stream = nullptr;
    uint64_t limit = 0;
    uint64_t written = 0;
    bool limit_includes_missing = false;
};

}
