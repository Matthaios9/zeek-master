

#pragma once

#include "zeek/OpaqueVal.h"
#include "zeek/Val.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/file_analysis/File.h"

namespace zeek::file_analysis::detail {




class Entropy : public file_analysis::Analyzer {
public:



    ~Entropy() override;








    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file);







    bool DeliverStream(const u_char* data, uint64_t len) override;





    bool EndOfFile() override;








    bool Undelivered(uint64_t offset, uint64_t len) override;

protected:







    Entropy(RecordValPtr args, file_analysis::File* file);





    void Finalize();

private:
    EntropyVal* entropy;
    bool fed;
};

}
