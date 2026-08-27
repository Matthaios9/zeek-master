

#pragma once

#include "zeek/OpaqueVal.h"
#include "zeek/Val.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/analyzer/hash/events.bif.h"

namespace zeek::file_analysis::detail {




class Hash : public file_analysis::Analyzer {
public:



    ~Hash() override;







    bool DeliverStream(const u_char* data, uint64_t len) override;





    bool EndOfFile() override;








    bool Undelivered(uint64_t offset, uint64_t len) override;

protected:







    Hash(RecordValPtr args, file_analysis::File* file, HashVal* hv, StringValPtr kind);





    void Finalize();

private:
    HashVal* hash = nullptr;
    bool fed = false;
    StringValPtr kind;
};




class MD5 final : public Hash {
public:







    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file) {
        return file_hash ? new MD5(std::move(args), file) : nullptr;
    }

private:





    MD5(RecordValPtr args, file_analysis::File* file) : Hash(std::move(args), file, new MD5Val(), MD5::kind_val) {}

    static StringValPtr kind_val;
};




class SHA1 final : public Hash {
public:







    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file) {
        return file_hash ? new SHA1(std::move(args), file) : nullptr;
    }

private:





    SHA1(RecordValPtr args, file_analysis::File* file) : Hash(std::move(args), file, new SHA1Val(), SHA1::kind_val) {}

    static StringValPtr kind_val;
};




class SHA224 final : public Hash {
public:







    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file) {
        return file_hash ? new SHA224(std::move(args), file) : nullptr;
    }

private:





    SHA224(RecordValPtr args, file_analysis::File* file)
        : Hash(std::move(args), file, new SHA224Val(), SHA224::kind_val) {}

    static StringValPtr kind_val;
};




class SHA256 final : public Hash {
public:







    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file) {
        return file_hash ? new SHA256(std::move(args), file) : nullptr;
    }

private:





    SHA256(RecordValPtr args, file_analysis::File* file)
        : Hash(std::move(args), file, new SHA256Val(), SHA256::kind_val) {}

    static StringValPtr kind_val;
};




class SHA384 final : public Hash {
public:







    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file) {
        return file_hash ? new SHA384(std::move(args), file) : nullptr;
    }

private:





    SHA384(RecordValPtr args, file_analysis::File* file)
        : Hash(std::move(args), file, new SHA384Val(), SHA384::kind_val) {}

    static StringValPtr kind_val;
};




class SHA512 final : public Hash {
public:







    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file) {
        return file_hash ? new SHA512(std::move(args), file) : nullptr;
    }

private:





    SHA512(RecordValPtr args, file_analysis::File* file)
        : Hash(std::move(args), file, new SHA512Val(), SHA512::kind_val) {}

    static StringValPtr kind_val;
};

}
