
#pragma once

#include <string>

#include "zeek/Conn.h"
#include "zeek/analyzer/Analyzer.h"

namespace zeek::analyzer {

namespace mime {
class MIME_Message;
}

namespace smtp {

class SMTP_Analyzer;

namespace detail {






struct BDATCmd {
    uint64_t chunk_size = 0;
    bool is_last_chunk = false;
    const char* error = nullptr;
};







struct BDATCmd parse_bdat_arg(int length, const char* arg);






enum class ChunkType : uint8_t {
    None,
    Intermediate,
    Last,
};









class SMTP_BDAT_Analyzer : public zeek::analyzer::Analyzer {
public:







    SMTP_BDAT_Analyzer(zeek::Connection* conn, mime::MIME_Message* mail, size_t max_line_length);







    void NextChunk(smtp::detail::ChunkType chunk_type, uint64_t chunk_size);




    void DeliverStream(int len, const u_char* data, bool is_orig) override;




    void Done() override;




    uint64_t RemainingChunkSize() const { return remaining_chunk_size; }




    bool IsLastChunk() const { return cur_chunk_type == ChunkType::Last; }

private:
    ChunkType cur_chunk_type = ChunkType::None;
    uint64_t remaining_chunk_size = 0;
    std::string buf;

    size_t max_line_length = 0;

    mime::MIME_Message* mail;
};

}
}
}
