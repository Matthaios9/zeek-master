

#pragma once

#include <cstddef>
#include <memory>
#include <optional>

namespace zeek::detail {











class FuzzBuffer {
public:
    struct Chunk {
        std::unique_ptr<unsigned char[]> data;
        size_t size;
        bool is_orig;
    };

    static constexpr int PKT_MAGIC_LEN = 4;
    static constexpr unsigned char PKT_MAGIC[PKT_MAGIC_LEN + 1] = "\1PKT";
    static constexpr int MAX_CHUNK_COUNT = 64;






    FuzzBuffer(const unsigned char* data, size_t size) : begin(data), end(data + size) {}







    bool Valid(int chunk_count_limit = MAX_CHUNK_COUNT) const;






    int ChunkCount(int chunk_count_limit = 0) const;





    bool ExceedsChunkLimit(int chunk_count_limit) const {
        return ChunkCount(chunk_count_limit + 1) > chunk_count_limit;
    }




    std::optional<Chunk> Next();

private:
    const unsigned char* begin;
    const unsigned char* end;
};

}
