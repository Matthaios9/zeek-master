

#pragma once

#include <sys/types.h>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <map>

#include "zeek/Obj.h"

namespace zeek {



enum ReassemblerType : uint8_t {
    REASSEM_UNKNOWN,
    REASSEM_TCP,
    REASSEM_FRAG,
    REASSEM_FILE,


    REASSEM_NUM,
};

class Reassembler;




class DataBlock {
public:



    DataBlock(const u_char* data, uint64_t size, uint64_t seq);

    DataBlock(const DataBlock& other) {
        seq = other.seq;
        upper = other.upper;
        auto size = other.Size();
        block = new u_char[size];
        memcpy(block, other.block, size);
    }

    DataBlock(DataBlock&& other) noexcept {
        seq = other.seq;
        upper = other.upper;
        block = other.block;
        other.block = nullptr;
    }

    DataBlock& operator=(const DataBlock& other) {
        if ( this == &other )
            return *this;

        seq = other.seq;
        upper = other.upper;
        auto size = other.Size();
        delete[] block;
        block = new u_char[size];
        memcpy(block, other.block, size);
        return *this;
    }

    DataBlock& operator=(DataBlock&& other) noexcept {
        if ( this == &other )
            return *this;

        seq = other.seq;
        upper = other.upper;
        delete[] block;
        block = other.block;
        other.block = nullptr;
        return *this;
    }

    ~DataBlock() { delete[] block; }




    uint64_t Size() const { return upper - seq; }

    uint64_t seq;
    uint64_t upper;
    u_char* block;
};

using DataBlockMap = std::map<uint64_t, DataBlock>;





class DataBlockList {
public:
    DataBlockList() = default;

    DataBlockList(Reassembler* r) : reassembler(r) {}

    ~DataBlockList() { Clear(); }




    DataBlockMap::const_iterator Begin() const { return block_map.begin(); }




    DataBlockMap::const_iterator End() const { return block_map.end(); }





    const DataBlock& FirstBlock() const {
        assert(! block_map.empty());
        return block_map.begin()->second;
    }





    const DataBlock& LastBlock() const {
        assert(! block_map.empty());
        return block_map.rbegin()->second;
    }




    bool Empty() const { return block_map.empty(); };




    size_t NumBlocks() const { return block_map.size(); };




    size_t DataSize() const { return total_data_size; }










    void DataSize(uint64_t seq_cutoff, uint64_t* below, uint64_t* above) const;




    void Clear();










    DataBlockMap::const_iterator Insert(uint64_t seq, uint64_t upper, const u_char* data,
                                        DataBlockMap::const_iterator* hint = nullptr);








    void Append(DataBlock block, uint64_t limit);










    uint64_t Trim(uint64_t seq, uint64_t max_old, DataBlockList* old_list);







    DataBlockMap::const_iterator FirstBlockAtOrBefore(uint64_t seq) const;

private:









    DataBlockMap::const_iterator Insert(uint64_t seq, uint64_t upper, const u_char* data,
                                        DataBlockMap::const_iterator hint);






    void Delete(DataBlockMap::const_iterator it);







    DataBlock Remove(DataBlockMap::const_iterator it);

    Reassembler* reassembler = nullptr;
    size_t total_data_size = 0;
    DataBlockMap block_map;
};

class Reassembler : public Obj {
public:
    Reassembler(uint64_t init_seq, ReassemblerType reassem_type = REASSEM_UNKNOWN);

    void NewBlock(double t, uint64_t seq, uint64_t len, const u_char* data);



    uint64_t TrimToSeq(uint64_t seq);


    void ClearBlocks();
    void ClearOldBlocks();

    bool HasBlocks() const { return ! block_list.Empty(); }

    uint64_t LastReassemSeq() const { return last_reassem_seq; }

    uint64_t TrimSeq() const { return trim_seq; }

    void SetTrimSeq(uint64_t seq) {
        if ( seq > trim_seq )
            trim_seq = seq;
    }

    uint64_t TotalSize() const;

    void Describe(ODesc* d) const override;

    static uint64_t TotalMemoryAllocation() { return total_size; }


    static uint64_t MemoryAllocation(ReassemblerType rtype);

    void SetMaxOldBlocks(uint32_t count) { max_old_blocks = count; }

protected:
    friend class DataBlockList;

    virtual void Undelivered(uint64_t up_to_seq);

    virtual void BlockInserted(DataBlockMap::const_iterator it) = 0;
    virtual void Overlap(const u_char* b1, const u_char* b2, uint64_t n) = 0;

    void CheckOverlap(const DataBlockList& list, uint64_t seq, uint64_t len, const u_char* data);

    DataBlockList block_list;
    DataBlockList old_block_list;

    uint64_t last_reassem_seq = 0;
    uint64_t trim_seq = 0;
    uint32_t max_old_blocks = 0;

    ReassemblerType rtype = REASSEM_UNKNOWN;

    static uint64_t total_size;
    static uint64_t sizes[REASSEM_NUM];
};

}
