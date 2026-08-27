

#pragma once

#include "zeek/Reassem.h"

namespace zeek {

class Connection;

namespace file_analysis {

class File;

class FileReassembler final : public Reassembler {
public:
    FileReassembler(File* f, uint64_t starting_offset);

    void Done();



    void CheckEOF();







    uint64_t Flush();








    uint64_t FlushTo(uint64_t sequence);





    bool IsCurrentlyFlushing() const { return flushing; }

protected:
    void Undelivered(uint64_t up_to_seq) override;
    void BlockInserted(DataBlockMap::const_iterator it) override;
    void Overlap(const u_char* b1, const u_char* b2, uint64_t n) override;

    File* the_file = nullptr;
    bool flushing = false;
};

}
}
