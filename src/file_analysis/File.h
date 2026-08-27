

#pragma once

#include <list>
#include <string>

#include "zeek/Tag.h"
#include "zeek/WeirdState.h"
#include "zeek/ZeekArgs.h"
#include "zeek/ZeekString.h"
#include "zeek/file_analysis/AnalyzerSet.h"

namespace zeek {

class Connection;
class EventHandlerPtr;
class RecordVal;
class RecordType;
using RecordValPtr = IntrusivePtr<RecordVal>;
using RecordTypePtr = IntrusivePtr<RecordType>;

namespace file_analysis {

class FileReassembler;




class File {
public:




    ~File();




    const RecordValPtr& ToVal() const { return val; }





    std::string GetSource() const;





    void SetSource(const std::string& source);




    double GetTimeoutInterval() const;





    void SetTimeoutInterval(double interval);







    bool SetExtractionLimit(RecordValPtr args, uint64_t bytes);




    const std::string& GetID() const { return id; }




    double GetLastActivityTime() const;




    void UpdateLastActivityTime();





    void SetTotalBytes(uint64_t size);







    bool IsComplete() const;






    void ScheduleInactivityTimer() const;








    bool AddAnalyzer(const zeek::Tag& tag, RecordValPtr args);







    bool RemoveAnalyzer(const zeek::Tag& tag, RecordValPtr args);




    void DoneWithAnalyzer(Analyzer* analyzer);







    void DataIn(const u_char* data, uint64_t len, uint64_t offset);






    void DataIn(const u_char* data, uint64_t len);




    void EndOfFile();






    void Gap(uint64_t offset, uint64_t len);





    bool FileEventAvailable(EventHandlerPtr h);






    void FileEvent(EventHandlerPtr h);






    void FileEvent(EventHandlerPtr h, Args args);



















    bool SetMime(const std::string& mime_type);





    bool PermitWeird(const char* name, uint64_t threshold, uint64_t rate, double duration);

protected:
    friend class Manager;
    friend class FileReassembler;












    File(const std::string& file_id, const std::string& source_name, Connection* conn = nullptr,
         const zeek::Tag& tag = zeek::Tag::Error, bool is_orig = false);








    bool UpdateConnectionFields(Connection* conn, bool is_orig);




    void RaiseFileOverNewConnection(Connection* conn, bool is_orig);






    void IncrementByteCount(uint64_t size, int field_idx);







    uint64_t LookupFieldDefaultCount(int idx) const;







    double LookupFieldDefaultInterval(int idx) const;







    bool BufferBOF(const u_char* data, uint64_t len);






    void InferMetadata();




    void EnableReassembly();






    void DisableReassembly();




    void SetReassemblyBuffer(uint64_t max);




    void DeliverStream(const u_char* data, uint64_t len);




    void DeliverChunk(const u_char* data, uint64_t len, uint64_t offset);







    static int Idx(const std::string& field_name, const RecordType* type);
    static int Idx(const std::string& field_name, const RecordTypePtr& type) { return Idx(field_name, type.get()); }




    static void StaticInit();

protected:
    std::string id;
    RecordValPtr val;
    FileReassembler* file_reassembler = nullptr;
    uint64_t stream_offset = 0;
    uint64_t reassembly_max_buffer = 0;
    bool did_metadata_inference = false;
    bool reassembly_enabled = false;
    bool postpone_timeout = false;
    bool done = false;
    uint64_t seen_bytes = 0;
    uint64_t missing_bytes = 0;
    uint64_t overflow_bytes = 0;
    detail::AnalyzerSet analyzers;
    std::list<Analyzer*> done_analyzers;


    struct BOF_Buffer {
        BOF_Buffer() = default;
        ~BOF_Buffer() {
            for ( auto* chunk : chunks )
                delete chunk;
        }

        bool full = false;
        uint64_t size = 0;
        String::CVec chunks;
    } bof_buffer;

    zeek::detail::WeirdStateMap weird_state;

    static int id_idx;
    static int parent_id_idx;
    static int source_idx;
    static int is_orig_idx;
    static int conns_idx;
    static int last_active_idx;
    static int seen_bytes_idx;
    static int total_bytes_idx;
    static int missing_bytes_idx;
    static int overflow_bytes_idx;
    static int timeout_interval_idx;
    static int bof_buffer_size_idx;
    static int bof_buffer_idx;
    static int mime_type_idx;
    static int mime_types_idx;
    static int meta_inferred_idx;

    static int meta_mime_type_idx;
    static int meta_mime_types_idx;
};

}
}
