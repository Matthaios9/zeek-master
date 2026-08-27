

#pragma once

#include "zeek/logging/Types.h"
#include "zeek/logging/WriterBackend.h"

namespace zeek::logging {

class Manager;


namespace detail {







class WriteBuffer {
public:



    explicit WriteBuffer(size_t buffer_size) : buffer_size(buffer_size) {}






    void WriteRecord(LogRecord&& record) { records.emplace_back(std::move(record)); }






    std::vector<LogRecord> TakeRecords() && {
        auto tmp = std::move(records);


        records.clear();
        records.reserve(buffer_size);

        return tmp;
    }




    size_t Size() const { return records.size(); }




    size_t Empty() const { return records.empty(); }




    bool Full() const { return records.size() >= buffer_size; }

private:
    size_t buffer_size;
    std::vector<LogRecord> records;
};

}










class WriterFrontend {
public:



















    WriterFrontend(const WriterBackend::WriterInfo& info, EnumVal* stream, EnumVal* writer, bool local, bool remote);






    virtual ~WriterFrontend();








    void Stop();













    void Init(int num_fields, const threading::Field* const* fields);






















    void Write(detail::LogRecord&& rec);












    void SetBuf(bool enabled);













    void Flush(double network_time);












    void Rotate(const char* rotated_path, double open, double close, bool terminating);







    void FlushWriteBuffer();













    void SetDisable() { disabled = true; }




    bool Disabled() { return disabled; }




    const WriterBackend::WriterInfo& Info() const { return *info; }







    const char* Name() const { return name; }




    const std::string& GetFilterName() const { return info->filter_name; }




    const std::vector<threading::Field>& GetFields() const { return header.fields; }

protected:
    friend class Manager;

    WriterBackend* backend;
    bool disabled;
    bool initialized;
    bool buf;
    bool local;
    bool remote;

    const char* name;
    WriterBackend::WriterInfo* info;

    detail::LogWriteHeader header;
    detail::WriteBuffer write_buffer;
};

}
