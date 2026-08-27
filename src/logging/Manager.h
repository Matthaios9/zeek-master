



#pragma once

#include "zeek/zeek-config.h"

#include <string_view>

#include "zeek/EventHandler.h"
#include "zeek/Tag.h"
#include "zeek/Val.h"
#include "zeek/logging/Component.h"
#include "zeek/logging/Types.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/plugin/ComponentManager.h"
#include "zeek/telemetry/Manager.h"

namespace broker {
struct endpoint_info;
}

namespace zeek {

namespace detail {
class SerializationFormat;
}

namespace logging {

class WriterFrontend;
class RotationFinishedMessage;
class RotationTimer;

namespace detail {

class LogFlushWriteBufferTimer;

class DelayInfo;

using WriteIdx = uint64_t;




struct WriteContext {
    EnumValPtr id = nullptr;
    RecordValPtr record = nullptr;
    WriteIdx idx = 0;

    bool operator<(const WriteContext& o) const {
        assert(id->Get() == o.id->Get());
        return idx < o.idx;
    }

    bool operator==(const WriteContext& o) const {
        assert(id->Get() == o.id->Get());
        return idx == o.idx;
    }
};

}




class Manager : public plugin::ComponentManager<Component> {
public:



    Manager();




    ~Manager();




    void InitPostScript();









    std::string FormatRotationPath(EnumValPtr writer, std::string_view path, double open, double close,
                                   bool terminating, FuncPtr postprocesor);











    bool CreateStream(EnumVal* id, RecordVal* stream);









    bool RemoveStream(EnumVal* id);









    bool EnableStream(EnumVal* id);









    bool DisableStream(EnumVal* id);











    bool AddFilter(EnumVal* id, RecordVal* filter);











    bool RemoveFilter(EnumVal* id, StringVal* name);











    bool RemoveFilter(EnumVal* id, const std::string& name);












    bool Write(EnumVal* id, RecordVal* columns);


















    ValPtr Delay(const EnumValPtr& id, const RecordValPtr record, FuncPtr post_delay_cb);












    bool DelayFinish(const EnumValPtr& id, const RecordValPtr& record, const ValPtr& token);













    bool SetMaxDelayInterval(const EnumValPtr& id, double max_delay);










    bool SetMaxDelayQueueSize(const EnumValPtr& id, zeek_uint_t max_queue_length);








    zeek_int_t GetDelayQueueSize(const EnumValPtr& id);




















    bool CreateWriterForRemoteLog(EnumVal* id, EnumVal* writer, WriterBackend::WriterInfo* info, int num_fields,
                                  const threading::Field* const* fields);

















    bool WriteFromRemote(EnumVal* id, EnumVal* writer, const std::string& path, detail::LogRecord&& rec);






















    bool WriteBatchFromRemote(const detail::LogWriteHeader& header, std::vector<detail::LogRecord>&& records);




    void SendAllWritersTo(const broker::endpoint_info& ei);












    bool SetBuf(EnumVal* id, bool enabled);









    bool Flush(EnumVal* id);




    void FlushAll();




    void Terminate();






    bool EnableRemoteLogs(EnumVal* stream_id);






    bool DisableRemoteLogs(EnumVal* stream_id);




    bool RemoteLogsAreEnabled(EnumVal* stream_id);





    RecordType* StreamColumns(EnumVal* stream_id);

protected:
    friend class WriterFrontend;
    friend class RotationFinishedMessage;
    friend class RotationFailedMessage;
    friend class RotationTimer;
    friend class detail::LogFlushWriteBufferTimer;



    WriterBackend* CreateBackend(WriterFrontend* frontend, EnumVal* tag);




    WriterFrontend* CreateWriter(EnumVal* id, EnumVal* writer, WriterBackend::WriterInfo* info, int num_fields,
                                 const threading::Field* const* fields, bool local, bool remote, bool from_remote,
                                 const std::string& instantiating_filter = "");


    bool FinishedRotation(WriterFrontend* writer, const char* new_name, const char* old_name, double open, double close,
                          bool success, bool terminating);


    void StartLogFlushTimer();

private:
    struct Filter;
    struct Stream;
    struct WriterInfo;




    enum class WriterOrigin : uint8_t {
        REMOTE,
        LOCAL,
    };








    WriterFrontend* CreateWriterForFilter(Filter* filter, const std::string& path, WriterOrigin origin);

    bool TraverseRecord(Stream* stream, Filter* filter, RecordType* rt, TableVal* include, TableVal* exclude,
                        const std::string& path, const std::list<int>& indices);

    detail::LogRecord RecordToLogRecord(WriterInfo* info, Filter* filter, const Stream* stream, RecordVal* columns);
    threading::Value ValToLogVal(WriterInfo* info, const Stream* stream, std::optional<ZVal>& val, Type* ty);

    Stream* FindStream(EnumVal* id);
    void RemoveDisabledWriters(Stream* stream);
    void InstallRotationTimer(WriterInfo* winfo);
    void Rotate(WriterInfo* info);
    WriterInfo* FindWriter(WriterFrontend* writer);
    bool CompareFields(const Filter* filter, const WriterFrontend* writer);
    bool CheckFilterWriterConflict(const WriterInfo* winfo, const Filter* filter);


    enum class PolicyVerdict : uint8_t {
        PASS,
        VETO,
    };
    bool WriteToFilters(const Manager::Stream* stream, zeek::RecordValPtr columns, PolicyVerdict stream_verdict);

    bool RemoveStream(unsigned int idx);

    bool DelayCompleted(Manager::Stream* stream, detail::DelayInfo& delay_info);

    std::vector<Stream*> streams;
    int rotations_pending = 0;
    FuncPtr rotation_format_func;
    FuncPtr log_stream_policy_hook;

    size_t max_log_record_size = 0;
    size_t total_record_size = 0;
    size_t total_string_bytes = 0;
    size_t total_container_elements = 0;

    std::shared_ptr<telemetry::CounterFamily> total_log_stream_writes_family;
    std::shared_ptr<telemetry::CounterFamily> total_log_writer_writes_family;
    std::shared_ptr<telemetry::CounterFamily> total_log_writer_discarded_writes_family;
    std::shared_ptr<telemetry::CounterFamily> total_log_writer_truncated_string_fields_family;
    std::shared_ptr<telemetry::CounterFamily> total_log_writer_truncated_container_fields_family;

    zeek_uint_t last_delay_token = 0;
    std::vector<detail::WriteContext> active_writes;


    detail::LogFlushWriteBufferTimer* log_flush_timer = nullptr;
};

}

ZEEK_EXTERN_DATA logging::Manager* log_mgr;

}
