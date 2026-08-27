



#pragma once

#include "zeek/zeek-config.h"

#include <map>

#include "zeek/EventHandler.h"
#include "zeek/Tag.h"
#include "zeek/input/Component.h"
#include "zeek/plugin/ComponentManager.h"
#include "zeek/threading/SerialTypes.h"

namespace zeek {

class RecordVal;

namespace input {

class ReaderFrontend;
class ReaderBackend;




class Manager : public plugin::ComponentManager<Component> {
public:



    Manager();




    ~Manager();











    bool CreateTableStream(RecordVal* description);










    bool CreateEventStream(RecordVal* description);











    bool CreateAnalysisStream(RecordVal* description);













    bool ForceUpdate(const std::string& id);









    bool RemoveStream(const std::string& id);




    void Terminate();














    static bool IsCompatibleType(Type* t, bool atomic_only = false);

protected:
    friend class ReaderFrontend;
    friend class PutMessage;
    friend class DeleteMessage;
    friend class ClearMessage;
    friend class SendEntryMessage;
    friend class EndCurrentSendMessage;
    friend class ReaderClosedMessage;
    friend class DisableMessage;
    friend class EndOfDataMessage;
    friend class ReaderErrorMessage;




    void Put(ReaderFrontend* reader, threading::Value** vals);
    void Clear(ReaderFrontend* reader);
    bool Delete(ReaderFrontend* reader, threading::Value** vals);


    void SendEndOfData(ReaderFrontend* reader);




    void SendEntry(ReaderFrontend* reader, threading::Value** vals);
    void EndCurrentSend(ReaderFrontend* reader);



    ReaderBackend* CreateBackend(ReaderFrontend* frontend, EnumVal* tag);







    bool RemoveStreamContinuation(ReaderFrontend* reader);




    void Info(ReaderFrontend* reader, const char* msg) const;
    void Warning(ReaderFrontend* reader, const char* msg) const;
    void Error(ReaderFrontend* reader, const char* msg) const;









    bool RemoveStream(ReaderFrontend* frontend);

private:
    class Stream;
    class TableStream;
    class EventStream;
    class AnalysisStream;



    bool RemoveStream(Stream* i);

    bool CreateStream(Stream*, RecordVal* description);




    bool CheckErrorEventTypes(const std::string& stream_name, const Func* error_event, bool table) const;


    int SendEntryTable(Stream* i, const threading::Value* const* vals);


    int PutTable(Stream* i, const threading::Value* const* vals);


    int SendEventStreamEvent(Stream* i, EnumVal* type, const threading::Value* const* vals);




    bool UnrollRecordType(std::vector<threading::Field*>* fields, const RecordType* rec, const std::string& nameprepend,
                          bool allow_file_func) const;


    void SendEvent(EventHandlerPtr ev, const int numvals, ...) const;
    void SendEvent(EventHandlerPtr ev, const std::list<Val*>& events) const;


    void SendEndOfData(const Stream* i);


    bool CallPred(Func* pred_func, const int numvals, ...) const;


    zeek::detail::HashKey* HashValues(const int num_elements, const threading::Value* const* vals) const;


    int GetValueLength(const threading::Value* val) const;



    int CopyValue(char* data, const int startpos, const threading::Value* val) const;


    Val* ValueToVal(const Stream* i, const threading::Value* val, Type* request_type, bool& have_error) const;


    Val* ValueToIndexVal(const Stream* i, int num_fields, const RecordType* type, const threading::Value* const* vals,
                         bool& have_error) const;



    RecordVal* ValueToRecordVal(const Stream* i, const threading::Value* const* vals, RecordType* request_type,
                                int* position, bool& have_error) const;

    Val* RecordValToIndexVal(RecordVal* r) const;


    RecordVal* ListValToRecordVal(ListVal* list, RecordType* request_type, int* position) const;



    void Info(const Stream* i, const char* fmt, ...) const __attribute__((format(printf, 3, 4)));
    void Warning(const Stream* i, const char* fmt, ...) const __attribute__((format(printf, 3, 4)));
    void Error(const Stream* i, const char* fmt, ...) const __attribute__((format(printf, 3, 4)));

    enum class ErrorType : uint8_t { INFO, WARNING, ERROR };
    void ErrorHandler(const Stream* i, ErrorType et, bool reporter_send, const char* fmt, ...) const
        __attribute__((format(printf, 5, 6)));
    void ErrorHandler(const Stream* i, ErrorType et, bool reporter_send, const char* fmt, va_list ap) const
        __attribute__((format(printf, 5, 0)));

    Stream* FindStream(const std::string& name) const;
    Stream* FindStream(ReaderFrontend* reader) const;

    enum StreamType : uint8_t { TABLE_STREAM, EVENT_STREAM, ANALYSIS_STREAM };

    std::map<ReaderFrontend*, Stream*> readers;

    EventHandlerPtr end_of_data;
};

}

ZEEK_EXTERN_DATA input::Manager* input_mgr;

}
