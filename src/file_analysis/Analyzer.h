

#pragma once

#include <sys/types.h>

#include "zeek/Tag.h"

namespace zeek {

class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace file_analysis {

class File;
using ID = uint32_t;




class Analyzer {
public:




    virtual ~Analyzer();




    virtual void Init() {}




    virtual void Done() {}









    virtual bool DeliverChunk(const u_char* data, uint64_t len, uint64_t offset) { return true; }








    virtual bool DeliverStream(const u_char* data, uint64_t len) { return true; }








    virtual bool EndOfFile() { return true; }









    virtual bool Undelivered(uint64_t offset, uint64_t len) { return true; }




    zeek::Tag Tag() const { return tag; }




    const char* GetAnalyzerName() const;






    ID GetID() const { return id; }




    const RecordValPtr& GetArgs() const { return args; }




    File* GetFile() const { return file; }







    void SetAnalyzerTag(const zeek::Tag& tag);




    bool GotStreamDelivery() const { return got_stream_delivery; }




    void SetGotStreamDelivery() { got_stream_delivery = true; }








    void SetSkip(bool do_skip) { skip = do_skip; }





    bool Skipping() const { return skip; }











    virtual void AnalyzerConfirmation(zeek::Tag tag = zeek::Tag());


















    virtual void AnalyzerViolation(const char* reason, const char* data = nullptr, int len = 0,
                                   zeek::Tag tag = zeek::Tag());





    void Weird(const char* name, const char* addl = "");

protected:







    Analyzer(zeek::Tag arg_tag, RecordValPtr arg_args, File* arg_file);










    Analyzer(RecordValPtr arg_args, File* arg_file);

private:
    ID id;
    zeek::Tag tag;
    RecordValPtr args;
    File* file;
    bool got_stream_delivery;
    bool skip;
    bool analyzer_confirmed;

    uint64_t analyzer_violations = 0;

    static ID id_counter;
};

}
}
