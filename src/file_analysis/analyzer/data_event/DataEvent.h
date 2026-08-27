

#pragma once

#include "zeek/EventHandler.h"
#include "zeek/Val.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/file_analysis/File.h"

namespace zeek::file_analysis::detail {




class DataEvent : public file_analysis::Analyzer {
public:








    bool DeliverChunk(const u_char* data, uint64_t len, uint64_t offset) override;








    bool DeliverStream(const u_char* data, uint64_t len) override;








    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file);

protected:









    DataEvent(RecordValPtr args, file_analysis::File* file, EventHandlerPtr ce, EventHandlerPtr se);

private:
    EventHandlerPtr chunk_event;
    EventHandlerPtr stream_event;
};

}
