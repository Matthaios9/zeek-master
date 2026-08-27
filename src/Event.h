

#pragma once

#include "zeek/zeek-config.h"

#include <tuple>
#include <type_traits>
#include <vector>

#include "zeek/RunState.h"
#include "zeek/ZeekArgs.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/util-types.h"

namespace zeek {

class EventMgr;

namespace detail {




class MetadataEntry {
public:
    MetadataEntry(zeek_uint_t id, zeek::ValPtr val) : id(id), val(std::move(val)) {}

    zeek_uint_t Id() const { return id; }
    const zeek::ValPtr& Val() const { return val; }




    RecordValPtr BuildVal() const;

private:
    zeek_uint_t id;
    zeek::ValPtr val;
};

using EventMetadataVector = std::vector<MetadataEntry>;
using EventMetadataVectorPtr = std::unique_ptr<EventMetadataVector>;




EventMetadataVectorPtr MakeEventMetadataVector(double t);

constexpr double NO_TIMESTAMP = -1.0;

}

class Event final : public Obj {
public:
    void SetNext(Event* n) { next_event = n; }
    Event* NextEvent() const { return next_event; }

    util::detail::SourceID Source() const { return src; }
    analyzer::ID Analyzer() const { return aid; }
    EventHandlerPtr Handler() const { return handler; }
    const zeek::Args& Args() const { return args; }
    double Time() const;




    const detail::EventMetadataVector* Metadata() const { return meta.get(); }






    VectorValPtr MetadataValues(const EnumValPtr& id) const;

    void Describe(ODesc* d) const override;

private:
    friend class EventMgr;


    Event(detail::EventMetadataVectorPtr arg_meta, const EventHandlerPtr& arg_handler, zeek::Args arg_args,
          util::detail::SourceID arg_src, analyzer::ID arg_aid, Obj* arg_obj);



    void Dispatch();

    EventHandlerPtr handler;
    zeek::Args args;
    detail::EventMetadataVectorPtr meta;
    util::detail::SourceID src;
    analyzer::ID aid;
    zeek::IntrusivePtr<Obj> obj;
    Event* next_event = nullptr;
};

class EventMgr final : public Obj, public iosource::IOSource {
public:
    ~EventMgr() override;















    void Enqueue(const EventHandlerPtr& h, zeek::Args vl, util::detail::SourceID src = util::detail::SOURCE_LOCAL,
                 analyzer::ID aid = 0, Obj* obj = nullptr);




    template<class... Args>
        requires std::is_convertible_v<std::tuple_element_t<0, std::tuple<Args...>>, ValPtr>
    void Enqueue(const EventHandlerPtr& h, Args&&... args) {
        return Enqueue(h, zeek::Args{std::forward<Args>(args)...});
    }











    void Enqueue(detail::EventMetadataVectorPtr meta, const EventHandlerPtr& h, zeek::Args vl,
                 util::detail::SourceID src = util::detail::SOURCE_LOCAL, analyzer::ID aid = 0, Obj* obj = nullptr);





    void Dispatch(const EventHandlerPtr& h, zeek::Args vl);

    void Drain();
    bool IsDraining() const { return current != nullptr; }

    bool HasEvents() const { return head != nullptr; }


    util::detail::SourceID CurrentSource() const { return current ? current->Source() : util::detail::SOURCE_LOCAL; }



    analyzer::ID CurrentAnalyzer() const { return current ? current->Analyzer() : 0; }






    double CurrentEventTime() const { return current ? current->Time() : detail::NO_TIMESTAMP; }

    int Size() const { return num_events_queued - num_events_dispatched; }

    void Describe(ODesc* d) const override;



    double GetNextTimeout() override { return head ? 0.0 : -1.0; }




    const Event* CurrentEvent() const { return current; }

    void Process() override;
    const char* Tag() override { return "EventManager"; }
    void InitPostScript();

    uint64_t num_events_queued = 0;
    uint64_t num_events_dispatched = 0;

private:
    void QueueEvent(Event* event);

    Event* current = nullptr;
    Event* head = nullptr;
    Event* tail = nullptr;
};

ZEEK_EXTERN_DATA EventMgr event_mgr;

}
