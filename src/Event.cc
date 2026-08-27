

#include "zeek/Event.h"

#include <cinttypes>

#include "zeek/Desc.h"
#include "zeek/EventRegistry.h"
#include "zeek/Trigger.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"
#include "zeek/plugin/Manager.h"
#include "zeek/util.h"

#include "const.bif.netvar_h"
#include "event.bif.netvar_h"

zeek::EventMgr zeek::event_mgr;

namespace zeek {

detail::EventMetadataVectorPtr detail::MakeEventMetadataVector(double t) {
    auto tv = make_intrusive<TimeVal>(t);
    auto entry = detail::MetadataEntry{static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp), std::move(tv)};
    return std::make_unique<detail::EventMetadataVector>(std::vector{std::move(entry)});
}

RecordValPtr detail::MetadataEntry::BuildVal() const {
    static const auto rt = id::find_type<RecordType>("EventMetadata::Entry");
    auto rv = make_intrusive<RecordVal>(rt);
    const auto* desc = event_registry->LookupMetadata(id);
    if ( ! desc ) {
        zeek::reporter->InternalWarning("unable to find metadata descriptor for id %" PRIu64, id);
        return rv;
    }

    rv->Assign(0, desc->IdVal());
    rv->Assign(1, val);

    return rv;
}

Event::Event(detail::EventMetadataVectorPtr arg_meta, const EventHandlerPtr& arg_handler, zeek::Args arg_args,
             util::detail::SourceID arg_src, analyzer::ID arg_aid, Obj* arg_obj)
    : handler(arg_handler),
      args(std::move(arg_args)),
      meta(std::move(arg_meta)),
      src(arg_src),
      aid(arg_aid),
      obj(zeek::NewRef{}, arg_obj) {}

zeek::VectorValPtr Event::MetadataValues(const EnumValPtr& id) const {
    static const auto& any_vec_t = zeek::id::find_type<zeek::VectorType>("any_vec");
    auto result = zeek::make_intrusive<zeek::VectorVal>(any_vec_t);

    if ( ! meta )
        return result;

    auto id_int = id->Get();
    if ( id_int < 0 )
        zeek::reporter->InternalError("Negative enum value %s: %" PRId64, obj_desc_short(id.get()).c_str(), id_int);

    zeek_uint_t uintid = static_cast<zeek_uint_t>(id_int);
    const auto* desc = event_registry->LookupMetadata(uintid);
    if ( ! desc )
        return result;

    for ( const auto& entry : *meta ) {
        if ( entry.Id() != uintid )
            continue;


        if ( ! same_type(desc->Type(), entry.Val()->GetType()) ) {
            zeek::reporter->InternalWarning("metadata has unexpected type %s, wanted %s",
                                            obj_desc_short(entry.Val()->GetType().get()).c_str(),
                                            obj_desc_short(desc->Type().get()).c_str());
            continue;
        }

        result->Append(entry.Val());
    }

    return result;
}

double Event::Time() const {
    if ( ! meta )
        return detail::NO_TIMESTAMP;

    for ( const auto& m : *meta )
        if ( m.Id() == static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp) ) {
            if ( m.Val()->GetType()->Tag() != TYPE_TIME ) {

                zeek::reporter->InternalError("event metadata timestamp has wrong type: %s",
                                              obj_desc_short(m.Val()->GetType().get()).c_str());
            }

            return m.Val()->AsTime();
        }

    return detail::NO_TIMESTAMP;
}

void Event::Describe(ODesc* d) const {
    if ( d->IsReadable() )
        d->AddSP("event");

    bool s = d->IsShort();
    d->SetShort(s);

    if ( ! d->IsBinary() )
        d->Add("(");
    describe_vals(args, d);
    if ( ! d->IsBinary() )
        d->Add("(");
}

void Event::Dispatch() {
    if ( handler->ErrorHandler() )
        reporter->BeginErrorHandler();

    try {
        handler->Call(&args);
    } catch ( InterpreterException& e ) {

    }


    obj.reset();

    if ( handler->ErrorHandler() )
        reporter->EndErrorHandler();
}

EventMgr::~EventMgr() {
    while ( head ) {
        Event* n = head->NextEvent();
        Unref(head);
        head = n;
    }
}

void EventMgr::Enqueue(const EventHandlerPtr& h, Args vl, util::detail::SourceID src, analyzer::ID aid, Obj* obj) {
    detail::EventMetadataVectorPtr meta;







    bool want_network_timestamp =
        BifConst::EventMetadata::add_network_timestamp &&
        ((src == util::detail::SOURCE_LOCAL) ||
         (src == util::detail::SOURCE_BROKER && BifConst::EventMetadata::add_missing_remote_network_timestamp));

    if ( want_network_timestamp )
        meta = detail::MakeEventMetadataVector(run_state::network_time);

    QueueEvent(new Event(std::move(meta), h, std::move(vl), src, aid, obj));
}

void EventMgr::Enqueue(detail::EventMetadataVectorPtr meta, const EventHandlerPtr& h, Args vl,
                       util::detail::SourceID src, analyzer::ID aid, Obj* obj) {











    bool want_network_timestamp =
        BifConst::EventMetadata::add_network_timestamp &&
        ((src == util::detail::SOURCE_LOCAL) ||
         (src == util::detail::SOURCE_BROKER && BifConst::EventMetadata::add_missing_remote_network_timestamp));

    if ( want_network_timestamp ) {
        bool has_time = false;

        if ( ! meta ) {

            meta = detail::MakeEventMetadataVector(run_state::network_time);
        }
        else {

            for ( const auto& m : *meta ) {
                if ( m.Id() == static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp) ) {
                    has_time = true;

                    if ( m.Val()->GetType()->Tag() != TYPE_TIME ) {

                        zeek::reporter->InternalError("event metadata timestamp has wrong type: %s",
                                                      obj_desc_short(m.Val()->GetType().get()).c_str());
                    }
                }
            }

            if ( ! has_time ) {
                auto tv = zeek::make_intrusive<zeek::TimeVal>(run_state::network_time);
                meta->push_back({static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp), std::move(tv)});
            }
        }
    }

    QueueEvent(new Event(std::move(meta), h, std::move(vl), src, aid, obj));
}

void EventMgr::QueueEvent(Event* event) {
    bool done = PLUGIN_HOOK_WITH_RESULT(HOOK_QUEUE_EVENT, HookQueueEvent(event), false);

    if ( done )
        return;

    if ( ! head ) {
        head = tail = event;
    }
    else {
        tail->SetNext(event);
        tail = event;
    }

    ++event_mgr.num_events_queued;
}

void EventMgr::Dispatch(const EventHandlerPtr& h, zeek::Args vl) {
    detail::EventMetadataVectorPtr meta;


    if ( BifConst::EventMetadata::add_network_timestamp )
        meta = detail::MakeEventMetadataVector(run_state::network_time);

    auto* ev = new Event(std::move(meta), h, std::move(vl), util::detail::SOURCE_LOCAL, 0, nullptr);



    bool done = PLUGIN_HOOK_WITH_RESULT(HOOK_QUEUE_EVENT, HookQueueEvent(ev), false);
    if ( done )
        return;

    Event* old_current = current;
    current = ev;
    ev->Dispatch();
    current = old_current;
    Unref(ev);
}

void EventMgr::Drain() {
    if ( event_queue_flush_point )
        Enqueue(event_queue_flush_point, Args{});

    PLUGIN_HOOK_VOID(HOOK_DRAIN_EVENTS, HookDrainEvents());








    for ( int round = 0; head && round < 2; round++ ) {
        Event* event = head;
        head = nullptr;
        tail = nullptr;

        while ( event ) {
            Event* next = event->NextEvent();

            current = event;
            event->Dispatch();
            Unref(event);

            ++event_mgr.num_events_dispatched;
            event = next;
        }
    }



    current = nullptr;



    detail::trigger_mgr->Process();
}

void EventMgr::Describe(ODesc* d) const {
    int n = 0;
    Event* e;
    for ( e = head; e; e = e->NextEvent() )
        ++n;

    d->AddCount(n);

    for ( e = head; e; e = e->NextEvent() ) {
        e->Describe(d);
        d->NL();
    }
}

void EventMgr::Process() {




}

void EventMgr::InitPostScript() {

    const auto& et = zeek::id::find_type<zeek::EnumType>("EventMetadata::ID");
    if ( ! et )
        zeek::reporter->FatalError("Failed to find EventMetadata::ID");

    const auto& net_ts_val = et->GetEnumVal(et->Lookup("EventMetadata::NETWORK_TIMESTAMP"));
    if ( ! net_ts_val )
        zeek::reporter->FatalError("Failed to lookup EventMetadata::NETWORK_TIMESTAMP");

    if ( ! zeek::event_registry->RegisterMetadata(net_ts_val, zeek::base_type(zeek::TYPE_TIME)) )
        zeek::reporter->FatalError("Failed to register NETWORK_TIMESTAMP metadata");


    if ( BifConst::EventMetadata::add_missing_remote_network_timestamp &&
         ! BifConst::EventMetadata::add_network_timestamp )
        zeek::reporter->FatalError(
            "Setting EventMetadata::add_missing_remote_network_timestamp is only valid together with "
            "EventMetadata::add_network_timestamp");


    iosource_mgr->Register(this, true, false);
}
}
