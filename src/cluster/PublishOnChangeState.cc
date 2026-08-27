

#include "zeek/cluster/PublishOnChangeState.h"

#include <cstdio>
#include <optional>

#include "zeek/Attr.h"
#include "zeek/DebugLogger.h"
#include "zeek/Desc.h"
#include "zeek/Dict.h"
#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Timer.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/broker/Data.h"
#include "zeek/cluster/Backend.h"

namespace {


uint8_t changes_to_bitmask(const zeek::TableVal& changes) {
    uint8_t result = 0;

    for ( const auto& [k, _] : changes.ToMap() ) {
        assert(k->GetType()->Tag() == zeek::TYPE_LIST);
        assert(k->AsListVal()->Length() == 1);

        zeek_int_t enum_value = k->AsListVal()->Idx(0)->AsEnum();
        if ( enum_value > static_cast<zeek_int_t>(zeek::BifEnum::TABLE_ELEMENT_EXPIRED) )
            zeek::reporter->InternalError("invalid change in changes field: %" PRId64, enum_value);

        auto bifenum_val = static_cast<zeek::BifEnum::TableChange>(enum_value);
        result |= zeek::detail::table_change_to_bit(bifenum_val);
    }

    return result;
}


zeek::VectorValPtr listval_to_anyvec(const zeek::ListVal& lv) {
    static const auto& any_vec_type = zeek::id::find_type<zeek::VectorType>("any_vec");

    auto index_vec = zeek::make_intrusive<zeek::VectorVal>(any_vec_type);
    index_vec->Reserve(lv.Length());

    for ( int i = 0; i < lv.Length(); i++ )
        index_vec->Append(lv.Idx(i));

    return index_vec;
}





zeek::ValPtr maybe_unwrap_broker_data(zeek::Type& t, zeek::Val* any) {
    if ( any->GetType() == zeek::Broker::detail::DataVal::ScriptDataType() ) {
        auto ov = any->AsRecordVal()->GetField<zeek::OpaqueVal>(0);
        if ( ov->GetType() != zeek::Broker::detail::opaque_of_data_type ) {
            zeek::reporter->Error("PublishOnChange: bad broker::data wrapping: %s",
                                  zeek::obj_desc_short(ov->GetType()).c_str());
            return nullptr;
        }

        auto* data_val = static_cast<zeek::Broker::detail::DataVal*>(ov.get());

        if ( ! data_val->canCastTo(&t) ) {
            zeek::reporter->Error("PublishOnChange: cannot cast %s to %s", broker::to_string(data_val->data).c_str(),
                                  zeek::obj_desc_short(&t).c_str());
            return nullptr;
        }

        return data_val->castTo(&t);
    }

    return zeek::IntrusivePtr(zeek::NewRef{}, any);
}


zeek::ListValPtr raw_vec_to_listval(zeek::TypeListPtr tl, const std::vector<std::optional<zeek::ZVal>>& raw_vec) {
    std::vector<zeek::ValPtr> index_vals;

    const auto& types = tl->GetTypes();
    index_vals.reserve(raw_vec.size());

    for ( size_t i = 0; i < raw_vec.size(); i++ ) {
        const auto& typ = tl->IsPure() ? tl->GetPureType() : types[i];


        if ( ! raw_vec[i].has_value() ) {
            zeek::reporter->InternalWarning("PublishOnChange::raw_vec_to_listval: Unset raw_vec %zu", i);
            return nullptr;
        }


        zeek::Val* index_any_i = raw_vec[i]->AsAny();
        zeek::ValPtr index_i = maybe_unwrap_broker_data(*typ, index_any_i);
        if ( ! index_i ) {
            zeek::reporter->InternalWarning("PublishOnChange::raw_vec_to_listval: failed to unwrap %zu", i);
            return nullptr;
        }

        index_vals.emplace_back(index_i);
    }

    return zeek::make_intrusive<zeek::ListVal>(std::move(tl), std::move(index_vals));
}


bool topic_func_is_ok(const zeek::TableVal& tv, const zeek::Func& f) {
    const auto& index_types = tv.GetType<zeek::TableType>()->GetIndexTypes();
    const auto& arg_types = f.GetType()->ParamList()->GetTypes();
    const auto& yield_type = f.GetType()->Yield();

    if ( ! yield_type || yield_type->Tag() != zeek::TYPE_STRING )
        return false;

    if ( index_types.size() != arg_types.size() )
        return false;

    for ( size_t i = 0; i < index_types.size(); i++ ) {
        if ( ! zeek::same_type(index_types[i], arg_types[i]) )
            return false;
    }

    return true;
}

zeek::StringValPtr invoke_cluster_node_id() {
    const auto f = zeek::id::find_func("Cluster::node_id");
    zeek::Args args;
    const auto r = f->Invoke(&args);
    if ( ! r || r->GetType()->Tag() != zeek::TYPE_STRING )
        zeek::reporter->FatalError("Failed to invoke Cluster::node_id()");

    return zeek::cast_intrusive<zeek::StringVal>(r);
}


int field_offset_or_fatal(const zeek::RecordTypePtr& rt, const char* name) {
    int offset = rt->FieldOffset(name);

    if ( offset < 0 )
        zeek::reporter->FatalError("no field %s in type %s", name, rt->GetName().c_str());

    return offset;
}



class RecordBuilderHelper final {
public:
    RecordBuilderHelper() {
        poc_attr = zeek::id::find_type<zeek::RecordType>("Cluster::PublishOnChangeAttr");
        poc_attr_changes_offset = field_offset_or_fatal(poc_attr, "changes");
        poc_attr_topic_offset = field_offset_or_fatal(poc_attr, "topic");
        poc_attr_max_batch_size_offset = field_offset_or_fatal(poc_attr, "max_batch_size");
        poc_attr_max_batch_delay_offset = field_offset_or_fatal(poc_attr, "max_batch_delay");

        table_change_header = zeek::id::find_type<zeek::RecordType>("Cluster::TableChangeHeader");
        if ( ! table_change_header )
            zeek::reporter->FatalError("Cluster::TableChangeHeader not found");
        tch_id_offset = field_offset_or_fatal(table_change_header, "id");
        tch_ts_offset = field_offset_or_fatal(table_change_header, "ts");
        tch_node_id_offset = field_offset_or_fatal(table_change_header, "node_id");

        table_change_info = zeek::id::find_type<zeek::RecordType>("Cluster::TableChangeInfo");
        if ( ! table_change_info )
            zeek::reporter->FatalError("Cluster::TableChangeInfo not found");

        tci_change_offset = field_offset_or_fatal(table_change_info, "change");
        tci_ts_offset = field_offset_or_fatal(table_change_info, "ts");
        tci_index_offset = field_offset_or_fatal(table_change_info, "index");
        tci_value_offset = field_offset_or_fatal(table_change_info, "value");
        tci_previous_value_offset = field_offset_or_fatal(table_change_info, "previous_value");

        table_change_infos = zeek::id::find_type<zeek::VectorType>("Cluster::TableChangeInfos");
        if ( ! table_change_infos )
            zeek::reporter->FatalError("Cluster::TableChangeInfos not found");
    }

    zeek::RecordValPtr BuildTableChangeHeader(zeek::StringValPtr id, double now, zeek::StringValPtr node_id) const {
        assert(id->Len() > 0);
        assert(node_id->Len() > 0);

        auto tcheader = make_intrusive<zeek::RecordVal>(table_change_header);
        tcheader->Assign(tch_id_offset, id.get());
        tcheader->AssignTime(tch_ts_offset, now);
        tcheader->Assign(tch_node_id_offset, node_id.get());




        id.release();
        node_id.release();

        return tcheader;
    }
    zeek::VectorValPtr BuildTableChangeInfos() const { return make_intrusive<zeek::VectorVal>(table_change_infos); }

    zeek::RecordValPtr BuildChangeInfo(zeek_int_t change, double now, const zeek::ListVal& index,
                                       const zeek::ValPtr& value, const zeek::ValPtr& previous_value) const {

        auto tci = make_intrusive<zeek::RecordVal>(table_change_info);



        tci->Assign(tci_change_offset, change);
        tci->AssignTime(tci_ts_offset, now);
        tci->Assign(tci_index_offset, listval_to_anyvec(index));

        if ( value ) {
            if ( is_atomic_type(value->GetType()) )

                tci->Assign(tci_value_offset, value);
            else
                tci->Assign(tci_value_offset, value->Clone());
        }

        if ( previous_value ) {
            if ( zeek::is_atomic_type(previous_value->GetType()) )

                tci->Assign(tci_previous_value_offset, previous_value);
            else
                tci->Assign(tci_previous_value_offset, previous_value->Clone());
        }

        return tci;
    }


    zeek::RecordTypePtr poc_attr;
    int poc_attr_changes_offset = -1;
    int poc_attr_topic_offset = -1;
    int poc_attr_max_batch_size_offset = -1;
    int poc_attr_max_batch_delay_offset = -1;


    zeek::RecordTypePtr table_change_header;
    int tch_id_offset = -1;
    int tch_ts_offset = -1;
    int tch_node_id_offset = -1;

    zeek::RecordTypePtr table_change_info;


    int tci_change_offset = -1;
    int tci_ts_offset = -1;
    int tci_index_offset = -1;
    int tci_value_offset = -1;
    int tci_previous_value_offset = -1;

    zeek::VectorTypePtr table_change_infos;
};

}



#define debug(fmt, ...)                                                                                                \
    do {                                                                                                               \
        DBG_LOG(DBG_CLUSTER, fmt, __VA_ARGS__);                                                                        \
    } while ( 0 )



namespace zeek::detail {




class PublishQueuedChangesTimer : public Timer {
public:
    PublishQueuedChangesTimer(double t, PublishOnChangeState* state)
        : Timer(t, TIMER_TABLE_PUBLISH_QUEUED_CHANGES), state(state) {}

    void Dispatch(double t, bool is_expire) override {
        state->ResetTimer();
        state->PublishQueuedChanges(t);
    }

private:
    PublishOnChangeState* state;
};


std::optional<std::string> PublishOnChangeState::forward_topic;
EventHandlerPtr PublishOnChangeState::eh_table_change_infos;
EventHandlerPtr PublishOnChangeState::eh_forward_table_change_infos;
StringValPtr PublishOnChangeState::local_node_id;

PublishOnChangeState::PublishOnChangeState(StringValPtr identifier, TableVal* table_val, uint8_t change_mask,
                                           std::optional<std::string> topic, FuncPtr topic_func, size_t max_batch_size,
                                           double max_batch_delay)
    : identifier(std::move(identifier)),
      table_val(table_val),
      change_mask(change_mask),
      max_batch_size(max_batch_size),
      max_batch_delay(max_batch_delay),
      topic(std::move(topic)),
      topic_func(std::move(topic_func)) {}


PublishOnChangeState::~PublishOnChangeState() {

    CancelPublishTimer();
}


void PublishOnChangeState::QueueChange(BifEnum::TableChange change, const Val& index, const ValPtr& value,
                                       const ValPtr& previous_value) {

    static const auto helper = RecordBuilderHelper();


    static const auto change_new = id::find("TABLE_ELEMENT_NEW")->GetVal()->AsEnum();
    static const auto change_changed = id::find("TABLE_ELEMENT_CHANGED")->GetVal()->AsEnum();
    static const auto change_removed = id::find("TABLE_ELEMENT_REMOVED")->GetVal()->AsEnum();
    static const auto change_expired = id::find("TABLE_ELEMENT_EXPIRED")->GetVal()->AsEnum();


    if ( ! topic_func && ! topic.has_value() ) {
        const auto* loc = table_val->GetLocationInfo();
        std::string loc_str = util::fmt("%s:%d", loc->FileName(), loc->FirstLine());
        reporter->InternalError("No topic for table with &publish_on_change at %s", loc_str.c_str());
    }

    auto now = run_state::network_time;

    auto tcinfo = helper.BuildChangeInfo(change, now, *index.AsListVal(), value, previous_value);

    debug("queue %d index=%s value=%p %s tcinfo refs=%d", change, obj_desc_short(&index).c_str(), value.get(),
          value ? obj_desc_short(value).c_str() : "<no value>", tcinfo->RefCnt());


    if ( topic.has_value() ) {
        assert(! topic_func);
        assert(topic_changes.empty());

        if ( ! changes )
            changes = helper.BuildTableChangeInfos();

        if ( ! changes->Append(std::move(tcinfo)) )
            reporter->InternalError("failed to append rv to changes");
    }
    else if ( topic_func ) {

        const auto* lv = index.AsListVal();
        Args args;
        args.reserve(lv->Length());
        for ( int i = 0; i < lv->Length(); i++ )
            args.emplace_back(lv->Idx(i));

        auto result = topic_func->Invoke(&args);
        if ( ! result || result->GetType()->Tag() != TYPE_STRING ) {
            reporter->Error("PublishOnChange: Failed to call topic_func %s for %s (result=%s)",
                            obj_desc_short(topic_func).c_str(), identifier->ToStdString().c_str(),
                            result ? obj_desc_short(result).c_str() : "nil");
            return;
        }


        auto topic_sv = result->AsStringVal()->ToStdStringView();


        auto it = topic_changes.find(topic_sv);
        if ( it == topic_changes.end() ) {
            VectorValPtr topic_changes_value = helper.BuildTableChangeInfos();
            const auto [inserted_it, inserted] = topic_changes.emplace(topic_sv, std::move(topic_changes_value));
            assert(inserted);
            it = inserted_it;
        }


        if ( ! it->second->Append(std::move(tcinfo)) )
            reporter->InternalError("failed to append rv to topic_changes");
    }
    else {
        reporter->InternalError("Neither topic nor topic_func set for %s", identifier->ToStdString().c_str());
    }

    queued_changes++;











    if ( max_batch_delay == 0.0 || max_batch_size == 0 ) {
        PublishQueuedChanges(now);
    }
    else if ( (now - last_publish_ts) > max_batch_delay ) {
        PublishQueuedChanges(now);
    }
    else if ( queued_changes >= max_batch_size ) {
        PublishQueuedChanges(now);
    }

    else {

        if ( ! timer )
            timer = ArmPublishTimer(last_publish_ts);
    }
}

void PublishOnChangeState::PublishQueuedChanges(double now, const std::string& topic, RecordValPtr tcheader,
                                                VectorValPtr tcinfos) const {

    detail::EventMetadataVectorPtr meta;
    if ( BifConst::EventMetadata::add_network_timestamp )
        meta = detail::MakeEventMetadataVector(now);






    const auto& eh_effective = forward_topic.has_value() ? eh_forward_table_change_infos : eh_table_change_infos;
    const auto& topic_effective = forward_topic.has_value() ? forward_topic.value() : topic;

    debug("publish event=%s topic=%s topic_effective=%s table_change_infos=%u", eh_effective->Name(), topic.c_str(),
          topic_effective.c_str(), tcinfos->Size());


    Args args{std::move(tcheader), std::move(tcinfos)};



    if ( forward_topic.has_value() ) {
        args.emplace_back(make_intrusive<StringVal>(topic));
        debug("publish event - forwarding via %s", forward_topic.value().c_str());
    }

    cluster::Event ev{eh_effective, std::move(args), std::move(meta)};

    if ( ! cluster::backend->PublishEvent(topic_effective, ev) )
        reporter->Error("PublishOnChange: PublishEvent() failed for %s to %s", eh_effective->Name(),
                        topic_effective.c_str());
}

void PublishOnChangeState::PublishQueuedChanges(double now) {
    static const auto helper = RecordBuilderHelper();


    CancelPublishTimer();

    auto tcheader = helper.BuildTableChangeHeader(identifier, now, GetLocalNodeId());

    if ( topic.has_value() ) {
        if ( ! topic_changes.empty() )
            reporter->InternalError("topic set, but topic_changes not empty");

        if ( changes )
            PublishQueuedChanges(now, *topic, tcheader, changes);
        else
            reporter->InternalWarning("PublishOnChangeState: Weird: PublishQueuedChanges() without queud changes");

        changes = helper.BuildTableChangeInfos();
    }
    else if ( ! topic_changes.empty() ) {
        for ( const auto& [topic, tcinfos] : topic_changes ) {
            PublishQueuedChanges(now, topic, tcheader, tcinfos);
        }

        topic_changes.clear();
    }

    queued_changes = 0;
    last_publish_ts = now;
}

void PublishOnChangeState::ApplyChanges(const RecordVal& tcheader, const VectorVal& tcinfos) {
    static const auto helper = RecordBuilderHelper();




    InApplyChangesScope scope(this);

    const auto& raw_vec = tcinfos.RawVec();

    for ( size_t i = 0; i < tcinfos.Size(); i++ ) {

        const auto& tci = raw_vec[i]->AsRecord();

        auto change = tci->GetFieldAs<EnumVal>(helper.tci_change_offset);
        const auto& index_raw_vec = tci->GetFieldAs<VectorVal>(helper.tci_index_offset)->RawVec();

        ValPtr index = raw_vec_to_listval(table_val->GetType()->AsTableType()->GetIndices(), index_raw_vec);
        if ( ! index ) {
            reporter->InternalWarning("PublishOnChange: failed to create index (change=%" PRId64
                                      " i=%zu identifier=%s)",
                                      change, i, identifier->ToStdString().c_str());
            continue;
        }

        ValPtr value;
        if ( tci->HasField(helper.tci_value_offset) ) {

            value = tci->GetField(helper.tci_value_offset);

            if ( table_val->GetType()->IsSet() ) {
                reporter->InternalWarning("PublishOnChange: unexpected value for set (index=%s value=%s change=%" PRId64
                                          " i=%zu identifier=%s)",
                                          obj_desc_short(index).c_str(), obj_desc_short(value).c_str(), change, i,
                                          identifier->ToStdString().c_str());

                continue;
            }

            value =
                maybe_unwrap_broker_data(*table_val->GetType()->Yield(), tci->GetField(helper.tci_value_offset).get());
        }




        if ( tci->HasField(helper.tci_previous_value_offset) ) {

            if ( change == BifEnum::TABLE_ELEMENT_NEW || change == BifEnum::TABLE_ELEMENT_REMOVED ||
                 change == BifEnum::TABLE_ELEMENT_EXPIRED ) {
                reporter
                    ->InternalWarning("PublishOnChange: unexpected previous value (index=%s value=%s change=%" PRId64
                                      " i=%zu identifier=%s)",
                                      obj_desc_short(index).c_str(), obj_desc_short(value).c_str(), change, i,
                                      identifier->ToStdString().c_str());

                continue;
            }
        }


        switch ( static_cast<BifEnum::TableChange>(change) ) {
            case BifEnum::TABLE_ELEMENT_NEW:
            case BifEnum::TABLE_ELEMENT_CHANGED:
                debug("assigning %s %s (change=%" PRId64 ")", obj_desc_short(index).c_str(),
                      value ? obj_desc_short(value).c_str() : "<no value>", change);

                table_val->Assign(index, value, false, nullptr);

                break;

            case BifEnum::TABLE_ELEMENT_EXPIRED:
            case BifEnum::TABLE_ELEMENT_REMOVED:
                debug("removing %s (change=%" PRId64 ")", obj_desc_short(index).c_str(), change);
                table_val->Remove(*index, false, nullptr);
                break;

            default:
                reporter->InternalWarning("PublishOnChange: unexpected change (index=%s value=%s change=%" PRId64
                                          " i=%zu identifier=%s)",
                                          obj_desc_short(index).c_str(),
                                          value ? obj_desc_short(value).c_str() : "<no value>", change, i,
                                          identifier->ToStdString().c_str());
        }
    }
}

detail::Timer* PublishOnChangeState::ArmPublishTimer(double from) {
    auto* new_timer = new PublishQueuedChangesTimer(from + max_batch_delay, this);
    detail::timer_mgr->Add(new_timer);
    return new_timer;
}

void PublishOnChangeState::CancelPublishTimer() {
    if ( timer ) {
        debug("cancelling publish timer %p", timer);
        detail::timer_mgr->Cancel(timer);
        timer = nullptr;
    }
}

std::unique_ptr<PublishOnChangeState> PublishOnChangeState::Instantiate(const std::string& id, TableVal* table_val,
                                                                        const RecordVal& rec) {

    static const auto helper = RecordBuilderHelper();

    static const auto poc_attr_type = id::find_type<RecordType>("Cluster::PublishOnChangeAttr");
    static const int changes_offset = poc_attr_type->FieldOffset("changes");
    static const int topic_offset = poc_attr_type->FieldOffset("topic");
    static const int max_batch_size_offset = poc_attr_type->FieldOffset("max_batch_size");
    static const int max_batch_delay_offset = poc_attr_type->FieldOffset("max_batch_delay");

    if ( rec.GetType() != poc_attr_type )
        reporter->InternalError("got %s instead of %s", obj_desc_short(rec.GetType()).c_str(),
                                obj_desc_short(poc_attr_type).c_str());

    const auto changes = rec.GetField<TableVal>(changes_offset);
    assert(changes->GetType()->IsSet());
    assert(changes->GetType<TableType>()->GetIndexTypes().size() == 1);

    if ( changes->Size() == 0 ) {
        rec.Error("changes field for &publish_on_change cannot be empty");
        return nullptr;
    }

    uint8_t change_mask = changes_to_bitmask(*changes);

    std::optional<std::string> topic;
    FuncPtr topic_func;

    if ( rec.HasField(topic_offset) ) {

        auto topic_val = rec.GetField(topic_offset);
        const auto& topic_val_type = topic_val->GetType();

        if ( topic_val_type->Tag() == TYPE_STRING ) {
            topic = topic_val->AsStringVal()->ToStdString();
        }
        else if ( topic_val_type->Tag() == TYPE_FUNC ) {
            topic_func = topic_val->AsFuncVal()->AsFuncPtr();
            if ( ! topic_func_is_ok(*table_val, *topic_func) ) {
                rec.Error(util::fmt("topic function %s not applicable for table type %s",
                                    obj_desc_short(topic_func->GetType()).c_str(),
                                    obj_desc_short(table_val->GetType()).c_str()));

                return nullptr;
            }
        }
        else {
            rec.Error(util::fmt("topic must be string or a function returning a string, got %s",
                                obj_desc_short(topic_val).c_str()));

            return nullptr;
        }
    }
    else {


        const char* topic_sep = "/";
        topic = util::fmt("zeek%stable%s%s%s", topic_sep, topic_sep, id.c_str(), topic_sep);
        debug("using topic '%s' for table %s", topic->c_str(), id.c_str());
    }

    zeek_uint_t max_batch_size = rec.GetField<CountVal>(max_batch_size_offset)->AsCount();
    double max_batch_delay = rec.GetField<IntervalVal>(max_batch_delay_offset)->AsInterval();

    auto id_val = zeek::make_intrusive<zeek::StringVal>(id);

    return std::make_unique<PublishOnChangeState>(std::move(id_val), table_val, change_mask, std::move(topic),
                                                  std::move(topic_func), max_batch_size, max_batch_delay);
}

const StringValPtr& PublishOnChangeState::GetLocalNodeId() {
    if ( ! local_node_id )
        local_node_id = invoke_cluster_node_id();

    return local_node_id;
}

void PublishOnChangeState::InitPostScript() {

    eh_table_change_infos = event_registry->Register("Cluster::table_change_infos");
    if ( ! eh_table_change_infos.Ptr() )
        reporter->InternalError("could not find Cluster::table_change_infos event for &publish_on_change");

    eh_forward_table_change_infos = event_registry->Register("Cluster::forward_table_change_infos");
    if ( ! eh_forward_table_change_infos.Ptr() )
        reporter->InternalError("could not find Cluster::forward_table_change_infos event for &publish_on_change");

    const auto poc_attr_rt = id::find_type<RecordType>("Cluster::PublishOnChangeAttr");







    for ( const auto& [name, id] : global_scope()->Vars() ) {
        auto poc_attr = id->GetAttr(detail::ATTR_PUBLISH_ON_CHANGE);
        if ( ! poc_attr )
            continue;

        if ( id->GetType()->Tag() != TYPE_TABLE )
            reporter->InternalError("&publish_on_change attribute on non-table %s (%s)", id->Name(),
                                    id->GetType() ? obj_desc_short(id->GetType()).c_str() : "???");

        auto expr = poc_attr->GetExpr();






        if ( expr->Tag() == EXPR_RECORD_CONSTRUCTOR && expr->GetType()->GetName().empty() ) {
            auto rce = cast_intrusive<RecordConstructorExpr>(expr);
            expr = zeek::make_intrusive<RecordConstructorExpr>(poc_attr_rt, rce->Op());
        }

        ValPtr val;
        try {
            val = expr->Eval(nullptr);
        } catch ( InterpreterException& ) {

            continue;
        }

        if ( ! val || ! val->GetType() )

            continue;

        if ( val->GetType()->Tag() != TYPE_RECORD || val->GetType() != poc_attr_rt ) {
            expr->Error("&publish_on_change expects a record value of type PublishOnChangeAttr");
            continue;
        }



        auto table_val = cast_intrusive<TableVal>(id->GetVal());
        auto poc_rec_val = with_location_of(cast_intrusive<RecordVal>(val), table_val);

        auto poc_state = PublishOnChangeState::Instantiate(name, table_val.get(), *poc_rec_val);
        if ( poc_state )
            table_val->SetPublishOnChangeState(std::move(poc_state));
    }
}

bool cluster_publish_table(const std::string& topic, const TableVal& table_val, size_t batch_size) {

    static const auto helper = RecordBuilderHelper();




    const auto* poc_state = table_val.GetPublishOnChangeState();
    if ( ! poc_state )
        return false;


    auto now = run_state::network_time;
    auto tcheader =
        helper.BuildTableChangeHeader(poc_state->GetIdentifier(), now, PublishOnChangeState::GetLocalNodeId());


    size_t published = 0;

    const auto* dict = table_val.Get();

    auto tcinfos = helper.BuildTableChangeInfos();
    tcinfos->Reserve(std::min(dict->Length() - published, batch_size));

    for ( const auto& tve : *dict ) {
        ListValPtr index = table_val.RecreateIndex(*tve.GetHashKey());
        auto tcinfo = helper.BuildChangeInfo(BifEnum::TABLE_ELEMENT_NEW, now, *index, tve.value->GetVal(),
                                             nullptr);

        tcinfos->Append(std::move(tcinfo));

        if ( tcinfos->Size() == batch_size ) {
            poc_state->PublishQueuedChanges(now, topic, tcheader, tcinfos);
            tcinfos = helper.BuildTableChangeInfos();
            tcinfos->Reserve(std::min(dict->Length() - published, batch_size));
        }

        ++published;
    }


    if ( tcinfos->Size() > 0 )
        poc_state->PublishQueuedChanges(now, topic, tcheader, tcinfos);


    return true;
}
}
