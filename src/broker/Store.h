

#pragma once

#include <broker/backend.hh>
#include <broker/backend_options.hh>
#include <broker/store.hh>
#include <broker/store_event.hh>

#include "zeek/Expr.h"
#include "zeek/OpaqueVal.h"
#include "zeek/Trigger.h"
#include "zeek/broker/Data.h"
#include "zeek/broker/data.bif.h"
#include "zeek/broker/store.bif.h"

namespace zeek::Broker::detail {

extern OpaqueTypePtr opaque_of_store_handle;






EnumValPtr query_status(bool success);





inline RecordValPtr query_result() {
    auto rval = make_intrusive<RecordVal>(BifType::Record::Broker::QueryResult);
    rval->Assign(0, query_status(false));
    rval->Assign(1, make_intrusive<RecordVal>(BifType::Record::Broker::Data));
    return rval;
}






inline RecordValPtr query_result(RecordValPtr data) {
    auto rval = make_intrusive<RecordVal>(BifType::Record::Broker::QueryResult);
    rval->Assign(0, query_status(true));
    rval->Assign(1, std::move(data));
    return rval;
}






static std::optional<broker::timespan> convert_expiry(double e) {
    std::optional<broker::timespan> ts;

    if ( e ) {
        broker::timespan x;
        broker::convert(e, x);
        ts = x;
    }

    return ts;
}




class StoreQueryCallback {
public:
    StoreQueryCallback(zeek::detail::trigger::Trigger* arg_trigger, const void* arg_assoc, broker::store store)
        : trigger(arg_trigger), assoc(arg_assoc), store(std::move(store)) {
        Ref(trigger);
    }

    ~StoreQueryCallback() { Unref(trigger); }

    void Result(const RecordValPtr& result) {
        trigger->Cache(assoc, result.get());
        trigger->Release();
    }

    void Abort() {
        auto result = query_result();
        trigger->Cache(assoc, result.get());
        trigger->Release();
    }

    bool Disabled() const { return trigger->Disabled(); }

    const broker::store& Store() const { return store; }

private:
    zeek::detail::trigger::Trigger* trigger;
    const void* assoc;
    broker::store store;
};




class StoreHandleVal : public OpaqueVal {
public:
    StoreHandleVal() : OpaqueVal(Broker::detail::opaque_of_store_handle) {}

    StoreHandleVal(broker::store s)
        : OpaqueVal(Broker::detail::opaque_of_store_handle),
          store{std::move(s)},
          proxy{store},
          store_pid{store.frontend_id()},
          forward_to{},
          have_store{true} {}

    void Put(BrokerData&& key, BrokerData&& value, std::optional<BrokerTimespan> expiry = std::nullopt);

    void Erase(BrokerData&& key);

    void ValDescribe(ODesc* d) const override;

    broker::store store;
    broker::store::proxy proxy;
    broker::entity_id store_pid;

    TableValPtr forward_to;
    bool have_store = false;

protected:
    IntrusivePtr<Val> DoClone(CloneState* state) override { return {NewRef{}, this}; }

    DECLARE_OPAQUE_VALUE_DATA(StoreHandleVal)
};


broker::backend to_backend_type(BifEnum::Broker::BackendType type);


broker::backend_options to_backend_options(broker::backend backend, RecordVal* options);

}
