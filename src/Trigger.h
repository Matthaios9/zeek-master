

#pragma once

#include "zeek/zeek-config.h"

#include <list>
#include <map>
#include <vector>

#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Notifier.h"
#include "zeek/Obj.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/util.h"

namespace zeek {

class ODesc;
class Val;

using ValPtr = IntrusivePtr<Val>;

namespace telemetry {
class Gauge;
class Counter;
using GaugePtr = std::shared_ptr<Gauge>;
using CounterPtr = std::shared_ptr<Counter>;
}

namespace detail {

class Frame;
class Stmt;
class Expr;
class CallExpr;
class ID;
class WhenInfo;

using StmtPtr = IntrusivePtr<Stmt>;

namespace trigger {




class TriggerTimer;
class TriggerTraversalCallback;

class Trigger final : public Obj, public notifier::detail::Receiver {
public:

















    Trigger(const std::shared_ptr<WhenInfo>& wi, const IDSet& globals, std::vector<ValPtr> local_aggrs, double timeout,
            Frame* f, const Location* loc = nullptr);

    ~Trigger() override;





    bool Eval();


    void Timeout();


    double TimeoutValue() const { return timeout_value; }



    void Hold() { delayed = true; }


    void Release() { delayed = false; }



    void Attach(Trigger* trigger);








    bool Cache(const void* obj, Val* val);
    Val* Lookup(const void* obj);



    void Disable();

    bool Disabled() const { return disabled; }

    void Describe(ODesc* d) const override;



    void Modified(zeek::notifier::detail::Modifiable* m) override;




    void Terminate() override;

    const char* Name() const { return name.c_str(); }

private:
    friend class TriggerTimer;

    void ReInit(const std::vector<ValPtr>& index_expr_results);

    void Register(const ID* id);
    void Register(Val* val);
    void UnregisterAll();

    ExprPtr cond;
    StmtPtr body;
    StmtPtr timeout_stmts;
    ExprPtr timeout;
    double timeout_value;
    Frame* frame;
    bool is_return;

    std::string name;

    TriggerTimer* timer;
    Trigger* attached;

    bool delayed;
    bool disabled;


    IDSet globals;
    IDSet locals;



    bool have_trigger_elems = false;




    std::vector<ValPtr> local_aggrs;

    std::vector<std::pair<Obj*, notifier::detail::Modifiable*>> objs;

    using ValCache = std::map<const void*, Val*>;
    ValCache cache;
};

class Manager final : public iosource::IOSource {
public:
    Manager();
    ~Manager() override;

    void InitPostScript();

    double GetNextTimeout() override;
    void Process() override;
    const char* Tag() override { return "TriggerMgr"; }

    void Queue(Trigger* trigger);

    struct Stats {
        unsigned long total;
        unsigned long pending;
    };

    void GetStats(Stats* stats);

private:
    using TriggerList = std::list<Trigger*>;
    TriggerList* pending;
    telemetry::CounterPtr trigger_count;
    telemetry::GaugePtr trigger_pending;
};

}

ZEEK_EXTERN_DATA trigger::Manager* trigger_mgr;

}
}
