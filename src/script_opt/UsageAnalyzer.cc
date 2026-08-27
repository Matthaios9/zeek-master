

#include "zeek/script_opt/UsageAnalyzer.h"

#include "zeek/EventRegistry.h"
#include "zeek/script_opt/IDOptInfo.h"

namespace zeek::detail {



std::unordered_set<std::string> script_events;

void register_new_event(const IDPtr& id) { script_events.insert(id->Name()); }

UsageAnalyzer::UsageAnalyzer(std::vector<FuncInfo>& funcs) {


    auto script_events_orig = script_events;
    script_events.clear();

    for ( auto& ev : script_events_orig )
        if ( ! event_registry->NotOnlyRegisteredFromScript(ev) )
            script_events.insert(ev);


    current_scope = global_scope();

    FindSeeds(reachables);
    FullyExpandReachables();









    auto& globals = global_scope()->Vars();

    for ( auto& gpair : globals ) {
        auto& id = gpair.second;
        auto& t = id->GetType();

        if ( ! t || t->Tag() != TYPE_FUNC )
            continue;

        if ( auto gv = id->GetVal() )
            for ( const auto& body : gv->AsFunc()->GetBodies() )
                if ( body.stmts->Tag() == STMT_CPP )

                    return;

        if ( t->AsFuncType()->Flavor() == FUNC_FLAVOR_FUNCTION )
            continue;

        if ( reachables.contains(id) )
            continue;

        auto flavor = t->AsFuncType()->FlavorString();
        auto loc = id->GetLocationInfo();

        id->Warn(util::fmt("handler for non-existing %s cannot be invoked", flavor.c_str()));





        reachables.insert(id);
        Expand(id);
    }


    for ( auto& gpair : globals ) {
        auto& id = gpair.second;

        if ( reachables.contains(id) )
            continue;

        auto f = GetFuncIfAny(id);
        if ( ! f )
            continue;

        auto loc = id->GetLocationInfo();

        id->Warn("non-exported function does not have any callers");








    }
}







class AttrExprIdsCollector : public TraversalCallback {
public:
    TraversalCode PreAttr(const Attr* attr) override {
        ++attr_depth;
        return TC_CONTINUE;
    }

    TraversalCode PostAttr(const Attr* attr) override {
        --attr_depth;
        return TC_CONTINUE;
    }

    TraversalCode PreType(const Type* t) override {
        if ( analyzed_types.contains(t) )
            return TC_ABORTSTMT;

        analyzed_types.insert(t);
        return TC_CONTINUE;
    }

    TraversalCode PreID(const ID* raw_id) override {
        IDPtr id{NewRef{}, const_cast<ID*>(raw_id)};

        if ( ids.contains(id) )
            return TC_ABORTSTMT;

        if ( attr_depth > 0 )
            ids.insert(id);

        auto& t = id->GetType();
        if ( t )
            t->Traverse(this);

        if ( auto& attrs = id->GetAttrs() )
            attrs->Traverse(this);

        return TC_CONTINUE;
    }

    int attr_depth = 0;
    std::unordered_set<IDPtr> ids;
    std::set<const Type*> analyzed_types;
};

void UsageAnalyzer::FindSeeds(IDSet& seeds) const {
    AttrExprIdsCollector attr_ids_collector;
    for ( auto& gpair : global_scope()->Vars() ) {
        auto& id = gpair.second;

        if ( id->GetAttr(ATTR_IS_USED) || id->GetAttr(ATTR_DEPRECATED) ) {
            seeds.insert(id);
            continue;
        }

        auto f = GetFuncIfAny(id);

        if ( f && id->GetType<FuncType>()->Flavor() == FUNC_FLAVOR_EVENT ) {
            if ( ! script_events.contains(f->GetName()) )
                seeds.insert(id);

            continue;
        }




        if ( id->IsExport() || id->ModuleName() == "GLOBAL" )
            seeds.insert(id);
        else


            id->Traverse(&attr_ids_collector);
    }

    seeds.insert(attr_ids_collector.ids.begin(), attr_ids_collector.ids.end());
}

const Func* UsageAnalyzer::GetFuncIfAny(const IDPtr& id) const {
    auto& t = id->GetType();
    if ( ! t || t->Tag() != TYPE_FUNC )
        return nullptr;

    auto fv = cast_intrusive<FuncVal>(id->GetVal());
    if ( ! fv )
        return nullptr;

    auto func = fv->Get();
    return func->GetKind() == Func::SCRIPT_FUNC ? func : nullptr;
}

void UsageAnalyzer::FullyExpandReachables() {


    if ( ExpandReachables(reachables) ) {
        auto r = new_reachables;
        reachables.insert(r.begin(), r.end());

        while ( ExpandReachables(r) ) {
            r = new_reachables;
            reachables.insert(r.begin(), r.end());
        }
    }
}

bool UsageAnalyzer::ExpandReachables(const IDSet& curr_r) {
    new_reachables.clear();

    for ( const auto& r : curr_r )
        Expand(r);

    return ! new_reachables.empty();
}

void UsageAnalyzer::Expand(const IDPtr& id) {













    analyzed_IDs.clear();

    id->Traverse(this);
}

TraversalCode UsageAnalyzer::PreID(const ID* raw_id) {
    IDPtr id{NewRef{}, const_cast<ID*>(raw_id)};

    if ( analyzed_IDs.contains(id) )

        return TC_ABORTSTMT;


    analyzed_IDs.insert(id);

    auto f = GetFuncIfAny(id);

    if ( f && ! reachables.contains(id) )

        new_reachables.insert(id);

    auto& t = id->GetType();
    if ( t )
        t->Traverse(this);

    auto& attrs = id->GetAttrs();
    if ( attrs )
        attrs->Traverse(this);



    for ( auto& ie : id->GetOptInfo()->GetInitExprs() )
        if ( ie )
            ie->Traverse(this);

    return TC_CONTINUE;
}

TraversalCode UsageAnalyzer::PreType(const Type* t) {
    if ( analyzed_types.contains(t) )
        return TC_ABORTSTMT;


    analyzed_types.insert(t);
    return TC_CONTINUE;
}

}
