

#include "zeek/script_opt/Inline.h"

#include "zeek/EventRegistry.h"
#include "zeek/module_util.h"
#include "zeek/script_opt/Expr.h"
#include "zeek/script_opt/FuncInfo.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/StmtOptInfo.h"
#include "zeek/script_opt/ZAM/Support.h"

namespace zeek::detail {

constexpr int MAX_INLINE_SIZE = 1000;

void Inliner::Analyze() {




    std::unordered_map<const Func*, std::unordered_set<const Func*>> call_set;



    for ( auto& f : funcs ) {







        if ( is_special_script_func(f.Func()->GetName()) )
            continue;



        if ( is_ZAM_replaceable_script_func(f.Func()->GetName()) )
            continue;

        std::unordered_set<const Func*> cs;


        non_recursive_funcs.insert(f.Func());

        for ( auto& func : f.Profile()->ScriptCalls() ) {
            cs.insert(func);

            if ( func == f.Func() ) {
                if ( report_recursive )
                    printf("%s is directly recursive\n", func->GetName().c_str());

                non_recursive_funcs.erase(func);
            }
        }

        call_set[f.Func()] = cs;

        for ( auto& ind_func : f.Profile()->IndirectFuncs() ) {
            auto& v = ind_func->GetVal();
            if ( ! v )

                continue;

            auto vf = v->AsFunc();
            if ( vf->GetKind() != BuiltinFunc::SCRIPT_FUNC )

                continue;

            auto sf = static_cast<const ScriptFunc*>(vf);








            if ( report_recursive )
                printf("%s is used indirectly, and thus potentially recursively\n", sf->GetName().c_str());

            non_recursive_funcs.erase(sf);
        }
    }











    bool did_addition = true;
    while ( did_addition ) {
        did_addition = false;


        for ( auto& c : call_set ) {



            std::unordered_set<const Func*> addls;

            for ( auto& cc : c.second ) {
                if ( cc == c.first )

                    continue;



                for ( auto& ccc : call_set[cc] ) {


                    if ( c.second.contains(ccc) )

                        continue;

                    addls.insert(ccc);

                    if ( ccc != c.first )

                        continue;

                    if ( report_recursive )
                        printf("%s is indirectly recursive, called by %s\n", c.first->GetName().c_str(),
                               cc->GetName().c_str());

                    non_recursive_funcs.erase(c.first);
                    non_recursive_funcs.erase(cc);
                }
            }

            if ( ! addls.empty() ) {
                did_addition = true;

                for ( auto& a : addls )
                    c.second.insert(a);
            }
        }
    }

    for ( auto& f : funcs ) {
        if ( f.ShouldSkip() )
            continue;

        const auto& func_ptr = f.FuncPtr();
        const auto& func = func_ptr.get();
        const auto& body = f.Body();



        if ( func->Flavor() != FUNC_FLAVOR_FUNCTION )
            continue;

        if ( ! non_recursive_funcs.contains(func) )
            continue;

        if ( ! is_ZAM_compilable(f.Profile()) )
            continue;

        inline_ables[func] = f.Profile();
    }

    if ( ! analysis_options.no_eh_coalescence )
        CoalesceEventHandlers();

    for ( auto& f : funcs )
        if ( f.ShouldAnalyze() )
            InlineFunction(&f);
}

void Inliner::CoalesceEventHandlers() {
    std::unordered_map<ScriptFunc*, size_t> event_handlers;
    BodyInfo body_to_info;
    for ( size_t i = 0U; i < funcs.size(); ++i ) {
        auto& f = funcs[i];
        if ( ! f.ShouldAnalyze() )
            continue;

        auto& func_ptr = f.FuncPtr();
        const auto& func = func_ptr.get();
        const auto& func_type = func->GetType();

        if ( func_type->AsFuncType()->Flavor() != FUNC_FLAVOR_EVENT )
            continue;






        static std::string zeek_init_name = "zeek_init";
        if ( func->GetName() == zeek_init_name )
            continue;

        const auto& body = f.Body();

        if ( func->GetKind() == Func::SCRIPT_FUNC && func->GetBodies().size() > 1 && body->Tag() != STMT_CPP ) {
            ++event_handlers[func];
            ASSERT(! body_to_info.contains(body.get()));
            body_to_info[body.get()] = i;
        }
    }

    for ( auto& e : event_handlers ) {
        auto func = e.first;
        auto& bodies = func->GetBodies();
        if ( bodies.size() != e.second )






            continue;

        CoalesceEventHandlers({NewRef{}, func}, bodies, body_to_info);
    }
}

void Inliner::CoalesceEventHandlers(ScriptFuncPtr func, const std::vector<Func::Body>& bodies,
                                    const BodyInfo& body_to_info) {

    auto& b0 = func->GetBodies()[0].stmts;
    auto merged_body = with_location_of(make_intrusive<StmtList>(), b0);
    auto oi = merged_body->GetOptInfo();

    auto& params = func->GetType()->Params();
    auto nparams = params->NumFields();
    size_t init_frame_size = static_cast<size_t>(nparams);

    PreInline(oi, init_frame_size);

    auto b0_info = body_to_info.find(b0.get());
    ASSERT(b0_info != body_to_info.end());
    auto& info0 = funcs[b0_info->second];
    auto& scope0 = info0.Scope();
    auto& vars = scope0->OrderedVars();




    auto empty_attrs = std::make_unique<std::vector<AttrPtr>>();
    push_scope(scope0->GetID(), std::move(empty_attrs));

    std::vector<IDPtr> param_ids;

    for ( auto i = 0; i < nparams; ++i ) {
        auto& vi = vars[i];


        auto p = install_ID(vi->Name(), "<event>", false, false);
        p->SetType(vi->GetType());
        param_ids.push_back(std::move(p));
    }

    auto new_scope = pop_scope();


    auto args = with_location_of(make_intrusive<ListExpr>(), b0);
    for ( auto& p : param_ids )
        args->Append(with_location_of(make_intrusive<NameExpr>(p), b0));

    for ( auto& b : bodies ) {
        auto bp = b.stmts;
        auto bi_find = body_to_info.find(bp.get());
        ASSERT(bi_find != body_to_info.end());
        auto& bi = funcs[bi_find->second];
        auto ie = DoInline(func, bp, args, bi.Scope(), bi.Profile());

        if ( ! ie )




            return;

        auto ie_s = with_location_of(make_intrusive<ExprStmt>(ie), bp);
        merged_body->Stmts().emplace_back(std::move(ie_s));
    }



    Func::Body new_body = {.stmts = merged_body};

    auto inlined_func = make_intrusive<CoalescedScriptFunc>(new_body, new_scope, func);
    inlined_func->SetScope(new_scope);


    auto* eh = event_registry->Lookup(func->GetName());
    ASSERT(eh);
    eh->SetFunc(inlined_func);


    auto fid = lookup_ID(func->GetName().c_str(), GLOBAL_MODULE_NAME, false, false, false);
    ASSERT(fid);
    fid->SetVal(make_intrusive<FuncVal>(inlined_func));

    PostInline(oi, inlined_func);




    Func::Body body{.stmts = merged_body};
    funcs.emplace_back(inlined_func, new_scope, std::move(body));

    auto pf = std::make_shared<ProfileFunc>(inlined_func.get(), merged_body);
    funcs.back().SetProfile(std::move(pf));
}

void Inliner::InlineFunction(FuncInfo* f) {
    auto oi = f->Body()->GetOptInfo();
    PreInline(oi, f->Scope()->Length());
    f->Body()->Inline(this);
    PostInline(oi, f->FuncPtr());
}

void Inliner::PreInline(StmtOptInfo* oi, size_t frame_size) {
    max_inlined_frame_size = 0;
    curr_frame_size = frame_size;
    num_stmts = oi->num_stmts;
    num_exprs = oi->num_exprs;
}

void Inliner::PostInline(StmtOptInfo* oi, ScriptFuncPtr f) {
    oi->num_stmts = num_stmts;
    oi->num_exprs = num_exprs;

    int new_frame_size = curr_frame_size + max_inlined_frame_size;

    if ( new_frame_size > f->FrameSize() )
        f->SetFrameSize(new_frame_size);
}

ExprPtr Inliner::CheckForInlining(CallExprPtr c) {
    auto f = c->Func();

    if ( f->Tag() != EXPR_NAME )

        return c;

    auto n = f->AsNameExpr();
    auto func = n->Id();

    if ( ! func->IsGlobal() )
        return c;

    const auto& func_v = func->GetVal();
    if ( ! func_v )
        return c;

    auto function = func_v->AsFuncVal()->AsFuncPtr();

    if ( function->GetKind() != Func::SCRIPT_FUNC )
        return c;

    auto func_vf = cast_intrusive<ScriptFunc>(function);

    auto ia = inline_ables.find(func_vf.get());
    if ( ia == inline_ables.end() )
        return c;

    if ( c->IsInWhen() ) {


        skipped_inlining.insert(func_vf.get());
        return c;
    }





    if ( function->GetType()->Params()->NumFields() == 1 && c->Args()->Exprs().size() != 1 ) {
        skipped_inlining.insert(func_vf.get());
        return c;
    }


    auto body = func_vf->GetBodies()[0].stmts;

    if ( body->Tag() == STMT_CPP )
        return c;

    auto scope = func_vf->GetScope();
    auto ie = DoInline(func_vf, body, c->ArgsPtr(), scope, ia->second);

    if ( ie ) {
        ie->SetLocationInfo(c->GetLocationInfo());
        did_inline.insert(func_vf.get());
    }

    return ie;
}

ExprPtr Inliner::DoInline(ScriptFuncPtr sf, StmtPtr body, ListExprPtr args, ScopePtr scope, const ProfileFunc* pf) {

    auto oi = body->GetOptInfo();

    if ( num_stmts + oi->num_stmts + num_exprs + oi->num_exprs > MAX_INLINE_SIZE ) {
        skipped_inlining.insert(sf.get());
        return nullptr;
    }

    num_stmts += oi->num_stmts;
    num_exprs += oi->num_exprs;

    auto body_dup = body->Duplicate();
    body_dup->GetOptInfo()->num_stmts = oi->num_stmts;
    body_dup->GetOptInfo()->num_exprs = oi->num_exprs;










    auto& vars = scope->OrderedVars();
    int nparam = sf->GetType()->Params()->NumFields();

    std::vector<IDPtr> params;
    std::vector<bool> param_is_modified;

    for ( int i = 0; i < nparam; ++i ) {
        auto& vi = vars[i];
        params.emplace_back(vi);
        param_is_modified.emplace_back((pf->Assignees().contains(vi)));
    }




    int frame_size = sf->FrameSize();

    int hold_curr_frame_size = curr_frame_size;
    curr_frame_size = frame_size;

    int hold_max_inlined_frame_size = max_inlined_frame_size;
    max_inlined_frame_size = 0;

    body_dup->Inline(this);

    curr_frame_size = hold_curr_frame_size;

    int new_frame_size = frame_size + max_inlined_frame_size;
    if ( new_frame_size > hold_max_inlined_frame_size )
        max_inlined_frame_size = new_frame_size;
    else
        max_inlined_frame_size = hold_max_inlined_frame_size;

    auto t = scope->GetReturnType();

    ASSERT(params.size() == args->Exprs().size());
    return with_location_of(make_intrusive<InlineExpr>(sf, args, params, param_is_modified, body_dup, curr_frame_size,
                                                       t),
                            body);
}

}
