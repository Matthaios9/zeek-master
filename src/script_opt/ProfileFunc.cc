

#include "zeek/script_opt/ProfileFunc.h"

#include <cerrno>

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/Stmt.h"
#include "zeek/script_opt/FuncInfo.h"
#include "zeek/script_opt/IDOptInfo.h"

namespace zeek::detail {



p_hash_type p_hash(const Obj* o) {
    ODesc d;
    d.SetDeterminism(true);
    o->Describe(&d);
    return p_hash(d.Description());
}

ProfileFunc::ProfileFunc(const Func* func, const StmtPtr& body) {
    profiled_func = func;
    profiled_scope = profiled_func->GetScope();
    profiled_body = body.get();

    profiled_func_t = cast_intrusive<FuncType>(func->GetType());
    auto& fcaps = profiled_func_t->GetCaptures();

    if ( fcaps ) {
        int offset = 0;

        for ( auto& c : *fcaps ) {
            const auto& cid = c.Id();
            captures.insert(cid);
            captures_offsets[cid] = offset++;
        }
    }

    TrackType(profiled_func_t);
    body->Traverse(this);






    num_params = profiled_func_t->Params()->NumFields();

    for ( const auto& l : locals ) {
        if ( ! captures.contains(l) && l->Offset() < num_params )
            params.insert(l);
    }
}

ProfileFunc::ProfileFunc(const Stmt* s) {
    profiled_body = s;
    s->Traverse(this);
}

ProfileFunc::ProfileFunc(const Expr* e) {
    profiled_expr = e;

    if ( e->Tag() == EXPR_LAMBDA ) {
        auto func = e->AsLambdaExpr();
        ASSERT(func->GetType()->Tag() == TYPE_FUNC);
        profiled_scope = func->GetScope();
        profiled_func_t = cast_intrusive<FuncType>(func->GetType());

        int offset = 0;

        for ( const auto& oid : func->OuterIDs() ) {
            captures.insert(oid);
            captures_offsets[oid] = offset++;
        }

        auto ft = func->GetType()->AsFuncType();
        auto& body = func->Ingredients()->Body();

        num_params = ft->Params()->NumFields();

        auto& ov = profiled_scope->OrderedVars();
        for ( int i = 0; i < num_params; ++i )
            params.insert(ov[i]);

        TrackType(ft);
        body->Traverse(this);
    }

    else


        e->Traverse(this);
}

TraversalCode ProfileFunc::PreStmt(const Stmt* s) {
    stmts.emplace_back(NewRef{}, const_cast<Stmt*>(s));

    switch ( s->Tag() ) {
        case STMT_INIT:
            for ( const auto& id : s->AsInitStmt()->Inits() ) {
                inits.insert(id);

                auto& t = id->GetType();
                TrackType(t);

                auto attrs = id->GetAttrs();
                if ( attrs && ! attrs->GetAttrs().empty() )
                    constructor_attrs[attrs.get()] = t;

                if ( t->Tag() == TYPE_RECORD )
                    CheckRecordConstructor(t);
            }




            return TC_ABORTSTMT;

        case STMT_WHEN: {
            ++num_when_stmts;

            auto w = s->AsWhenStmt();
            auto wi = w->Info();

            for ( const auto& wl : wi->WhenNewLocals() )
                when_locals.insert(wl);
        } break;

        case STMT_FOR: {
            auto sf = s->AsForStmt();
            auto loop_vars = sf->LoopVars();
            auto value_var = sf->ValueVar();

            for ( const auto& id : *loop_vars )
                locals.insert(id);

            if ( value_var )
                locals.insert(value_var);
        } break;

        case STMT_SWITCH: {








            auto sw = s->AsSwitchStmt();
            bool is_type_switch = false;

            for ( auto& c : *sw->Cases() ) {
                auto idl = c->TypeCases();
                if ( idl ) {
                    for ( const auto& id : *idl )



                        if ( id->Name() )
                            locals.insert(id);

                    is_type_switch = true;
                }
            }

            if ( is_type_switch )
                type_switches.insert(sw);
            else
                expr_switches.insert(sw);
        } break;

        default: break;
    }

    return TC_CONTINUE;
}

TraversalCode ProfileFunc::PreExpr(const Expr* e) {
    exprs.emplace_back(NewRef{}, const_cast<Expr*>(e));

    TrackType(e->GetType());

    switch ( e->Tag() ) {
        case EXPR_CONST: constants.push_back(e->AsConstExpr()); break;

        case EXPR_NAME: {
            auto n = e->AsNameExpr();
            auto id = n->IdPtr();

            TrackID(id);




            TrackType(id->GetType());

            if ( id->IsGlobal() ) {
                PreID(id.get());
                break;
            }

            locals.insert(id);

            break;
        }

        case EXPR_FIELD: {
            auto f = e->AsFieldExpr()->Field();
            addl_hashes.push_back(p_hash(f));
            break;
        }

        case EXPR_HAS_FIELD: {
            auto f = e->AsHasFieldExpr()->Field();
            addl_hashes.push_back(std::hash<int>{}(f));
            break;
        }

        case EXPR_INDEX: {
            auto lhs_t = e->GetOp1()->GetType();
            if ( lhs_t->Tag() == TYPE_TABLE )
                tbl_refs.insert(lhs_t.get());
        } break;

        case EXPR_INCR:
        case EXPR_DECR:
        case EXPR_ADD_TO:
        case EXPR_REMOVE_FROM:
        case EXPR_ASSIGN: {
            auto lhs = e->GetOp1();
            bool is_assign = e->Tag() == EXPR_ASSIGN;

            if ( is_assign ) {



                auto rhs = e->GetOp2();
                if ( rhs->Tag() == EXPR_NAME ) {
                    auto& rhs_id = rhs->AsNameExpr()->IdPtr();
                    const auto& t = rhs_id->GetType();
                    if ( t->Tag() == TYPE_FUNC && t->AsFuncType()->Flavor() == FUNC_FLAVOR_FUNCTION )
                        indirect_funcs.insert(rhs_id);
                }
            }

            if ( lhs->Tag() == EXPR_REF )
                lhs = lhs->GetOp1();

            else if ( is_assign )


                break;

            auto lhs_t = lhs->GetType();

            switch ( lhs->Tag() ) {
                case EXPR_NAME: {
                    auto id = lhs->AsNameExpr()->IdPtr();
                    TrackAssignment(id);

                    if ( is_assign ) {
                        auto a_e = static_cast<const AssignExpr*>(e);
                        auto& av = a_e->AssignVal();
                        if ( av )


                            when_locals.insert(id);
                    }
                    else if ( IsAggr(lhs_t->Tag()) )
                        aggr_mods.insert(lhs_t.get());
                } break;

                case EXPR_INDEX: {
                    auto lhs_aggr = lhs->GetOp1();
                    auto lhs_aggr_t = lhs_aggr->GetType();





                    if ( is_assign )
                        aggr_mods.insert(lhs_aggr_t.get());
                    else
                        aggr_mods.insert(lhs_t.get());

                    if ( lhs_aggr_t->Tag() == TYPE_TABLE ) {





                        lhs->GetOp1()->Traverse(this);
                        lhs->GetOp2()->Traverse(this);

                        auto rhs = e->GetOp2();
                        if ( rhs )
                            rhs->Traverse(this);

                        return TC_ABORTSTMT;
                    }
                } break;

                case EXPR_FIELD: aggr_mods.insert(lhs_t.get()); break;

                case EXPR_LIST: {
                    for ( auto id : lhs->AsListExpr()->Exprs() ) {
                        auto id_t = id->GetType();
                        if ( IsAggr(id_t->Tag()) )
                            aggr_mods.insert(id_t.get());
                    }
                } break;

                default: reporter->InternalError("bad expression in ProfileFunc: %s", obj_desc(e).c_str());
            }
        } break;

        case EXPR_AGGR_ADD:
        case EXPR_AGGR_DEL: {
            auto lhs = e->GetOp1();
            if ( lhs )
                aggr_mods.insert(lhs->GetType().get());
            else
                aggr_mods.insert(e->GetType().get());
        } break;

        case EXPR_CALL: {
            auto c = e->AsCallExpr();
            auto args = c->Args();
            auto f = c->Func();

            const NameExpr* n = nullptr;
            IDPtr func;

            if ( f->Tag() == EXPR_NAME ) {
                n = f->AsNameExpr();
                func = n->IdPtr();

                if ( ! func->IsGlobal() )
                    does_indirect_calls = true;
            }
            else
                does_indirect_calls = true;




            if ( does_indirect_calls || ! is_idempotent(func->Name()) ) {
                for ( auto& arg : args->Exprs() )
                    if ( arg->Tag() == EXPR_NAME ) {
                        auto& arg_id = arg->AsNameExpr()->IdPtr();
                        const auto& t = arg_id->GetType();
                        if ( t->Tag() == TYPE_FUNC && t->AsFuncType()->Flavor() == FUNC_FLAVOR_FUNCTION )
                            indirect_funcs.insert(arg_id);
                    }
            }

            if ( does_indirect_calls )


                return TC_CONTINUE;

            all_globals.insert(func);

            auto func_v = func->GetVal();
            if ( func_v ) {
                auto func_vf = func_v->AsFunc();

                if ( func_vf->GetKind() == Func::SCRIPT_FUNC ) {
                    auto sf = static_cast<ScriptFunc*>(func_vf);
                    script_calls.insert(sf);
                }

                else {
                    BiF_globals.insert(func);
                    if ( obj_matches_opt_files(e) != AnalyzeDecision::SHOULD_NOT )

                        called_BiF_globals.insert(func);
                }
            }
            else {




            }


            args->Traverse(this);










            TrackType(n->GetType());
            TrackType(func->GetType());

            TrackID(func);

            return TC_ABORTSTMT;
        }

        case EXPR_EVENT: {
            auto ev = e->AsEventExpr()->Name();
            events.insert(ev);
            addl_hashes.push_back(p_hash(ev));
        } break;

        case EXPR_LAMBDA: {
            auto l = e->AsLambdaExpr();
            lambdas.push_back(l);

            for ( const auto& i : l->OuterIDs() ) {
                locals.insert(i);
                TrackID(i);
            }




            auto pf = std::make_shared<ProfileFunc>(l->Ingredients()->Body().get());
            script_calls.insert(pf->ScriptCalls().begin(), pf->ScriptCalls().end());

            return TC_ABORTSTMT;
        }

        case EXPR_RECORD_CONSTRUCTOR:
        case EXPR_REC_CONSTRUCT_WITH_REC: CheckRecordConstructor(e->GetType()); break;

        case EXPR_SET_CONSTRUCTOR: {
            auto sc = static_cast<const SetConstructorExpr*>(e);
            const auto& attrs = sc->GetAttrs();

            if ( attrs && ! attrs->GetAttrs().empty() )
                constructor_attrs[attrs.get()] = sc->GetType();
        } break;

        case EXPR_TABLE_CONSTRUCTOR: {
            auto tc = static_cast<const TableConstructorExpr*>(e);
            const auto& attrs = tc->GetAttrs();

            if ( attrs && ! attrs->GetAttrs().empty() )
                constructor_attrs[attrs.get()] = tc->GetType();
        } break;

        case EXPR_RECORD_COERCE:


            CheckRecordConstructor(e->GetType());
            break;

        case EXPR_TABLE_COERCE: {


            auto res_type = e->GetType().get();
            auto orig_type = e->GetOp1()->GetType().get();
            if ( ! type_aliases.contains(res_type) )
                type_aliases[orig_type] = {res_type};
            else
                type_aliases[orig_type].insert(res_type);
        } break;

        default: break;
    }

    return TC_CONTINUE;
}

TraversalCode ProfileFunc::PreID(const ID* id_raw) {
    IDPtr id{NewRef{}, const_cast<ID*>(id_raw)};

    if ( id->IsGlobal() ) {
        globals.insert(id);
        all_globals.insert(id);

        const auto& t = id->GetType();
        TrackType(t);

        if ( t->Tag() == TYPE_FUNC )
            if ( t->AsFuncType()->Flavor() == FUNC_FLAVOR_EVENT )
                events.insert(id->Name());
    }


    return TC_ABORTSTMT;
}

TraversalCode ProfileFunc::PreType(const Type* t) {
    TrackType(t);


    return TC_ABORTSTMT;
}

void ProfileFunc::TrackType(const Type* t) {
    if ( ! t )
        return;

    auto [it, inserted] = types.insert(t);

    if ( ! inserted )

        return;

    ordered_types.push_back(t);
}

void ProfileFunc::TrackID(const IDPtr id) {
    if ( ! id )
        return;

    auto [it, inserted] = ids.insert(id);

    if ( ! inserted )

        return;

    if ( id->IsGlobal() ) {
        globals.insert(id);
        all_globals.insert(id);
        TrackType(id->GetType());
    }

    ordered_ids.push_back(id);
}

void ProfileFunc::TrackAssignment(const IDPtr id) {
    if ( assignees.contains(id) )
        ++assignees[id];
    else
        assignees[id] = 1;

    if ( id->IsGlobal() || captures.contains(id) )
        non_local_assignees.insert(id);
}

void ProfileFunc::CheckRecordConstructor(TypePtr t) {
    auto rt = cast_intrusive<RecordType>(t);
    for ( auto td : *rt->Types() ) {
        auto attrs = td->attrs.get();
        if ( attrs && ! attrs->GetAttrs().empty() ) {





            constructor_attrs[attrs] = rt;

            if ( ! rec_constructor_attrs.contains(rt.get()) )
                rec_constructor_attrs[rt.get()] = {attrs};
            else
                rec_constructor_attrs[rt.get()].insert(attrs);
        }
    }
}

ProfileFuncs::ProfileFuncs(std::vector<FuncInfo>& funcs, is_compilable_pred pred, bool _compute_func_hashes) {
    compute_func_hashes = _compute_func_hashes;

    for ( auto& f : funcs ) {
        auto pf = std::make_shared<ProfileFunc>(f.Func(), f.Body());

        if ( ! pred || (*pred)(pf.get(), nullptr) )
            MergeInProfile(pf.get());
        else if ( pred )
            f.SetSkip(true);






        auto prev_pf = f.Profile();
        if ( ! compute_func_hashes && prev_pf && prev_pf->HasHashVal() )
            pf->SetHashVal(prev_pf->HashVal());

        f.SetProfile(std::move(pf));
        func_profs[f.Func()] = f.ProfilePtr();
    }



    ComputeTypeHashes(main_types);

    do {





        DrainPendingExprs();



        ComputeBodyHashes(funcs);



    } while ( ! pending_exprs.empty() );



    ComputeSideEffects();
}

void ProfileFuncs::ProfileLambda(const LambdaExpr* l) {
    if ( profiled_lambdas.contains(l) )
        return;

    lambdas.insert(l);
    profiled_lambdas.insert(l);
    pending_exprs.push_back(l);

    do
        DrainPendingExprs();
    while ( ! pending_exprs.empty() );

    AnalyzeLambdaProfile(l);

    auto pf = ExprProf(l);
    if ( ! pf->HasHashVal() )
        ComputeProfileHash(pf);

    for ( auto sub_l : pf->Lambdas() )
        ProfileLambda(sub_l);
}

bool ProfileFuncs::IsTableWithDefaultAggr(const Type* t) {
    auto analy = tbl_has_aggr_default.find(t);
    if ( analy != tbl_has_aggr_default.end() )

        return analy->second;


    if ( t->AsTableType()->Yield() ) {
        for ( auto& at : tbl_has_aggr_default )
            if ( same_type(at.first, t) ) {
                tbl_has_aggr_default[t] = at.second;
                return at.second;
            }
    }

    tbl_has_aggr_default[t] = false;
    return false;
}

bool ProfileFuncs::HasSideEffects(SideEffectsOp::AccessType access, const TypePtr& t) const {
    IDSet nli;
    TypeSet aggrs;

    if ( GetSideEffects(access, t.get(), nli, aggrs) )
        return true;

    return ! nli.empty() || ! aggrs.empty();
}

bool ProfileFuncs::GetSideEffects(SideEffectsOp::AccessType access, const Type* t, IDSet& non_local_ids,
                                  TypeSet& aggrs) const {
    for ( const auto& se : side_effects_ops )
        if ( AssessSideEffects(se.get(), access, t, non_local_ids, aggrs) )
            return true;

    return false;
}

bool ProfileFuncs::GetCallSideEffects(const NameExpr* n, IDSet& non_local_ids, TypeSet& aggrs, bool& is_unknown) {
    auto fid = n->Id();
    auto fv = fid->GetVal();

    if ( ! fv || ! fid->IsConst() ) {

        is_unknown = true;
        return true;
    }

    auto func = fv->AsFunc();
    if ( func->GetKind() == Func::BUILTIN_FUNC ) {
        if ( has_script_side_effects(func->GetName()) )
            is_unknown = true;
        return true;
    }

    const auto& bodies = func->GetBodies();
    if ( bodies.size() == 1 && bodies[0].stmts->Tag() == STMT_CPP ) {
        is_unknown = true;
        return true;
    }

    auto sf = static_cast<ScriptFunc*>(func);
    auto seo = GetCallSideEffects(sf);
    if ( ! seo )
        return false;

    if ( seo->HasUnknownChanges() )
        is_unknown = true;

    for ( auto a : seo->ModAggrs() )
        aggrs.insert(a);
    for ( const auto& nl : seo->ModNonLocals() )
        non_local_ids.insert(nl);

    return true;
}

void ProfileFuncs::MergeInProfile(ProfileFunc* pf) {
    all_globals.insert(pf->AllGlobals().begin(), pf->AllGlobals().end());

    for ( auto& g : pf->Globals() ) {
        auto [it, inserted] = globals.emplace(g);

        if ( ! inserted )
            continue;

        TraverseValue(g->GetVal());

        const auto& t = g->GetType();
        if ( t->Tag() == TYPE_TYPE )
            (void)HashType(t->AsTypeType()->GetType());

        auto& init_exprs = g->GetOptInfo()->GetInitExprs();
        for ( const auto& i_e : init_exprs )
            if ( i_e ) {
                pending_exprs.push_back(i_e.get());

                if ( i_e->Tag() == EXPR_LAMBDA )
                    lambdas.insert(i_e->AsLambdaExpr());
            }

        auto& attrs = g->GetAttrs();
        if ( attrs )
            AnalyzeAttrs(attrs.get(), t.get());
    }

    constants.insert(pf->Constants().begin(), pf->Constants().end());
    main_types.insert(main_types.end(), pf->OrderedTypes().begin(), pf->OrderedTypes().end());
    script_calls.insert(pf->ScriptCalls().begin(), pf->ScriptCalls().end());
    BiF_globals.insert(pf->BiFGlobals().begin(), pf->BiFGlobals().end());
    called_BiF_globals.insert(pf->CalledBiFGlobals().begin(), pf->CalledBiFGlobals().end());
    events.insert(pf->Events().begin(), pf->Events().end());

    for ( auto& i : pf->Lambdas() ) {
        lambdas.insert(i);
        pending_exprs.push_back(i);
    }

    for ( auto& a : pf->ConstructorAttrs() )
        AnalyzeAttrs(a.first, a.second.get());

    for ( auto& ta : pf->TypeAliases() ) {
        if ( ! type_aliases.contains(ta.first) )
            type_aliases[ta.first] = std::set<const Type*>{};
        type_aliases[ta.first].insert(ta.second.begin(), ta.second.end());
    }
}

void ProfileFuncs::TraverseValue(const ValPtr& v) {
    if ( ! v )
        return;

    const auto& t = v->GetType();
    (void)HashType(t);

    switch ( t->Tag() ) {
        case TYPE_ADDR:
        case TYPE_ANY:
        case TYPE_BOOL:
        case TYPE_COUNT:
        case TYPE_DOUBLE:
        case TYPE_ENUM:
        case TYPE_ERROR:
        case TYPE_FILE:
        case TYPE_FUNC:
        case TYPE_INT:
        case TYPE_INTERVAL:
        case TYPE_OPAQUE:
        case TYPE_PATTERN:
        case TYPE_PORT:
        case TYPE_STRING:
        case TYPE_SUBNET:
        case TYPE_TIME:
        case TYPE_VOID: break;

        case TYPE_RECORD: {
            auto r = cast_intrusive<RecordVal>(v);
            auto n = r->NumFields();

            for ( auto i = 0u; i < n; ++i )
                TraverseValue(r->GetField(i));
        } break;

        case TYPE_TABLE: {
            auto tv = cast_intrusive<TableVal>(v);
            auto tv_map = tv->ToMap();

            for ( auto& tv_i : tv_map ) {
                TraverseValue(tv_i.first);
                TraverseValue(tv_i.second);
            }
        } break;

        case TYPE_LIST: {
            auto lv = cast_intrusive<ListVal>(v);
            auto n = lv->Length();

            for ( auto i = 0; i < n; ++i )
                TraverseValue(lv->Idx(i));
        } break;

        case TYPE_VECTOR: {
            auto vv = cast_intrusive<VectorVal>(v);
            auto n = vv->Size();

            for ( auto i = 0u; i < n; ++i )
                TraverseValue(vv->ValAt(i));
        } break;

        case TYPE_TYPE: (void)HashType(t->AsTypeType()->GetType()); break;
    }
}

void ProfileFuncs::DrainPendingExprs() {
    while ( ! pending_exprs.empty() ) {


        auto pe = pending_exprs;
        pending_exprs.clear();

        for ( auto e : pe ) {
            auto pf = std::make_shared<ProfileFunc>(e);

            expr_profs[e] = pf;
            MergeInProfile(pf.get());









            ComputeTypeHashes(pf->OrderedTypes());
        }
    }
}

void ProfileFuncs::ComputeTypeHashes(const std::vector<const Type*>& types) {
    for ( auto t : types )
        (void)HashType(t);
}

void ProfileFuncs::ComputeBodyHashes(std::vector<FuncInfo>& funcs) {
    for ( auto& f : funcs ) {
        if ( f.ShouldSkip() )
            continue;
        auto pf = f.ProfilePtr();
        if ( compute_func_hashes || ! pf->HasHashVal() )
            ComputeProfileHash(pf);
    }

    for ( auto& l : lambdas )
        AnalyzeLambdaProfile(l);
}

void ProfileFuncs::AnalyzeLambdaProfile(const LambdaExpr* l) {
    if ( processed_lambdas.contains(l) )
        return;

    processed_lambdas.insert(l);

    auto pf = ExprProf(l);
    func_profs[l->PrimaryFunc().get()] = pf;
    lambda_primaries[l->Name()] = l->PrimaryFunc().get();

    if ( compute_func_hashes || ! pf->HasHashVal() )
        ComputeProfileHash(pf);
}

void ProfileFuncs::ComputeProfileHash(const std::shared_ptr<ProfileFunc>& pf) {
    p_hash_type h = 0;





    h = merge_p_hashes(h, p_hash("params"));
    h = merge_p_hashes(h, HashType(pf->ProfiledFuncType()));

    h = merge_p_hashes(h, p_hash("stmts"));
    for ( auto& i : pf->Stmts() )
        h = merge_p_hashes(h, p_hash(i->Tag()));

    h = merge_p_hashes(h, p_hash("exprs"));
    for ( auto& i : pf->Exprs() )
        h = merge_p_hashes(h, p_hash(i->Tag()));

    h = merge_p_hashes(h, p_hash("ids"));
    for ( const auto& i : pf->OrderedIdentifiers() )
        h = merge_p_hashes(h, p_hash(i->Name()));

    h = merge_p_hashes(h, p_hash("constants"));
    for ( auto i : pf->Constants() )
        h = merge_p_hashes(h, p_hash(i->Value()));

    h = merge_p_hashes(h, p_hash("types"));
    for ( auto i : pf->OrderedTypes() )
        h = merge_p_hashes(h, HashType(i));

    h = merge_p_hashes(h, p_hash("lambdas"));
    for ( auto i : pf->Lambdas() )
        h = merge_p_hashes(h, p_hash(i));

    h = merge_p_hashes(h, p_hash("addl"));
    for ( auto i : pf->AdditionalHashes() )
        h = merge_p_hashes(h, i);

    pf->SetHashVal(h);
}

p_hash_type ProfileFuncs::HashType(const Type* t) {
    if ( ! t )
        return 0;

    auto it = type_hashes.find(t);

    if ( it != type_hashes.end() )

        return it->second;

    auto& tn = t->GetName();
    if ( ! tn.empty() ) {
        auto seen_it = seen_type_names.find(tn);

        if ( seen_it != seen_type_names.end() ) {


            auto seen_t = seen_it->second;
            auto h = type_hashes[seen_t];

            type_hashes[t] = h;
            type_to_rep[t] = type_to_rep[seen_t];

            return h;
        }
    }

    auto h = p_hash(t->Tag());
    if ( ! tn.empty() )
        h = merge_p_hashes(h, p_hash(tn));








    type_hashes[t] = h;

    switch ( t->Tag() ) {
        case TYPE_ADDR:
        case TYPE_ANY:
        case TYPE_BOOL:
        case TYPE_COUNT:
        case TYPE_DOUBLE:
        case TYPE_ENUM:
        case TYPE_ERROR:
        case TYPE_INT:
        case TYPE_INTERVAL:
        case TYPE_OPAQUE:
        case TYPE_PATTERN:
        case TYPE_PORT:
        case TYPE_STRING:
        case TYPE_SUBNET:
        case TYPE_TIME:
        case TYPE_VOID: h = merge_p_hashes(h, p_hash(t)); break;

        case TYPE_RECORD: {
            const auto& ft = t->AsRecordType();
            auto n = ft->NumFields();
            auto orig_n = ft->NumOrigFields();

            h = merge_p_hashes(h, p_hash("record"));
            h = merge_p_hashes(h, p_hash(orig_n));

            for ( auto i = 0; i < orig_n; ++i ) {
                const auto& f = ft->FieldDecl(i);
                auto type_h = HashType(f->type);

                h = merge_p_hashes(h, p_hash(f->id));
                h = merge_p_hashes(h, type_h);




                if ( f->attrs ) {
                    h = merge_p_hashes(h, HashAttrs(f->attrs));
                    AnalyzeAttrs(f->attrs.get(), ft);
                }
            }
        } break;

        case TYPE_TABLE: {
            auto tbl = t->AsTableType();
            h = merge_p_hashes(h, p_hash("table"));
            h = merge_p_hashes(h, p_hash("indices"));
            h = merge_p_hashes(h, HashType(tbl->GetIndices()));
            h = merge_p_hashes(h, p_hash("tbl-yield"));
            h = merge_p_hashes(h, HashType(tbl->Yield()));
        } break;

        case TYPE_FUNC: {
            auto ft = t->AsFuncType();
            auto flv = ft->FlavorString();
            h = merge_p_hashes(h, p_hash(flv));
            h = merge_p_hashes(h, p_hash("params"));
            h = merge_p_hashes(h, HashType(ft->Params()));
            h = merge_p_hashes(h, p_hash("func-yield"));
            h = merge_p_hashes(h, HashType(ft->Yield()));
        } break;

        case TYPE_LIST: {
            auto& tl = t->AsTypeList()->GetTypes();

            h = merge_p_hashes(h, p_hash("list"));
            h = merge_p_hashes(h, p_hash(tl.size()));

            for ( const auto& tl_i : tl )
                h = merge_p_hashes(h, HashType(tl_i));
        } break;

        case TYPE_VECTOR:
            h = merge_p_hashes(h, p_hash("vec"));
            h = merge_p_hashes(h, HashType(t->AsVectorType()->Yield()));
            break;

        case TYPE_FILE:
            h = merge_p_hashes(h, p_hash("file"));
            h = merge_p_hashes(h, HashType(t->AsFileType()->Yield()));
            break;

        case TYPE_TYPE:
            h = merge_p_hashes(h, p_hash("type"));
            h = merge_p_hashes(h, HashType(t->AsTypeType()->GetType()));
            break;
    }

    type_hashes[t] = h;

    auto [rep_it, rep_inserted] = type_hash_reps.emplace(h, t);

    if ( rep_inserted ) {
        type_to_rep[t] = t;
        rep_types.push_back(t);
    }
    else
        type_to_rep[t] = rep_it->second;

    if ( ! tn.empty() )
        seen_type_names[tn] = t;

    return h;
}

p_hash_type ProfileFuncs::HashAttrs(const AttributesPtr& Attrs) {



    auto attrs = Attrs->GetAttrs();
    p_hash_type h = 0;

    for ( const auto& a : attrs ) {
        h = merge_p_hashes(h, p_hash(a->Tag()));
        auto e = a->GetExpr();




        if ( e ) {
            h = merge_p_hashes(h, HashType(e->GetType()));
            h = merge_p_hashes(h, p_hash(e.get()));
        }
    }

    return h;
}

void ProfileFuncs::AnalyzeAttrs(const Attributes* attrs, const Type* t) {
    for ( const auto& a : attrs->GetAttrs() ) {
        auto& e = a->GetExpr();

        if ( ! e )
            continue;

        pending_exprs.push_back(e.get());

        auto prev_ea = expr_attrs.find(a.get());
        if ( prev_ea == expr_attrs.end() )
            expr_attrs[a.get()] = {t};
        else {



            bool found = false;
            for ( auto ea : prev_ea->second )
                if ( ea == t ) {
                    found = true;
                    break;
                }

            if ( ! found )
                prev_ea->second.push_back(t);
        }

        if ( e->Tag() == EXPR_LAMBDA )
            lambdas.insert(e->AsLambdaExpr());
    }
}

void ProfileFuncs::ComputeSideEffects() {





    for ( auto& ea : expr_attrs ) {


        auto a = ea.first;
        auto at = a->Tag();
        if ( at == ATTR_DEFAULT || at == ATTR_DEFAULT_INSERT || at == ATTR_ON_CHANGE ) {
            if ( at == ATTR_DEFAULT ) {

                for ( auto t : ea.second ) {
                    if ( t->Tag() != TYPE_TABLE )
                        continue;

                    auto y = t->AsTableType()->Yield();

                    if ( y && IsAggr(y->Tag()) ) {
                        tbl_has_aggr_default[t] = true;
                        for ( auto ta : type_aliases[t] )
                            tbl_has_aggr_default[ta] = true;
                    }
                }
            }


            if ( ! DefinitelyHasNoSideEffects(a->GetExpr()) )
                candidates.insert(a);
        }
    }






    while ( ! candidates.empty() ) {

        AttrSet made_decision;

        for ( auto c : candidates ) {
            IDSet non_local_ids;
            TypeSet aggrs;
            bool is_unknown = false;



            curr_candidate = c;

            if ( ! AssessSideEffects(c->GetExpr(), non_local_ids, aggrs, is_unknown) )

                continue;


            made_decision.insert(c);
            SetSideEffects(c, non_local_ids, aggrs, is_unknown);
        }

        if ( made_decision.empty() ) {







            IDSet non_local_ids;
            TypeSet aggrs;

            for ( auto c : candidates )
                SetSideEffects(c, non_local_ids, aggrs, true);


            break;
        }

        for ( auto md : made_decision )
            candidates.erase(md);
    }
}

bool ProfileFuncs::DefinitelyHasNoSideEffects(const ExprPtr& e) const {
    if ( e->Tag() == EXPR_CONST || e->Tag() == EXPR_VECTOR_CONSTRUCTOR )
        return true;

    if ( e->Tag() == EXPR_NAME )
        return e->GetType()->Tag() != TYPE_FUNC;

    auto ep = expr_profs.find(e.get());
    ASSERT(ep != expr_profs.end());

    const auto& pf = ep->second;

    if ( ! pf->NonLocalAssignees().empty() || ! pf->TableRefs().empty() || ! pf->AggrMods().empty() ||
         ! pf->ScriptCalls().empty() )
        return false;

    for ( auto& b : pf->BiFGlobals() )
        if ( has_script_side_effects(b->Name()) )
            return false;

    return true;
}

void ProfileFuncs::SetSideEffects(const Attr* a, IDSet& non_local_ids, TypeSet& aggrs, bool is_unknown) {
    auto seo_vec = std::vector<std::shared_ptr<SideEffectsOp>>{};
    bool is_rec = expr_attrs[a][0]->Tag() == TYPE_RECORD;

    SideEffectsOp::AccessType at;
    if ( is_rec )
        at = SideEffectsOp::CONSTRUCTION;
    else if ( a->Tag() == ATTR_ON_CHANGE )
        at = SideEffectsOp::WRITE;
    else
        at = SideEffectsOp::READ;

    if ( non_local_ids.empty() && aggrs.empty() && ! is_unknown )

        seo_vec.push_back(std::make_shared<SideEffectsOp>());
    else {
        attrs_with_side_effects.insert(a);


        for ( auto ea_t : expr_attrs[a] ) {
            auto seo = std::make_shared<SideEffectsOp>(at, ea_t);
            seo->AddModNonGlobal(non_local_ids);
            seo->AddModAggrs(aggrs);

            if ( is_unknown )
                seo->SetUnknownChanges();

            side_effects_ops.push_back(seo);
            seo_vec.push_back(std::move(seo));
        }
    }

    if ( is_rec )
        record_constr_with_side_effects[a] = std::move(seo_vec);
    else
        aggr_side_effects[a] = std::move(seo_vec);
}

AttrVec ProfileFuncs::AssociatedAttrs(const Type* t) {
    AttrVec assoc_attrs;




    FindAssociatedAttrs(candidates, t, assoc_attrs);
    FindAssociatedAttrs(attrs_with_side_effects, t, assoc_attrs);

    return assoc_attrs;
}

void ProfileFuncs::FindAssociatedAttrs(const AttrSet& attrs, const Type* t, AttrVec& assoc_attrs) {
    for ( auto a : attrs ) {
        for ( auto ea_t : expr_attrs[a] ) {
            if ( same_type(t, ea_t) ) {
                assoc_attrs.push_back(a);
                break;
            }

            for ( auto ta : type_aliases[ea_t] )
                if ( same_type(t, ta) ) {
                    assoc_attrs.push_back(a);
                    break;
                }
        }
    }
}

bool ProfileFuncs::AssessSideEffects(const ExprPtr& e, IDSet& non_local_ids, TypeSet& aggrs, bool& is_unknown) {
    if ( e->Tag() == EXPR_NAME && e->GetType()->Tag() == TYPE_FUNC )


        return GetCallSideEffects(e->AsNameExpr(), non_local_ids, aggrs, is_unknown);

    ASSERT(expr_profs.contains(e.get()));
    auto pf = expr_profs[e.get()];
    return AssessSideEffects(pf.get(), non_local_ids, aggrs, is_unknown);
}

bool ProfileFuncs::AssessSideEffects(const ProfileFunc* pf, IDSet& non_local_ids, TypeSet& aggrs, bool& is_unknown) {
    if ( pf->DoesIndirectCalls() ) {
        is_unknown = true;
        return true;
    }

    for ( auto& b : pf->BiFGlobals() )
        if ( has_script_side_effects(b->Name()) ) {
            is_unknown = true;
            return true;
        }

    IDSet nla;
    TypeSet mod_aggrs;

    for ( auto& a : pf->NonLocalAssignees() )
        nla.insert(a);

    for ( auto& r : pf->RecordConstructorAttrs() )
        if ( ! AssessAggrEffects(SideEffectsOp::CONSTRUCTION, r.first, nla, mod_aggrs, is_unknown) )

            return false;

    for ( auto& tr : pf->TableRefs() )
        if ( ! AssessAggrEffects(SideEffectsOp::READ, tr, nla, mod_aggrs, is_unknown) )
            return false;

    for ( auto& tm : pf->AggrMods() ) {
        if ( tm->Tag() == TYPE_TABLE && ! AssessAggrEffects(SideEffectsOp::WRITE, tm, nla, mod_aggrs, is_unknown) )
            return false;

        mod_aggrs.insert(tm);
    }

    for ( auto& f : pf->ScriptCalls() ) {
        if ( f->Flavor() != FUNC_FLAVOR_FUNCTION ) {


            is_unknown = true;
            return true;
        }

        auto pff = func_profs[f];
        if ( active_func_profiles.contains(pff) )



            continue;


        active_func_profiles.insert(pff);
        auto a = AssessSideEffects(pff.get(), nla, mod_aggrs, is_unknown);
        active_func_profiles.erase(pff);

        if ( ! a )
            return false;
    }

    non_local_ids.insert(nla.begin(), nla.end());
    aggrs.insert(mod_aggrs.begin(), mod_aggrs.end());

    return true;
}

bool ProfileFuncs::AssessAggrEffects(SideEffectsOp::AccessType access, const Type* t, IDSet& non_local_ids,
                                     TypeSet& aggrs, bool& is_unknown) {
    auto assoc_attrs = AssociatedAttrs(t);

    for ( auto a : assoc_attrs ) {
        if ( a == curr_candidate )


            continue;



        auto ase = aggr_side_effects.find(a);
        if ( ase == aggr_side_effects.end() ) {
            ase = record_constr_with_side_effects.find(a);
            if ( ase == record_constr_with_side_effects.end() )

                return false;
        }

        for ( auto& se : ase->second )
            if ( AssessSideEffects(se.get(), access, t, non_local_ids, aggrs) ) {
                is_unknown = true;
                return true;
            }
    }

    return true;
}

bool ProfileFuncs::AssessSideEffects(const SideEffectsOp* se, SideEffectsOp::AccessType access, const Type* t,
                                     IDSet& non_local_ids, TypeSet& aggrs) const {

    if ( se->GetAccessType() != access )
        return false;

    if ( ! same_type(se->GetType(), t) )
        return false;


    if ( se->HasUnknownChanges() )
        return true;

    for ( auto a : se->ModAggrs() )
        aggrs.insert(a);
    for ( const auto& nl : se->ModNonLocals() )
        non_local_ids.insert(nl);

    return false;
}

std::shared_ptr<SideEffectsOp> ProfileFuncs::GetCallSideEffects(const ScriptFunc* sf) {
    if ( lambda_primaries.contains(sf->GetName()) )
        sf = lambda_primaries[sf->GetName()];

    auto sf_se = func_side_effects.find(sf);
    if ( sf_se != func_side_effects.end() )

        return sf_se->second;

    bool is_unknown = false;
    IDSet nla;
    TypeSet mod_aggrs;

    ASSERT(func_profs.contains(sf));
    auto pf = func_profs[sf];
    if ( ! AssessSideEffects(pf.get(), nla, mod_aggrs, is_unknown) )

        return nullptr;

    auto seo = std::make_shared<SideEffectsOp>(SideEffectsOp::CALL);
    seo->AddModNonGlobal(nla);
    seo->AddModAggrs(mod_aggrs);

    if ( is_unknown )
        seo->SetUnknownChanges();

    func_side_effects[sf] = seo;

    return seo;
}


static std::unordered_map<std::string, std::string> filename_module;

void switch_to_module(const char* module_name) {
    auto loc = GetCurrentLocation();
    if ( loc.FirstLine() != 0 && ! filename_module.contains(loc.FileName()) )
        filename_module[loc.FileName()] = module_name;
}

std::string func_name_at_loc(std::string fname, const Location* loc) {
    auto find_module = filename_module.find(loc->FileName());
    if ( find_module == filename_module.end() )

        return fname;

    auto& module = find_module->second;
    if ( module.empty() || module == "GLOBAL" )

        return fname;

    auto mod_prefix = module + "::";

    if ( fname.starts_with(mod_prefix) )
        return fname;

    return mod_prefix + fname;
}

TraversalCode SetBlockLineNumbers::PreStmt(const Stmt* s) {
    auto loc = const_cast<Location*>(s->GetLocationInfo());
    UpdateLocInfo(loc);
    block_line_range.emplace_back(loc->FirstLine(), loc->LastLine());
    return TC_CONTINUE;
}

TraversalCode SetBlockLineNumbers::PostStmt(const Stmt* s) {
    auto loc = const_cast<Location*>(s->GetLocationInfo());
    auto r = block_line_range.back();
    loc->SetLines(r.first, r.second);

    block_line_range.pop_back();

    if ( ! block_line_range.empty() ) {

        auto& r_p = block_line_range.back();
        r_p.first = std::min(r_p.first, r.first);
        r_p.second = std::max(r_p.second, r.second);
    }

    return TC_CONTINUE;
}

TraversalCode SetBlockLineNumbers::PreExpr(const Expr* e) {
    ASSERT(! block_line_range.empty());
    UpdateLocInfo(const_cast<Location*>(e->GetLocationInfo()));
    return TC_CONTINUE;
}

void SetBlockLineNumbers::UpdateLocInfo(Location* loc) {
    auto first_line = loc->FirstLine();
    auto last_line = loc->LastLine();

    if ( ! block_line_range.empty() ) {
        auto& r = block_line_range.back();
        r.first = std::min(r.first, first_line);
        r.second = std::max(r.second, last_line);
    }
}

ASTBlockAnalyzer::ASTBlockAnalyzer(std::vector<FuncInfo>& funcs) {
    for ( auto& f : funcs ) {
        if ( ! f.ShouldAnalyze() )
            continue;

        auto func = f.Func();
        auto fn = func->GetName();
        const auto& body = f.Body();


        SetBlockLineNumbers sbln;
        body->Traverse(&sbln);

        auto body_loc = body->GetLocationInfo();
        fn = func_name_at_loc(fn, body_loc);

        parents.emplace_back(fn, fn);
        func_name_prefix = fn + ":";
        body->Traverse(this);
        parents.pop_back();
    }


    func_name_prefix = "<MISSING>:";
}

static bool is_compound_stmt(const Stmt* s) {
    static std::set<StmtTag> compound_stmts = {STMT_FOR, STMT_IF, STMT_LIST, STMT_SWITCH, STMT_WHEN, STMT_WHILE};
    return compound_stmts.contains(s->Tag());
}

TraversalCode ASTBlockAnalyzer::PreStmt(const Stmt* s) {
    auto loc = s->GetLocationInfo();
    auto ls = BuildExpandedDescription(loc);

    if ( is_compound_stmt(s) )
        parents.emplace_back(LocWithFunc(loc), std::move(ls));

    return TC_CONTINUE;
}

TraversalCode ASTBlockAnalyzer::PostStmt(const Stmt* s) {
    if ( is_compound_stmt(s) )
        parents.pop_back();

    return TC_CONTINUE;
}

TraversalCode ASTBlockAnalyzer::PreExpr(const Expr* e) {
    (void)BuildExpandedDescription(e->GetLocationInfo());
    return TC_CONTINUE;
}

std::string ASTBlockAnalyzer::BuildExpandedDescription(const Location* loc) {
    ASSERT(loc && loc->FirstLine() != 0);

    auto ls = LocWithFunc(loc);
    if ( ! parents.empty() ) {
        auto& parent_pair = parents.back();
        if ( parent_pair.first == ls )
            ls = parent_pair.second;
        else
            ls = parent_pair.second + ";" + ls;
    }

    auto lk = LocKey(loc);
    if ( ! exp_desc.contains(lk) )
        exp_desc[lk] = ls;

    return ls;
}

std::unique_ptr<ASTBlockAnalyzer> AST_blocks;

}
