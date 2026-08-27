

#include "zeek/script_opt/GenIDDefs.h"

#include "zeek/Desc.h"
#include "zeek/Expr.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/script_opt/Expr.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/StmtOptInfo.h"

namespace zeek::detail {

GenIDDefs::GenIDDefs(std::shared_ptr<ProfileFunc> _pf, const FuncPtr& f, ScopePtr scope, StmtPtr body)
    : pf(std::move(_pf)) {
    TraverseFunction(f, scope, body);
}

void GenIDDefs::TraverseFunction(const FuncPtr& f, ScopePtr scope, StmtPtr body) {
    func_flavor = f->Flavor();


    modified_IDs.emplace_back();

    for ( const auto& g : pf->Globals() ) {
        g->GetOptInfo()->Clear();
        TrackID(g);
    }



    for ( const auto& l : pf->Locals() )
        l->GetOptInfo()->Clear();

    const auto& args = scope->OrderedVars();
    int nparam = f->GetType()->Params()->NumFields();

    for ( const auto& a : args ) {
        if ( --nparam < 0 )
            break;

        a->GetOptInfo()->Clear();
        TrackID(a);
    }

    for ( const auto& o_id : cast_intrusive<ScriptFunc>(f)->GetOuterIDs() ) {
        o_id->GetOptInfo()->Clear();
        TrackID(o_id);
    }

    stmt_num = 0;

    body->Traverse(this);
}

TraversalCode GenIDDefs::PreStmt(const Stmt* s) {
    last_stmt_traversed = s;

    auto si = s->GetOptInfo();
    si->stmt_num = ++stmt_num;
    si->block_level = confluence_blocks.size() + 1;

    switch ( s->Tag() ) {
        case STMT_CATCH_RETURN: {
            auto cr = s->AsCatchReturnStmt();
            auto block = cr->Block();

            cr_active.push_back(confluence_blocks.size());
















            bool did_confluence = false;

            if ( block->Tag() == STMT_LIST ) {
                auto prev_stmt = s;
                auto& stmts = block->AsStmtList()->Stmts();
                for ( auto& st : stmts ) {
                    if ( ! did_confluence && st->CouldReturn(false) ) {
                        StartConfluenceBlock(prev_stmt);
                        did_confluence = true;
                    }

                    st->Traverse(this);
                }
            }
            else {







                StartConfluenceBlock(s);
                did_confluence = true;
                block->Traverse(this);
            }

            if ( did_confluence )
                EndConfluenceBlock();

            cr_active.pop_back();

            auto retvar = cr->RetVar();
            if ( retvar )
                TrackID(retvar->IdPtr());

            return TC_ABORTSTMT;
        }

        case STMT_IF: {
            auto i = s->AsIfStmt();
            auto cond = i->StmtExpr();
            auto t_branch = i->TrueBranch();
            auto f_branch = i->FalseBranch();

            cond->Traverse(this);

            StartConfluenceBlock(s);

            t_branch->Traverse(this);
            if ( ! t_branch->NoFlowAfter(false) )
                BranchBeyond(last_stmt_traversed, s, true);

            f_branch->Traverse(this);
            if ( ! f_branch->NoFlowAfter(false) )
                BranchBeyond(last_stmt_traversed, s, true);

            EndConfluenceBlock(true);

            return TC_ABORTSTMT;
        }

        case STMT_SWITCH: AnalyzeSwitch(s->AsSwitchStmt()); return TC_ABORTSTMT;

        case STMT_FOR: {
            auto f = s->AsForStmt();

            auto ids = f->LoopVars();
            auto e = f->LoopExpr();
            auto body = f->LoopBody();
            auto val_var = f->ValueVar();

            e->Traverse(this);

            for ( const auto& id : *ids )
                TrackID(id);

            if ( val_var )
                TrackID(val_var);

            StartConfluenceBlock(s);
            body->Traverse(this);

            if ( ! body->NoFlowAfter(false) )
                BranchBackTo(last_stmt_traversed, s, true);

            EndConfluenceBlock();

            return TC_ABORTSTMT;
        }

        case STMT_WHEN: {
            auto w = s->AsWhenStmt();

            for ( const auto& c : *w->Captures() )
                CheckVarUsage(with_location_of(make_intrusive<NameExpr>(c.Id()), w).get(), c.Id());

            auto te = w->TimeoutExpr();
            if ( te )
                te->Traverse(this);

            return TC_ABORTSTMT;
        }

        case STMT_WHILE: {
            auto w = s->AsWhileStmt();

            StartConfluenceBlock(s);

            auto cond_pred_stmt = w->CondPredStmt();
            if ( cond_pred_stmt )
                cond_pred_stmt->Traverse(this);






            auto cond_stmt = w->ConditionAsStmt();
            cond_stmt->Traverse(this);

            auto body = w->Body();
            body->Traverse(this);

            if ( ! body->NoFlowAfter(false) )
                BranchBackTo(last_stmt_traversed, s, true);

            EndConfluenceBlock();

            return TC_ABORTSTMT;
        }

        default: return TC_CONTINUE;
    }
}

void GenIDDefs::AnalyzeSwitch(const SwitchStmt* sw) {
    sw->StmtExpr()->Traverse(this);

    for ( const auto& c : *sw->Cases() ) {





        StartConfluenceBlock(sw);

        auto body = c->Body();

        auto exprs = c->ExprCases();
        if ( exprs )
            exprs->Traverse(this);

        auto type_ids = c->TypeCases();
        if ( type_ids ) {
            for ( const auto& id : *type_ids )
                if ( id->Name() )
                    TrackID(id);
        }

        body->Traverse(this);
        EndConfluenceBlock(false);
    }
}

TraversalCode GenIDDefs::PostStmt(const Stmt* s) {
    switch ( s->Tag() ) {
        case STMT_INIT: {
            auto init = s->AsInitStmt();
            auto& inits = init->Inits();

            for ( const auto& id : inits ) {
                auto id_t = id->GetType();


                if ( zeek::IsAggr(id->GetType()->Tag()) )
                    TrackID(id);
            }

            break;
        }

        case STMT_RETURN: ReturnAt(s); break;

        case STMT_NEXT: BranchBackTo(last_stmt_traversed, FindLoop(), false); break;

        case STMT_BREAK: {
            auto target = FindBreakTarget();

            if ( target )
                BranchBeyond(s, target, false);

            else {
                ASSERT(func_flavor == FUNC_FLAVOR_HOOK);
                ReturnAt(s);
            }

            break;
        }



        case STMT_FALLTHROUGH:
        default: break;
    }

    return TC_CONTINUE;
}

TraversalCode GenIDDefs::PreExpr(const Expr* e) {
    e->GetOptInfo()->stmt_num = stmt_num;

    switch ( e->Tag() ) {
        case EXPR_NAME: CheckVarUsage(e, e->AsNameExpr()->IdPtr()); break;

        case EXPR_ASSIGN: {
            auto lhs = e->GetOp1();

            if ( lhs->Tag() == EXPR_LIST && in_table_constructor > 0 )


                return TC_CONTINUE;

            auto op2 = e->GetOp2();
            op2->Traverse(this);

            if ( ! CheckLHS(lhs, op2) )



                lhs->Traverse(this);

            return TC_ABORTSTMT;
        }

        case EXPR_COND:






            ++suppress_usage;
            e->GetOp1()->Traverse(this);
            e->GetOp2()->Traverse(this);
            e->GetOp3()->Traverse(this);
            --suppress_usage;

            return TC_ABORTSTMT;

        case EXPR_LAMBDA: {
            auto l = static_cast<const LambdaExpr*>(e);
            const auto& ids = l->OuterIDs();

            for ( auto& id : ids )
                CheckVarUsage(e, id);



            return TC_ABORTSTMT;
        }

        case EXPR_TABLE_CONSTRUCTOR: ++in_table_constructor; break;

        default: break;
    }

    return TC_CONTINUE;
}

TraversalCode GenIDDefs::PostExpr(const Expr* e) {






    auto t = e->Tag();
    if ( t == EXPR_INCR || t == EXPR_DECR || t == EXPR_ADD_TO || t == EXPR_REMOVE_FROM ) {
        auto op = e->GetOp1();
        if ( ! IsAggr(op) )
            (void)CheckLHS(op);
    }
    else if ( t == EXPR_TABLE_CONSTRUCTOR )
        --in_table_constructor;

    return TC_CONTINUE;
}

bool GenIDDefs::CheckLHS(const ExprPtr& lhs, const ExprPtr& rhs) {
    switch ( lhs->Tag() ) {
        case EXPR_REF: return CheckLHS(lhs->GetOp1(), rhs);

        case EXPR_NAME: {
            auto n = lhs->AsNameExpr();
            TrackID(n->IdPtr(), rhs);
            return true;
        }

        case EXPR_LIST: {
            auto l = lhs->AsListExpr();
            for ( const auto& expr : l->Exprs() ) {
                if ( expr->Tag() != EXPR_NAME )


                    return false;

                auto n = expr->AsNameExpr();
                TrackID(n->IdPtr());
            }

            return true;
        }



        case EXPR_FIELD:



        case EXPR_INDEX: return false;

        default: reporter->InternalError("bad tag in GenIDDefs::CheckLHS");
    }
}

bool GenIDDefs::IsAggr(const Expr* e) const {
    if ( e->Tag() != EXPR_NAME )
        return false;

    auto n = e->AsNameExpr();
    auto id = n->Id();
    auto tag = id->GetType()->Tag();

    return zeek::IsAggr(tag);
}

void GenIDDefs::CheckVarUsage(const Expr* e, const IDPtr& id) {
    if ( analysis_options.usage_issues != 1 || id->IsGlobal() || suppress_usage > 0 )
        return;

    auto oi = id->GetOptInfo();

    if ( ! oi->DidUndefinedWarning() && ! oi->IsDefinedBefore(last_stmt_traversed) &&
         ! id->GetAttr(ATTR_IS_ASSIGNED) ) {
        if ( ! oi->IsPossiblyDefinedBefore(last_stmt_traversed) ) {
            e->Warn("used without definition");
            oi->SetDidUndefinedWarning();
        }

        else if ( ! oi->DidPossiblyUndefinedWarning() ) {
            e->Warn("possibly used without definition");
            oi->SetDidPossiblyUndefinedWarning();
        }
    }
}

void GenIDDefs::StartConfluenceBlock(const Stmt* s) {
    confluence_blocks.push_back(s);
    modified_IDs.emplace_back();
}

void GenIDDefs::EndConfluenceBlock(bool no_orig) {
    for ( const auto& id : modified_IDs.back() )
        id->GetOptInfo()->ConfluenceBlockEndsAfter(last_stmt_traversed, no_orig);

    confluence_blocks.pop_back();
    modified_IDs.pop_back();
}

void GenIDDefs::BranchBackTo(const Stmt* from, const Stmt* to, bool close_all) {
    for ( const auto& id : modified_IDs.back() )
        id->GetOptInfo()->BranchBackTo(from, to, close_all);
}

void GenIDDefs::BranchBeyond(const Stmt* from, const Stmt* to, bool close_all) {
    for ( const auto& id : modified_IDs.back() )
        id->GetOptInfo()->BranchBeyond(from, to, close_all);

    to->GetOptInfo()->contains_branch_beyond = true;
}

const Stmt* GenIDDefs::FindLoop() {
    int i = confluence_blocks.size() - 1;
    while ( i >= 0 ) {
        auto t = confluence_blocks[i]->Tag();
        if ( t == STMT_WHILE || t == STMT_FOR )
            break;

        --i;
    }

    ASSERT(i >= 0);

    return confluence_blocks[i];
}

const Stmt* GenIDDefs::FindBreakTarget() {
    int i = confluence_blocks.size() - 1;
    while ( i >= 0 ) {
        auto cb = confluence_blocks[i];
        auto t = cb->Tag();
        if ( t == STMT_WHILE || t == STMT_FOR || t == STMT_SWITCH )
            return cb;

        --i;
    }

    return nullptr;
}

void GenIDDefs::ReturnAt(const Stmt* s) {



    if ( cr_active.empty() || cr_active.back() != confluence_blocks.size() )
        for ( const auto& id : modified_IDs.back() )
            id->GetOptInfo()->ReturnAt(s);
}

void GenIDDefs::TrackID(const IDPtr& id, const ExprPtr& e) {
    auto oi = id->GetOptInfo();








    oi->SetDefinedAfter(last_stmt_traversed, e, confluence_blocks, 0);



    for ( auto i = 0U; i < confluence_blocks.size(); ++i )


        modified_IDs[i + 1].insert(id);

    if ( confluence_blocks.empty() )

        modified_IDs[0].insert(id);
}

}
