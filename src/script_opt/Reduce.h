

#pragma once

#include "zeek/script_opt/ObjMgr.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

class TempVar;

class Reducer {
public:
    Reducer(const ScriptFuncPtr& func, std::shared_ptr<ProfileFunc> pf, std::shared_ptr<ProfileFuncs> pfs);

    StmtPtr Reduce(StmtPtr s);

    void SetReadyToOptimize() { opt_ready = true; }

    void SetCurrStmt(const Stmt* stmt) {
        om.AddObj(stmt);
        curr_stmt = stmt;
    }

    ExprPtr GenTemporaryExpr(const TypePtr& t, ExprPtr rhs);

    NameExprPtr UpdateName(NameExprPtr n);
    bool NameIsReduced(const NameExpr* n);

    void UpdateIDs(IDPList* ids);
    bool IDsAreReduced(const IDPList* ids) const;

    void UpdateIDs(std::vector<IDPtr>& ids);
    bool IDsAreReduced(const std::vector<IDPtr>& ids) const;

    IDPtr UpdateID(IDPtr id);
    bool ID_IsReduced(const IDPtr& id) const;


    bool ID_IsReducedOrTopLevel(const IDPtr& id);









    StmtPtr GenParam(const IDPtr& id, ExprPtr rhs, bool is_modified);



    NameExprPtr GenInlineBlockName(const IDPtr& id);

    int NumNewLocals() const { return new_locals.size(); }



    void PushInlineBlock();
    void PopInlineBlock();




    NameExprPtr GetRetVar(TypePtr type);




    bool BifurcationOkay() const { return bifurcation_level <= 12; }
    int BifurcationLevel() const { return bifurcation_level; }

    void PushBifurcation() { ++bifurcation_level; }
    void PopBifurcation() { --bifurcation_level; }

    int NumTemps() const { return temps.size(); }


    bool IsNewLocal(const NameExpr* n) const { return IsNewLocal(n->IdPtr()); }
    bool IsNewLocal(const IDPtr& id) const;

    bool IsTemporary(const IDPtr& id) const { return FindTemporary(id) != nullptr; }
    bool IsParamTemp(const IDPtr& id) const { return param_temps.contains(id); }

    bool IsConstantVar(const IDPtr& id) const { return constant_vars.contains(id); }



    bool Optimizing() const { return ! IsPruning() && opt_ready; }



    bool IsPruning() const { return ! omitted_stmts.empty(); }



    bool ShouldOmitStmt(const Stmt* s) const { return omitted_stmts.contains(s); }



    StmtPtr ReplacementStmt(const StmtPtr& s) const {
        auto repl = replaced_stmts.find(s.get());
        if ( repl == replaced_stmts.end() )
            return nullptr;
        else
            return repl->second;
    }



    void AddStmtToOmit(const Stmt* s) {
        om.AddObj(s);
        omitted_stmts.insert(s);
    }



    void AddStmtToReplace(const Stmt* s_old, StmtPtr s_new) {
        om.AddObj(s_old);
        replaced_stmts[s_old] = std::move(s_new);
    }



    void ResetAlteredStmts() {
        omitted_stmts.clear();
        replaced_stmts.clear();
    }











    void CheckForCSE(const AssignExpr* a, const NameExpr* lhs, const Expr* rhs);



    ConstExprPtr Fold(ExprPtr e);


    void FoldedTo(ExprPtr orig, ConstExprPtr c);




    StmtPtr MergeStmts(const NameExpr* lhs, ExprPtr rhs, const StmtPtr& succ_stmt);





    ExprPtr OptExpr(Expr* e);
    ExprPtr OptExpr(const ExprPtr& e) { return OptExpr(e.get()); }





    ExprPtr UpdateExpr(ExprPtr e, const Expr* parent);

protected:



    ExprPtr NewVarUsage(IDPtr var, const Expr* orig);

    void BindExprToCurrStmt(const ExprPtr& e);
    void BindStmtToCurrStmt(const StmtPtr& s);







    IDPtr FindExprTmp(const Expr* rhs, const Expr* a, const std::shared_ptr<const TempVar>& lhs_tmp);




    ExprPtr GetExprUpdate(ExprPtr e);



    bool ExprValid(const IDPtr& id, const Expr* e1, const Expr* e2) const;





    void CheckIDs(const ExprPtr& e, std::vector<IDPtr>& ids) const;

    IDPtr GenTemporary(TypePtr t, ExprPtr rhs, IDPtr id = nullptr);
    std::shared_ptr<TempVar> FindTemporary(const IDPtr& id) const;



    IDPtr FindNewLocal(const IDPtr& id);
    IDPtr FindNewLocal(const NameExprPtr& n) { return FindNewLocal(n->IdPtr()); }

    void AddNewLocal(const IDPtr& l);





    IDPtr GenLocal(const IDPtr& orig);




    const ConstExpr* CheckForConst(const IDPtr& id, int stmt_num) const;


    std::shared_ptr<ProfileFunc> pf;


    std::shared_ptr<ProfileFuncs> pfs;



    std::vector<std::shared_ptr<TempVar>> temps;



    std::vector<std::shared_ptr<const TempVar>> expr_temps;



    std::unordered_map<IDPtr, std::shared_ptr<TempVar>> ids_to_temps;


    IDSet tracked_ids;


    IDSet new_locals;



    IDSet param_temps;



    std::unordered_map<IDPtr, IDPtr> orig_to_new_locals;



    std::unordered_map<const Expr*, ConstExprPtr> constant_exprs;



    std::vector<ExprPtr> folded_exprs;



    std::unordered_set<const Stmt*> omitted_stmts;


    std::unordered_map<const Stmt*, StmtPtr> replaced_stmts;


    IDSet ret_vars;



    int inline_block_level = 0;




    std::vector<std::unordered_map<IDPtr, IDPtr>> block_locals;



    ObjMgr om;





    int bifurcation_level = 0;



    IDSet constant_vars;


    StmtPtr reduction_root;


    const Stmt* curr_stmt = nullptr;

    bool opt_ready = false;
};



extern const Expr* non_reduced_perp;
extern bool checking_reduction;


extern bool NonReduced(const Expr* perp);






extern bool same_expr(const ExprPtr& e1, const ExprPtr& e2);

}
