




#pragma once

#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

class GenIDDefs : public TraversalCallback {
public:
    GenIDDefs(std::shared_ptr<ProfileFunc> _pf, const FuncPtr& f, ScopePtr scope, StmtPtr body);

private:


    void TraverseFunction(const FuncPtr& f, ScopePtr scope, StmtPtr body);

    TraversalCode PreStmt(const Stmt*) override;
    void AnalyzeSwitch(const SwitchStmt* sw);

    TraversalCode PostStmt(const Stmt*) override;
    TraversalCode PreExpr(const Expr*) override;
    TraversalCode PostExpr(const Expr*) override;






    bool CheckLHS(const ExprPtr& lhs, const ExprPtr& rhs = nullptr);


    bool IsAggr(const ExprPtr& e) const { return IsAggr(e.get()); }
    bool IsAggr(const Expr* e) const;



    void CheckVarUsage(const Expr* e, const IDPtr& id);


    void StartConfluenceBlock(const Stmt* s);




    void EndConfluenceBlock(bool no_orig_flow = false);





    void BranchBackTo(const Stmt* from, const Stmt* to, bool close_all);
    void BranchBeyond(const Stmt* from, const Stmt* to, bool close_all);




    const Stmt* FindLoop();
    const Stmt* FindBreakTarget();



    void ReturnAt(const Stmt* s);





    void TrackID(const IDPtr& id, const ExprPtr& e = nullptr);



    std::shared_ptr<ProfileFunc> pf;




    FunctionFlavor func_flavor;


    const Stmt* last_stmt_traversed = nullptr;



    int in_table_constructor = 0;


    int stmt_num;


    std::vector<const Stmt*> confluence_blocks;







    std::vector<zeek_uint_t> cr_active;





    std::vector<IDSet> modified_IDs;




    int suppress_usage = 0;
};

}
