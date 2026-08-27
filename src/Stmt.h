

#pragma once



#include "zeek/Dict.h"
#include "zeek/Expr.h"
#include "zeek/ID.h"
#include "zeek/StmtBase.h"
#include "zeek/Type.h"
#include "zeek/ZeekList.h"

namespace zeek::detail {

class CompositeHash;
class NameExpr;
using NameExprPtr = IntrusivePtr<zeek::detail::NameExpr>;

class ZAMCompiler;

class ExprListStmt : public Stmt {
public:
    ~ExprListStmt() override;

    const ListExpr* ExprList() const { return l.get(); }
    const ListExprPtr& ExprListPtr() const { return l; }

    TraversalCode Traverse(TraversalCallback* cb) const override;


    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

protected:
    ExprListStmt(StmtTag t, ListExprPtr arg_l);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    virtual ValPtr DoExec(std::vector<ValPtr> vals, StmtFlowType& flow) = 0;

    void StmtDescribe(ODesc* d) const override;

    ListExprPtr l;





    virtual StmtPtr DoSubclassReduce(ListExprPtr singletons, Reducer* c) = 0;
};

class PrintStmt final : public ExprListStmt {
public:
    template<typename L>
    explicit PrintStmt(L&& l) : ExprListStmt(STMT_PRINT, std::forward<L>(l)) {}


    StmtPtr Duplicate() override;

protected:
    ValPtr DoExec(std::vector<ValPtr> vals, StmtFlowType& flow) override;


    StmtPtr DoSubclassReduce(ListExprPtr singletons, Reducer* c) override;
};

extern void do_print_stmt(const std::vector<ValPtr>& vals);

class ExprStmt : public Stmt {
public:
    explicit ExprStmt(ExprPtr e);
    ~ExprStmt() override;




    ExprStmt(StmtTag t, ExprPtr e);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    const Expr* StmtExpr() const { return e.get(); }
    ExprPtr StmtExprPtr() const;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

protected:
    virtual ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow);

    bool IsPure() const override;

    ExprPtr e;
};

class IfStmt : public ExprStmt {
public:
    IfStmt(ExprPtr test, StmtPtr s1, StmtPtr s2);
    ~IfStmt() override;

    const Stmt* TrueBranch() const { return s1.get(); }
    const Stmt* FalseBranch() const { return s2.get(); }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    bool NoFlowAfter(bool ignore_break) const override;
    bool CouldReturn(bool ignore_break) const override;

protected:
    ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) override;
    bool IsPure() const override;

    bool IsMinMaxConstruct() const;
    StmtPtr ConvertToMinMaxConstruct();

    StmtPtr s1;
    StmtPtr s2;
};

class DebugIfStmt final : public IfStmt {
public:
    DebugIfStmt(ExprPtr test, StmtPtr s1, StmtPtr s2) : IfStmt(test, s1, s2) {}

protected:
    ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) override;
};

class Case final : public Obj {
public:
    Case(ListExprPtr c, IDPList* types, StmtPtr arg_s);
    ~Case() override;

    const ListExpr* ExprCases() const { return expr_cases.get(); }
    ListExpr* ExprCases() { return expr_cases.get(); }

    const IDPList* TypeCases() const { return type_cases; }
    IDPList* TypeCases() { return type_cases; }

    const Stmt* Body() const { return s.get(); }
    Stmt* Body() { return s.get(); }

    void UpdateBody(StmtPtr new_body) { s = std::move(new_body); }

    void Describe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const;


    IntrusivePtr<Case> Duplicate();

protected:
    ListExprPtr expr_cases;
    IDPList* type_cases;
    StmtPtr s;
};

using case_list = PList<Case>;

class SwitchStmt final : public ExprStmt {
public:
    SwitchStmt(ExprPtr index, case_list* cases);
    ~SwitchStmt() override;

    const case_list* Cases() const { return cases; }
    bool HasDefault() const { return default_case_idx != -1; }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    bool NoFlowAfter(bool ignore_break) const override;
    bool CouldReturn(bool ignore_break) const override;

protected:
    friend class ZAMCompiler;
    friend class CPPCompile;

    int DefaultCaseIndex() const { return default_case_idx; }
    const auto& ValueMap() const { return case_label_value_map; }
    const std::vector<std::pair<IDPtr, int>>* TypeMap() const { return &case_label_type_list; }
    const CompositeHash* CompHash() const { return comp_hash; }

    ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) override;
    bool IsPure() const override;


    void Init();





    bool AddCaseLabelValueMapping(const Val* v, int idx);




    bool AddCaseLabelTypeMapping(IDPtr t, int idx);





    std::pair<int, IDPtr> FindCaseLabelMatch(const Val* v) const;

    case_list* cases = nullptr;
    int default_case_idx = -1;
    CompositeHash* comp_hash = nullptr;
    std::unordered_map<const Val*, int> case_label_value_map;
    PDict<int> case_label_hash_map;
    std::vector<std::pair<IDPtr, int>> case_label_type_list;
};

class EventStmt final : public ExprStmt {
public:
    explicit EventStmt(EventExprPtr e);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override;

    StmtPtr DoReduce(Reducer* c) override;

protected:
    EventExprPtr event_expr;
};

class WhileStmt final : public Stmt {
public:
    WhileStmt(ExprPtr loop_condition, StmtPtr body);
    ~WhileStmt() override;

    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    const ExprPtr& Condition() const { return loop_condition; }
    StmtPtr CondPredStmt() const { return loop_cond_pred_stmt; }
    const StmtPtr& Body() const { return body; }
    const StmtPtr& ConditionAsStmt() const { return stmt_loop_condition; }




    bool CouldReturn(bool ignore_break) const override;

protected:
    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    ExprPtr loop_condition;
    StmtPtr body;






    StmtPtr loop_cond_pred_stmt = nullptr;




    StmtPtr stmt_loop_condition = nullptr;
};

class ForStmt final : public ExprStmt {
public:
    ForStmt(IDPList* loop_vars, ExprPtr loop_expr);

    ForStmt(IDPList* loop_vars, ExprPtr loop_expr, IDPtr val_var);
    ~ForStmt() override;

    void AddBody(StmtPtr arg_body) { body = std::move(arg_body); }

    const IDPList* LoopVars() const { return loop_vars; }
    IDPtr ValueVar() const { return value_var; }
    const Expr* LoopExpr() const { return e.get(); }
    const Stmt* LoopBody() const { return body.get(); }

    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;




    bool CouldReturn(bool ignore_break) const override;

protected:
    ValPtr DoExec(Frame* f, Val* v, StmtFlowType& flow) override;

    IDPList* loop_vars;
    StmtPtr body;


    IDPtr value_var;
};

class NextStmt final : public Stmt {
public:
    NextStmt() : Stmt(STMT_NEXT) {}

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override { return SetSucc(new NextStmt()); }

    bool NoFlowAfter(bool ignore_break) const override { return true; }

protected:
};

class BreakStmt final : public Stmt {
public:
    BreakStmt() : Stmt(STMT_BREAK) {}

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override { return SetSucc(new BreakStmt()); }

    bool NoFlowAfter(bool ignore_break) const override { return ! ignore_break; }
    bool CouldReturn(bool ignore_break) const override { return ! ignore_break; }

protected:
};

class FallthroughStmt final : public Stmt {
public:
    FallthroughStmt() : Stmt(STMT_FALLTHROUGH) {}

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override { return SetSucc(new FallthroughStmt()); }

protected:
};

class ReturnStmt final : public ExprStmt {
public:
    explicit ReturnStmt(ExprPtr e);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    void StmtDescribe(ODesc* d) const override;


    StmtPtr Duplicate() override;



    ReturnStmt(ExprPtr e, bool ignored);


    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    bool NoFlowAfter(bool ignore_break) const override { return true; }
    bool CouldReturn(bool ignore_break) const override { return true; }
};

class StmtList : public Stmt {
public:
    StmtList();

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    const auto& Stmts() const { return stmts; }
    auto& Stmts() { return stmts; }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override;
    void Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    bool NoFlowAfter(bool ignore_break) const override;
    bool CouldReturn(bool ignore_break) const override;


    StmtList(StmtPtr s1, StmtPtr s2);
    StmtList(StmtPtr s1, StmtPtr s2, StmtPtr s3);

protected:
    bool IsPure() const override;

    std::vector<StmtPtr> stmts;


    bool ReduceStmt(unsigned int& s_i, std::vector<StmtPtr>& f_stmts, Reducer* c);

    void ResetStmts(std::vector<StmtPtr> new_stmts) { stmts = std::move(new_stmts); }
};

class DebugStmtList : public StmtList {
public:
    DebugStmtList() = default;

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
};

class InitStmt final : public Stmt {
public:
    explicit InitStmt(std::vector<IDPtr> arg_inits);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    const std::vector<IDPtr>& Inits() const { return inits; }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

protected:
    std::vector<IDPtr> inits;
};

class NullStmt final : public Stmt {
public:
    NullStmt(bool arg_is_directive = false);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    bool IsPure() const override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override { return SetSucc(new NullStmt()); }


    bool IsDirective() const { return is_directive; };

private:
    bool is_directive;
};

class AssertStmt final : public ExprStmt {
public:
    explicit AssertStmt(ExprPtr cond, ExprPtr msg = nullptr);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    const auto& CondDesc() const { return cond_desc; }
    const auto& Msg() const { return msg; }
    const auto& MsgSetupStmt() const { return msg_setup_stmt; }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

private:
    std::string cond_desc;
    ExprPtr msg;



    StmtPtr msg_setup_stmt;
};





extern void report_assert(bool cond, std::string_view cond_desc, StringValPtr msg_val, const Location* loc);




class WhenInfo {
public:

    WhenInfo(ExprPtr cond, FuncType::CaptureList* cl, bool is_return);


    WhenInfo(const WhenInfo* orig);


    WhenInfo(bool is_return);

    ~WhenInfo() { delete cl; }

    void AddBody(StmtPtr arg_s) { s = std::move(arg_s); }

    void AddTimeout(ExprPtr arg_timeout, StmtPtr arg_timeout_s) {
        timeout = std::move(arg_timeout);
        timeout_s = std::move(arg_timeout_s);
    }





    void Build(StmtPtr ws = nullptr);


    const LambdaExprPtr& Lambda() const { return lambda; }




    void Instantiate(Frame* f);
    void Instantiate(ValPtr func);


    const ExprPtr& OrigCond() const { return cond; }
    const StmtPtr& OrigBody() const { return s; }
    const ExprPtr& OrigTimeout() const { return timeout; }
    const StmtPtr& OrigTimeoutStmt() const { return timeout_s; }


    ExprPtr Cond();
    StmtPtr WhenBody();
    StmtPtr TimeoutStmt();

    ExprPtr TimeoutExpr() const { return timeout; }
    void SetTimeoutExpr(ExprPtr e) { timeout = std::move(e); }
    double TimeoutVal(Frame* f);

    FuncType::CaptureList* Captures() { return cl; }
    const FuncType::CaptureList* Captures() const { return cl; }

    bool IsReturn() const { return is_return; }




    const auto& WhenExprLocals() const { return when_expr_locals; }
    const auto& WhenExprGlobals() const { return when_expr_globals; }


    const auto& WhenNewLocals() const { return when_new_locals; }



    bool HasUnreducedIDs(Reducer* c) const;
    void UpdateIDs(Reducer* c);

private:


    void BuildProfile();


    void BuildInvokeElems();

    ExprPtr cond;
    StmtPtr s;
    StmtPtr timeout_s;
    ExprPtr timeout;
    FuncType::CaptureList* cl = nullptr;

    bool is_return = false;



    std::string lambda_param_id;
    IDPtr param_id;


    LambdaExprPtr lambda;
    FuncTypePtr lambda_ft;



    ExprPtr curr_lambda;



    ListExprPtr invoke_cond;
    ListExprPtr invoke_s;
    ListExprPtr invoke_timeout;


    ConstExprPtr one_const;
    ConstExprPtr two_const;
    ConstExprPtr three_const;

    std::vector<IDPtr> when_expr_locals;
    IDSet when_expr_globals;


    IDSet when_new_locals;
};

class WhenStmt final : public Stmt {
public:
    WhenStmt(std::shared_ptr<WhenInfo> wi);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;
    bool IsPure() const override;

    ExprPtr Cond() const { return wi->Cond(); }
    StmtPtr Body() const { return wi->WhenBody(); }
    ExprPtr TimeoutExpr() const { return wi->TimeoutExpr(); }
    StmtPtr TimeoutBody() const { return wi->TimeoutStmt(); }
    bool IsReturn() const { return wi->IsReturn(); }

    const FuncType::CaptureList* Captures() const { return wi->Captures(); }

    auto Info() const { return wi; }

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    StmtPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

private:
    std::shared_ptr<WhenInfo> wi;
};




class CatchReturnStmt : public Stmt {
public:
    explicit CatchReturnStmt(ScriptFuncPtr sf, StmtPtr block, NameExprPtr ret_var);

    const ScriptFuncPtr& Func() const { return sf; }
    StmtPtr Block() const { return block; }



    const NameExpr* RetVar() const { return ret_var.get(); }



    StmtPtr AssignStmt() const { return assign_stmt; }

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    bool IsPure() const override;



    StmtPtr DoReduce(Reducer* c) override;





    StmtPtr Duplicate() override;

    void StmtDescribe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;

protected:

    ScriptFuncPtr sf;


    StmtPtr block;


    NameExprPtr ret_var;



    StmtPtr assign_stmt;
};




class CheckAnyLenStmt : public ExprStmt {
public:
    explicit CheckAnyLenStmt(ExprPtr e, int expected_len);

    int ExpectedLen() const { return expected_len; }

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    StmtPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    StmtPtr DoReduce(Reducer* c) override;

    void StmtDescribe(ODesc* d) const override;

protected:
    int expected_len;
};



class StdFunctionStmt : public Stmt {
public:
    StdFunctionStmt(std::function<void(const zeek::Args&, StmtFlowType&)> f)
        : Stmt(STMT_STD_FUNCTION), func(std::move(f)) {}

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;

    StmtPtr Duplicate() override { return make_intrusive<StdFunctionStmt>(func); }

    TraversalCode Traverse(TraversalCallback* cb) const override { return TC_CONTINUE; }

private:
    std::function<void(const zeek::Args&, StmtFlowType&)> func;
};

}
