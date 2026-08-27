

#pragma once





#include "zeek/zeek-config.h"

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"
#include "zeek/RunState.h"
#include "zeek/StmtEnums.h"
#include "zeek/TraverseTypes.h"
#include "zeek/util.h"

namespace zeek {

class Val;
using ValPtr = IntrusivePtr<Val>;

namespace detail {

class CompositeHash;
class Frame;

class AssertStmt;
class CatchReturnStmt;
class ExprStmt;
class ForStmt;
class IfStmt;
class InitStmt;
class NullStmt;
class PrintStmt;
class ReturnStmt;
class StmtList;
class SwitchStmt;
class WhenStmt;
class WhileStmt;

class EventExpr;
class ListExpr;

using EventExprPtr = IntrusivePtr<EventExpr>;
using ListExprPtr = IntrusivePtr<ListExpr>;

class Inliner;
class Reducer;

class Stmt;
using StmtPtr = IntrusivePtr<Stmt>;

class StmtOptInfo;

class Stmt : public Obj {
public:
    StmtTag Tag() const { return tag; }

    ~Stmt() override;

    virtual ValPtr Exec(Frame* f, StmtFlowType& flow) = 0;

    Stmt* Ref() {
        zeek::Ref(this);
        return this;
    }
    StmtPtr ThisPtr() { return {NewRef{}, this}; }

    bool SetLocationInfo(const Location* loc) override { return Stmt::SetLocationInfo(loc, loc); }
    bool SetLocationInfo(const Location* start, const Location* end) override;


    virtual bool IsPure() const;

    StmtList* AsStmtList();
    const StmtList* AsStmtList() const;

    ForStmt* AsForStmt();
    const ForStmt* AsForStmt() const;

    const ExprStmt* AsExprStmt() const;
    const PrintStmt* AsPrintStmt() const;
    const InitStmt* AsInitStmt() const;
    const CatchReturnStmt* AsCatchReturnStmt() const;
    const ReturnStmt* AsReturnStmt() const;
    const IfStmt* AsIfStmt() const;
    const WhileStmt* AsWhileStmt() const;
    const WhenStmt* AsWhenStmt() const;
    const SwitchStmt* AsSwitchStmt() const;
    const NullStmt* AsNullStmt() const;
    const AssertStmt* AsAssertStmt() const;

    void RegisterAccess() const {
        last_access = run_state::network_time;
        access_count++;
    }
    void AccessStats(ODesc* d) const;
    uint32_t GetAccessCount() const { return access_count; }

    void Describe(ODesc* d) const final;

    virtual void IncrBPCount() { ++breakpoint_count; }
    virtual void DecrBPCount();

    virtual unsigned int BPCount() const { return breakpoint_count; }

    virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;










    virtual StmtPtr Duplicate() = 0;


    virtual void Inline(Inliner* inl) {}


    virtual bool IsReduced(Reducer* c) const;



    StmtPtr Reduce(Reducer* c);
    virtual StmtPtr DoReduce(Reducer* c) { return ThisPtr(); }







    virtual bool NoFlowAfter(bool ignore_break) const { return false; }





    virtual bool CouldReturn(bool ignore_break) const { return false; }








    virtual StmtPtr SetSucc(Stmt* succ) {
        succ->SetLocationInfo(GetLocationInfo());
        return {AdoptRef{}, succ};
    }



    StmtOptInfo* GetOptInfo() const { return opt_info; }


    static int GetNumStmts() { return num_stmts; }


    static void ResetNumStmts() { num_stmts = 0; }

protected:
    explicit Stmt(StmtTag arg_tag);



    StmtPtr TransformMe(StmtPtr new_me, Reducer* c);

    void AddTag(ODesc* d) const;
    virtual void StmtDescribe(ODesc* d) const;
    void DescribeDone(ODesc* d) const;

    StmtTag tag;
    int breakpoint_count;


    mutable double last_access;
    mutable uint32_t access_count;



    StmtOptInfo* opt_info;


    static int num_stmts;
};

}
}
