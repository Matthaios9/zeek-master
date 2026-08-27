



#pragma once

#include <unordered_set>

#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/Scope.h"

namespace zeek::detail {

class FuncInfo;
class ProfileFunc;

class Inliner {
public:



    Inliner(std::vector<FuncInfo>& _funcs, bool _report_recursive)
        : funcs(_funcs), report_recursive(_report_recursive) {
        Analyze();
    }



    ExprPtr CheckForInlining(CallExprPtr c);


    bool WasFullyInlined(const Func* f) { return did_inline.contains(f) && ! skipped_inlining.contains(f); }

protected:


    void Analyze();





    using BodyInfo = std::unordered_map<const Stmt*, size_t>;



    void CoalesceEventHandlers();





    void CoalesceEventHandlers(ScriptFuncPtr sf, const std::vector<Func::Body>& bodies, const BodyInfo& body_to_info);


    void InlineFunction(FuncInfo* f);


    void PreInline(StmtOptInfo* oi, size_t frame_size);


    void PostInline(StmtOptInfo* oi, ScriptFuncPtr f);


    ExprPtr DoInline(ScriptFuncPtr sf, StmtPtr body, ListExprPtr args, ScopePtr scope, const ProfileFunc* pf);



    std::vector<FuncInfo>& funcs;



    std::unordered_map<const Func*, const ProfileFunc*> inline_ables;


    std::unordered_set<const Func*> did_inline;



    std::unordered_set<const Func*> skipped_inlining;



    int max_inlined_frame_size;



    int curr_frame_size;




    int num_stmts;
    int num_exprs;



    bool report_recursive;
};

}
