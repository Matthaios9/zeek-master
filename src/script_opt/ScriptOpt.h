



#pragma once

#include <regex>
#include <string>
#include <unordered_set>
#include <vector>

#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/Scope.h"

namespace zeek {
struct Options;
}

namespace zeek::detail {

using ObjPtr = IntrusivePtr<Obj>;
using TypeSet = std::unordered_set<const Type*>;



struct AnalyOpt {




    std::vector<std::regex> only_funcs;


    std::vector<std::regex> only_files;



    std::vector<std::regex> skip_funcs;
    std::vector<std::regex> skip_files;



    bool report_uncompilable = false;




    bool activate = false;




    bool compile_all = false;


    bool optimize_AST = false;


    bool inliner = false;




    bool no_inliner = false;


    bool no_eh_coalescence = false;


    bool keep_asserts = false;



    bool report_recursive = false;



    bool validate_ZAM = false;



    bool gen_ZAM = false;



    bool gen_ZAM_code = false;


    bool no_ZAM_opt = false;


    bool no_ZAM_control_flow_opt = false;


    bool profile_ZAM = false;


    int profile_sampling_rate = 100;


    FILE* profile_file = nullptr;




    bool dump_xform = false;


    bool dump_uds = false;


    bool dump_ZAM = false;


    bool dump_final_ZAM = false;









    int usage_issues = 0;




    bool gen_CPP = false;



    bool gen_standalone_CPP = false;


    bool use_CPP = false;


    bool report_CPP = false;



    bool allow_cond = false;
};

extern AnalyOpt analysis_options;

class ProfileFunc;

using ScriptFuncPtr = IntrusivePtr<ScriptFunc>;


class FuncInfo {
public:
    FuncInfo(ScriptFuncPtr _func, ScopePtr _scope, Func::Body _body)
        : func(std::move(_func)), scope(std::move(_scope)), body(std::move(_body)) {}

    ScriptFunc* Func() const { return func.get(); }
    const ScriptFuncPtr& FuncPtr() const { return func; }
    const ScopePtr& Scope() const { return scope; }
    const StmtPtr& Body() const { return body.stmts; }
    int Priority() const { return body.priority; }
    auto EventGroups() const { return body.groups; }
    const ProfileFunc* Profile() const { return pf.get(); }
    std::shared_ptr<ProfileFunc> ProfilePtr() const { return pf; }

    void SetScope(ScopePtr new_scope) { scope = std::move(new_scope); }
    void SetBody(StmtPtr new_body) { body.stmts = std::move(new_body); }
    void SetProfile(std::shared_ptr<ProfileFunc> _pf) { pf = std::move(_pf); }

    bool ShouldAnalyze() const { return should_analyze; }
    void SetShouldNotAnalyze() {
        should_analyze = false;
        skip = true;
    }



    bool ShouldSkip() const { return skip; }
    void SetSkip(bool should_skip) { skip = should_skip; }

protected:
    ScriptFuncPtr func;
    ScopePtr scope;
    Func::Body body;
    std::shared_ptr<ProfileFunc> pf;





    bool should_analyze = true;



    bool skip = false;
};



class CoalescedScriptFunc : public ScriptFunc {
public:
    CoalescedScriptFunc(Func::Body merged_body, ScopePtr scope, ScriptFuncPtr orig_func)
        : ScriptFunc(orig_func->GetName(), orig_func->GetType(), {std::move(merged_body)}), orig_func(orig_func) {
        SetScope(std::move(scope));
    };

    ValPtr Invoke(zeek::Args* args, Frame* parent) const override {


        if ( orig_func->HasAllBodiesEnabled() )
            return ScriptFunc::Invoke(args, parent);

        return orig_func->Invoke(args, parent);
    }

private:
    ScriptFuncPtr orig_func;
};





extern std::unordered_set<const Func*> non_recursive_funcs;


extern void analyze_func(ScriptFuncPtr f);


extern void analyze_lambda(LambdaExpr* f);



extern void analyze_when_lambda(LambdaExpr* f);



extern void register_lambda_alias(const StmtPtr& orig, const StmtPtr& alias);



extern const Stmt* look_up_lambda_alias(const Stmt* alias);


extern bool is_lambda(const ScriptFunc* f);
extern bool is_when_lambda(const ScriptFunc* f);


extern void analyze_global_stmts(Stmt* stmts);


extern std::pair<StmtPtr, ScopePtr> get_global_stmts();



extern void switch_to_module(const char* module);


extern void add_func_analysis_pattern(AnalyOpt& opts, const char* pat, bool is_only);


extern void add_file_analysis_pattern(AnalyOpt& opts, const char* pat, bool is_only);



extern bool should_analyze(const ScriptFuncPtr& f, const StmtPtr& body);




enum class AnalyzeDecision : uint8_t { SHOULD, SHOULD_NOT, DEFAULT };
extern AnalyzeDecision filename_matches_opt_files(const char* filename);
extern AnalyzeDecision obj_matches_opt_files(const Obj* obj);
inline auto obj_matches_opt_files(const ObjPtr& obj) { return obj_matches_opt_files(obj.get()); }



extern void analyze_scripts(bool no_unused_warnings);




extern void validate_ZAM_insts();



extern void clear_script_analysis();


extern void finish_script_execution();



extern zeek_uint_t set_module_profiling(const std::string& mod, bool active);


extern RecordValPtr get_module_profile(const std::string& mod);




extern bool has_AST_node_unknown_to_script_opt(const ProfileFunc* prof, bool );



extern bool IsZAM_BuiltInCond(const CallExpr* c);



extern void (*CPP_init_hook)();

}
