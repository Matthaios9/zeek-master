



#pragma once

#include "zeek/script_opt/Expr.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/UseDefs.h"
#include "zeek/script_opt/ZAM/ZBody.h"
#include "zeek/script_opt/ZAM/ZInst.h"

namespace zeek {
class EventHandler;
}

namespace zeek::detail {

class NameExpr;
class ConstExpr;
class FieldExpr;
class ListExpr;

class Stmt;
class SwitchStmt;
class CatchReturnStmt;

using InstLabel = ZInstI*;





class ZAMStmt {
protected:
    friend class ZAMCompiler;

    ZAMStmt() { stmt_num = -1;  }
    ZAMStmt(int _stmt_num) { stmt_num = _stmt_num; }

    int stmt_num;
};




class OpaqueVals {
public:
    OpaqueVals(ZInstAux* _aux) { aux = _aux; }

    ZInstAux* aux;
};











class ZAMCompiler {
public:
    ZAMCompiler(ScriptFuncPtr f, std::shared_ptr<ProfileFuncs> pfs, std::shared_ptr<ProfileFunc> pf, ScopePtr scope,
                StmtPtr body, std::shared_ptr<UseDefs> ud, std::shared_ptr<Reducer> rd);
    ~ZAMCompiler();

    const FrameReMap& FrameDenizens() const { return shared_frame_denizens_final; }

    const std::vector<int>& ManagedSlots() const { return managed_slotsI; }

    const std::vector<GlobalInfo>& Globals() const { return globalsI; }

    bool NonRecursive() const { return non_recursive; }

    const TableIterVec& GetTableIters() const { return table_iters; }
    int NumStepIters() const { return num_step_iters; }

    template<typename T>
    const CaseMaps<T>& GetCases() const {
        if constexpr ( std::is_same_v<T, zeek_int_t> )
            return int_cases;
        else if constexpr ( std::is_same_v<T, zeek_uint_t> )
            return uint_cases;
        else if constexpr ( std::is_same_v<T, double> )
            return double_cases;
        else if constexpr ( std::is_same_v<T, std::string> )
            return str_cases;
    }

    StmtPtr CompileBody();

    void Dump();

private:
    friend class SimpleZBI;
    friend class CondZBI;
    friend class OptAssignZBI;
    friend class SortZBI;
    friend class CatZBI;
    friend class MultiZBI;






    template<typename T>
    using CaseMapI = std::map<T, InstLabel>;
    template<typename T>
    using CaseMapsI = std::vector<CaseMapI<T>>;

#include "zeek/script_opt/ZAM/AM-Opt.h"
#include "zeek/script_opt/ZAM/Branches.h"
#include "zeek/script_opt/ZAM/Driver.h"
#include "zeek/script_opt/ZAM/Expr.h"
#include "zeek/script_opt/ZAM/Inst-Gen.h"
#include "zeek/script_opt/ZAM/Low-Level.h"
#include "zeek/script_opt/ZAM/Stmt.h"
#include "zeek/script_opt/ZAM/Vars.h"


#include "zeek/ZAM-MethodDecls.h"




    std::vector<ZInstI*> insts1;
    std::vector<ZInstI*> insts2;



    ZInstI* pending_inst = nullptr;





    ZInstI* last_added_inst = nullptr;




    GoToSets breaks;
    GoToSets nexts;
    GoToSets fallthroughs;
    GoToSets catches;




    std::vector<const NameExpr*> retvars;

    ScriptFuncPtr func;
    std::shared_ptr<ProfileFuncs> pfs;
    std::shared_ptr<ProfileFunc> pf;
    ScopePtr scope;
    StmtPtr body;
    std::shared_ptr<UseDefs> ud;
    std::shared_ptr<Reducer> reducer;


    std::unordered_map<IDPtr, int> frame_layout1;



    FrameMap frame_denizens;


    FrameReMap shared_frame_denizens;



    FrameReMap shared_frame_denizens_final;




    std::vector<int> frame1_to_frame2;



    using AssociatedLocals = std::unordered_map<const ZInstI*, IDSet>;





    AssociatedLocals inst_beginnings;




    AssociatedLocals inst_endings;


    using AssociatedInsts = std::unordered_map<int, const ZInstI*>;



    AssociatedInsts denizen_beginning;
    AssociatedInsts denizen_ending;




    std::vector<GlobalInfo> globalsI;
    std::unordered_map<IDPtr, int> global_id_to_info;



    CaseMapsI<zeek_int_t> int_casesI;
    CaseMapsI<zeek_uint_t> uint_casesI;
    CaseMapsI<double> double_casesI;



    CaseMapsI<std::string> str_casesI;


    CaseMaps<zeek_int_t> int_cases;
    CaseMaps<zeek_uint_t> uint_cases;
    CaseMaps<double> double_cases;
    CaseMaps<std::string> str_cases;

    std::vector<int> managed_slotsI;

    int frame_sizeI;

    TableIterVec table_iters;
    int num_step_iters = 0;

    bool non_recursive = false;


    int top_main_inst;





    int pending_global_store = -1;
    int pending_capture_store = -1;
};


class FuncInfo;
extern void finalize_functions(const std::vector<FuncInfo>& funcs);

}
