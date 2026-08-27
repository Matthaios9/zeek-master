

#pragma once


#include "zeek/Desc.h"
#include "zeek/script_opt/CPP/Func.h"
#include "zeek/script_opt/CPP/InitsInfo.h"
#include "zeek/script_opt/CPP/Tracker.h"
#include "zeek/script_opt/CPP/Util.h"
#include "zeek/script_opt/ScriptOpt.h"
















































































































namespace zeek::detail {

class CPPCompile {
public:

    CPPCompile(std::vector<FuncInfo>& _funcs, std::shared_ptr<ProfileFuncs> pfs, const std::string& gen_name,
               bool _standalone, bool report_uncompilable);
    ~CPPCompile();



    p_hash_type BodyHash(const Stmt* body);



    bool NotFullyCompilable(const std::string& fname) const { return not_fully_compilable.contains(fname); }

private:
#include "zeek/script_opt/CPP/Attrs.h"
#include "zeek/script_opt/CPP/Consts.h"
#include "zeek/script_opt/CPP/DeclFunc.h"
#include "zeek/script_opt/CPP/Driver.h"
#include "zeek/script_opt/CPP/Emit.h"
#include "zeek/script_opt/CPP/Exprs.h"
#include "zeek/script_opt/CPP/GenFunc.h"
#include "zeek/script_opt/CPP/Inits.h"
#include "zeek/script_opt/CPP/Stmts.h"
#include "zeek/script_opt/CPP/Types.h"
#include "zeek/script_opt/CPP/Vars.h"






    friend class CPP_InitsInfo;
    IndicesManager& IndMgr() { return indices_mgr; }

    IndicesManager indices_mgr;






    std::shared_ptr<CPP_InitsInfo> type_info;
    std::shared_ptr<CPP_InitsInfo> attr_info;
    std::shared_ptr<CPP_InitsInfo> attrs_info;
    std::shared_ptr<CPP_InitsInfo> call_exprs_info;
    std::shared_ptr<CPP_InitsInfo> lambda_reg_info;
    std::shared_ptr<CPP_InitsInfo> global_id_info;



    std::set<std::shared_ptr<CPP_InitsInfo>> all_global_info;



    std::unordered_map<std::string, std::shared_ptr<CallExprInitInfo>> init_infos;
};

}
