



#pragma once

#include <vector>

#include "zeek/script_opt/ZAM/IterInfo.h"

namespace zeek::detail {


class GlobalInfo {
public:
    IDPtr id;
    int slot;
};




template<typename T>
using CaseMap = std::map<T, int>;
template<typename T>
using CaseMaps = std::vector<CaseMap<T>>;

using TableIterVec = std::vector<TableIterInfo>;

struct ProfVal {
    zeek_uint_t num_samples = 0;
    double CPU_time = 0.0;
};

using ProfVec = std::vector<ProfVal>;
using ProfMap = std::unordered_map<std::string, ProfVal>;
using CallStack = std::vector<const ZAMLocInfo*>;

class ZBody : public Stmt {
public:
    ZBody(std::string _func_name, const ZAMCompiler* zc);

    ~ZBody() override;



    void SetInsts(std::vector<ZInstI*>& instsI);

    ValPtr Exec(Frame* f, StmtFlowType& flow) override;







    void Dump() const;


    void SetProfilingCalls(bool active) {
        profile_calls = active;
        profiling_set_call = ncall;
    }
    bool IsProfilingCalls() const { return profile_calls; }

    uint64_t NumBodyCalls() const { return ncall; }
    uint64_t NumBodyInsts() const;
    uint64_t NumModuleInsts(const std::string& mod) const;

    double CPUTimeEst() const { return tot_CPU_time; }
    uint64_t MemoryEst() const { return tot_mem; }

    void ReportExecutionProfile(ProfMap& pm);

    const std::string& FuncName() const { return func_name; }
    const std::set<std::string>& Modules() const { return modules; }





    static ZVal CheckAndLookupField(RecordVal* r, int f, const std::shared_ptr<ZAMLocInfo>& loc) {
        auto opt_zv = r->RawOptField(f);
        if ( ! opt_zv ) {
            auto fn = r->GetType<RecordType>()->FieldName(f);
            ZAM_run_time_error(loc, util::fmt("field value missing ($%s)", fn));
        }

        return *opt_zv;
    }

private:
    friend class CPPCompile;

    auto Instructions() const { return insts; }
    auto NumInsts() const { return end_pc; }

    std::shared_ptr<ProfVec> BuildProfVec() const;

    void ReportProfile(ProfMap& pm, const ProfVec& pv, const std::string& prefix,
                       const std::set<std::string>& caller_modules) const;

    StmtPtr Duplicate() override { return {NewRef{}, this}; }

    void StmtDescribe(ODesc* d) const override;
    TraversalCode Traverse(TraversalCallback* cb) const override;

    std::string func_name;

    const ZInst* insts = nullptr;
    unsigned int end_pc = 0;

    FrameReMap frame_denizens;
    int frame_size;


    std::vector<int> managed_slots;



    ZVal* fixed_frame = nullptr;




    TableIterVec table_iters;




    int num_step_iters;

    std::vector<GlobalInfo> globals;
    int num_globals;

    CaseMaps<zeek_int_t> int_cases;
    CaseMaps<zeek_uint_t> uint_cases;
    CaseMaps<double> double_cases;
    CaseMaps<std::string> str_cases;


    bool profile_calls = false;
    bool sample_CPU_mem = false;




    uint64_t profiling_set_call = 0;



    uint64_t* inst_cnt = nullptr;

    uint64_t ncall = 0;

    int prof_sampling_rate = 0;
    uint64_t num_sampled_inst = 0;
    double tot_CPU_time = 0.0;
    uint64_t tot_mem = 0;


    std::map<CallStack, std::shared_ptr<ProfVec>> prof_vecs;


    std::shared_ptr<ProfVec> default_prof_vec;


    ProfVec* curr_prof_vec;



    std::set<std::string> modules;
};

extern bool copy_vec_elem(VectorVal* vv, zeek_uint_t ind, ZVal zv, const TypePtr& t);

extern VectorVal* vec_coerce_DI(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);
extern VectorVal* vec_coerce_DU(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);
extern VectorVal* vec_coerce_ID(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);
extern VectorVal* vec_coerce_IU(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);
extern VectorVal* vec_coerce_UD(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);
extern VectorVal* vec_coerce_UI(VectorVal* vec, const std::shared_ptr<ZAMLocInfo>& z_loc);



extern double CPU_prof_overhead;
extern double mem_prof_overhead;

}
