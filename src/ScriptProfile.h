



#pragma once

#include <string>

#include "zeek/Func.h"

namespace zeek {

namespace detail {





class ScriptProfileStats {
public:
    struct StackData {
        int call_count = 0;
        double cpu_time = 0.0;
        uint64_t memory = 0;
    };

    ScriptProfileStats() = default;
    ScriptProfileStats(std::string arg_name) : name(std::move(arg_name)) {}

    virtual ~ScriptProfileStats() = default;

    ScriptProfileStats(ScriptProfileStats&&) = default;
    ScriptProfileStats(const ScriptProfileStats&) = default;

    ScriptProfileStats& operator=(ScriptProfileStats&&) = default;
    ScriptProfileStats& operator=(const ScriptProfileStats&) = default;

    const auto& Name() const { return name; }



    int NumInstances() const { return ninstances; }


    int NumCalls() const { return ncalls; }


    double CPUTime() const { return CPU_time; }
    uint64_t Memory() const { return memory; }


    std::unordered_map<std::string, StackData> Stacks() const { return stacks; }


    void AddInstance() { ++ninstances; }



    void AddIn(const ScriptProfileStats* eps, bool bump_num_calls = true, const std::string& stack = "");


    void AddIn(double delta_CPU_time, uint64_t delta_memory) {
        CPU_time += delta_CPU_time;
        memory += delta_memory;
    }


    void SetStats(double arg_CPU_time, uint64_t arg_memory) {
        CPU_time = arg_CPU_time;
        memory = arg_memory;
    }


    void NewCall() { ++ncalls; }

private:
    std::string name;
    int ninstances = 0;
    int ncalls = 0;
    double CPU_time = 0.0;
    uint64_t memory = 0;
    std::unordered_map<std::string, StackData> stacks;
};



class ScriptProfile : public ScriptProfileStats {
public:
    ScriptProfile(const Func* _func, const detail::StmtPtr& body) : ScriptProfileStats(_func->GetName()) {
        func = {NewRef{}, const_cast<Func*>(_func)};
        is_BiF = body == nullptr;

        if ( is_BiF )
            loc = *func->GetLocationInfo();
        else
            loc = *body->GetLocationInfo();
    }


    ScriptProfile() : ScriptProfileStats("non-scripts") {
        func = nullptr;
        is_BiF = false;
    }


    void StartActivation();
    void EndActivation(const std::string& stack = "");


    void ChildFinished(const ScriptProfile* child);

    bool IsBiF() const { return is_BiF; }
    double DeltaCPUTime() const { return delta_stats.CPUTime(); }
    uint64_t DeltaMemory() const { return delta_stats.Memory(); }


    void Report(FILE* f, bool with_traces) const;

private:


    FuncPtr func;
    bool is_BiF;
    detail::Location loc;




    ScriptProfileStats child_stats;


    ScriptProfileStats start_stats;


    ScriptProfileStats delta_stats;
};


class ScriptProfileMgr {
public:

    ScriptProfileMgr(FILE* f);


    ~ScriptProfileMgr();



    void StartInvocation(const Func* f, const detail::StmtPtr& body = nullptr);
    void EndInvocation();

    void EnableTraces() { with_traces = true; }

private:
    FILE* f;



    ScriptProfile non_scripts;


    std::vector<ScriptProfile*> call_stack;



    std::unordered_map<const Obj*, std::unique_ptr<ScriptProfile>> profiles;



    std::unordered_map<const Obj*, const Func*> body_to_func;



    std::vector<const Obj*> objs;

    bool with_traces = false;
};


extern std::unique_ptr<ScriptProfileMgr> spm;

}



extern void activate_script_profiling(const char* fn, bool with_traces);

}
