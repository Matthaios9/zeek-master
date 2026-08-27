




#pragma once

#include "zeek/Func.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {






class CPPFunc : public Func {
public:
    bool IsPure() const override { return is_pure; }

    void Describe(ODesc* d) const override;

protected:

    CPPFunc(const char* _name, bool _is_pure) {
        name = _name;
        is_pure = _is_pure;
    }

    std::string name;
    bool is_pure;
};



class CPPStmt : public Stmt {
public:
    CPPStmt(const char* _name, const char* filename, int line_num);

    const std::string& Name() { return name; }


    virtual void SetLambdaCaptures(Frame* f) {}
    virtual std::vector<ValPtr> SerializeLambdaCaptures() const { return std::vector<ValPtr>{}; }

    virtual IntrusivePtr<CPPStmt> Clone() { return {NewRef{}, this}; }

protected:


    StmtPtr Duplicate() override {
        ASSERT(0);
        return ThisPtr();
    }

    TraversalCode Traverse(TraversalCallback* cb) const override { return TC_CONTINUE; }

    std::string name;


    CallExprPtr ce;
};

using CPPStmtPtr = IntrusivePtr<CPPStmt>;






class CPPLambdaFunc : public ScriptFunc {
public:
    CPPLambdaFunc(std::string name, FuncTypePtr ft, CPPStmtPtr l_body);

protected:

    std::optional<BrokerData> SerializeCaptures() const override;
    void SetCaptures(Frame* f) override;

    FuncPtr DoClone() override;

    CPPStmtPtr l_body;
};




struct CompiledScript {
    std::string zeek_name;
    CPPStmtPtr body;
    int priority;
    std::vector<std::string> events;
    std::string module_group;
    std::vector<std::string> attr_groups;
    void (*finish_init_func)();
};


extern std::unordered_map<p_hash_type, CompiledScript> compiled_scripts;






extern std::unordered_map<std::string, std::unordered_set<p_hash_type>> added_bodies;


extern std::unordered_map<p_hash_type, void (*)()> standalone_callbacks;


extern std::vector<void (*)()> standalone_finalizations;

}
