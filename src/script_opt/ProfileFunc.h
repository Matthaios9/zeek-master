






























#pragma once

#include <string_view>

#include "zeek/Expr.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"
#include "zeek/script_opt/ScriptOpt.h"

namespace zeek::detail {





using p_hash_type = unsigned long long;



inline p_hash_type p_hash(int val) { return std::hash<int>{}(val); }

inline p_hash_type p_hash(std::string_view val) { return std::hash<std::string_view>{}(val); }

extern p_hash_type p_hash(const Obj* o);
inline p_hash_type p_hash(const IntrusivePtr<Obj>& o) { return p_hash(o.get()); }

inline p_hash_type merge_p_hashes(p_hash_type h1, p_hash_type h2) {




    return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
}

using AttrSet = std::unordered_set<const Attr*>;
using AttrVec = std::vector<const Attr*>;

class ProfileFuncs;


class ProfileFunc : public TraversalCallback {
public:


    ProfileFunc(const Func* func, const StmtPtr& body);





    ProfileFunc(const Stmt* body);
    ProfileFunc(const Expr* func);



    const Func* ProfiledFunc() const { return profiled_func; }
    const FuncTypePtr& ProfiledFuncType() const { return profiled_func_t; }
    const ScopePtr& ProfiledScope() const { return profiled_scope; }
    const Stmt* ProfiledBody() const { return profiled_body; }
    const Expr* ProfiledExpr() const { return profiled_expr; }



    const IDSet& Globals() const { return globals; }
    const IDSet& AllGlobals() const { return all_globals; }
    const IDSet& Locals() const { return locals; }
    const IDSet& Captures() const { return captures; }
    const auto& CapturesOffsets() const { return captures_offsets; }
    const IDSet& WhenLocals() const { return when_locals; }
    const IDSet& Params() const { return params; }
    const std::unordered_map<IDPtr, int>& Assignees() const { return assignees; }
    const IDSet& NonLocalAssignees() const { return non_local_assignees; }
    const auto& TableRefs() const { return tbl_refs; }
    const auto& AggrMods() const { return aggr_mods; }
    const IDSet& Inits() const { return inits; }
    const std::vector<StmtPtr>& Stmts() const { return stmts; }
    const std::vector<ExprPtr>& Exprs() const { return exprs; }
    const std::vector<const LambdaExpr*>& Lambdas() const { return lambdas; }
    const std::vector<const ConstExpr*>& Constants() const { return constants; }
    const std::vector<IDPtr>& OrderedIdentifiers() const { return ordered_ids; }
    const TypeSet& UnorderedTypes() const { return types; }
    const std::vector<const Type*>& OrderedTypes() const { return ordered_types; }
    const auto& TypeAliases() const { return type_aliases; }
    const std::unordered_set<ScriptFunc*>& ScriptCalls() const { return script_calls; }
    const IDSet& BiFGlobals() const { return BiF_globals; }
    const IDSet& CalledBiFGlobals() const { return called_BiF_globals; }
    const std::unordered_set<std::string>& Events() const { return events; }
    const std::unordered_map<const Attributes*, TypePtr>& ConstructorAttrs() const { return constructor_attrs; }
    const std::unordered_map<const Type*, std::set<const Attributes*>>& RecordConstructorAttrs() const {
        return rec_constructor_attrs;
    }
    const std::unordered_set<const SwitchStmt*>& ExprSwitches() const { return expr_switches; }
    const std::unordered_set<const SwitchStmt*>& TypeSwitches() const { return type_switches; }

    bool DoesIndirectCalls() const { return does_indirect_calls; }
    const IDSet& IndirectFuncs() const { return indirect_funcs; }

    int NumParams() const { return num_params; }
    int NumLambdas() const { return lambdas.size(); }
    int NumWhenStmts() const { return num_when_stmts; }

    const std::vector<p_hash_type>& AdditionalHashes() const { return addl_hashes; }


    void SetHashVal(p_hash_type hash) { hash_val = hash; }
    p_hash_type HashVal() const {
        ASSERT(hash_val);
        return *hash_val;
    }
    bool HasHashVal() const { return hash_val.has_value(); }

protected:

    void Profile(const FuncType* ft, const StmtPtr& body);

    TraversalCode PreStmt(const Stmt*) override;
    TraversalCode PreExpr(const Expr*) override;
    TraversalCode PreID(const ID*) override;
    TraversalCode PreType(const Type*) override;


    void TrackType(const Type* t);
    void TrackType(const TypePtr& t) { TrackType(t.get()); }


    void TrackID(IDPtr id);


    void TrackAssignment(IDPtr id);



    void CheckRecordConstructor(TypePtr t);



    const Func* profiled_func = nullptr;
    ScopePtr profiled_scope;
    FuncTypePtr profiled_func_t;
    const Stmt* profiled_body = nullptr;
    const Expr* profiled_expr = nullptr;





    IDSet globals;


    IDSet all_globals;


    IDSet locals;


    IDSet when_locals;



    IDSet params;




    int num_params = -1;





    std::unordered_map<IDPtr, int> assignees;


    IDSet non_local_assignees;


    TypeSet tbl_refs;


    TypeSet aggr_mods;



    IDSet inits;



    std::vector<StmtPtr> stmts;



    std::vector<ExprPtr> exprs;




    std::vector<const LambdaExpr*> lambdas;


    IDSet captures;


    std::unordered_map<IDPtr, int> captures_offsets;


    std::vector<const ConstExpr*> constants;


    IDSet ids;


    std::vector<IDPtr> ordered_ids;



    TypeSet types;


    std::vector<const Type*> ordered_types;



    std::unordered_map<const Type*, std::set<const Type*>> type_aliases;



    std::unordered_set<ScriptFunc*> script_calls;



    IDSet BiF_globals;


    IDSet called_BiF_globals;


    std::unordered_set<ScriptFunc*> when_calls;


    std::unordered_set<std::string> events;



    std::unordered_map<const Attributes*, TypePtr> constructor_attrs;



    std::unordered_map<const Type*, std::set<const Attributes*>> rec_constructor_attrs;


    std::unordered_set<const SwitchStmt*> expr_switches;
    std::unordered_set<const SwitchStmt*> type_switches;



    bool does_indirect_calls = false;




    IDSet indirect_funcs;



    std::vector<p_hash_type> addl_hashes;


    std::optional<p_hash_type> hash_val;




    int num_when_stmts = 0;
};



class SideEffectsOp {
public:






    enum AccessType : uint8_t { NONE, CALL, CONSTRUCTION, READ, WRITE };

    SideEffectsOp(AccessType at = NONE, const Type* t = nullptr) : access(at), type(t) {}

    auto GetAccessType() const { return access; }
    const Type* GetType() const { return type; }

    void SetUnknownChanges() { has_unknown_changes = true; }
    bool HasUnknownChanges() const { return has_unknown_changes; }

    void AddModNonGlobal(IDSet ids) { mod_non_locals.insert(ids.begin(), ids.end()); }
    void AddModAggrs(TypeSet types) { mod_aggrs.insert(types.begin(), types.end()); }

    const auto& ModNonLocals() const { return mod_non_locals; }
    const auto& ModAggrs() const { return mod_aggrs; }

private:
    AccessType access;
    const Type* type;


    IDSet mod_non_locals;


    TypeSet mod_aggrs;






    bool has_unknown_changes = false;
};





using is_compilable_pred = bool (*)(const ProfileFunc*, const char** reason);


class ProfileFuncs {
public:





    ProfileFuncs(std::vector<FuncInfo>& funcs, is_compilable_pred pred, bool compute_func_hashes);



    void ProfileLambda(const LambdaExpr* l);




    const IDSet& Globals() const { return globals; }
    const IDSet& AllGlobals() const { return all_globals; }
    const std::unordered_set<const ConstExpr*>& Constants() const { return constants; }
    const std::vector<const Type*>& MainTypes() const { return main_types; }
    const std::vector<const Type*>& RepTypes() const { return rep_types; }
    const std::unordered_set<ScriptFunc*>& ScriptCalls() const { return script_calls; }
    const IDSet& BiFGlobals() const { return BiF_globals; }
    const IDSet& CalledBiFGlobals() const { return called_BiF_globals; }
    const std::unordered_set<const LambdaExpr*>& Lambdas() const { return lambdas; }
    const std::unordered_set<std::string>& Events() const { return events; }
    const auto& ExprAttrs() const { return expr_attrs; }

    const auto& FuncProfs() const { return func_profs; }



    std::shared_ptr<ProfileFunc> ExprProf(const Expr* e) { return expr_profs[e]; }



    bool IsTableWithDefaultAggr(const Type* t);


    bool HasSideEffects(SideEffectsOp::AccessType access, const TypePtr& t) const;







    bool GetSideEffects(SideEffectsOp::AccessType access, const Type* t, IDSet& non_local_ids, TypeSet& aggrs) const;










    bool GetCallSideEffects(const NameExpr* n, IDSet& non_local_ids, TypeSet& aggrs, bool& is_unknown);



    const Type* TypeRep(const Type* orig) {
        auto it = type_to_rep.find(orig);
        ASSERT(it != type_to_rep.end());
        return it->second;
    }



    p_hash_type HashType(const TypePtr& t) { return HashType(t.get()); }
    p_hash_type HashType(const Type* t);

    p_hash_type HashAttrs(const AttributesPtr& attrs);

protected:

    void MergeInProfile(ProfileFunc* pf);



    void TraverseValue(const ValPtr& v);






    void DrainPendingExprs();



    void ComputeTypeHashes(const std::vector<const Type*>& types);


    void ComputeBodyHashes(std::vector<FuncInfo>& funcs);


    void AnalyzeLambdaProfile(const LambdaExpr* l);


    void ComputeProfileHash(const std::shared_ptr<ProfileFunc>& pf);



    void AnalyzeAttrs(const Attributes* attrs, const Type* t);







    void ComputeSideEffects();




    bool DefinitelyHasNoSideEffects(const ExprPtr& e) const;


    void SetSideEffects(const Attr* a, IDSet& non_local_ids, TypeSet& aggrs, bool is_unknown);


    AttrVec AssociatedAttrs(const Type* t);



    void FindAssociatedAttrs(const AttrSet& candidate_attrs, const Type* t, AttrVec& assoc_attrs);




    bool AssessSideEffects(const ExprPtr& e, IDSet& non_local_ids, TypeSet& types, bool& is_unknown);


    bool AssessSideEffects(const ProfileFunc* pf, IDSet& non_local_ids, TypeSet& types, bool& is_unknown);




    bool AssessAggrEffects(SideEffectsOp::AccessType access, const Type* t, IDSet& non_local_ids, TypeSet& aggrs,
                           bool& is_unknown);




    bool AssessSideEffects(const SideEffectsOp* se, SideEffectsOp::AccessType access, const Type* t,
                           IDSet& non_local_ids, TypeSet& aggrs) const;




    std::shared_ptr<SideEffectsOp> GetCallSideEffects(const ScriptFunc* f);



    IDSet globals;


    IDSet all_globals;


    std::unordered_set<const ConstExpr*> constants;



    std::vector<const Type*> main_types;




    std::vector<const Type*> rep_types;


    std::unordered_map<const Type*, const Type*> type_to_rep;




    std::unordered_map<const Type*, std::set<const Type*>> type_aliases;


    std::unordered_set<ScriptFunc*> script_calls;





    IDSet BiF_globals;
    IDSet called_BiF_globals;


    std::unordered_set<const LambdaExpr*> lambdas;



    std::unordered_set<const LambdaExpr*> processed_lambdas;



    std::unordered_set<const LambdaExpr*> profiled_lambdas;


    std::unordered_set<std::string> events;





    std::unordered_map<const ScriptFunc*, std::shared_ptr<ProfileFunc>> func_profs;


    std::unordered_map<std::string, const ScriptFunc*> lambda_primaries;




    std::unordered_map<const ScriptFunc*, std::shared_ptr<SideEffectsOp>> func_side_effects;


    std::unordered_map<const Expr*, std::shared_ptr<ProfileFunc>> expr_profs;








    std::unordered_map<const Attr*, std::vector<const Type*>> expr_attrs;





    std::unordered_map<const Type*, bool> tbl_has_aggr_default;



    std::unordered_map<const Attr*, std::vector<std::shared_ptr<SideEffectsOp>>> aggr_side_effects;


    std::unordered_map<const Attr*, std::vector<std::shared_ptr<SideEffectsOp>>> record_constr_with_side_effects;




    AttrSet candidates;




    const Attr* curr_candidate;


    AttrSet attrs_with_side_effects;


    std::vector<std::shared_ptr<SideEffectsOp>> side_effects_ops;



    std::unordered_set<std::shared_ptr<ProfileFunc>> active_func_profiles;


    std::unordered_map<const Type*, p_hash_type> type_hashes;


    std::unordered_map<p_hash_type, const Type*> type_hash_reps;



    std::unordered_map<std::string, const Type*> seen_type_names;



    std::vector<const Expr*> pending_exprs;



    bool compute_func_hashes;
};




class SetBlockLineNumbers : public TraversalCallback {
public:




    TraversalCode PreStmt(const Stmt*) override;
    TraversalCode PostStmt(const Stmt*) override;
    TraversalCode PreExpr(const Expr*) override;

private:
    void UpdateLocInfo(Location* loc);






    std::vector<std::pair<int, int>> block_line_range;
};



class ASTBlockAnalyzer : public TraversalCallback {
public:
    ASTBlockAnalyzer(std::vector<FuncInfo>& funcs);

    TraversalCode PreStmt(const Stmt*) override;
    TraversalCode PostStmt(const Stmt*) override;
    TraversalCode PreExpr(const Expr*) override;



    std::string GetDesc(const Location* loc) const {
        auto e_d = exp_desc.find(LocKey(loc));
        if ( e_d == exp_desc.end() )
            return LocWithFunc(loc);
        else
            return e_d->second;
    }





    bool HaveExpDesc(const Location* loc) const { return exp_desc.contains(LocKey(loc)); }

private:




    std::string BuildExpandedDescription(const Location* loc);



    std::string LocKey(const Location* loc) const {
        return std::string(loc->FileName()) + ":" + std::to_string(loc->FirstLine()) + "-" +
               std::to_string(loc->LastLine());
    }



    std::string LocWithFunc(const Location* loc) const {
        auto res = func_name_prefix + std::to_string(loc->FirstLine());

        if ( loc->FirstLine() != loc->LastLine() )
            res += "-" + std::to_string(loc->LastLine());

        return res;
    }



    std::string func_name_prefix;




    std::vector<std::pair<std::string, std::string>> parents;


    std::unordered_map<std::string, std::string> exp_desc;
};



extern std::unique_ptr<ASTBlockAnalyzer> AST_blocks;





extern std::string func_name_at_loc(std::string fname, const Location* loc);

}
