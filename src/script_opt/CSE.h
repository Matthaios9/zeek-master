

#pragma once

#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

class TempVar;








class CSE_ValidityChecker : public TraversalCallback {
public:
    CSE_ValidityChecker(std::shared_ptr<ProfileFuncs> pfs, const std::vector<IDPtr>& ids, const Expr* start_e,
                        const Expr* end_e);

    TraversalCode PreStmt(const Stmt*) override;
    TraversalCode PostStmt(const Stmt*) override;
    TraversalCode PreExpr(const Expr*) override;
    TraversalCode PostExpr(const Expr*) override;

    TraversalCode PreType(const Type* t) override {
        if ( types_seen.contains(t) )
            return TC_ABORTSTMT;
        types_seen.insert(t);
        return TC_CONTINUE;
    }


    bool IsValid() const {
        if ( ! is_valid )
            return false;

        if ( ! have_end_e )
            reporter->InternalError("CSE_ValidityChecker: saw start but not end");
        return true;
    }

protected:


    bool CheckID(const IDPtr& id, bool ignore_orig);



    bool CheckAggrMod(const TypePtr& t);



    bool CheckRecordConstructor(const TypePtr& t);


    bool CheckTableMod(const TypePtr& t);


    bool CheckTableRef(const TypePtr& t);


    bool CheckCall(const CallExpr* c);


    bool CheckSideEffects(SideEffectsOp::AccessType access, const TypePtr& t);



    bool CheckSideEffects(const IDSet& non_local_ids, const TypeSet& aggrs);



    bool Invalid() {
        is_valid = false;
        return true;
    }


    std::shared_ptr<ProfileFuncs> pfs;



    const std::vector<IDPtr>& ids;



    const Expr* start_e;



    const Expr* end_e;


    const Stmt* end_s;



    int field;


    TypePtr field_type;


    bool is_valid = true;



    bool have_start_e = false;
    bool have_end_e = false;






    int in_aggr_mod_expr = 0;


    std::unordered_set<const Type*> types_seen;
};



extern const Expr* non_reduced_perp;
extern bool checking_reduction;


extern bool NonReduced(const Expr* perp);

}
