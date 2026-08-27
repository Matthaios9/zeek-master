

#pragma once

#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "zeek/Expr.h"
#include "zeek/script_opt/ObjMgr.h"

namespace zeek::detail {







class UseDefSet;
using UDs = std::shared_ptr<UseDefSet>;

class UseDefSet {
public:
    UseDefSet() = default;
    UseDefSet(const UDs& uds) { Replicate(uds); }

    void Replicate(const UDs& from) { use_defs = from->use_defs; }

    bool HasID(const IDPtr& id) const { return use_defs.contains(id); }

    void Add(IDPtr id) { use_defs.insert(std::move(id)); }
    void Remove(const IDPtr& id) { use_defs.erase(id); }

    const IDSet& IterateOver() const { return use_defs; }

    void Dump() const;
    void DumpNL() const {
        Dump();
        printf("\n");
    }

protected:
    IDSet use_defs;
};

class Reducer;

class UseDefs {
public:
    UseDefs(StmtPtr body, std::shared_ptr<Reducer> rc, FuncTypePtr ft);




    void Analyze();


    bool HasUsage(const StmtPtr& s) const { return HasUsage(s.get()); }
    bool HasUsage(const Stmt* s) const { return use_defs_map.contains(s); }


    UDs GetUsage(const Stmt* s) const { return FindUsage(s); }
    UDs GetUsage(const StmtPtr& s) const { return FindUsage(s.get()); }





    StmtPtr RemoveUnused();

    void Dump();

private:






    bool RemoveUnused(int iter);




    bool CheckIfUnused(const Stmt* s, const IDPtr& id, bool report);











    UDs PropagateUDs(const StmtPtr& s, UDs succ_UDs, const StmtPtr& succ_stmt, bool second_pass) {
        return PropagateUDs(s.get(), std::move(succ_UDs), succ_stmt.get(), second_pass);
    }
    UDs PropagateUDs(const Stmt* s, UDs succ_UDs, const Stmt* succ_stmt, bool second_pass);

    UDs FindUsage(const Stmt* s) const;
    UDs FindSuccUsage(const Stmt* s) const;



    UDs ExprUDs(const Expr* e);



    void AddInExprUDs(const UDs& uds, const Expr* e);


    void AddID(const UDs& uds, IDPtr id) const;



    UDs RemoveID(const IDPtr& id, const UDs& uds);


    void RemoveUDFrom(const UDs& uds, const IDPtr& id);



    void FoldInUDs(UDs& main_UDs, const UDs& u1, const UDs& u2 = nullptr);


    void UpdateUDs(const Stmt* s, const UDs& uds);


    UDs UD_Union(const UDs& u1, const UDs& u2, const UDs& u3 = nullptr) const;



    UDs UseUDs(const Stmt* s, UDs uds);




    UDs CreateExprUDs(const Stmt* s, const Expr* e, const UDs& uds);


    UDs CreateUDs(const Stmt* s, UDs uds);



    std::unordered_map<const Stmt*, UDs> use_defs_map;



    std::unordered_set<const Stmt*> UDs_are_copies;



    std::vector<const Stmt*> stmts;






    std::unordered_map<const Stmt*, const Stmt*> successor;




    std::unordered_map<const Stmt*, const Stmt*> successor2;

    ObjMgr om;

    StmtPtr body;
    std::shared_ptr<Reducer> rc;
    FuncTypePtr ft;
};

}
