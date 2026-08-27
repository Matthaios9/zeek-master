




#pragma once

#include <set>

#include "zeek/Expr.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"

namespace zeek::detail {

class Expr;
class Stmt;

using ExprPtr = IntrusivePtr<Expr>;

constexpr int NO_DEF = -1;






class IDDefRegion {
public:
    IDDefRegion(const Stmt* s, bool maybe, int def);
    IDDefRegion(int stmt_num, int level, bool maybe, int def);
    IDDefRegion(const Stmt* s, const IDDefRegion& ur);

    void Init(bool maybe, int def) {
        if ( def != NO_DEF )
            maybe_defined = true;
        else
            maybe_defined = maybe;

        defined = def;
    }



    int StartsAfter() const { return start_stmt; }





    int EndsAfter() const { return end_stmt; }
    void SetEndsAfter(int _end_stmt) { end_stmt = _end_stmt; }





    bool EndedDueToAssignment() const { return ended_due_to_assignment; }
    void SetEndedDueToAssignment() { ended_due_to_assignment = true; }




    int BlockLevel() const { return block_level; }


    bool MaybeDefined() const { return maybe_defined; }




    int DefinedAfter() const { return defined; }
    void UpdateDefinedAfter(int _defined) { defined = _defined; }






    const ExprPtr& DefExprAfter() const { return def_expr; }
    void SetDefExpr(ExprPtr e) { def_expr = std::move(e); }


    void Dump() const;

protected:


    int start_stmt;



    int end_stmt = NO_DEF;



    bool ended_due_to_assignment = false;


    int block_level;


    bool maybe_defined;




    int defined;




    ExprPtr def_expr;
};




class IDInitInfo {
public:
    IDInitInfo(const ID* _id, ExprPtr _init, InitClass _ic) : id(_id), init(std::move(_init)), ic(_ic) {}

    const ID* Id() const { return id; }
    const ExprPtr& Init() const { return init; }
    InitClass IC() const { return ic; }

private:
    const ID* id;
    ExprPtr init;
    InitClass ic;
};



class IDOptInfo {
public:
    IDOptInfo(const ID* id) { my_id = id; }




    void Clear();






    void AddInitExpr(ExprPtr init_expr, InitClass ic = INIT_NONE);


    const std::vector<ExprPtr>& GetInitExprs() const { return init_exprs; }
    const std::vector<InitClass>& GetInitClasses() const { return init_classes; }



    static auto& GetGlobalInitExprs() { return global_init_exprs; }
    static void ClearGlobalInitExprs() { global_init_exprs.clear(); }




    const ConstExpr* Const() const { return const_expr; }



    void SetConst(const ConstExpr* _const) { const_expr = _const; }



    bool IsTemp() const { return is_temp; }
    void SetTemp() { is_temp = true; }







    void SetDefinedAfter(const Stmt* s, const ExprPtr& e, const std::vector<const Stmt*>& conf_blocks,
                         zeek_uint_t conf_start);


    void ReturnAt(const Stmt* s);






    void BranchBackTo(const Stmt* from, const Stmt* to, bool close_all);





    void BranchBeyond(const Stmt* end_s, const Stmt* block, bool close_all);



    void StartConfluenceBlock(const Stmt* s);





    void ConfluenceBlockEndsAfter(const Stmt* s, bool no_orig_flow);



    bool IsPossiblyDefinedBefore(const Stmt* s);
    bool IsDefinedBefore(const Stmt* s);
    int DefinitionBefore(const Stmt* s);
    ExprPtr DefExprBefore(const Stmt* s);


    bool IsPossiblyDefinedBefore(int stmt_num);
    bool IsDefinedBefore(int stmt_num);
    int DefinitionBefore(int stmt_num);
    ExprPtr DefExprBefore(int stmt_num);



    bool DidUndefinedWarning() const { return did_undefined_warning; }
    bool DidPossiblyUndefinedWarning() const { return did_possibly_undefined_warning; }

    void SetDidUndefinedWarning() { did_undefined_warning = true; }
    void SetDidPossiblyUndefinedWarning() { did_possibly_undefined_warning = true; }

private:

    void EndRegionsAfter(int stmt_num, int level);



    IDDefRegion& FindRegionBefore(int stmt_num) { return usage_regions[FindRegionBeforeIndex(stmt_num)]; }
    int FindRegionBeforeIndex(int stmt_num);




    IDDefRegion* ActiveRegion() {
        auto ind = ActiveRegionIndex();
        return ind >= 0 ? &usage_regions[ind] : nullptr;
    }
    int ActiveRegionIndex();


    void DumpBlocks() const;





    std::vector<ExprPtr> init_exprs;




    std::vector<InitClass> init_classes;


    static std::vector<IDInitInfo> global_init_exprs;



    const ConstExpr* const_expr = nullptr;




    std::vector<IDDefRegion> usage_regions;





    using ConfluenceSet = std::set<int>;



    std::map<const Stmt*, ConfluenceSet> pending_confluences;



    std::vector<const Stmt*> confluence_stmts;





    std::vector<bool> block_has_orig_flow;


    bool is_temp = false;




    const ID* my_id;


    bool tracing = false;


    bool did_undefined_warning = false;
    bool did_possibly_undefined_warning = false;
};



extern const char* trace_ID;

}
