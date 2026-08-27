



#pragma once

#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/TraverseTypes.h"
#include "zeek/script_opt/ZAM/BuiltInSupport.h"
#include "zeek/script_opt/ZAM/Frame.h"
#include "zeek/script_opt/ZAM/Support.h"

namespace zeek::detail {

class ZInst;
class ZInstI;

class Attributes;
using AttributesPtr = IntrusivePtr<Attributes>;




class AuxElem {
public:
    AuxElem() = default;


    void SetInt(int _i) { i = _i; }
    void SetInt(int _i, TypePtr _t) {
        i = _i;
        SetType(std::move(_t));
    }
    void SetSlot(int slot) { i = slot; }
    void SetConstant(ValPtr _c) {
        c = std::move(_c);

        if ( c ) {
            SetType(c->GetType());
            zc = ZVal(c, t);
        }
    }


    ValPtr ToVal(const ZVal* frame) const {
        if ( c )
            return c;
        else
            return frame[i].ToVal(t);
    }


    ZVal ToZVal(const ZVal* frame) const {
        ZVal zv = c ? zc : frame[i];
        if ( is_managed )
            Ref(zv.ManagedVal());
        return zv;
    }



    const ZVal& ToDirectZVal(const ZVal* frame) const {
        if ( c )
            return zc;
        if ( i >= 0 )
            return frame[i];




        static ZVal null_zval;
        return null_zval;
    }

    int Slot() const { return i; }
    int IntVal() const { return i; }
    const ValPtr& Constant() const { return c; }
    ZVal ZConstant() const { return zc; }
    const TypePtr& GetType() const { return t; }
    bool IsManaged() const { return is_managed; }

private:
    void SetType(TypePtr _t) {
        t = std::move(_t);
        is_managed = t ? ZVal::IsManagedType(t) : false;
    }

    int i = -1;
    ValPtr c;
    ZVal zc;
    TypePtr t;
    bool is_managed = false;
};

enum ControlFlowType : uint8_t {
    CFT_IF,
    CFT_BLOCK_END,
    CFT_ELSE,
    CFT_LOOP,
    CFT_LOOP_COND,
    CFT_LOOP_END,
    CFT_NEXT,
    CFT_BREAK,
    CFT_DEFAULT,
    CFT_INLINED_RETURN,

    CFT_NONE,
};




class ZInstAux {
public:


    ZInstAux(int _n) {
        n = _n;
        if ( n > 0 )
            elems = new AuxElem[n];
    }

    ~ZInstAux() {
        delete[] elems;
        delete[] cat_args;
    }


    ValPtr ToVal(const ZVal* frame, int i) const { return elems[i].ToVal(frame); }
    ZVal ToZVal(const ZVal* frame, int i) const { return elems[i].ToZVal(frame); }


    ListValPtr ToListVal(const ZVal* frame) const {
        auto lv = make_intrusive<ListVal>(TYPE_ANY);
        for ( auto i = 0; i < n; ++i )
            lv->Append(elems[i].ToVal(frame));

        return lv;
    }





    ListValPtr ToIndices(const ZVal* frame, int offset, int width) const {
        auto lv = make_intrusive<ListVal>(TYPE_ANY);
        for ( auto i = 0; i < 0 + width; ++i )
            lv->Append(elems[offset + i].ToVal(frame));

        return lv;
    }


    const ValVec& ToValVec(const ZVal* frame) {
        vv.clear();
        FillValVec(vv, frame);
        return vv;
    }



    void FillValVec(ValVec& vec, const ZVal* frame) const {
        for ( auto i = 0; i < n; ++i )
            vec.push_back(elems[i].ToVal(frame));
    }


    const std::vector<std::optional<ZVal>>& ToZValVec(const ZVal* frame) {
        for ( auto i = 0; i < n; ++i )
            zvec[i] = elems[i].ToZVal(frame);
        return zvec;
    }




    std::vector<std::optional<ZVal>>& ToZValVecWithMap(const ZVal* frame) {
        for ( auto i = 0; i < n; ++i )
            zvec[map[i]] = elems[i].ToZVal(frame);
        return zvec;
    }



    void Add(int i, int slot, TypePtr t) { elems[i].SetInt(slot, t); }


    void Add(int i, int v_i) { elems[i].SetInt(v_i); }


    void Add(int i, ValPtr c) { elems[i].SetConstant(c); }

    void Dump(FILE* f) const;

    TraversalCode Traverse(TraversalCallback* cb) const;





    int n;
    AuxElem* elems = nullptr;
    bool elems_has_slots = true;


    LambdaExprPtr lambda;


    std::shared_ptr<WhenInfo> wi;


    std::unique_ptr<CatArg>* cat_args = nullptr;


    IDPtr id_val;



    CallExprPtr call_expr;


    Func* func = nullptr;


    bool is_BiF_call = false;


    std::map<ControlFlowType, int> cft;


    EventHandler* event_handler = nullptr;


    AttributesPtr attrs;




    bool can_change_non_locals = false;




    std::vector<int> map;



    std::vector<int> rhs_map;






    std::vector<int> lhs_map;


    std::vector<TypePtr> types;


    std::vector<bool> is_managed;





    std::vector<int> loop_vars;



    TypePtr value_var_type;






    ValVec vv;


    std::vector<std::optional<ZVal>> zvec;



    std::unique_ptr<std::vector<std::pair<int, std::shared_ptr<detail::FieldInit>>>> field_inits;
};

}
