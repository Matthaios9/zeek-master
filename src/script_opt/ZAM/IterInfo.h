



#pragma once

#include "zeek/Dict.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/script_opt/ZAM/ZInstAux.h"

namespace zeek::detail {




class TableIterInfo {
public:



    TableIterInfo() = default;



    TableIterInfo(const std::vector<TypePtr>* _loop_var_types, const std::vector<bool>* _lvt_is_managed,
                  TypePtr _value_var_type) {
        SetIterInfo(_loop_var_types, _lvt_is_managed, std::move(_value_var_type));
    }


    void SetIterInfo(const std::vector<TypePtr>* _loop_var_types, const std::vector<bool>* _lvt_is_managed,
                     TypePtr _value_var_type) {
        loop_var_types = _loop_var_types;
        lvt_is_managed = _lvt_is_managed;
        value_var_type = std::move(_value_var_type);
    }



    ~TableIterInfo() { Clear(); }




    void BeginLoop(TableValPtr _tv, ZVal* frame, ZInstAux* aux) {
        tv = std::move(_tv);


        loop_vars.clear();

        for ( auto lv : aux->loop_vars )
            if ( lv < 0 )
                loop_vars.push_back(nullptr);
            else
                loop_vars.push_back(&frame[lv]);

        SetIterInfo(&aux->types, &aux->is_managed, aux->value_var_type);

        PrimeIter();
    }

    void BeginLoop(TableValPtr _tv, std::vector<ZVal*> _loop_vars) {
        tv = std::move(_tv);
        loop_vars = std::move(_loop_vars);
        PrimeIter();
    }

    void PrimeIter() {
        auto tvd = tv->AsTable();
        tbl_iter = tvd->begin();
        tbl_end = tvd->end();
    }


    bool IsDoneIterating() const { return *tbl_iter == *tbl_end; }


    void IterFinished() { ++*tbl_iter; }



    void NextIter() {
        auto ind_lv = tv->RecreateIndex(*(*tbl_iter)->GetHashKey());
        for ( int i = 0; i < ind_lv->Length(); ++i ) {
            auto lv = loop_vars[i];
            if ( ! lv )
                continue;

            ValPtr ind_lv_p = ind_lv->Idx(i);
            if ( (*lvt_is_managed)[i] )
                ZVal::DeleteManagedType(*lv);
            *lv = ZVal(ind_lv_p, (*loop_var_types)[i]);
        }

        IterFinished();
    }


    ZVal IterValue() {
        auto tev = (*tbl_iter)->value;
        return {tev->GetVal(), value_var_type};
    }


    void EndIter() { Clear(); }


    void Clear() {
        tbl_iter = std::nullopt;
        tbl_end = std::nullopt;
    }

private:
    TableValPtr tv = nullptr;

    std::vector<ZVal*> loop_vars;
    const std::vector<TypePtr>* loop_var_types = nullptr;
    const std::vector<bool>* lvt_is_managed = nullptr;
    TypePtr value_var_type;

    std::optional<DictIterator<TableEntryVal>> tbl_iter;
    std::optional<DictIterator<TableEntryVal>> tbl_end;
};




class StepIterInfo {
public:






    void InitLoop(const std::vector<std::optional<ZVal>>* _vv) {
        vv = _vv;
        n = vv->size();
        iter = 0;
    }


    void InitLoop(const String* _s) {
        s = _s;
        n = s->Len();
        iter = 0;
    }


    bool IsDoneIterating() const { return iter >= n; }


    void IterFinished() { ++iter; }


    zeek_uint_t iter;
    zeek_uint_t n;


    const std::vector<std::optional<ZVal>>* vv;
    const String* s;
};

}
