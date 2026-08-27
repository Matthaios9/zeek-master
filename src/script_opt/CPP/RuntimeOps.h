



#pragma once

#include "zeek/Frame.h"
#include "zeek/OpaqueVal.h"
#include "zeek/script_opt/CPP/Func.h"

namespace zeek {

using IntVec = std::vector<int>;
using ValVec = std::vector<ValPtr>;
using SubNetValPtr = IntrusivePtr<zeek::SubNetVal>;

namespace detail {

class CPPRuntime {
public:
    static auto& RawField(const RecordValPtr& rv, int field) { return rv->RawField(field); }
    static auto& RawField(RecordVal* rv, int field) { return rv->RawField(field); }
    static auto& RawOptField(const RecordValPtr& rv, int field) { return rv->RawOptField(field); }
    static auto& RawOptField(RecordVal* rv, int field) { return rv->RawOptField(field); }

    static const auto& GetCreationInits(const RecordType* rt) { return rt->CreationInits(); }

    static RecordVal* BuildRecordVal(RecordTypePtr t, std::vector<std::optional<ZVal>> init_vals) {
        return new RecordVal(std::move(t), std::move(init_vals));
    }
};


extern StringValPtr str_concat__CPP(const String* s1, const String* s2);


extern bool str_in__CPP(const String* s1, const String* s2);



extern ListValPtr index_val__CPP(const ValVec& indices);






extern ValPtr index_table__CPP(const TableValPtr& t, const ValVec& indices);
extern ValPtr index_patstr_table__CPP(const TableValPtr& t, const ValVec& indices);
extern ValPtr index_vec__CPP(const VectorValPtr& vec, int index);
extern ValPtr index_string__CPP(const StringValPtr& svp, const ValVec& indices);


extern ValPtr when_index_table__CPP(const TableValPtr& t, const ValVec& indices);
extern ValPtr when_index_patstr__CPP(const TableValPtr& t, const ValVec& indices);
extern ValPtr when_index_vec__CPP(const VectorValPtr& vec, int index);



extern ValPtr when_index_slice__CPP(VectorVal* vec, const ListVal* lv);



inline ValPtr invoke_void__CPP(Func* f, ValVec args, Frame* frame) { return f->Invoke(&args, frame); }


class CPPInterpreterException : public InterpreterException {};




inline ValPtr invoke__CPP(Func* f, ValVec args, Frame* frame) {
    auto v = f->Invoke(&args, frame);
    if ( ! v )
        throw CPPInterpreterException();

    return v;
}






extern ValPtr when_invoke__CPP(Func* f, ValVec args, Frame* frame, void* caller_addr);


class CPPDelayedCallException : public InterpreterException {};



inline ValPtr set_global__CPP(IDPtr g, ValPtr v) {
    g->SetVal(v);
    return v;
}



extern ValPtr set_event__CPP(IDPtr g, ValPtr v, EventHandlerPtr& gh);



extern ValPtr cast_value_to_type__CPP(const ValPtr& v, const TypePtr& t);



extern ValPtr from_any__CPP(const ValPtr& v, const TypePtr& t);



extern ValPtr from_any_vec__CPP(const ValPtr& v, const TypePtr& t);



extern SubNetValPtr addr_mask__CPP(const IPAddr& a, uint32_t mask);



inline ValPtr assign_field__CPP(RecordValPtr rec, int field, ValPtr v) {
    rec->Assign(field, v);
    return v;
}



inline ValPtr field_access__CPP(const RecordValPtr& rec, int field) {
    auto v = rec->GetFieldOrDefault(field);
    if ( ! v )
        reporter->CPPRuntimeError("field value missing");

    return v;
}

#define NATIVE_FIELD_ACCESS(type, zaccessor, vaccessor)                                                                \
    inline type field_access_##type##__CPP(const RecordValPtr& r, int field) {                                         \
        auto rv = CPPRuntime::RawOptField(r, field);                                                                   \
        if ( rv )                                                                                                      \
            return (*rv).zaccessor();                                                                                  \
        return field_access__CPP(r, field)->vaccessor();                                                               \
    }

NATIVE_FIELD_ACCESS(bool, AsInt, AsBool)
NATIVE_FIELD_ACCESS(int, AsInt, AsInt)
NATIVE_FIELD_ACCESS(zeek_int_t, AsInt, AsInt)
NATIVE_FIELD_ACCESS(zeek_uint_t, AsCount, AsCount)
NATIVE_FIELD_ACCESS(double, AsDouble, AsDouble)

#define VP_FIELD_ACCESS(type, zaccessor)                                                                               \
    inline type##Ptr field_access_##type##__CPP(const RecordValPtr& r, int field) {                                    \
        auto rv = CPPRuntime::RawOptField(r, field);                                                                   \
        if ( rv )                                                                                                      \
            return {NewRef{}, rv->zaccessor()};                                                                        \
        return cast_intrusive<type>(field_access__CPP(r, field));                                                      \
    }

VP_FIELD_ACCESS(StringVal, AsString)
VP_FIELD_ACCESS(AddrVal, AsAddr)
VP_FIELD_ACCESS(SubNetVal, AsSubNet)
VP_FIELD_ACCESS(ListVal, AsList)
VP_FIELD_ACCESS(OpaqueVal, AsOpaque)
VP_FIELD_ACCESS(PatternVal, AsPattern)
VP_FIELD_ACCESS(TableVal, AsTable)
VP_FIELD_ACCESS(RecordVal, AsRecord)
VP_FIELD_ACCESS(VectorVal, AsVector)
VP_FIELD_ACCESS(TypeVal, AsType)
VP_FIELD_ACCESS(Val, AsAny)



extern ValPtr assign_to_index__CPP(TableValPtr v1, ValPtr v2, ValPtr v3);
extern ValPtr assign_to_index__CPP(VectorValPtr v1, ValPtr v2, ValPtr v3);
extern ValPtr assign_to_index__CPP(StringValPtr v1, ValPtr v2, ValPtr v3);


extern void add_element__CPP(TableValPtr aggr, ListValPtr indices);


extern void remove_element__CPP(TableValPtr aggr, ListValPtr indices);




inline TableValPtr table_coerce__CPP(const ValPtr& v, const TypePtr& t) {
    TableVal* tv = v->AsTableVal();

    if ( tv->Size() > 0 )
        reporter->CPPRuntimeError("coercion of non-empty table/set");

    return make_intrusive<TableVal>(cast_intrusive<TableType>(t), tv->GetAttrs());
}


inline TableValPtr table_append__CPP(const TableValPtr& t1, const TableValPtr& t2) {
    t2->AddTo(t1.get(), false);
    return t1;
}


inline TableValPtr table_remove_from__CPP(const TableValPtr& t1, const TableValPtr& t2) {
    if ( t2->Size() > 0 )
        t2->RemoveFrom(t1.get());
    return t1;
}


inline VectorValPtr vector_coerce__CPP(const ValPtr& v, const TypePtr& t) {
    VectorVal* vv = v->AsVectorVal();

    if ( vv->Size() > 0 )
        reporter->CPPRuntimeError("coercion of non-empty vector");

    return make_intrusive<VectorVal>(cast_intrusive<VectorType>(t));
}






extern AttributesPtr build_attrs__CPP(IntVec attr_tags, std::vector<ValPtr> attr_vals);



extern TableValPtr set_constructor__CPP(const ValVec& elements, TableTypePtr t, IntVec attr_tags, ValVec attr_vals);




extern TableValPtr table_constructor__CPP(ValVec indices, ValVec vals, TableTypePtr t, IntVec attr_tags,
                                          ValVec attr_vals);



extern RecordValPtr record_constructor__CPP(ValVec vals, RecordTypePtr t);


extern RecordValPtr record_constructor_map__CPP(ValVec vals, IntVec map, RecordTypePtr t);


extern VectorValPtr vector_constructor__CPP(ValVec vals, VectorTypePtr t);


inline PatternValPtr re_append__CPP(const PatternValPtr& p1, const PatternValPtr& p2) {
    p2->AddTo(p1.get(), false);
    return p1;
}




extern ValPtr schedule__CPP(double dt, EventHandlerPtr event, ValVec args);


inline zeek_uint_t iabs__CPP(zeek_int_t v) { return v < 0 ? -v : v; }

inline double fabs__CPP(double v) { return v < 0.0 ? -v : v; }



inline zeek_int_t idiv__CPP(zeek_int_t v1, zeek_int_t v2) {
    if ( v2 == 0 )
        reporter->CPPRuntimeError("division by zero");
    return v1 / v2;
}

inline zeek_int_t imod__CPP(zeek_int_t v1, zeek_int_t v2) {
    if ( v2 == 0 )
        reporter->CPPRuntimeError("modulo by zero");
    return v1 % v2;
}

inline zeek_uint_t udiv__CPP(zeek_uint_t v1, zeek_uint_t v2) {
    if ( v2 == 0 )
        reporter->CPPRuntimeError("division by zero");
    return v1 / v2;
}

inline zeek_uint_t umod__CPP(zeek_uint_t v1, zeek_uint_t v2) {
    if ( v2 == 0 )
        reporter->CPPRuntimeError("modulo by zero");
    return v1 % v2;
}

inline double fdiv__CPP(double v1, double v2) {
    if ( v2 == 0.0 )
        reporter->CPPRuntimeError("division by zero");
    return v1 / v2;
}

}
}
