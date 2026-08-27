



#pragma once

#include "zeek/IntrusivePtr.h"

namespace zeek {

class AddrVal;
class EnumVal;
class File;
class Func;
class ListVal;
class OpaqueVal;
class PatternVal;
class RecordVal;
class StringVal;
class SubNetVal;
class TableVal;
class Type;
class TypeVal;
class Val;
class VectorVal;

using AddrValPtr = IntrusivePtr<AddrVal>;
using EnumValPtr = IntrusivePtr<EnumVal>;
using ListValPtr = IntrusivePtr<ListVal>;
using OpaqueValPtr = IntrusivePtr<OpaqueVal>;
using PatternValPtr = IntrusivePtr<PatternVal>;
using RecordValPtr = IntrusivePtr<RecordVal>;
using StringValPtr = IntrusivePtr<StringVal>;
using SubNetValPtr = IntrusivePtr<SubNetVal>;
using TableValPtr = IntrusivePtr<TableVal>;
using TypePtr = IntrusivePtr<Type>;
using TypeValPtr = IntrusivePtr<TypeVal>;
using ValPtr = IntrusivePtr<Val>;
using VectorValPtr = IntrusivePtr<VectorVal>;

namespace detail {
class ZBody;
}












union ZVal {

    ZVal() { managed_val = nullptr; }


    ZVal(ValPtr v, const TypePtr& t);


    ZVal(const TypePtr& t);


    ZVal(bool v) { int_val = v; }
    ZVal(zeek_int_t v) { int_val = v; }
    ZVal(zeek_uint_t v) { uint_val = v; }
    ZVal(double v) { double_val = v; }

    ZVal(StringVal* v) { string_val = v; }
    ZVal(AddrVal* v) { addr_val = v; }
    ZVal(SubNetVal* v) { subnet_val = v; }
    ZVal(File* v) { file_val = v; }
    ZVal(Func* v) { func_val = v; }
    ZVal(ListVal* v) { list_val = v; }
    ZVal(OpaqueVal* v) { opaque_val = v; }
    ZVal(PatternVal* v) { re_val = v; }
    ZVal(TableVal* v) { table_val = v; }
    ZVal(RecordVal* v) { record_val = v; }
    ZVal(VectorVal* v) { vector_val = v; }
    ZVal(TypeVal* v) { type_val = v; }
    ZVal(Val* v) { any_val = v; }

    ZVal(StringValPtr v) { string_val = v.release(); }
    ZVal(AddrValPtr v) { addr_val = v.release(); }
    ZVal(SubNetValPtr v) { subnet_val = v.release(); }
    ZVal(ListValPtr v) { list_val = v.release(); }
    ZVal(OpaqueValPtr v) { opaque_val = v.release(); }
    ZVal(PatternValPtr v) { re_val = v.release(); }
    ZVal(TableValPtr v) { table_val = v.release(); }
    ZVal(RecordValPtr v) { record_val = v.release(); }
    ZVal(VectorValPtr v) { vector_val = v.release(); }
    ZVal(TypeValPtr v) { type_val = v.release(); }



    ValPtr ToVal(const TypePtr& t) const;

    zeek_int_t AsInt() const { return int_val; }
    zeek_uint_t AsCount() const { return uint_val; }
    double AsDouble() const { return double_val; }

    StringVal* AsString() const { return string_val; }
    AddrVal* AsAddr() const { return addr_val; }
    SubNetVal* AsSubNet() const { return subnet_val; }
    File* AsFile() const { return file_val; }
    Func* AsFunc() const { return func_val; }
    ListVal* AsList() const { return list_val; }
    OpaqueVal* AsOpaque() const { return opaque_val; }
    PatternVal* AsPattern() const { return re_val; }
    TableVal* AsTable() const { return table_val; }
    RecordVal* AsRecord() const { return record_val; }
    VectorVal* AsVector() const { return vector_val; }
    TypeVal* AsType() const { return type_val; }
    Val* AsAny() const { return any_val; }

    Obj* ManagedVal() const { return managed_val; }
    void ClearManagedVal() { managed_val = nullptr; }



    zeek_int_t& AsIntRef() { return int_val; }
    zeek_uint_t& AsCountRef() { return uint_val; }
    double& AsDoubleRef() { return double_val; }
    StringVal*& AsStringRef() { return string_val; }
    AddrVal*& AsAddrRef() { return addr_val; }
    SubNetVal*& AsSubNetRef() { return subnet_val; }
    File*& AsFileRef() { return file_val; }
    Func*& AsFuncRef() { return func_val; }
    ListVal*& AsListRef() { return list_val; }
    OpaqueVal*& AsOpaqueRef() { return opaque_val; }
    PatternVal*& AsPatternRef() { return re_val; }
    TableVal*& AsTableRef() { return table_val; }
    RecordVal*& AsRecordRef() { return record_val; }
    VectorVal*& AsVectorRef() { return vector_val; }
    TypeVal*& AsTypeRef() { return type_val; }
    Val*& AsAnyRef() { return any_val; }
    Obj*& ManagedValRef() { return managed_val; }



    static bool IsManagedType(const TypePtr& t);



    static void DeleteManagedType(ZVal& v) { Unref(v.ManagedVal()); }


    static void DeleteIfManaged(ZVal& v, const TypePtr& t) {
        if ( IsManagedType(t) )
            DeleteManagedType(v);
    }






    static void SetZValNilStatusAddr(bool* _zval_was_nil_addr) { zval_was_nil_addr = _zval_was_nil_addr; }

private:
    friend class RecordVal;
    friend class VectorVal;


    zeek_int_t int_val;


    zeek_uint_t uint_val;


    double double_val;





    StringVal* string_val;
    AddrVal* addr_val;
    SubNetVal* subnet_val;
    File* file_val;
    Func* func_val;
    ListVal* list_val;
    OpaqueVal* opaque_val;
    PatternVal* re_val;
    TableVal* table_val;
    RecordVal* record_val;
    VectorVal* vector_val;
    TypeVal* type_val;


    Val* any_val;


    Obj* managed_val;







    static bool* zval_was_nil_addr;
};

}
