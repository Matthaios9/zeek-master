

#pragma once

#include "zeek/zeek-config.h"

#include <forward_list>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "zeek/Attr.h"
#include "zeek/Notifier.h"
#include "zeek/Obj.h"
#include "zeek/TraverseTypes.h"

namespace zeek {

class Func;
class Val;
class RecordType;
class TableType;
class VectorType;
class EnumType;
class Type;
using TypePtr = IntrusivePtr<Type>;
using RecordTypePtr = IntrusivePtr<RecordType>;
using TableTypePtr = IntrusivePtr<TableType>;
using VectorTypePtr = IntrusivePtr<VectorType>;
using EnumTypePtr = IntrusivePtr<EnumType>;
using ValPtr = IntrusivePtr<Val>;
using FuncPtr = IntrusivePtr<Func>;

}

namespace zeek::detail {

class Attributes;
class Expr;
using ExprPtr = IntrusivePtr<Expr>;

enum InitClass : uint8_t {
    INIT_NONE,
    INIT_FULL,
    INIT_EXTRA,
    INIT_REMOVE,
    INIT_SKIP,
};
enum IDScope : uint8_t { SCOPE_FUNCTION, SCOPE_MODULE, SCOPE_GLOBAL };

class ID;
using IDPtr = IntrusivePtr<ID>;
using IDPList = std::vector<IDPtr>;
using IDSet = std::unordered_set<IDPtr>;

class IDOptInfo;

class ID final : public Obj, public notifier::detail::Modifiable {
public:
    static inline const IDPtr nil;

    ID(const char* name, IDScope arg_scope, bool arg_is_export);

    ~ID() override;

    const char* Name() const { return name; }

    int Scope() const { return scope; }
    bool IsGlobal() const { return scope != SCOPE_FUNCTION; }

    bool IsExport() const { return is_export; }
    void SetExport() { is_export = true; }

    std::string ModuleName() const;

    void SetType(TypePtr t);

    const TypePtr& GetType() const { return type; }

    template<class T>
    IntrusivePtr<T> GetType() const {
        return cast_intrusive<T>(type);
    }

    bool IsType() const { return is_type; }
    void MakeType() { is_type = true; }

    void SetVal(ValPtr v);

    void SetVal(ValPtr v, InitClass c);
    void SetVal(ExprPtr ev, InitClass c);

    bool HasVal() const { return val != nullptr; }

    const ValPtr& GetVal() const { return val; }

    void ClearVal();

    void SetConst() { is_const = true; }
    bool IsConst() const { return is_const; }

    void SetOption();
    bool IsOption() const { return is_option; }

    void SetBlank() { is_blank = true; }
    bool IsBlank() const { return is_blank; };

    void SetEnumConst() { is_enum_const = true; }
    bool IsEnumConst() const { return is_enum_const; }

    void SetOffset(int arg_offset) { offset = arg_offset; }
    int Offset() const { return offset; }

    bool IsRedefinable() const;

    void SetAttrs(AttributesPtr attr);
    void AddAttr(AttrPtr a, bool is_redef = false);
    void AddAttrs(AttributesPtr attr, bool is_redef = false);
    void RemoveAttr(AttrTag a);
    void UpdateValAttrs();

    const AttributesPtr& GetAttrs() const { return attrs; }

    const AttrPtr& GetAttr(AttrTag t) const;

    bool IsDeprecated() const;

    void MakeDeprecated(ExprPtr deprecation);

    std::string GetDeprecationWarning() const;

    void Error(const char* msg, const Obj* o2 = nullptr);

    void Describe(ODesc* d) const override;

    void DescribeExtended(ODesc* d) const;

    void DescribeReST(ODesc* d, bool roles_only = false) const;
    void DescribeReSTShort(ODesc* d) const;

    bool DoInferReturnType() const { return infer_return_type; }
    void SetInferReturnType(bool infer) { infer_return_type = infer; }

    TraversalCode Traverse(TraversalCallback* cb) const;

    bool HasOptionHandlers() const { return ! option_handlers.empty(); }

    void AddOptionHandler(FuncPtr callback, int priority);
    std::vector<Func*> GetOptionHandlers() const;

    IDOptInfo* GetOptInfo() const { return opt_info; }
    void ClearOptInfo();

protected:
    void EvalFunc(ExprPtr ef, ExprPtr ev);

    const char* name;
    TypePtr type;
    IDScope scope;
    bool is_export;
    bool is_capture = false;
    bool is_const = false;
    bool is_enum_const = false;
    bool is_type = false;
    bool is_option = false;
    bool is_blank = false;
    bool infer_return_type = false;
    int offset;
    ValPtr val;
    AttributesPtr attrs;


    using OptionHandler = std::pair<int, FuncPtr>;
    std::forward_list<OptionHandler> option_handlers;





    IDOptInfo* opt_info;
};

}

namespace zeek::id {







const detail::IDPtr& find(std::string_view name);







const TypePtr& find_type(std::string_view name);







template<class T>
IntrusivePtr<T> find_type(std::string_view name) {
    return cast_intrusive<T>(find_type(name));
}







const ValPtr& find_val(std::string_view name);







template<class T>
IntrusivePtr<T> find_val(std::string_view name) {
    return cast_intrusive<T>(find_val(name));
}







const ValPtr& find_const(std::string_view name);







template<class T>
IntrusivePtr<T> find_const(std::string_view name) {
    return cast_intrusive<T>(find_const(name));
}







FuncPtr find_func(std::string_view name);

ZEEK_EXTERN_DATA RecordTypePtr conn_id;
ZEEK_EXTERN_DATA RecordTypePtr conn_id_ctx;
ZEEK_EXTERN_DATA RecordTypePtr endpoint;
ZEEK_EXTERN_DATA RecordTypePtr connection;
ZEEK_EXTERN_DATA RecordTypePtr fa_file;
ZEEK_EXTERN_DATA RecordTypePtr fa_metadata;
ZEEK_EXTERN_DATA EnumTypePtr transport_proto;
ZEEK_EXTERN_DATA TableTypePtr string_set;
ZEEK_EXTERN_DATA TableTypePtr string_array;
ZEEK_EXTERN_DATA TableTypePtr count_set;
ZEEK_EXTERN_DATA VectorTypePtr string_vec;
ZEEK_EXTERN_DATA VectorTypePtr index_vec;

namespace detail {

void init_types();

}
}
