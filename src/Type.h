

#pragma once

#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>

#include "zeek/Attr.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"
#include "zeek/Traverse.h"
#include "zeek/ZeekList.h"

namespace zeek {

class Val;
union ZVal;
class EnumVal;
class RecordVal;
class TableVal;
using ValPtr = IntrusivePtr<Val>;
using EnumValPtr = IntrusivePtr<EnumVal>;
using TableValPtr = IntrusivePtr<TableVal>;

namespace detail {

class Attributes;
class CompositeHash;
class Expr;
class HashKey;
class ListExpr;
class ZAMCompiler;
class CPPRuntime;

using ExprPtr = IntrusivePtr<Expr>;
using ListExprPtr = IntrusivePtr<ListExpr>;


class FieldInit {
public:
    virtual ~FieldInit() = default;


    virtual ZVal Generate() const = 0;


    virtual bool IsDeferrable() const { return true; }



    virtual ExprPtr InitExpr() const;
};

}

namespace plugin {
template<class>
class ComponentManager;
}


enum TypeTag : uint8_t {
    TYPE_VOID,
    TYPE_BOOL,
    TYPE_INT,
    TYPE_COUNT,
    TYPE_DOUBLE,
    TYPE_TIME,
    TYPE_INTERVAL,
    TYPE_STRING,
    TYPE_PATTERN,
    TYPE_ENUM,
    TYPE_PORT,
    TYPE_ADDR,
    TYPE_SUBNET,
    TYPE_ANY,
    TYPE_TABLE,
    TYPE_RECORD,
    TYPE_LIST,
    TYPE_FUNC,
    TYPE_FILE,
    TYPE_VECTOR,
    TYPE_OPAQUE,
    TYPE_TYPE,
    TYPE_ERROR
#define NUM_TYPES (int(TYPE_ERROR) + 1)
};


extern const char* type_name(TypeTag t);

constexpr bool is_network_order(TypeTag tag) noexcept { return tag == TYPE_PORT; }

enum FunctionFlavor : uint8_t { FUNC_FLAVOR_FUNCTION, FUNC_FLAVOR_EVENT, FUNC_FLAVOR_HOOK };

enum InternalTypeTag : uint8_t {
    TYPE_INTERNAL_VOID,
    TYPE_INTERNAL_INT,
    TYPE_INTERNAL_UNSIGNED,
    TYPE_INTERNAL_DOUBLE,
    TYPE_INTERNAL_STRING,
    TYPE_INTERNAL_ADDR,
    TYPE_INTERNAL_SUBNET,
    TYPE_INTERNAL_OTHER,
    TYPE_INTERNAL_ERROR
};

constexpr InternalTypeTag to_internal_type_tag(TypeTag tag) noexcept {
    switch ( tag ) {
        case TYPE_VOID: return TYPE_INTERNAL_VOID;

        case TYPE_BOOL:
        case TYPE_INT:
        case TYPE_ENUM: return TYPE_INTERNAL_INT;

        case TYPE_COUNT:
        case TYPE_PORT: return TYPE_INTERNAL_UNSIGNED;

        case TYPE_DOUBLE:
        case TYPE_TIME:
        case TYPE_INTERVAL: return TYPE_INTERNAL_DOUBLE;

        case TYPE_STRING: return TYPE_INTERNAL_STRING;

        case TYPE_ADDR: return TYPE_INTERNAL_ADDR;

        case TYPE_SUBNET: return TYPE_INTERNAL_SUBNET;

        case TYPE_PATTERN:
        case TYPE_ANY:
        case TYPE_TABLE:
        case TYPE_RECORD:
        case TYPE_LIST:
        case TYPE_FUNC:
        case TYPE_FILE:
        case TYPE_OPAQUE:
        case TYPE_VECTOR:
        case TYPE_TYPE: return TYPE_INTERNAL_OTHER;

        case TYPE_ERROR: return TYPE_INTERNAL_ERROR;
    }


    return TYPE_INTERNAL_VOID;
}

class Type;
class TypeList;
class TableType;
class SetType;
class RecordType;
class FuncType;
class EnumType;
class VectorType;
class TypeType;
class OpaqueType;
class FileType;

using TypePtr = IntrusivePtr<Type>;
using TypeListPtr = IntrusivePtr<TypeList>;
using TableTypePtr = IntrusivePtr<TableType>;
using SetTypePtr = IntrusivePtr<SetType>;
using RecordTypePtr = IntrusivePtr<RecordType>;
using FuncTypePtr = IntrusivePtr<FuncType>;
using EnumTypePtr = IntrusivePtr<EnumType>;
using VectorTypePtr = IntrusivePtr<VectorType>;
using TypeTypePtr = IntrusivePtr<TypeType>;
using OpaqueTypePtr = IntrusivePtr<OpaqueType>;
using FileTypePtr = IntrusivePtr<FileType>;

constexpr int DOES_NOT_MATCH_INDEX = 0;
constexpr int MATCHES_INDEX_SCALAR = 1;
constexpr int MATCHES_INDEX_VECTOR = 2;

class Type : public Obj {
public:
    static inline const TypePtr nil;

    explicit Type(TypeTag tag, bool base_type = false);









    virtual TypePtr ShallowClone();

    TypeTag Tag() const { return tag; }
    InternalTypeTag InternalType() const { return internal_tag; }


    bool IsNetworkOrder() const { return is_network_order; }








    virtual int MatchesIndex(detail::ListExpr* index) const;




    virtual const TypePtr& Yield() const;

    const TypeList* AsTypeList() const;
    TypeList* AsTypeList();

    const TableType* AsTableType() const;
    TableType* AsTableType();

    [[deprecated("Remove in v9.1. Use AsTableType() instead.")]]
    const SetType* AsSetType() const;

    [[deprecated("Remove in v9.1. Use AsTableType() instead.")]]
    SetType* AsSetType();

    const RecordType* AsRecordType() const;
    RecordType* AsRecordType();

    const FuncType* AsFuncType() const;
    FuncType* AsFuncType();

    const FileType* AsFileType() const;
    FileType* AsFileType();

    const EnumType* AsEnumType() const;
    EnumType* AsEnumType();

    const VectorType* AsVectorType() const;
    VectorType* AsVectorType();

    const OpaqueType* AsOpaqueType() const;
    OpaqueType* AsOpaqueType();

    const TypeType* AsTypeType() const;
    TypeType* AsTypeType();

    bool IsSet() const { return tag == TYPE_TABLE && ! Yield(); }

    bool IsTable() const { return tag == TYPE_TABLE && Yield(); }

    Type* Ref() {
        ::zeek::Ref(this);
        return this;
    }

    void Describe(ODesc* d) const override;
    virtual void DescribeReST(ODesc* d, bool roles_only = false) const;

    void SetName(const std::string& arg_name) { name = arg_name; }
    const std::string& GetName() const { return name; }

    virtual detail::TraversalCode Traverse(detail::TraversalCallback* cb) const;

    struct TypePtrComparer {
        bool operator()(const TypePtr& a, const TypePtr& b) const { return a.get() < b.get(); }
    };
    using TypePtrSet = std::set<TypePtr, TypePtrComparer>;
    using TypeAliasMap = std::map<std::string, TypePtrSet, std::less<>>;





    static const TypeAliasMap& GetAliasMap() { return type_aliases; }




    static bool HasAliases(std::string_view type_name) { return Type::type_aliases.contains(type_name); }





    static const TypePtrSet& Aliases(std::string_view type_name) {
        static TypePtrSet empty;
        auto it = Type::type_aliases.find(type_name);
        return it == Type::type_aliases.end() ? empty : it->second;
    }








    static bool RegisterAlias(std::string_view type_name, TypePtr type) {
        auto it = Type::type_aliases.find(type_name);
        if ( it == Type::type_aliases.end() )
            it = Type::type_aliases.emplace(std::string{type_name}, TypePtrSet{}).first;
        return it->second.emplace(std::move(type)).second;
    }

protected:
    virtual void DoDescribe(ODesc* d) const;

    Type() = default;

    void SetError();

private:
    TypeTag tag;
    InternalTypeTag internal_tag;
    bool is_network_order;
    bool base_type;
    std::string name;

    static TypeAliasMap type_aliases;
};

class TypeList final : public Type {
public:
    explicit TypeList(TypePtr arg_pure_type = nullptr) : Type(TYPE_LIST), pure_type(std::move(arg_pure_type)) {}

    const std::vector<TypePtr>& GetTypes() const { return types; }

    bool IsPure() const { return pure_type != nullptr; }



    const TypePtr& GetPureType() const { return pure_type; }



    void CheckPure();




    bool AllMatch(const Type* t, bool is_init) const;
    bool AllMatch(const TypePtr& t, bool is_init) const { return AllMatch(t.get(), is_init); }

    void Append(TypePtr t);
    void AppendEvenIfNotPure(TypePtr t);


    void Clear() { types.clear(); }

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const override;

protected:
    void DoDescribe(ODesc* d) const override;

    TypePtr pure_type;
    std::vector<TypePtr> types;
};

class IndexType : public Type {
public:
    int MatchesIndex(detail::ListExpr* index) const override;

    const TypeListPtr& GetIndices() const { return indices; }

    const std::vector<TypePtr>& GetIndexTypes() const { return indices->GetTypes(); }

    const TypePtr& Yield() const override { return yield_type; }

    void DescribeReST(ODesc* d, bool roles_only = false) const override;


    bool IsSubNetIndex() const { return is_subnet_index; }


    bool IsPatternIndex() const { return is_pattern_index; }

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const override;

protected:
    IndexType(TypeTag t, TypeListPtr arg_indices, TypePtr arg_yield_type)
        : Type(t), indices(std::move(arg_indices)), yield_type(std::move(arg_yield_type)) {


        if ( indices )
            SetSpecialIndices();
        else
            is_subnet_index = is_pattern_index = false;
    }

    void SetSpecialIndices() {
        const auto& types = indices->GetTypes();
        is_subnet_index = types.size() == 1 && types[0]->Tag() == TYPE_SUBNET;
        is_pattern_index = types.size() == 1 && types[0]->Tag() == TYPE_PATTERN;
    }

    void DoDescribe(ODesc* d) const override;

    TypeListPtr indices;
    TypePtr yield_type;

    bool is_subnet_index;
    bool is_pattern_index;
};

class TableType : public IndexType {
public:
    TableType(TypeListPtr ind, TypePtr yield);

    ~TableType() override;








    bool CheckExpireFuncCompatibility(const detail::AttrPtr& attr);

    TypePtr ShallowClone() override;



    bool IsUnspecifiedTable() const;

    const detail::CompositeHash* GetTableHash() const { return table_hash.get(); }



    void RegenerateHash();

private:
    bool DoExpireCheck(const detail::AttrPtr& attr);

    std::unique_ptr<detail::CompositeHash> table_hash;


    bool reported_error = false;
};

class [[deprecated("Remove in v9.1. Use TableType instead.")]] SetType final : public TableType {
public:
    SetType(TypeListPtr ind, detail::ListExprPtr arg_elements);
    ~SetType() override;

    TypePtr ShallowClone() override;

    const detail::ListExprPtr& Elements() const { return elements; }

protected:
    detail::ListExprPtr elements;
};

class FuncType final : public Type {
public:
    static inline const FuncTypePtr nil;






    struct Prototype {
        bool deprecated;
        std::string deprecation_msg;
        RecordTypePtr args;


        std::map<int, int> offsets;
    };

    FuncType(RecordTypePtr args, TypePtr yield, FunctionFlavor f);

    TypePtr ShallowClone() override;

    const RecordTypePtr& Params() const { return args; }

    const TypePtr& Yield() const override { return yield; }

    void SetYieldType(TypePtr arg_yield) { yield = std::move(arg_yield); }
    FunctionFlavor Flavor() const { return flavor; }
    std::string FlavorString() const;


    void ClearYieldType(FunctionFlavor arg_flav) {
        yield = nullptr;
        flavor = arg_flav;
    }

    int MatchesIndex(detail::ListExpr* index) const override;
    bool CheckArgs(const TypePList* args, bool is_init = false, bool do_warn = true) const;
    bool CheckArgs(const std::vector<TypePtr>& args, bool is_init = false, bool do_warn = true) const;

    const TypeListPtr& ParamList() const { return arg_types; }

    void DescribeReST(ODesc* d, bool roles_only = false) const override;




    void AddPrototype(Prototype s);




    std::optional<Prototype> FindPrototype(const RecordType& args) const;




    const std::vector<Prototype>& Prototypes() const { return prototypes; }




    class Capture {
    public:
        Capture(detail::IDPtr _id, bool _deep_copy);

        Capture(const Capture&) = default;
        Capture(Capture&&) = default;
        Capture& operator=(const Capture&) = default;
        Capture& operator=(Capture&&) = default;
        ~Capture() = default;

        auto& Id() const { return id; }
        bool IsDeepCopy() const { return deep_copy; }
        bool IsManaged() const { return is_managed; }


        void SetID(detail::IDPtr new_id) { id = std::move(new_id); }

    private:
        detail::IDPtr id;
        bool deep_copy;
        bool is_managed;
    };

    using CaptureList = std::vector<Capture>;






    void SetCaptures(std::optional<CaptureList> captures);






    const std::optional<CaptureList>& GetCaptures() const { return captures; }






    bool ExpressionlessReturnOkay() const { return expressionless_return_okay; }






    void SetExpressionlessReturnOkay(bool is_ok) { expressionless_return_okay = is_ok; }

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const override;

protected:
    friend FuncTypePtr make_intrusive<FuncType>();

    FuncType() : Type(TYPE_FUNC) { flavor = FUNC_FLAVOR_FUNCTION; }

    void DoDescribe(ODesc* d) const override;

    RecordTypePtr args;
    TypeListPtr arg_types;
    TypePtr yield;
    FunctionFlavor flavor;
    std::vector<Prototype> prototypes;

    std::optional<CaptureList> captures;

    bool expressionless_return_okay = false;


    bool reported_error = false;
};

class TypeType final : public Type {
public:
    explicit TypeType(TypePtr t) : zeek::Type(TYPE_TYPE), type(std::move(t)) {}
    TypePtr ShallowClone() override { return make_intrusive<TypeType>(type); }

    const TypePtr& GetType() const { return type; }

    template<class T>
    IntrusivePtr<T> GetType() const {
        return cast_intrusive<T>(type);
    }

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const override;

protected:
    TypePtr type;
};

class TypeDecl final {
public:
    TypeDecl() = default;
    TypeDecl(const char* i, TypePtr t, detail::AttributesPtr attrs = nullptr);
    TypeDecl(const TypeDecl& other);
    ~TypeDecl();

    TypeDecl& operator=(const TypeDecl& other);

    const detail::AttrPtr& GetAttr(detail::AttrTag a) const { return attrs ? attrs->Find(a) : detail::Attr::nil; }

    const detail::Location* GetLocationInfo() const { return &loc; }

    void DescribeReST(ODesc* d, bool roles_only = false) const;

    TypePtr type;
    detail::AttributesPtr attrs;
    const char* id = nullptr;
    bool is_managed = false;
    TypeTag tag = TYPE_ERROR;

private:
    detail::Location loc = detail::GetCurrentLocation();
};

using type_decl_list = PList<TypeDecl>;

class RecordType final : public Type {
public:
    explicit RecordType(type_decl_list* types);
    TypePtr ShallowClone() override;

    ~RecordType() override;

    bool HasField(const char* field) const;





    const TypePtr& GetFieldType(const char* field_name) const { return GetFieldType(FieldOffset(field_name)); }





    template<class T>
    IntrusivePtr<T> GetFieldType(const char* field_name) const {
        return cast_intrusive<T>(GetFieldType(field_name));
    }





    const TypePtr& GetFieldType(int field_index) const { return (*types)[field_index]->type; }





    template<class T>
    IntrusivePtr<T> GetFieldType(int field_index) const {
        return cast_intrusive<T>((*types)[field_index]->type);
    }

    ValPtr FieldDefault(int field) const;



    int FieldOffset(const char* field) const;


    const char* FieldName(int field) const;

    const type_decl_list* Types() const { return types; }
    type_decl_list* Types() { return types; }


    const TypeDecl* FieldDecl(int field) const { return (*types)[field]; }
    TypeDecl* FieldDecl(int field) { return (*types)[field]; }



    [[deprecated(
        "Remove in v9.1: Unused and optimization related internal. Use TypeDecl's is_managed member instead.")]]
    const std::vector<bool>& ManagedFields() const {
        return managed_fields;
    }

    int NumFields() const { return num_fields; }
    int NumOrigFields() const { return num_orig_fields; }









    TableValPtr GetRecordFieldsVal(const RecordVal* rv = nullptr) const;


    const char* AddFields(const type_decl_list& types, bool add_log_attr = false);

    void AddFieldsDirectly(const type_decl_list& types, bool add_log_attr = false);

    void DescribeReST(ODesc* d, bool roles_only = false) const override;
    void DescribeFields(ODesc* d, bool func_args = false) const;
    void DescribeFieldsReST(ODesc* d, bool func_args) const;

    bool IsFieldDeprecated(int field) const {
        const TypeDecl* decl = FieldDecl(field);
        return decl && decl->GetAttr(detail::ATTR_DEPRECATED) != nullptr;
    }

    bool FieldHasAttr(int field, detail::AttrTag at) const {
        const TypeDecl* decl = FieldDecl(field);
        return decl && decl->GetAttr(at) != nullptr;
    }

    std::string GetFieldDeprecationWarning(int field, bool has_check) const;

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const override;






    bool IsDeferrable() const;




    bool IdempotentCreation() const { return creation_inits.empty(); }

    static void InitPostScript();

private:
    RecordType() { types = nullptr; }

    void AddField(unsigned int field, const TypeDecl* td);

    void DoDescribe(ODesc* d) const override;




    std::vector<std::shared_ptr<detail::FieldInit>> deferred_inits;







    std::vector<std::pair<int, std::shared_ptr<detail::FieldInit>>> creation_inits;

    class CreationInitsOptimizer;
    friend zeek::RecordVal;
    friend zeek::detail::ZAMCompiler;
    friend zeek::detail::CPPRuntime;
    const auto& DeferredInits() const { return deferred_inits; }
    const auto& CreationInits() const { return creation_inits; }




    std::vector<bool> managed_fields;


    int num_fields = 0;


    int num_orig_fields = 0;

    type_decl_list* types = nullptr;
    std::set<std::string> field_ids;
};

class FileType final : public Type {
public:
    explicit FileType(TypePtr yield_type);
    TypePtr ShallowClone() override { return make_intrusive<FileType>(yield); }
    ~FileType() override;

    const TypePtr& Yield() const override { return yield; }

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const override;

protected:
    void DoDescribe(ODesc* d) const override;

    TypePtr yield;
};

class OpaqueType : public Type {
public:
    explicit OpaqueType(const std::string& name);
    TypePtr ShallowClone() override { return make_intrusive<OpaqueType>(name); }

    const std::string& Name() const { return name; }

    void DescribeReST(ODesc* d, bool roles_only = false) const override;


    virtual bool SupportsHashing() const { return false; }
    virtual bool HashSingleValue(const detail::CompositeHash* ch, detail::HashKey& hk, const Val* v, bool type_check,
                                 bool singleton) const;
    virtual bool RecoverValFromHash(const detail::CompositeHash* ch, const detail::HashKey& hk, ValPtr* pval,
                                    bool singleton) const;
    virtual bool ReserveHashKeySize(const detail::CompositeHash* ch, detail::HashKey& hk, const Val* v, bool type_check,
                                    bool calc_static_size, bool singleton) const;



    virtual bool CanCastTo(const Type* ) const { return false; }
    virtual ValPtr CastValueTo(const ValPtr& v, const Type* t, std::string& err) const;



    virtual ValPtr DefaultVal() const;

protected:
    OpaqueType() = default;

    void DoDescribe(ODesc* d) const override;

    std::string name;
};

class EnumType final : public Type {
public:
    using enum_name_list = std::list<std::pair<std::string, zeek_int_t>>;

    explicit EnumType(const EnumType* e);
    explicit EnumType(const std::string& arg_name);
    TypePtr ShallowClone() override;
    ~EnumType() override;



    void AddName(const std::string& module_name, const char* name, bool is_export, detail::Expr* deprecation = nullptr,
                 bool from_redef = false);




    void AddName(const std::string& module_name, const char* name, zeek_int_t val, bool is_export,
                 detail::Expr* deprecation = nullptr, bool from_redef = false);



    zeek_int_t Lookup(const std::string& module_name, const char* name) const;
    zeek_int_t Lookup(const std::string& full_name) const;

    const char* Lookup(zeek_int_t value) const;



    enum_name_list Names() const;

    bool HasRedefs() const { return has_redefs; }

    void DescribeReST(ODesc* d, bool roles_only = false) const override;

    const EnumValPtr& GetEnumVal(zeek_int_t i);




    void AddNameInternal(const std::string& full_name, zeek_int_t val);

protected:
    void AddNameInternal(const std::string& module_name, const char* name, zeek_int_t val, bool is_export);

    void CheckAndAddName(const std::string& module_name, const char* name, zeek_int_t val, bool is_export,
                         detail::Expr* deprecation = nullptr, bool from_redef = false);

    void DoDescribe(ODesc* d) const override;

    std::map<std::string, zeek_int_t> names;
    std::map<zeek_int_t, std::string> rev_names;


    bool has_redefs = false;

    std::unordered_map<zeek_int_t, EnumValPtr> vals;







    zeek_int_t counter;












    template<class>
    friend class zeek::plugin::ComponentManager;
    friend bool same_type(const Type& t1, const Type& t2, bool is_init, bool match_record_field_names);

    void SetParentType(EnumTypePtr arg_parent) { parent = std::move(arg_parent); }
    const EnumTypePtr& GetParentType() const { return parent; }


    EnumTypePtr parent;
};

class VectorType final : public Type {
public:
    explicit VectorType(TypePtr t);
    TypePtr ShallowClone() override;
    ~VectorType() override;

    const TypePtr& Yield() const override;

    int MatchesIndex(detail::ListExpr* index) const override;



    bool IsUnspecifiedVector() const;

    void DescribeReST(ODesc* d, bool roles_only = false) const override;

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const override;

protected:
    void DoDescribe(ODesc* d) const override;

    TypePtr yield_type;
};




extern bool same_type(const Type& t1, const Type& t2, bool is_init = false, bool match_record_field_names = true);
inline bool same_type(const TypePtr& t1, const TypePtr& t2, bool is_init = false,
                      bool match_record_field_names = true) {

    if ( t1.get() == t2.get() )
        return true;

    return same_type(*t1, *t2, is_init, match_record_field_names);
}
inline bool same_type(const Type* t1, const Type* t2, bool is_init = false, bool match_record_field_names = true) {

    if ( t1 == t2 )
        return true;

    return same_type(*t1, *t2, is_init, match_record_field_names);
}
inline bool same_type(const TypePtr& t1, const Type* t2, bool is_init = false, bool match_record_field_names = true) {

    if ( t1.get() == t2 )
        return true;

    return same_type(*t1, *t2, is_init, match_record_field_names);
}
inline bool same_type(const Type* t1, const TypePtr& t2, bool is_init = false, bool match_record_field_names = true) {

    if ( t1 == t2.get() )
        return true;

    return same_type(*t1, *t2, is_init, match_record_field_names);
}


extern bool same_attrs(const detail::Attributes* a1, const detail::Attributes* a2);



extern bool record_promotion_compatible(const RecordType* super_rec, const RecordType* sub_rec);



extern const Type* flatten_type(const Type* t);
extern Type* flatten_type(Type* t);


extern TypeTag max_type(TypeTag t1, TypeTag t2);




TypePtr merge_types(const TypePtr& t1, const TypePtr& t2);




TypePtr maximal_type(detail::ListExpr* elements);


TypePtr init_type(const detail::ExprPtr& init);


bool is_atomic_type(const Type& t);
inline bool is_atomic_type(const Type* t) { return is_atomic_type(*t); }
inline bool is_atomic_type(const TypePtr& t) { return is_atomic_type(*t); }


extern bool is_assignable(TypeTag t);
inline bool is_assignable(Type* t) { return is_assignable(t->Tag()); }


inline bool IsIntegral(TypeTag t) { return (t == TYPE_INT || t == TYPE_COUNT); }


inline bool IsArithmetic(TypeTag t) { return (IsIntegral(t) || t == TYPE_DOUBLE); }


inline bool IsBool(TypeTag t) { return (t == TYPE_BOOL); }


inline bool IsInterval(TypeTag t) { return (t == TYPE_INTERVAL); }


inline bool IsRecord(TypeTag t) { return (t == TYPE_RECORD); }


inline bool IsFunc(TypeTag t) { return (t == TYPE_FUNC); }


inline bool IsVector(TypeTag t) { return (t == TYPE_VECTOR); }


inline bool IsString(TypeTag t) { return (t == TYPE_STRING); }


inline bool IsAggr(TypeTag tag) { return tag == TYPE_VECTOR || tag == TYPE_TABLE || tag == TYPE_RECORD; }
inline bool IsAggr(const Type* t) { return IsAggr(t->Tag()); }
inline bool IsAggr(const TypePtr& t) { return IsAggr(t->Tag()); }


inline bool IsContainer(TypeTag tag) { return tag == TYPE_VECTOR || tag == TYPE_TABLE; }


inline bool IsErrorType(TypeTag t) { return (t == TYPE_ERROR); }


inline bool BothIntegral(TypeTag t1, TypeTag t2) { return (IsIntegral(t1) && IsIntegral(t2)); }


inline bool BothArithmetic(TypeTag t1, TypeTag t2) { return (IsArithmetic(t1) && IsArithmetic(t2)); }


inline bool EitherArithmetic(TypeTag t1, TypeTag t2) { return (IsArithmetic(t1) || IsArithmetic(t2)); }


inline bool BothBool(TypeTag t1, TypeTag t2) { return (IsBool(t1) && IsBool(t2)); }


inline bool BothInterval(TypeTag t1, TypeTag t2) { return (IsInterval(t1) && IsInterval(t2)); }


inline bool BothString(TypeTag t1, TypeTag t2) { return (IsString(t1) && IsString(t2)); }


inline bool EitherError(TypeTag t1, TypeTag t2) { return (IsErrorType(t1) || IsErrorType(t2)); }


const TypePtr& base_type(TypeTag tag);


inline const TypePtr& error_type() { return base_type(TYPE_ERROR); }

}

extern zeek::OpaqueTypePtr md5_type;
extern zeek::OpaqueTypePtr sha1_type;
extern zeek::OpaqueTypePtr sha224_type;
extern zeek::OpaqueTypePtr sha256_type;
extern zeek::OpaqueTypePtr sha384_type;
extern zeek::OpaqueTypePtr sha512_type;
extern zeek::OpaqueTypePtr entropy_type;
extern zeek::OpaqueTypePtr cardinality_type;
extern zeek::OpaqueTypePtr topk_type;
extern zeek::OpaqueTypePtr bloomfilter_type;
extern zeek::OpaqueTypePtr x509_opaque_type;
extern zeek::OpaqueTypePtr ocsp_resp_opaque_type;
extern zeek::OpaqueTypePtr paraglob_type;
extern zeek::OpaqueTypePtr counter_metric_type;
extern zeek::OpaqueTypePtr counter_metric_family_type;
extern zeek::OpaqueTypePtr gauge_metric_type;
extern zeek::OpaqueTypePtr gauge_metric_family_type;
extern zeek::OpaqueTypePtr histogram_metric_type;
extern zeek::OpaqueTypePtr histogram_metric_family_type;
