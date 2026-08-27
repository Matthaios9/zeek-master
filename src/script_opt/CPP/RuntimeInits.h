







#include "zeek/Expr.h"
#include "zeek/script_opt/CPP/RuntimeInitSupport.h"

#pragma once

namespace zeek::detail {

using FileValPtr = IntrusivePtr<FileVal>;
using FuncValPtr = IntrusivePtr<FuncVal>;
using TypeValPtr = IntrusivePtr<TypeVal>;

class InitsManager;









extern size_t generate_indices_set(int* inits, std::vector<std::vector<int>>& indices_set);






extern std::vector<std::vector<std::vector<int>>> generate_indices_set(int* inits);




constexpr int END_OF_VEC_VEC = -100;
constexpr int END_OF_VEC_VEC_VEC = -200;



constexpr int NAMED_TYPE_MARKER = -300;



constexpr int DO_NOT_CONSTRUCT_VALUE_MARKER = -400;





class CPP_AbstractInitAccessor {
public:
    virtual ~CPP_AbstractInitAccessor() = default;
    virtual ValPtr Get(int index) const { return nullptr; }
};




struct CPP_ValElem {
    TypeTag tag;
    int offset;
};





class CPP_FieldMapping {
public:
    CPP_FieldMapping(int _rec, std::string _field_name, int _field_type, int _field_attrs)
        : rec(_rec), field_name(std::move(_field_name)), field_type(_field_type), field_attrs(_field_attrs) {}

    zeek_int_t ComputeOffset(InitsManager* im) const;

    int RecTypeIndex() const { return rec; }
    int FieldTypeIndex() const { return field_type; }

private:
    int rec;
    std::string field_name;




    int field_type;
    int field_attrs;
};





class CPP_EnumMapping {
public:
    CPP_EnumMapping(int _e_type, std::string _e_name, bool _construct_if_missing)
        : e_type(_e_type), e_name(std::move(_e_name)), construct_if_missing(_construct_if_missing) {}

    zeek_int_t ComputeOffset(InitsManager* im) const;

    int EnumTypeIndex() const { return e_type; }

private:
    int e_type;
    std::string e_name;
    bool construct_if_missing;
};





class InitsManager {
public:
    InitsManager(std::vector<CPP_ValElem>& _const_vals,
                 std::map<TypeTag, std::shared_ptr<CPP_AbstractInitAccessor>>& _consts,
                 std::vector<std::vector<int>>& _indices, std::vector<const char*>& _strings,
                 std::vector<p_hash_type>& _hashes, std::vector<TypePtr>& _types,
                 std::vector<AttributesPtr>& _attributes, std::vector<AttrPtr>& _attrs,
                 std::vector<CallExprPtr>& _call_exprs, std::vector<zeek_int_t>& _field_mappings,
                 std::vector<CPP_FieldMapping>& _field_mappings_init, std::vector<zeek_int_t>& _enum_mappings,
                 std::vector<CPP_EnumMapping>& _enum_mappings_init);



    void RecordTypeBuilt(int rt_index);



    void EnumTypeBuilt(int e_index);



    ValPtr ConstVals(int offset) const {
        auto& cv = const_vals[offset];
        return Consts(cv.tag, cv.offset);
    }


    ValPtr Consts(TypeTag tag, int index) const { return consts[tag]->Get(index); }



    const std::vector<int>& Indices(int offset) const { return indices[offset]; }
    const char* Strings(int offset) const {
        ASSERT(offset >= 0 && offset < static_cast<int>(strings.size()));
        ASSERT(strings[offset]);
        return strings[offset];
    }
    p_hash_type Hashes(int offset) const {
        ASSERT(offset >= 0 && offset < static_cast<int>(hashes.size()));
        return hashes[offset];
    }
    const TypePtr& Types(int offset) const {
        ASSERT(offset >= 0 && offset < static_cast<int>(types.size()));
        ASSERT(types[offset]);
        return types[offset];
    }
    const AttributesPtr& Attributes(int offset) const {
        ASSERT(offset >= 0 && offset < static_cast<int>(attributes.size()));
        ASSERT(attributes[offset]);
        return attributes[offset];
    }
    const AttrPtr& Attrs(int offset) const {
        ASSERT(offset >= 0 && offset < static_cast<int>(attrs.size()));
        ASSERT(attrs[offset]);
        return attrs[offset];
    }
    const CallExprPtr& CallExprs(int offset) const {
        ASSERT(offset >= 0 && offset < static_cast<int>(call_exprs.size()));
        ASSERT(call_exprs[offset]);
        return call_exprs[offset];
    }

private:
    std::vector<CPP_ValElem>& const_vals;
    std::map<TypeTag, std::shared_ptr<CPP_AbstractInitAccessor>>& consts;
    std::vector<std::vector<int>>& indices;
    std::vector<const char*>& strings;
    std::vector<p_hash_type>& hashes;
    std::vector<TypePtr>& types;
    std::vector<AttributesPtr>& attributes;
    std::vector<AttrPtr>& attrs;
    std::vector<CallExprPtr>& call_exprs;

    std::set<int> field_types;
    std::vector<zeek_int_t>& field_mappings;
    std::vector<CPP_FieldMapping>& field_mappings_init;

    std::set<int> enum_types;
    std::vector<zeek_int_t>& enum_mappings;
    std::vector<CPP_EnumMapping>& enum_mappings_init;
};


template<class T>
class CPP_Init {
public:
    virtual ~CPP_Init() = default;


    virtual void PreInit(InitsManager* im, std::vector<T>& inits_vec, int offset) const {}


    virtual void Generate(InitsManager* im, std::vector<T>& inits_vec, int offset) const {}
};



template<class T1, class T2>
class CPP_AbstractInits {
public:
    CPP_AbstractInits(std::vector<T1>& _inits_vec, int _offsets_set, std::vector<T2> _inits)
        : inits_vec(_inits_vec), offsets_set(_offsets_set), inits(std::move(_inits)) {

        int num_inits = 0;

        for ( const auto& cohort : inits )
            num_inits += cohort.size();

        inits_vec.resize(num_inits);
    }

    virtual ~CPP_AbstractInits() = default;


    void InitializeCohort(InitsManager* im, int cohort) {

        auto& offsets_vec = im->Indices(offsets_set);

        if ( cohort == 0 )
            DoPreInits(im, offsets_vec);


        auto& cohort_offsets = im->Indices(offsets_vec[cohort]);

        InitializeCohortWithOffsets(im, cohort, cohort_offsets);
    }

protected:
    virtual void InitializeCohortWithOffsets(InitsManager* im, int cohort, const std::vector<int>& cohort_offsets) {}


    virtual void DoPreInits(InitsManager* im, const std::vector<int>& offsets_vec) {}


    std::vector<T1>& inits_vec;


    int offsets_set;


    std::vector<T2> inits;
};



template<class T>
using CPP_InitVec = std::vector<std::shared_ptr<CPP_Init<T>>>;
template<class T>
class CPP_CustomInits : public CPP_AbstractInits<T, CPP_InitVec<T>> {
public:
    CPP_CustomInits(std::vector<T>& _inits_vec, int _offsets_set, std::vector<CPP_InitVec<T>> _inits)
        : CPP_AbstractInits<T, CPP_InitVec<T>>(_inits_vec, _offsets_set, std::move(_inits)) {}

private:
    void DoPreInits(InitsManager* im, const std::vector<int>& offsets_vec) override {
        int cohort = 0;
        for ( const auto& co : this->inits ) {
            auto& cohort_offsets = im->Indices(offsets_vec[cohort]);
            for ( auto i = 0U; i < co.size(); ++i )
                co[i]->PreInit(im, this->inits_vec, cohort_offsets[i]);
            ++cohort;
        }
    }

    void InitializeCohortWithOffsets(InitsManager* im, int cohort, const std::vector<int>& cohort_offsets) override {

        auto& co = this->inits[cohort];
        for ( auto i = 0U; i < co.size(); ++i )
            co[i]->Generate(im, this->inits_vec, cohort_offsets[i]);
    }
};


template<class T>
class CPP_InitAccessor : public CPP_AbstractInitAccessor {
public:
    CPP_InitAccessor(std::vector<T>& _inits_vec) : inits_vec(_inits_vec) {}

    ValPtr Get(int index) const override { return inits_vec[index]; }

private:
    std::vector<T>& inits_vec;
};



using ValElemVec = std::vector<int>;
using ValElemVecVec = std::vector<ValElemVec>;



template<class T>
class CPP_IndexedInits : public CPP_AbstractInits<T, ValElemVecVec> {
public:
    CPP_IndexedInits(std::vector<T>& _inits_vec, int _offsets_set, int* raw_inits)
        : CPP_AbstractInits<T, ValElemVecVec>(_inits_vec, _offsets_set, generate_indices_set(raw_inits)) {}

protected:
    void InitializeCohortWithOffsets(InitsManager* im, int cohort, const std::vector<int>& cohort_offsets) override;





    void Generate(InitsManager* im, std::vector<EnumValPtr>& ivec, int offset, ValElemVec& init_vals);
    void Generate(InitsManager* im, std::vector<StringValPtr>& ivec, int offset, ValElemVec& init_vals);
    void Generate(InitsManager* im, std::vector<PatternValPtr>& ivec, int offset, ValElemVec& init_vals);
    void Generate(InitsManager* im, std::vector<ListValPtr>& ivec, int offset, ValElemVec& init_vals) const;
    void Generate(InitsManager* im, std::vector<VectorValPtr>& ivec, int offset, ValElemVec& init_vals) const;
    void Generate(InitsManager* im, std::vector<RecordValPtr>& ivec, int offset, ValElemVec& init_vals) const;
    void Generate(InitsManager* im, std::vector<TableValPtr>& ivec, int offset, ValElemVec& init_vals) const;
    void Generate(InitsManager* im, std::vector<FileValPtr>& ivec, int offset, ValElemVec& init_vals) const;
    void Generate(InitsManager* im, std::vector<FuncValPtr>& ivec, int offset, ValElemVec& init_vals) const;
    void Generate(InitsManager* im, std::vector<TypeValPtr>& ivec, int offset, ValElemVec& init_vals) const;
    void Generate(InitsManager* im, std::vector<AttrPtr>& ivec, int offset, ValElemVec& init_vals) const;
    void Generate(InitsManager* im, std::vector<AttributesPtr>& ivec, int offset, ValElemVec& init_vals) const;



    virtual void Generate(InitsManager* im, std::vector<TypePtr>& ivec, int offset, ValElemVec& init_vals) const {
        ASSERT(0);
    }
};



class CPP_TypeInits : public CPP_IndexedInits<TypePtr> {
public:
    CPP_TypeInits(std::vector<TypePtr>& _inits_vec, int _offsets_set, int* raw_inits)
        : CPP_IndexedInits<TypePtr>(_inits_vec, _offsets_set, raw_inits) {}

protected:
    void DoPreInits(InitsManager* im, const std::vector<int>& offsets_vec) override;
    void PreInit(InitsManager* im, int offset, ValElemVec& init_vals);

    void Generate(InitsManager* im, std::vector<TypePtr>& ivec, int offset, ValElemVec& init_vals) const override;

    void CheckBuiltType(InitsManager* im, TypeTag t, int offset) const;

    TypePtr BuildEnumType(InitsManager* im, ValElemVec& init_vals) const;
    TypePtr BuildOpaqueType(InitsManager* im, ValElemVec& init_vals) const;
    TypePtr BuildTypeType(InitsManager* im, ValElemVec& init_vals) const;
    TypePtr BuildVectorType(InitsManager* im, ValElemVec& init_vals) const;
    TypePtr BuildTypeList(InitsManager* im, ValElemVec& init_vals, int offset) const;
    TypePtr BuildTableType(InitsManager* im, ValElemVec& init_vals, int offset) const;
    TypePtr BuildFuncType(InitsManager* im, ValElemVec& init_vals) const;
    TypePtr BuildRecordType(InitsManager* im, ValElemVec& init_vals, int offset) const;
};










template<class T1, typename T2>
class CPP_AbstractBasicConsts {
public:
    CPP_AbstractBasicConsts(std::vector<T1>& _inits_vec, int _offsets_set, std::vector<T2> _inits)
        : inits_vec(_inits_vec), offsets_set(_offsets_set), inits(std::move(_inits)) {
        inits_vec.resize(inits.size());
    }

    virtual ~CPP_AbstractBasicConsts() = default;

    void InitializeCohort(InitsManager* im, int cohort) {
        ASSERT(cohort == 0);
        auto& offsets_vec = im->Indices(offsets_set);
        auto& cohort_offsets = im->Indices(offsets_vec[cohort]);
        for ( auto i = 0U; i < inits.size(); ++i )
            InitElem(im, cohort_offsets[i], i);
    }

protected:
    virtual void InitElem(InitsManager* im, int offset, int index) { ASSERT(0); }

protected:

    std::vector<T1>& inits_vec;
    int offsets_set;
    std::vector<T2> inits;
};




template<class T1, typename T2, class T3>
class CPP_BasicConsts : public CPP_AbstractBasicConsts<T1, T2> {
public:
    CPP_BasicConsts(std::vector<T1>& _inits_vec, int _offsets_set, std::vector<T2> _inits)
        : CPP_AbstractBasicConsts<T1, T2>(_inits_vec, _offsets_set, std::move(_inits)) {}

    void InitElem(InitsManager* , int offset, int index) override {
        this->inits_vec[offset] = make_intrusive<T3>(this->inits[index]);
    }
};


class CPP_AddrConsts : public CPP_AbstractBasicConsts<AddrValPtr, int> {
public:
    CPP_AddrConsts(std::vector<AddrValPtr>& _inits_vec, int _offsets_set, std::vector<int> _inits)
        : CPP_AbstractBasicConsts<AddrValPtr, int>(_inits_vec, _offsets_set, std::move(_inits)) {}

    void InitElem(InitsManager* im, int offset, int index) override {
        auto s = im->Strings(this->inits[index]);
        this->inits_vec[offset] = make_intrusive<AddrVal>(s);
    }
};

class CPP_SubNetConsts : public CPP_AbstractBasicConsts<SubNetValPtr, int> {
public:
    CPP_SubNetConsts(std::vector<SubNetValPtr>& _inits_vec, int _offsets_set, std::vector<int> _inits)
        : CPP_AbstractBasicConsts<SubNetValPtr, int>(_inits_vec, _offsets_set, std::move(_inits)) {}

    void InitElem(InitsManager* im, int offset, int index) override {
        auto s = im->Strings(this->inits[index]);
        this->inits_vec[offset] = make_intrusive<SubNetVal>(s);
    }
};



class CPP_GlobalLookupInit : public CPP_Init<void*> {
public:
    CPP_GlobalLookupInit(IDPtr& _global, const char* _name, int _val)
        : CPP_Init<void*>(), global(_global), name(_name), val(_val) {}

    void Generate(InitsManager* im, std::vector<void*>& , int ) const override;

protected:
    IDPtr& global;
    const char* name;
    int val;
};

class CPP_GlobalInit : public CPP_Init<void*> {
public:
    CPP_GlobalInit(IDPtr& _global, const char* _name, int _type, int _attrs, int _val, bool is_exported, bool is_const,
                   bool is_option, bool is_enum_const, bool is_type, bool _func_with_no_val)
        : CPP_Init<void*>(),
          global(_global),
          name(_name),
          type(_type),
          attrs(_attrs),
          val(_val),
          func_with_no_val(_func_with_no_val) {
        gc.is_exported = is_exported;
        gc.is_const = is_const;
        gc.is_option = is_option;
        gc.is_enum_const = is_enum_const;
        gc.is_type = is_type;
    }

    void Generate(InitsManager* im, std::vector<void*>& , int ) const override;

protected:
    IDPtr& global;
    const char* name;
    int type;
    int attrs;
    int val;
    GlobalCharacteristics gc;
    bool func_with_no_val;
};


class CPP_AbstractCallExprInit : public CPP_Init<CallExprPtr> {
public:
    CPP_AbstractCallExprInit() : CPP_Init<CallExprPtr>() {}
};


template<class T>
class CPP_CallExprInit : public CPP_AbstractCallExprInit {
public:
    CPP_CallExprInit(CallExprPtr& _e_var) : CPP_AbstractCallExprInit(), e_var(_e_var) {}

    void Generate(InitsManager* , std::vector<CallExprPtr>& inits_vec, int offset) const override {
        auto wrapper_class = make_intrusive<T>();
        auto func_val = make_intrusive<FuncVal>(wrapper_class);
        auto func_expr = make_intrusive<ConstExpr>(func_val);
        auto empty_args = make_intrusive<ListExpr>();

        e_var = make_intrusive<CallExpr>(func_expr, empty_args);
        inits_vec[offset] = e_var;
    }

private:

    CallExprPtr& e_var;
};


class CPP_AbstractLambdaRegistration : public CPP_Init<void*> {
public:
    CPP_AbstractLambdaRegistration() : CPP_Init<void*>() {}
};


template<class T>
class CPP_LambdaRegistration : public CPP_AbstractLambdaRegistration {
public:
    CPP_LambdaRegistration(const char* _name, int _func_type, p_hash_type _h, bool _has_captures)
        : CPP_AbstractLambdaRegistration(), name(_name), func_type(_func_type), h(_h), has_captures(_has_captures) {}

    void Generate(InitsManager* im, std::vector<void*>& inits_vec, int offset) const override {
        auto l = make_intrusive<T>(name);
        auto& ft = im->Types(func_type);
        register_lambda__CPP(l, h, name, ft, has_captures);
    }

protected:
    const char* name;
    int func_type;
    p_hash_type h;
    bool has_captures;
};



class CPP_LookupBiF {
public:
    CPP_LookupBiF(zeek::Func*& _bif_func, std::string _bif_name)
        : bif_func(_bif_func), bif_name(std::move(_bif_name)) {}

    void ResolveBiF() const {




        if ( ! bif_func )
            bif_func = lookup_bif__CPP(bif_name.c_str());
    }

protected:
    zeek::Func*& bif_func;
    std::string bif_name;
};




struct CPP_RegisterBody {
    CPP_RegisterBody(std::string _zeek_name, std::string _func_name, void* _func, int _type_signature, int _priority,
                     p_hash_type _h, const char* _filename, int _line_num, std::vector<std::string> _events,
                     std::string _module_group, std::vector<std::string> _attr_groups)
        : zeek_name(std::move(_zeek_name)),
          func_name(std::move(_func_name)),
          func(_func),
          type_signature(_type_signature),
          priority(_priority),
          h(_h),
          filename(_filename),
          line_num(_line_num),
          events(std::move(_events)),
          module_group(std::move(_module_group)),
          attr_groups(std::move(_attr_groups)) {}

    std::string zeek_name;
    std::string func_name;
    void* func;
    int type_signature;
    int priority;
    p_hash_type h;
    const char* filename;
    int line_num;
    std::vector<std::string> events;
    std::string module_group;
    std::vector<std::string> attr_groups;
};

}
