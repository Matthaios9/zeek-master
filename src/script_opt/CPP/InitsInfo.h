











































































#include "zeek/File.h"
#include "zeek/Val.h"
#include "zeek/script_opt/ProfileFunc.h"

#pragma once

namespace zeek::detail {

class CPPCompile;


class CPP_InitInfo;



class CPP_InitsInfo {
public:
    CPP_InitsInfo(std::string _tag, const std::string& type) : tag(std::move(_tag)) {
        base_name = std::string("CPP__") + tag + "__";
        CPP_type = tag + type;
    }

    virtual ~CPP_InitsInfo() = default;




    const std::string& InitsName() const { return base_name; }



    std::string InitializersName() const { return base_name + "init"; }







    std::string Name(int index) const;



    std::string NextName() const { return Name(size); }


    int MaxCohort() const { return static_cast<int>(instances.size()) - 1; }



    int CohortSize(int c) const { return c > MaxCohort() ? 0 : instances[c].size(); }



    void GetCohortIDs(int c, std::vector<IDPtr>& ids) const;



    const std::string& CPPType() const { return CPP_type; }


    virtual void SetCPPType(std::string ct) { CPP_type = std::move(ct); }




    virtual bool UsesCompoundVectors() const { return false; }



    std::string InitsType() const { return inits_type; }


    void AddInstance(std::shared_ptr<CPP_InitInfo> g);


    virtual void GenerateInitializers(CPPCompile* c);

protected:
    virtual void GenerateCohorts(CPPCompile* c);


    void BuildOffsetSet(CPPCompile* c);



    std::string Declare() const;



    void BuildCohort(CPPCompile* c, std::vector<std::shared_ptr<CPP_InitInfo>>& cohort);



    virtual void BuildCohortElement(CPPCompile* c, const std::string& init_type, std::vector<std::string>& ivs);


    int size = 0;





    std::vector<std::vector<std::shared_ptr<CPP_InitInfo>>> instances;



    std::unordered_set<std::shared_ptr<CPP_InitInfo>> processed_instances;












    int offset_set = 0;


    std::string tag;


    std::string base_name;


    std::string CPP_type;


    std::string inits_type;
};





class CPP_CustomInitsInfo : public CPP_InitsInfo {
public:
    CPP_CustomInitsInfo(std::string _tag, const std::string& _type) : CPP_InitsInfo(std::move(_tag), _type) {
        BuildInitType();
    }

    void SetCPPType(std::string ct) override {
        CPP_InitsInfo::SetCPPType(std::move(ct));
        BuildInitType();
    }

    bool UsesCompoundVectors() const override { return true; }

private:
    void BuildInitType() { inits_type = std::string("CPP_CustomInits<") + CPPType() + ">"; }
};




class CPP_BasicConstInitsInfo : public CPP_CustomInitsInfo {
public:



    CPP_BasicConstInitsInfo(std::string _tag, const std::string& type, const std::string& c_type)
        : CPP_CustomInitsInfo(std::move(_tag), type) {
        if ( c_type.empty() )
            inits_type = std::string("CPP_") + tag + "Consts";
        else
            inits_type = std::string("CPP_BasicConsts<") + CPP_type + ", " + c_type + ", " + tag + "Val>";
    }

    bool UsesCompoundVectors() const override { return false; }

    void BuildCohortElement(CPPCompile* c, const std::string& init_type, std::vector<std::string>& ivs) override;
};



class CPP_CompoundInitsInfo : public CPP_InitsInfo {
public:
    CPP_CompoundInitsInfo(std::string _tag, const std::string& type) : CPP_InitsInfo(std::move(_tag), type) {
        if ( tag == "Type" )


            inits_type = "CPP_TypeInits";
        else
            inits_type = std::string("CPP_IndexedInits<") + CPPType() + ">";
    }



    bool UsesCompoundVectors() const override { return false; }

    void GenerateInitializers(CPPCompile* c) override;
    void GenerateCohorts(CPPCompile* c) override;

    void BuildCohortElement(CPPCompile* c, const std::string& init_type, std::vector<std::string>& ivs) override;
};


class CPP_InitInfo {
public:
    CPP_InitInfo(const IntrusivePtr<Obj>& _o) : o(_o.get()) {}
    CPP_InitInfo(const Obj* _o) : o(_o) {}

    virtual ~CPP_InitInfo() = default;



    void SetOffset(const CPP_InitsInfo* _inits_collection, int _offset) {
        inits_collection = _inits_collection;
        offset = _offset;
    }


    int Offset() const { return offset; }



    virtual std::string Name() const { return inits_collection->Name(offset); }


    int InitCohort() const { return init_cohort; }



    int FinalInitCohort() const { return final_init_cohort ? final_init_cohort : init_cohort; }


    virtual std::string InitializerType() const { return "<shouldn't-be-used>"; }



    virtual void InitializerVals(std::vector<std::string>& ivs) const = 0;


    virtual IDPtr InitIdentifier() const { return nullptr; }

    const Obj* InitObj() const { return o; }

protected:



    std::string ValElem(CPPCompile* c, ValPtr v);




    int init_cohort = 0;





    int final_init_cohort = 0;


    const CPP_InitsInfo* inits_collection = nullptr;


    int offset = -1;


    const Obj* o;
};


class BasicConstInfo : public CPP_InitInfo {
public:
    BasicConstInfo(std::string _val) : CPP_InitInfo(nullptr), val(std::move(_val)) {}

    void InitializerVals(std::vector<std::string>& ivs) const override { ivs.emplace_back(val); }

private:

    std::string val;
};



class DescConstInfo : public CPP_InitInfo {
public:
    DescConstInfo(CPPCompile* c, ValPtr v);

    void InitializerVals(std::vector<std::string>& ivs) const override { ivs.emplace_back(init); }

private:
    std::string init;
};

class EnumConstInfo : public CPP_InitInfo {
public:
    EnumConstInfo(CPPCompile* c, ValPtr v);

    void InitializerVals(std::vector<std::string>& ivs) const override {
        ivs.emplace_back(std::to_string(e_type));
        ivs.emplace_back(std::to_string(e_val));
    }

private:
    int e_type;
    int e_val;
};

class StringConstInfo : public CPP_InitInfo {
public:
    StringConstInfo(CPPCompile* c, ValPtr v);

    void InitializerVals(std::vector<std::string>& ivs) const override {
        ivs.emplace_back(std::to_string(chars));
        ivs.emplace_back(std::to_string(len));
    }

private:
    int chars;
    int len;
};

class PatternConstInfo : public CPP_InitInfo {
public:
    PatternConstInfo(CPPCompile* c, ValPtr v);

    void InitializerVals(std::vector<std::string>& ivs) const override {
        ivs.emplace_back(std::to_string(exact_pat));
        ivs.emplace_back(std::to_string(any_pat));
        ivs.emplace_back(std::to_string(is_case_insensitive));
        ivs.emplace_back(std::to_string(is_single_line));
    }

private:
    int exact_pat;
    int any_pat;
    int is_case_insensitive;
    int is_single_line;
};

class PortConstInfo : public CPP_InitInfo {
public:
    PortConstInfo(ValPtr v) : CPP_InitInfo(v), p(static_cast<UnsignedValImplementation*>(v->AsPortVal())->Get()) {}

    void InitializerVals(std::vector<std::string>& ivs) const override { ivs.emplace_back(std::to_string(p) + "U"); }

private:
    zeek_uint_t p;
};


class CompoundItemInfo : public CPP_InitInfo {
public:


    CompoundItemInfo(CPPCompile* c, ValPtr v);
    CompoundItemInfo(CPPCompile* _c) : CPP_InitInfo(nullptr), c(_c) { type = -1; }

    void InitializerVals(std::vector<std::string>& ivs) const override {
        if ( type >= 0 )
            ivs.emplace_back(std::to_string(type));

        for ( auto& v : vals )
            ivs.push_back(v);
    }

protected:
    CPPCompile* c;
    int type;
    std::vector<std::string> vals;
};


class ListConstInfo : public CompoundItemInfo {
public:
    ListConstInfo(CPPCompile* c, ValPtr v);
};

class VectorConstInfo : public CompoundItemInfo {
public:
    VectorConstInfo(CPPCompile* c, ValPtr v);
};

class RecordConstInfo : public CompoundItemInfo {
public:
    RecordConstInfo(CPPCompile* c, ValPtr v);
};

class TableConstInfo : public CompoundItemInfo {
public:
    TableConstInfo(CPPCompile* c, ValPtr v);
};

class FileConstInfo : public CompoundItemInfo {
public:
    FileConstInfo(CPPCompile* c, ValPtr v);
};

class FuncConstInfo : public CompoundItemInfo {
public:
    FuncConstInfo(CPPCompile* _c, ValPtr v);

    void InitializerVals(std::vector<std::string>& ivs) const override;

private:
    FuncVal* fv;
};

class TypeConstInfo : public CompoundItemInfo {
public:
    TypeConstInfo(CPPCompile* _c, ValPtr v);
};


class AttrInfo : public CompoundItemInfo {
public:
    AttrInfo(CPPCompile* c, const AttrPtr& attr);
};

class AttrsInfo : public CompoundItemInfo {
public:
    AttrsInfo(CPPCompile* c, const AttributesPtr& attrs);
};




class GlobalLookupInitInfo : public CPP_InitInfo {
public:
    GlobalLookupInitInfo(CPPCompile* c, IDPtr g, std::string CPP_name, bool do_init = false);

    std::string InitializerType() const override { return "CPP_GlobalLookupInit"; }
    void InitializerVals(std::vector<std::string>& ivs) const override;

protected:
    std::string Zeek_name;
    std::string CPP_name;
    std::string val;
};




struct GlobalCharacteristics {
    bool is_exported = false;
    bool is_const = false;
    bool is_option = false;
    bool is_enum_const = false;
    bool is_type = false;
};

class GlobalInitInfo : public GlobalLookupInitInfo {
public:
    GlobalInitInfo(CPPCompile* c, IDPtr g, std::string CPP_name);

    std::string InitializerType() const override { return "CPP_GlobalInit"; }
    void InitializerVals(std::vector<std::string>& ivs) const override;

    IDPtr InitIdentifier() const override { return g; }

protected:
    IDPtr g;
    int type;
    int attrs;
    std::string val;
    GlobalCharacteristics gc;
    bool func_with_no_val = false;
};



class CallExprInitInfo : public CPP_InitInfo {
public:
    CallExprInitInfo(CPPCompile* c, ExprPtr e, std::string e_name, std::string wrapper_class);

    std::string InitializerType() const override { return std::string("CPP_CallExprInit<") + wrapper_class + ">"; }
    void InitializerVals(std::vector<std::string>& ivs) const override { ivs.emplace_back(e_name); }



    const ExprPtr& GetExpr() const { return e; }
    std::string Name() const override { return e_name; }
    const std::string& WrapperClass() const { return wrapper_class; }

protected:
    ExprPtr e;
    std::string e_name;
    std::string wrapper_class;
};


class LambdaRegistrationInfo : public CPP_InitInfo {
public:
    LambdaRegistrationInfo(CPPCompile* c, std::string name, FuncTypePtr ft, std::string wrapper_class, p_hash_type h,
                           bool has_captures);

    std::string InitializerType() const override {
        return std::string("CPP_LambdaRegistration<") + wrapper_class + ">";
    }
    void InitializerVals(std::vector<std::string>& ivs) const override;

protected:
    std::string name;
    int func_type;
    std::string wrapper_class;
    p_hash_type h;
    bool has_captures;
};


class AbstractTypeInfo : public CPP_InitInfo {
public:
    AbstractTypeInfo(CPPCompile* _c, TypePtr _t) : CPP_InitInfo(_t), c(_c), t(std::move(_t)) {}

    void InitializerVals(std::vector<std::string>& ivs) const override {
        ivs.emplace_back(std::to_string(static_cast<int>(t->Tag())));
        AddInitializerVals(ivs);
    }

    virtual void AddInitializerVals(std::vector<std::string>& ivs) const {}

protected:
    CPPCompile* c;
    TypePtr t;
};


class BaseTypeInfo : public AbstractTypeInfo {
public:
    BaseTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) {}
};

class EnumTypeInfo : public AbstractTypeInfo {
public:
    EnumTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) {}

    void AddInitializerVals(std::vector<std::string>& ivs) const override;
};

class OpaqueTypeInfo : public AbstractTypeInfo {
public:
    OpaqueTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) {}

    void AddInitializerVals(std::vector<std::string>& ivs) const override;
};

class TypeTypeInfo : public AbstractTypeInfo {
public:
    TypeTypeInfo(CPPCompile* c, TypePtr _t);

    void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
    TypePtr tt;
};

class VectorTypeInfo : public AbstractTypeInfo {
public:
    VectorTypeInfo(CPPCompile* c, TypePtr _t);

    void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
    TypePtr yield;
};

class ListTypeInfo : public AbstractTypeInfo {
public:
    ListTypeInfo(CPPCompile* c, TypePtr _t);

    void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
    const std::vector<TypePtr>& types;
};

class TableTypeInfo : public AbstractTypeInfo {
public:
    TableTypeInfo(CPPCompile* c, TypePtr _t);

    void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
    int indices;
    TypePtr yield;
};

class FuncTypeInfo : public AbstractTypeInfo {
public:
    FuncTypeInfo(CPPCompile* c, TypePtr _t);

    void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
    FunctionFlavor flavor;
    RecordTypePtr params;
    TypePtr yield;
    bool expressionless_return_okay;
};

class RecordTypeInfo : public AbstractTypeInfo {
public:
    RecordTypeInfo(CPPCompile* c, TypePtr _t, int _addl_fields);

    void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:


    int addl_fields;

    std::vector<std::string> field_names;
    std::vector<TypePtr> field_types;
    std::vector<int> field_attrs;
};


class NamedTypeInfo : public AbstractTypeInfo {
public:
    NamedTypeInfo(CPPCompile* c, TypePtr _t);

    void AddInitializerVals(std::vector<std::string>& ivs) const override;
};













class IndicesManager {
public:
    IndicesManager() = default;



    int AddIndices(std::vector<int> indices) {
        int n = indices_set.size();
        indices_set.emplace_back(std::move(indices));
        return n;
    }



    void Generate(CPPCompile* c);

private:





    std::vector<std::vector<int>> indices_set;
};

}
