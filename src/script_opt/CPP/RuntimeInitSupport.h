



#pragma once

#include "zeek/Val.h"
#include "zeek/script_opt/CPP/Func.h"
#include "zeek/script_opt/CPP/InitsInfo.h"

namespace zeek {

using FuncValPtr = IntrusivePtr<zeek::FuncVal>;

namespace detail {




class CPPTableType : public TableType {
public:
    CPPTableType() : TableType(nullptr, nullptr) {};

    void SetIndexAndYield(TypeListPtr ind, TypePtr yield) {
        indices = std::move(ind);
        yield_type = std::move(yield);
        SetSpecialIndices();
        RegenerateHash();
    }
};



using CPP_init_func = void (*)();


extern std::vector<CPP_init_func> CPP_init_funcs;


extern void register_type__CPP(TypePtr t, const std::string& name);





extern void register_body__CPP(std::string zeek_name, CPPStmtPtr body, int priority, p_hash_type hash,
                               std::vector<std::string> events, void (*finish_init)());


extern void register_standalone_body__CPP(const std::string& zeek_name, CPPStmtPtr body, int priority, p_hash_type hash,
                                          std::vector<std::string> events, const std::string& module_group,
                                          std::vector<std::string> attr_groups, void (*finish_init)());



extern void add_standalone_bodies(Func* f);




extern void register_lambda__CPP(CPPStmtPtr body, p_hash_type hash, const char* name, TypePtr t, bool has_captures);



extern void register_scripts__CPP(p_hash_type h, void (*callback)());





extern void activate_bodies__CPP(const char* fn, const char* module, bool exported, TypePtr t,
                                 const std::vector<p_hash_type>& hashes);



extern IDPtr lookup_global__CPP(const char* g, const TypePtr& t, const GlobalCharacteristics& gc);


extern Func* lookup_bif__CPP(const char* bif);





extern FuncValPtr lookup_func__CPP(std::string name, int num_bodies, const std::vector<p_hash_type>& h,
                                   const TypePtr& t);



extern IDPtr find_global__CPP(const char* g);




extern RecordTypePtr get_record_type__CPP(const char* record_type_name);




extern EnumTypePtr get_enum_type__CPP(const std::string& enum_type_name);



extern EnumValPtr make_enum__CPP(TypePtr t, zeek_int_t i);

}
}
