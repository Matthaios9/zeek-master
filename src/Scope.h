

#pragma once

#include "zeek/zeek-config.h"

#include <map>
#include <string>
#include <string_view>
#include <utility>

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"
#include "zeek/TraverseTypes.h"
#include "zeek/ZeekList.h"

namespace zeek {

class Type;
template<class T>
class IntrusivePtr;
using TypePtr = IntrusivePtr<Type>;

namespace detail {

class Attr;
class ID;
using AttrPtr = IntrusivePtr<Attr>;
using IDPtr = IntrusivePtr<ID>;

class Scope;
using ScopePtr = IntrusivePtr<Scope>;

class Scope : public Obj {
public:
    explicit Scope(IDPtr id, std::unique_ptr<std::vector<AttrPtr>> al);

    const IDPtr& Find(std::string_view name) const;

    template<typename N, typename I>
    void Insert(N&& name, I&& id) {
        local[std::forward<N>(name)] = id;
        ordered_vars.push_back(std::forward<I>(id));
    }

    const IDPtr& GetID() const { return scope_id; }

    const std::unique_ptr<std::vector<AttrPtr>>& Attrs() const { return attrs; }

    const TypePtr& GetReturnType() const { return return_type; }

    size_t Length() const { return local.size(); }
    const auto& Vars() const { return local; }
    const auto& OrderedVars() const { return ordered_vars; }

    IDPtr GenerateTemporary(const char* name);



    std::vector<IDPtr> GetInits();


    void AddInit(IDPtr id) { inits.emplace_back(std::move(id)); }

    void Describe(ODesc* d) const override;

    TraversalCode Traverse(TraversalCallback* cb) const;

protected:
    IDPtr scope_id;
    std::unique_ptr<std::vector<AttrPtr>> attrs;
    TypePtr return_type;
    std::map<std::string, IDPtr, std::less<>> local;
    std::vector<IDPtr> inits;






    std::vector<IntrusivePtr<ID>> ordered_vars;
};


extern const IDPtr& lookup_ID(const char* name, const char* module, bool no_global = false,
                              bool same_module_only = false, bool check_export = true);

extern IDPtr install_ID(const char* name, const char* module_name, bool is_global, bool is_export);

extern void push_scope(IDPtr id, std::unique_ptr<std::vector<AttrPtr>> attrs);
extern void push_existing_scope(ScopePtr scope);


extern ScopePtr pop_scope();

extern ScopePtr current_scope();
extern ScopePtr global_scope();


ZEEK_EXTERN_DATA std::string current_module;

}
}

extern bool in_debug;
