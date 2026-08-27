

#pragma once

#include "zeek/zeek-config.h"

#include <forward_list>
#include <memory>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "zeek/Obj.h"
#include "zeek/Scope.h"
#include "zeek/StmtBase.h"
#include "zeek/StmtEnums.h"
#include "zeek/TraverseTypes.h"
#include "zeek/Type.h"





#include "zeek/Val.h"
#include "zeek/ZeekArgs.h"
#include "zeek/ZeekList.h"

namespace zeek {

class Val;
class FuncType;
class BrokerData;
class BrokerListView;

namespace detail {

class Scope;
class Stmt;
class CallExpr;
class ID;
class Frame;
using ScopePtr = IntrusivePtr<Scope>;
using IDPtr = IntrusivePtr<ID>;
using StmtPtr = IntrusivePtr<Stmt>;

class ScriptFunc;
class FunctionIngredients;

extern uint64_t max_recursion_depth;

}

class EventGroup;
using EventGroupPtr = std::shared_ptr<EventGroup>;

class Func;
using FuncPtr = IntrusivePtr<Func>;

class Func : public Obj {
public:
    static inline const FuncPtr nil;

    enum Kind : uint8_t { SCRIPT_FUNC, BUILTIN_FUNC };

    explicit Func(Kind arg_kind) : kind(arg_kind) {}

    virtual bool IsPure() const = 0;
    FunctionFlavor Flavor() const { return GetType()->Flavor(); }

    struct Body {
        detail::StmtPtr stmts;
        std::forward_list<EventGroupPtr> groups;
        int priority = 0;


        bool disabled = false;
    };

    const std::vector<Body>& GetBodies() const { return bodies; }
    bool HasBodies() const { return ! bodies.empty(); }






    bool HasEnabledBodies() const { return ! bodies.empty() && has_enabled_bodies; };






    bool HasAllBodiesEnabled() const { return all_bodies_enabled; };







    virtual ValPtr Invoke(zeek::Args* args, detail::Frame* parent = nullptr) const = 0;




    template<class... Args>
        requires std::is_convertible_v<std::tuple_element_t<0, std::tuple<Args...>>, ValPtr>
    ValPtr Invoke(Args&&... args) const {
        auto zargs = zeek::Args{std::forward<Args>(args)...};
        return Invoke(&zargs);
    }




    void AddBody(const detail::FunctionIngredients& ingr, detail::StmtPtr new_body = nullptr);


    void AddBody(std::function<void(const zeek::Args&, detail::StmtFlowType&)> body, int priority = 0);



    virtual void AddBody(Func::Body&& new_body, const std::vector<detail::IDPtr>& new_inits, size_t new_frame_size);


    [[deprecated("Remove in v9.1. Use AddBody(Func::Body...) interface instead.")]]
    virtual void AddBody(detail::StmtPtr new_body, const std::vector<detail::IDPtr>& new_inits, size_t new_frame_size,
                         int priority, const std::set<EventGroupPtr>& groups);
    [[deprecated("Remove in v9.1. Use AddBody(Func::Body...) interface instead.")]]
    void AddBody(detail::StmtPtr new_body, const std::vector<detail::IDPtr>& new_inits, size_t new_frame_size,
                 int priority = 0);
    [[deprecated("Remove in v9.1. Use AddBody(Func::Body...) interface instead.")]]
    void AddBody(detail::StmtPtr new_body, size_t new_frame_size);

    virtual void SetScope(detail::ScopePtr newscope);
    virtual detail::ScopePtr GetScope() const { return scope; }

    const FuncTypePtr& GetType() const { return type; }

    Kind GetKind() const { return kind; }

    const std::string& GetName() const { return name; }
    void SetName(const std::string& arg_name) { name = arg_name; }

    void Describe(ODesc* d) const override = 0;
    virtual void DescribeDebug(ODesc* d, const zeek::Args* args) const;

    virtual FuncPtr DoClone();

    virtual detail::TraversalCode Traverse(detail::TraversalCallback* cb) const;

protected:
    Func() = default;


    void CopyStateInto(Func* other) const;


    void CheckPluginResult(bool handled, const ValPtr& hook_result, FunctionFlavor flavor) const;

    std::vector<Body> bodies;
    detail::ScopePtr scope;
    Kind kind = SCRIPT_FUNC;
    FuncTypePtr type;
    std::string name;

private:



    friend class EventGroup;
    bool has_enabled_bodies = true;
    bool all_bodies_enabled = true;
};

namespace detail {

class ScriptFunc : public Func {
public:
    ScriptFunc(const IDPtr& id);


    ScriptFunc(std::string name, FuncTypePtr ft, std::vector<Func::Body> bodies);

    ~ScriptFunc() override;

    bool IsPure() const override;
    ValPtr Invoke(zeek::Args* args, Frame* parent) const override;









    void CreateCaptures(Frame* f);










    void CreateCaptures(std::unique_ptr<std::vector<ZVal>> cvec);







    Frame* GetCapturesFrame() const { return captures_frame; }







    auto& GetCapturesVec() const {
        ASSERT(captures_vec);
        return *captures_vec;
    }








    void SetCapturesVec(std::unique_ptr<std::vector<ZVal>> cv);


    using OffsetMap = std::unordered_map<std::string, int>;






    const OffsetMap* GetCapturesOffsetMap() const { return captures_offset_mapping; }






    virtual std::optional<BrokerData> SerializeCaptures() const;






    bool DeserializeCaptures(BrokerListView data);

    using Func::AddBody;

    void AddBody(Func::Body&& new_body, const std::vector<detail::IDPtr>& new_inits, size_t new_frame_size) override;


    void AddBody(detail::StmtPtr new_body, const std::vector<detail::IDPtr>& new_inits, size_t new_frame_size,
                 int priority, const std::set<EventGroupPtr>& groups) override;









    void ReplaceBody(const detail::StmtPtr& old_body, detail::StmtPtr new_body);

    const Body& CurrentBody() const { return current_body; }





    int FrameSize() const { return frame_size; }







    void SetFrameSize(int new_size) { frame_size = new_size; }


    const IDPList& GetOuterIDs() const { return outer_ids; }


    void SetOuterIDs(IDPList ids) { outer_ids = std::move(ids); }

    void Describe(ODesc* d) const override;

protected:
    ScriptFunc() : Func(SCRIPT_FUNC) {}

    StmtPtr AddInits(StmtPtr body, const std::vector<IDPtr>& inits);




    FuncPtr DoClone() override;








    virtual void SetCaptures(Frame* f);


    std::unique_ptr<std::vector<ZVal>> captures_vec;

private:
    size_t frame_size = 0;


    IDPList outer_ids;




    Frame* captures_frame = nullptr;

    OffsetMap* captures_offset_mapping = nullptr;


    Body current_body;
};

using built_in_func = ValPtr (*)(Frame* frame, const Args* args);

class BuiltinFunc final : public Func {
public:
    BuiltinFunc(built_in_func func, const char* name, bool is_pure);

    bool IsPure() const override;
    ValPtr Invoke(zeek::Args* args, Frame* parent) const override;
    built_in_func TheFunc() const { return func; }

    void Describe(ODesc* d) const override;

protected:
    BuiltinFunc() = default;
    built_in_func func = nullptr;
    bool is_pure = false;
};

extern bool check_built_in_call(BuiltinFunc* f, CallExpr* call);

struct CallInfo {
    const CallExpr* call = nullptr;
    Frame* frame = nullptr;
};


class FunctionIngredients {
public:


    FunctionIngredients(ScopePtr scope, StmtPtr body, const std::string& module_name);

    const IDPtr& GetID() const { return id; }

    const StmtPtr& Body() const { return body; }
    void ReplaceBody(StmtPtr new_body) { body = std::move(new_body); }

    const auto& Inits() const { return inits; }
    void ClearInits() { inits.clear(); }

    size_t FrameSize() const { return frame_size; }
    int Priority() const { return priority; }
    const ScopePtr& Scope() const { return scope; }
    const auto& Groups() const { return groups; }



    void SetFrameSize(size_t _frame_size) { frame_size = _frame_size; }

private:
    IDPtr id;
    StmtPtr body;
    std::vector<IDPtr> inits;
    size_t frame_size = 0;
    int priority = 0;
    ScopePtr scope;
    std::set<EventGroupPtr> groups;
};

using FunctionIngredientsPtr = std::shared_ptr<FunctionIngredients>;

ZEEK_EXTERN_DATA std::vector<CallInfo> call_stack;










zeek::RecordValPtr make_backtrace_element(std::string_view name, const VectorValPtr args,
                                          const zeek::detail::Location* loc);






zeek::VectorValPtr get_current_script_backtrace();


ZEEK_EXTERN_DATA bool did_builtin_init;
ZEEK_EXTERN_DATA std::vector<void (*)()> bif_initializers;
extern void init_primary_bifs();

inline void run_bif_initializers() {
    for ( const auto& bi : bif_initializers )
        bi();

    bif_initializers = {};
}

extern void emit_builtin_exception(const char* msg);
extern void emit_builtin_exception(const char* msg, const ValPtr& arg);
extern void emit_builtin_exception(const char* msg, Obj* arg);

}

extern std::string render_call_stack();


extern void emit_builtin_error(const char* msg);
extern void emit_builtin_error(const char* msg, const ValPtr&);
extern void emit_builtin_error(const char* msg, Obj* arg);

}
