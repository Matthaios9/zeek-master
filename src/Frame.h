

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"
#include "zeek/Type.h"
#include "zeek/ZeekArgs.h"

namespace zeek {

using ValPtr = IntrusivePtr<Val>;

class BrokerListView;
class BrokerData;
class Func;

namespace detail {

class CallExpr;
using IDPtr = IntrusivePtr<ID>;

namespace trigger {

class Trigger;
using TriggerPtr = IntrusivePtr<Trigger>;

}

class Frame;
using FramePtr = IntrusivePtr<Frame>;

class Frame : public Obj {
public:








    Frame(int size, const Func* func, const zeek::Args* fn_args);






    int FrameSize() const { return size; }





    const ValPtr& GetElement(int n) const {



        return frame[n];
    }






    void SetElement(int n, ValPtr v);








    void SetElement(const ID* id, ValPtr v);
    void SetElement(const IDPtr& id, ValPtr v) { SetElement(id.get(), std::move(v)); }








    const ValPtr& GetElementByID(const IDPtr& id) const { return GetElementByID(id.get()); }








    void AdjustOffset(int incr) { current_offset += incr; }






    void Reset(int startIdx);




    void Describe(ODesc* d) const override;




    const Func* GetFunction() const { return function; }





    const Args* GetFuncArgs() const { return func_args; }






    void SetFunction(Func* func) { function = func; }






    void SetNextStmt(Stmt* stmt) { next_stmt = stmt; }




    Stmt* GetNextStmt() const { return next_stmt; }


    void BreakBeforeNextStmt(bool should_break) { break_before_next_stmt = should_break; }
    bool BreakBeforeNextStmt() const { return break_before_next_stmt; }


    void BreakOnReturn(bool should_break) { break_on_return = should_break; }
    bool BreakOnReturn() const { return break_on_return; }






    Frame* Clone() const;






    Frame* CloneForTrigger() const;






    std::optional<BrokerData> Serialize();








    static std::pair<bool, FramePtr> Unserialize(BrokerListView data);



    void SetTrigger(trigger::TriggerPtr arg_trigger);
    void ClearTrigger();
    trigger::Trigger* GetTrigger() const { return trigger.get(); }

    void SetCall(const CallExpr* arg_call) {
        call = arg_call;
        SetTriggerAssoc(call);
    }
    void SetOnlyCall(const CallExpr* arg_call) { call = arg_call; }
    const CallExpr* GetCall() const { return call; }

    void SetTriggerAssoc(const void* arg_assoc) { assoc = arg_assoc; }
    const void* GetTriggerAssoc() const { return assoc; }

    const detail::Location* GetCallLocation() const;

    void SetDelayed() { delayed = true; }
    bool HasDelayed() const { return delayed; }

private:
    using OffsetMap = std::unordered_map<std::string, int>;




    using Element = ValPtr;

    const ValPtr& GetElementByID(const ID* id) const;


    int size;

    bool break_before_next_stmt = false;
    bool break_on_return = false;
    bool delayed = false;


    std::unique_ptr<Element[]> frame;






    int current_offset = 0;


    Frame* captures = nullptr;




    const OffsetMap* captures_offset_map = nullptr;


    const Func* function = nullptr;



    const zeek::Args* func_args = nullptr;


    Stmt* next_stmt = nullptr;

    trigger::TriggerPtr trigger;
    const CallExpr* call = nullptr;
    const void* assoc = nullptr;
};

}
}
