



#pragma once

#include "zeek/zeek-config.h"

#include <string>
#include <unordered_set>

#include "zeek/RunState.h"
#include "zeek/Type.h"
#include "zeek/ZeekArgs.h"

namespace zeek {

namespace telemetry {
class Counter;
}

class Func;
using FuncPtr = IntrusivePtr<Func>;

class EventHandler {
public:
    explicit EventHandler(std::string name);

    const char* Name() const { return name.data(); }

    const FuncPtr& GetFunc() const { return local; }

    const FuncTypePtr& GetType(bool check_export = true);

    void SetFunc(FuncPtr f);


    void Call(zeek::Args* vl);


    explicit operator bool() const;



    void SetErrorHandler() { error_handler = true; }
    bool ErrorHandler() const { return error_handler; }

    void SetEnable(bool arg_enable) { enabled = arg_enable; }



    void SetGenerateAlways(bool arg_generate_always = true) { generate_always = arg_generate_always; }
    bool GenerateAlways() const { return generate_always; }


    uint64_t CallCount() const;

private:
    void NewEvent(zeek::Args* vl);

    std::string name;
    FuncPtr local;
    FuncTypePtr type;
    bool used;
    bool enabled;
    bool error_handler;
    bool generate_always;


    std::shared_ptr<zeek::telemetry::Counter> call_count;
};


class EventHandlerPtr {
public:
    EventHandlerPtr(EventHandler* p = nullptr) { handler = p; }
    EventHandlerPtr(const EventHandlerPtr& h) { handler = h.handler; }

    const EventHandlerPtr& operator=(EventHandler* p) {
        handler = p;
        return *this;
    }
    const EventHandlerPtr& operator=(const EventHandlerPtr& h) {
        if ( this == &h )
            return *this;
        handler = h.handler;
        return *this;
    }

    bool operator==(const EventHandlerPtr& h) const { return handler == h.handler; }

    bool operator!=(const EventHandlerPtr& h) const { return ! (*this == h); }

    EventHandler* Ptr() { return handler; }

    explicit operator bool() const { return handler && *handler; }
    EventHandler* operator->() { return handler; }
    const EventHandler* operator->() const { return handler; }

private:
    EventHandler* handler;
};

}
