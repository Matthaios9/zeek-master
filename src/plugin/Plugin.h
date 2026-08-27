

#pragma once

#include <functional>
#include <list>
#include <optional>
#include <string>
#include <utility>

#include "zeek/ZeekArgs.h"
#include "zeek/logging/WriterBackend.h"






#ifndef ZEEK_PLUGIN_SKIP_VERSION_CHECK
#include "zeek/zeek-version.h"
#define ZEEK_PLUGIN_ZEEK_VERSION ZEEK_VERSION_FUNCTION
#endif

namespace zeek::threading {
struct Field;
}

namespace zeek {

#ifdef _MSC_VER
#undef VOID
#endif



constexpr int PLUGIN_API_VERSION = 7;

class ODesc;
class Event;
class Func;
class Obj;
class Packet;

template<class T>
class IntrusivePtr;
using ValPtr = IntrusivePtr<Val>;

namespace threading {
struct Field;
}
namespace detail {
class Frame;
}

namespace cluster {
class Backend;
class Event;
}

namespace plugin {

class Manager;
class Component;
class Plugin;





enum HookType : uint8_t {

    HOOK_LOAD_FILE,
    HOOK_LOAD_FILE_EXT,
    HOOK_CALL_FUNCTION,
    HOOK_QUEUE_EVENT,
    HOOK_DRAIN_EVENTS,
    HOOK_UPDATE_NETWORK_TIME,
    HOOK_SETUP_ANALYZER_TREE,
    HOOK_LOG_INIT,
    HOOK_LOG_WRITE,
    HOOK_REPORTER,
    HOOK_UNPROCESSED_PACKET,
    HOOK_OBJ_DTOR,
    HOOK_PUBLISH_EVENT,


    META_HOOK_PRE,
    META_HOOK_POST,


    NUM_HOOKS,
};




extern const char* hook_name(HookType h);




struct VersionNumber {
    int major = -1;
    int minor = -1;
    int patch = 0;




    explicit operator bool() const { return major >= 0 && minor >= 0 && patch >= 0; }
};




class Configuration {
public:
    std::string name = "";
    std::string description = "";
    VersionNumber version;




    inline Configuration() __attribute__((always_inline)) {





#ifndef ZEEK_PLUGIN_SKIP_VERSION_CHECK
        zeek_version = ZEEK_PLUGIN_ZEEK_VERSION;
#endif
    }

    Configuration(Configuration&& c) noexcept = default;
    Configuration(const Configuration& c) = default;
    Configuration& operator=(Configuration&& c) noexcept = default;
    Configuration& operator=(const Configuration& c) = default;

    ~Configuration() = default;





    std::function<const char*()> zeek_version;

private:
    friend class Plugin;
};




class BifItem final {
public:



    enum Type : uint8_t {
        FUNCTION = 1,
        EVENT = 2,
        CONSTANT = 3,
        GLOBAL = 4,
        TYPE = 5,
    };









    BifItem(const std::string& id, Type type);




    BifItem(const BifItem& other);




    BifItem& operator=(const BifItem& other);




    ~BifItem() = default;




    const std::string& GetID() const { return id; }




    Type GetType() const { return type; }

private:
    std::string id;
    Type type;
};




class HookArgument {
public:



    enum Type : uint8_t {
        BOOL,
        DOUBLE,
        EVENT,
        FRAME,
        FUNC,
        FUNC_RESULT,
        INT,
        STRING,
        VAL,
        VAL_LIST,
        VOID,
        VOIDP,
        WRITER_INFO,
        CONN,
        THREAD_FIELDS,
        LOCATION,
        ARG_LIST,
        INPUT_FILE,
        PACKET,
        CLUSTER_BACKEND,
        CLUSTER_EVENT,
    };




    HookArgument() { type = VOID; }




    explicit HookArgument(bool a) {
        type = BOOL;
        arg.bool_ = a;
    }




    explicit HookArgument(double a) {
        type = DOUBLE;
        arg.double_ = a;
    }




    explicit HookArgument(const Event* a) {
        type = EVENT;
        arg.event = a;
    }




    explicit HookArgument(const Connection* c) {
        type = CONN;
        arg.conn = c;
    }




    explicit HookArgument(const Func* a) {
        type = FUNC;
        arg.func = a;
    }




    explicit HookArgument(int a) {
        type = INT;
        arg.int_ = a;
    }




    explicit HookArgument(const std::string& a) {
        type = STRING;
        arg_string = a;
    }




    explicit HookArgument(const Val* a) {
        type = VAL;
        arg.val = a;
    }




    explicit HookArgument(const ValPList* a) {
        type = VAL_LIST;
        arg.vals = a;
    }




    explicit HookArgument(void* p) {
        type = VOIDP;
        arg.voidp = p;
    }




    explicit HookArgument(std::pair<bool, Val*> fresult) {
        type = FUNC_RESULT;
        func_result = std::move(fresult);
    }




    explicit HookArgument(zeek::detail::Frame* f) {
        type = FRAME;
        arg.frame = f;
    }




    explicit HookArgument(const logging::WriterBackend::WriterInfo* i) {
        type = WRITER_INFO;
        arg.winfo = i;
    }




    explicit HookArgument(const std::pair<int, const threading::Field* const*> fpair) {
        type = THREAD_FIELDS;
        tfields = fpair;
    }




    explicit HookArgument(const zeek::detail::Location* location) {
        type = LOCATION;
        arg.loc = location;
    }




    explicit HookArgument(const Args* args) {
        type = ARG_LIST;
        arg.args = args;
    }




    explicit HookArgument(std::pair<int, std::optional<std::string>> file) {
        type = INPUT_FILE;
        input_file = std::move(file);
    }





    explicit HookArgument(const Packet* packet) {
        type = PACKET;
        arg.packet = packet;
    }




    explicit HookArgument(zeek::cluster::Backend* backend) {
        type = CLUSTER_BACKEND;
        arg.cluster_backend = backend;
    }




    explicit HookArgument(zeek::cluster::Event* event) {
        type = CLUSTER_EVENT;
        arg.cluster_event = event;
    }





    bool AsBool() const {
        assert(type == BOOL);
        return arg.bool_;
    }





    double AsDouble() const {
        assert(type == DOUBLE);
        return arg.double_;
    }





    const Event* AsEvent() const {
        assert(type == EVENT);
        return arg.event;
    }





    const Connection* AsConnection() const {
        assert(type == CONN);
        return arg.conn;
    }





    const Func* AsFunc() const {
        assert(type == FUNC);
        return arg.func;
    }





    double AsInt() const {
        assert(type == INT);
        return arg.int_;
    }





    const std::string& AsString() const {
        assert(type == STRING);
        return arg_string;
    }





    const Val* AsVal() const {
        assert(type == VAL);
        return arg.val;
    }





    std::pair<bool, Val*> AsFuncResult() const {
        assert(type == FUNC_RESULT);
        return func_result;
    }





    const zeek::detail::Frame* AsFrame() const {
        assert(type == FRAME);
        return arg.frame;
    }





    const logging::WriterBackend::WriterInfo* AsWriterInfo() const {
        assert(type == WRITER_INFO);
        return arg.winfo;
    }





    std::pair<int, const threading::Field* const*> AsThreadFields() const {
        assert(type == THREAD_FIELDS);
        return tfields;
    }





    const ValPList* AsValList() const {
        assert(type == VAL_LIST);
        return arg.vals;
    }




    const Args* AsArgList() const {
        assert(type == ARG_LIST);
        return arg.args;
    }





    const void* AsVoidPtr() const {
        assert(type == VOIDP);
        return arg.voidp;
    }





    const Packet* AsPacket() const {
        assert(type == PACKET);
        return arg.packet;
    }




    const zeek::cluster::Backend* AsClusterBackend() const {
        assert(type == CLUSTER_EVENT);
        return arg.cluster_backend;
    }




    const zeek::cluster::Event* AsClusterEvent() const {
        assert(type == CLUSTER_EVENT);
        return arg.cluster_event;
    }




    Type GetType() const { return type; }






    void Describe(ODesc* d) const;

private:
    Type type;
    union {
        bool bool_;
        double double_;
        const Event* event;
        const Connection* conn;
        const Func* func;
        const zeek::detail::Frame* frame;
        int int_;
        const Val* val;
        const ValPList* vals;
        const Args* args;
        const void* voidp;
        const logging::WriterBackend::WriterInfo* winfo;
        const zeek::detail::Location* loc;
        const Packet* packet;
        const cluster::Backend* cluster_backend;
        const cluster::Event* cluster_event;
    } arg;


    std::pair<bool, Val*> func_result;
    std::pair<int, const threading::Field* const*> tfields;
    std::string arg_string;
    std::pair<int, std::optional<std::string>> input_file;
};

using HookArgumentList = std::list<HookArgument>;




























class Plugin {
public:
    using component_list = std::list<Component*>;
    using bif_item_list = std::list<BifItem>;
    using hook_list = std::list<std::pair<HookType, int>>;




    enum LoadType : uint8_t { SCRIPT, SIGNATURES, PLUGIN };




    Plugin();




    virtual ~Plugin();




    const std::string& Name() const;




    const std::string& Description() const;






    VersionNumber Version() const;




    bool DynamicPlugin() const;





    const std::string& PluginDirectory() const;






    const std::string& PluginPath() const;




    component_list Components() const;





    bif_item_list BifItems() const;








    void Describe(ODesc* d) const;



















    void AddBifItem(const std::string& name, BifItem::Type type);

















    bool LoadZeekFile(const std::string& file);

protected:
    friend class Manager;







    virtual void InitPreScript();







    virtual void InitPostScript();







    virtual void InitPreExecution();






    virtual void Done();






    void AddComponent(Component* c);




    void InitializeComponents();




















    void EnableHook(HookType hook, int priority = 0);







    void DisableHook(HookType hook);





    hook_list EnabledHooks() const;










    void RequestEvent(EventHandlerPtr handler);










    void RequestObjDtor(Obj* obj);



























    virtual int HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved);



































    virtual std::pair<int, std::optional<std::string>> HookLoadFileExtended(const LoadType type,
                                                                            const std::string& file,
                                                                            const std::string& resolved);























    virtual std::pair<bool, ValPtr> HookFunctionCall(const Func* func, zeek::detail::Frame* parent, Args* args);



















    virtual bool HookQueueEvent(Event* event);





    virtual void HookDrainEvents();







    virtual void HookUpdateNetworkTime(double network_time);








    virtual void HookSetupAnalyzerTree(Connection* conn);











    virtual void HookObjDtor(void* obj);


























    virtual void HookLogInit(const std::string& writer, const std::string& instantiating_filter, bool local,
                             bool remote, const logging::WriterBackend::WriterInfo& info, int num_fields,
                             const threading::Field* const* fields);



























    virtual bool HookLogWrite(const std::string& writer, const std::string& filter,
                              const logging::WriterBackend::WriterInfo& info, int num_fields,
                              const threading::Field* const* fields, threading::Value** vals);





























    virtual bool HookReporter(const std::string& prefix, const EventHandlerPtr event, const Connection* conn,
                              const ValPList* addl, bool location, const zeek::detail::Location* location1,
                              const zeek::detail::Location* location2, bool time, const std::string& message);








    virtual void HookUnprocessedPacket(const Packet* packet);




















    virtual bool HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic,
                                  zeek::cluster::Event& event);


    virtual void MetaHookPre(HookType hook, const HookArgumentList& args);
    virtual void MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result);

private:









    virtual Configuration Configure() = 0;





    void DoConfigure();













    void SetPluginLocation(const std::string& dir, const std::string& sopath);








    void SetDynamic(bool is_dynamic);

    Configuration config;

    std::string base_dir;
    std::string sopath;
    bool dynamic;

    component_list components;
    bif_item_list bif_items;
};

}
}
