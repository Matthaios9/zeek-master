

#pragma once

#include "zeek/zeek-config.h"

#include <map>
#include <set>
#include <string_view>
#include <utility>

#include "zeek/Reporter.h"
#include "zeek/ZeekArgs.h"
#include "zeek/plugin/Plugin.h"
#include "zeek/util-types.h"

namespace zeek {

namespace cluster {
class Backend;

namespace detail {
class Event;
}
}

namespace plugin {












#define PLUGIN_HOOK_VOID(hook, method_call)                                                                            \
    {                                                                                                                  \
        if ( zeek::plugin_mgr->HavePluginForHook(zeek::plugin::hook) )                                                 \
            zeek::plugin_mgr->method_call;                                                                             \
    }












#define PLUGIN_HOOK_WITH_RESULT(hook, method_call, default_result)                                                     \
    (zeek::plugin_mgr->HavePluginForHook(zeek::plugin::hook) ? zeek::plugin_mgr->method_call : (default_result))




class Manager {
public:
    using bif_init_func = void (*)(Plugin*);
    using plugin_list = std::list<Plugin*>;
    using component_list = Plugin::component_list;
    using inactive_plugin_list = std::list<std::pair<std::string, std::string>>;




    Manager();




    virtual ~Manager();












    void SearchDynamicPlugins(const std::string& dir);





















    zeek::expected<Plugin*, std::string> LoadDynamicPlugin(const std::string& path);













    void ActivateDynamicPlugin(const std::string& name);










    void ActivateDynamicPlugins(bool all);






    void InitPreScript();





    void InitBifs();






    void InitPostScript();






    void InitPreExecution();





    void FinishPlugins();






    plugin_list ActivePlugins() const;







    inactive_plugin_list InactivePlugins() const;






    template<class T>
    std::list<T*> Components() const;






    Plugin* LookupPluginByPath(std::string_view path);









    bool HavePluginForHook(HookType hook) const {

        return hooks[hook] != nullptr;
    }







    std::list<std::pair<HookType, int>> HooksEnabledForPlugin(const Plugin* plugin) const;










    void EnableHook(HookType hook, Plugin* plugin, int prio);








    void DisableHook(HookType hook, Plugin* plugin);













    void RequestEvent(EventHandlerPtr handler, Plugin* plugin);










    void RequestObjDtor(Obj* obj, Plugin* plugin);















    virtual int HookLoadFile(const Plugin::LoadType type, const std::string& file, const std::string& resolved);























    virtual std::pair<int, std::optional<std::string>> HookLoadFileExtended(const Plugin::LoadType type,
                                                                            const std::string& file,
                                                                            const std::string& resolved);
















    std::pair<bool, ValPtr> HookCallFunction(const Func* func, zeek::detail::Frame* parent, Args* args) const;









    bool HookQueueEvent(Event* event) const;






    void HookUpdateNetworkTime(double network_time) const;








    void HookSetupAnalyzerTree(Connection* conn) const;




    void HookDrainEvents() const;





    void HookObjDtor(void* obj) const;


























    void HookLogInit(const std::string& writer, const std::string& instantiating_filter, bool local, bool remote,
                     const logging::WriterBackend::WriterInfo& info, int num_fields,
                     const threading::Field* const* fields) const;



























    bool HookLogWrite(const std::string& writer, const std::string& filter,
                      const logging::WriterBackend::WriterInfo& info, int num_fields,
                      const threading::Field* const* fields, threading::Value** vals) const;





























    bool HookReporter(const std::string& prefix, const EventHandlerPtr event, const Connection* conn,
                      const ValPList* addl, bool location, const zeek::detail::Location* location1,
                      const zeek::detail::Location* location2, bool time, const std::string& message);








    void HookUnprocessedPacket(const Packet* packet) const;




















    bool HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic, zeek::cluster::Event& event) const;









    static void RegisterPlugin(Plugin* plugin);









    static void RegisterBifFile(const char* plugin, bif_init_func c);





    void ExtendZeekPathForPlugins();

private:
    bool ActivateDynamicPluginInternal(const std::string& name, bool ok_if_not_found, std::vector<std::string>* errors);
    void UpdateInputFiles();
    void MetaHookPre(HookType hook, const HookArgumentList& args) const;
    void MetaHookPost(HookType hook, const HookArgumentList& args, const HookArgument& result) const;





    std::set<std::string, std::less<>> searched_dirs;



    std::set<std::string> requested_plugins;


    using dynamic_plugin_map = std::map<std::string, std::string>;
    dynamic_plugin_map dynamic_plugins;



    using file_list = std::list<std::string>;
    file_list scripts_to_load;

    bool init;



    using hook_list = std::list<std::pair<int, Plugin*>>;



    hook_list** hooks;


    std::map<std::string, Plugin*> plugins_by_path;


    static Plugin* current_plugin;
    static const char* current_dir;
    static const char* current_sopath;




    static plugin_list* ActivePluginsInternal();

    using bif_init_func_list = std::list<bif_init_func>;
    using bif_init_func_map = std::map<std::string, bif_init_func_list*>;




    static bif_init_func_map* BifFilesInternal();
};

template<class T>
std::list<T*> Manager::Components() const {
    std::list<T*> result;

    for ( plugin_list::const_iterator p = ActivePluginsInternal()->begin(); p != ActivePluginsInternal()->end(); p++ ) {
        component_list components = (*p)->Components();

        for ( component_list::const_iterator c = components.begin(); c != components.end(); c++ ) {
            T* t = dynamic_cast<T*>(*c);

            if ( t )
                result.push_back(t);
        }
    }

    return result;
}

namespace detail {




class __RegisterBif {
public:
    __RegisterBif(const char* plugin, Manager::bif_init_func init) { Manager::RegisterBifFile(plugin, init); }
};

}
}

ZEEK_EXTERN_DATA plugin::Manager* plugin_mgr;

}
