



#pragma once

#include "zeek/zeek-config.h"

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/ZeekArgs.h"

namespace zeek {


enum class EventGroupKind : uint8_t {
    Attribute,
    Module,
};

class EnumVal;
class EventGroup;
class EventHandler;
class EventHandlerPtr;
class RE_Matcher;
class RecordVal;
class Type;

using EnumValPtr = IntrusivePtr<EnumVal>;
using EventGroupPtr = std::shared_ptr<EventGroup>;
using RecordValPtr = IntrusivePtr<RecordVal>;
using TypePtr = IntrusivePtr<Type>;

namespace detail {
class ScriptFunc;
using ScriptFuncPtr = zeek::IntrusivePtr<ScriptFunc>;




enum class MetadataType : uint8_t {
    NetworkTimestamp = 1,
};

}









class EventMetadataDescriptor {
public:
    EventMetadataDescriptor(zeek_uint_t id, EnumValPtr id_val, TypePtr type)
        : id(id), id_val(std::move(id_val)), type(std::move(type)) {}

    zeek_uint_t Id() const { return id; }
    const EnumValPtr& IdVal() const { return id_val; }
    const TypePtr& Type() const { return type; }

private:
    zeek_uint_t id;
    EnumValPtr id_val;
    TypePtr type;
};


class EventRegistry final {
public:
    EventRegistry();
    ~EventRegistry() noexcept;








    EventHandlerPtr Register(std::string_view name, bool is_from_script = false);

    void Register(EventHandlerPtr handler, bool is_from_script = false);


    EventHandler* Lookup(std::string_view name);




    bool NotOnlyRegisteredFromScript(std::string_view name);



    using string_list = std::vector<std::string>;
    string_list Match(RE_Matcher* pattern);




    void SetErrorHandler(std::string_view name);

    string_list AllHandlers();

    void PrintDebug();










    void ActivateAllHandlers();






    EventGroupPtr RegisterGroup(EventGroupKind kind, std::string_view name);






    EventGroupPtr LookupGroup(EventGroupKind kind, std::string_view name);







    bool RegisterMetadata(EnumValPtr id, TypePtr type);







    const EventMetadataDescriptor* LookupMetadata(zeek_uint_t id) const;


private:
    std::map<std::string, std::unique_ptr<EventHandler>, std::less<>> handlers;


    std::unordered_set<std::string> not_only_from_script;


    std::map<std::pair<EventGroupKind, std::string>, std::shared_ptr<EventGroup>, std::less<>> event_groups;


    std::unordered_map<zeek_uint_t, EventMetadataDescriptor> event_metadata_types;
};






















class EventGroup final {
public:
    EventGroup(EventGroupKind kind, std::string_view name);
    ~EventGroup() noexcept = default;
    EventGroup(const EventGroup& g) = delete;
    EventGroup& operator=(const EventGroup&) = delete;




    void Enable();




    void Disable();




    bool IsDisabled() { return ! enabled; }






    void AddFunc(detail::ScriptFuncPtr f);




    const auto& GetName() const { return name; }




    const auto& GetEventGroupKind() const { return kind; }

private:
    void UpdateFuncBodies();

    EventGroupKind kind;
    bool enabled = true;
    std::string name;
    std::unordered_set<detail::ScriptFuncPtr> funcs;
};

ZEEK_EXTERN_DATA EventRegistry* event_registry;

}
