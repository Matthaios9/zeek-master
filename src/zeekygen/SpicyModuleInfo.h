

#pragma once

#include <ctime>
#include <list>
#include <string>

#include "zeek/plugin/Plugin.h"
#include "zeek/zeekygen/Info.h"

namespace zeek::zeekygen::detail {




class SpicyModuleInfo : public Info {
public:





    explicit SpicyModuleInfo(std::string name, std::string description)
        : name(std::move(name)), description(std::move(description)) {}


    const auto& Description() const { return description; }




    const auto& Components() const { return components; }




    const auto& BifItems() const { return bif_items; }


    void AddComponent(plugin::Component* c) { components.push_back(c); }


    void AddBifItem(const std::string& id, plugin::BifItem::Type type) { bif_items.emplace_back(id, type); }

private:
    time_t DoGetModificationTime() const override { return time(nullptr); }
    std::string DoName() const override { return name; }
    std::string DoReStructuredText(bool roles_only) const override { return ""; }

    std::string name;
    std::string description;

    std::list<plugin::Component*> components;
    std::list<plugin::BifItem> bif_items;
};

}
