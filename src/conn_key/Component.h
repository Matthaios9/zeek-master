

#pragma once

#include <functional>
#include <memory>

#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"

namespace zeek::conn_key {

class Factory;
using FactoryPtr = std::unique_ptr<Factory>;

class Component : public plugin::Component {
public:
    using factory_callback = std::function<FactoryPtr()>;

    Component(const std::string& name, factory_callback factory, zeek::Tag::subtype_t subtype = 0);






    void Initialize() override;




    factory_callback Factory() const { return factory; }

protected:



    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};

}
