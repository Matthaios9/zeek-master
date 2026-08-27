

#pragma once

#include <functional>
#include <memory>

#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"

namespace zeek::packet_analysis {

class Analyzer;
using AnalyzerPtr = std::shared_ptr<Analyzer>;

class Component : public plugin::Component {
public:
    using factory_callback = std::function<AnalyzerPtr()>;

    Component(const std::string& name, factory_callback factory, zeek::Tag::subtype_t subtype = 0);






    void Initialize() override;




    factory_callback Factory() const { return factory; }

    void SetEnabled(bool arg_enabled) override;

protected:



    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};

}
