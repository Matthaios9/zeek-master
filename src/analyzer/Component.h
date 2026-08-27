

#pragma once

#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"

namespace zeek {

class Connection;

namespace analyzer {

class Analyzer;







class Component : public plugin::Component {
public:
    using factory_callback = Analyzer* (*)(Connection * conn);

































    Component(const std::string& name, factory_callback factory, zeek::Tag::subtype_t subtype = 0, bool enabled = true,
              bool partial = false, bool adapter = false);






    void Initialize() override;




    factory_callback Factory() const { return factory; }






    bool Partial() const { return partial; }

protected:



    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
    bool partial;
};

}
}
