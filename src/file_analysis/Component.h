

#pragma once

#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"

namespace zeek {

class RecordVal;
using RecordValPtr = zeek::IntrusivePtr<RecordVal>;

namespace file_analysis {

class File;
class Analyzer;
class Manager;







class Component : public plugin::Component {
public:
    using factory_function = Analyzer* (*)(RecordValPtr args, File* file);
























    Component(const std::string& name, factory_function factory, zeek::Tag::subtype_t subtype = 0, bool enabled = true);






    void Initialize() override;




    factory_function FactoryFunction() const { return factory_func; }

protected:



    void DoDescribe(ODesc* d) const override;

private:
    friend class Manager;

    factory_function factory_func;
};

}
}
