

#pragma once

#include "zeek/plugin/Component.h"

namespace zeek::logging {

class WriterFrontend;
class WriterBackend;




class Component : public plugin::Component {
public:
    using factory_callback = WriterBackend* (*)(WriterFrontend * frontend);













    Component(const std::string& name, factory_callback factory);






    void Initialize() override;




    factory_callback Factory() const { return factory; }

protected:



    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};

}
