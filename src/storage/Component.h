

#pragma once

#include <memory>

#include "zeek/IntrusivePtr.h"
#include "zeek/plugin/Component.h"

namespace zeek::storage {

class Backend;
class Serializer;




class BackendComponent : public plugin::Component {
public:
    using factory_callback = IntrusivePtr<Backend> (*)();













    BackendComponent(const std::string& name, factory_callback factory);






    void Initialize() override;




    factory_callback Factory() const { return factory; }

protected:



    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};




class SerializerComponent : public plugin::Component {
public:
    using factory_callback = std::unique_ptr<Serializer> (*)();













    SerializerComponent(const std::string& name, factory_callback factory);






    void Initialize() override;




    factory_callback Factory() const { return factory; }

protected:



    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};

}
