

#pragma once

#include <memory>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/plugin/Component.h"

namespace zeek::cluster {

class BackendComponent : public plugin::Component {
public:
    using factory_callback = std::unique_ptr<Backend> (*)(std::unique_ptr<EventSerializer>,
                                                          std::unique_ptr<LogSerializer>,
                                                          std::unique_ptr<detail::EventHandlingStrategy>);










    BackendComponent(const std::string& name, factory_callback factory);






    void Initialize() override;




    factory_callback Factory() const { return factory; }

protected:
    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};


class EventSerializerComponent : public plugin::Component {
public:
    using factory_callback = std::unique_ptr<EventSerializer> (*)();










    EventSerializerComponent(const std::string& name, factory_callback factory);






    void Initialize() override;




    factory_callback Factory() const { return factory; }

protected:
    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};

class LogSerializerComponent : public plugin::Component {
public:
    using factory_callback = std::unique_ptr<LogSerializer> (*)();










    LogSerializerComponent(const std::string& name, factory_callback factory);






    void Initialize() override;




    factory_callback Factory() const { return factory; }

protected:
    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};
}
