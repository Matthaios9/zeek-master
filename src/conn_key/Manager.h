

#pragma once

#include "zeek/zeek-config.h"

#include "zeek/Tag.h"
#include "zeek/conn_key/Component.h"
#include "zeek/conn_key/Factory.h"
#include "zeek/plugin/Component.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek {

namespace conn_key {





class Manager : public plugin::ComponentManager<conn_key::Component> {
public:



    Manager();




    ~Manager() = default;




    void InitPostScript();






    Factory& GetFactory() { return *factory; }

private:



    FactoryPtr InstantiateFactory(const EnumValPtr& tag);

    FactoryPtr factory;
};

}

ZEEK_EXTERN_DATA zeek::conn_key::Manager* conn_key_mgr;


}
