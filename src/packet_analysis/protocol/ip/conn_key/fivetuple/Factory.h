
#pragma once

#include "zeek/ConnKey.h"
#include "zeek/conn_key/Factory.h"

namespace zeek::conn_key::fivetuple {

class Factory : public zeek::conn_key::Factory {
public:
    static zeek::conn_key::FactoryPtr Instantiate() { return std::make_unique<Factory>(); }

protected:





    zeek::ConnKeyPtr DoNewConnKey() const override;










    zeek::expected<zeek::ConnKeyPtr, std::string> DoConnKeyFromVal(const zeek::Val& v) const override;
};

}
