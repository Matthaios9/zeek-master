
#pragma once

#include "zeek/ConnKey.h"
#include "zeek/util-types.h"

namespace zeek {

class Packet;
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace conn_key {

class Factory;
using FactoryPtr = std::unique_ptr<Factory>;




class Factory {
public:
    virtual ~Factory() = default;






    zeek::ConnKeyPtr NewConnKey() const { return DoNewConnKey(); }










    zeek::expected<zeek::ConnKeyPtr, std::string> ConnKeyFromVal(const zeek::Val& v) const {
        return DoConnKeyFromVal(v);
    }

protected:





    virtual zeek::ConnKeyPtr DoNewConnKey() const = 0;






    virtual zeek::expected<zeek::ConnKeyPtr, std::string> DoConnKeyFromVal(const zeek::Val& v) const = 0;
};

}
}
