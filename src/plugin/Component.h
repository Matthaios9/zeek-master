

#pragma once

#include <string>

#include "zeek/IntrusivePtr.h"
#include "zeek/Tag.h"

namespace zeek {

class ODesc;
class EnumType;
using EnumTypePtr = IntrusivePtr<EnumType>;
class EnumVal;
using EnumValPtr = IntrusivePtr<EnumVal>;
class StringVal;
using StringValPtr = IntrusivePtr<StringVal>;

namespace plugin {
namespace component {




enum Type : uint8_t {
    READER,
    WRITER,
    ANALYZER,
    PACKET_ANALYZER,
    FILE_ANALYZER,
    IOSOURCE,
    PKTSRC,
    PKTDUMPER,
    SESSION_ADAPTER,
    CLUSTER_BACKEND,
    EVENT_SERIALIZER,
    LOG_SERIALIZER,
    STORAGE_BACKEND,
    STORAGE_SERIALIZER,
    CONNKEY,
};

}






class Component {
public:

















    Component(component::Type type, std::string name, Tag::subtype_t tag_subtype = 0, EnumTypePtr etype = nullptr);




    virtual ~Component();


    Component(const Component& other) = delete;
    Component operator=(const Component& other) = delete;






    virtual void Initialize() {}




    component::Type Type() const { return type; }




    const std::string& Name() const { return name; }







    const std::string& CanonicalName() const { return canon_name; }
    StringValPtr CanonicalNameVal() const;










    void Describe(ODesc* d) const;





    void InitializeTag();




    zeek::Tag Tag() const;





    bool Enabled() const { return enabled; }












    virtual void SetEnabled(bool arg_enabled);

protected:







    virtual void DoDescribe(ODesc* d) const {}

private:
    component::Type type;
    std::string name;
    std::string canon_name;
    StringValPtr canon_name_val;


    zeek::Tag tag;
    EnumTypePtr etype;
    Tag::subtype_t tag_subtype;
    bool tag_initialized = false;
    bool enabled = true;


    static Tag::type_t type_counter;
};

}
}
