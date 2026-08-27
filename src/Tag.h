

#pragma once

#include <cstdint>
#include <string>

#include "zeek/IntrusivePtr.h"

namespace zeek {

class EnumVal;
using EnumValPtr = IntrusivePtr<EnumVal>;
class EnumType;
using EnumTypePtr = IntrusivePtr<EnumType>;



















class Tag {
public:



    using type_t = uint32_t;




    using subtype_t = uint32_t;




    type_t Type() const { return type; }




    subtype_t Subtype() const { return subtype; }





    Tag();












    Tag(const EnumTypePtr& etype, type_t type, subtype_t subtype = 0);











    explicit Tag(type_t type, subtype_t subtype = 0);






    explicit Tag(EnumValPtr val);




    Tag(const Tag& other);




    Tag(Tag&& other) noexcept;




    ~Tag();




    Tag& operator=(const Tag& other);




    Tag& operator=(Tag&& other) noexcept;




    bool operator==(const Tag& other) const { return type == other.type && subtype == other.subtype; }




    bool operator!=(const Tag& other) const { return type != other.type || subtype != other.subtype; }




    bool operator<(const Tag& other) const {
        return type != other.type ? type < other.type : (subtype < other.subtype);
    }





    std::string AsString() const;







    const EnumValPtr& AsVal() const { return val; }





    explicit operator bool() const { return *this != Error; }

    static const Tag Error;

private:
    type_t type = 0;
    subtype_t subtype = 0;
    EnumValPtr val;
    EnumTypePtr etype;
};

}
