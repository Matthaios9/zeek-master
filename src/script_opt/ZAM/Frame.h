



#pragma once

#include <vector>

#include "zeek/Attr.h"
#include "zeek/ID.h"
#include "zeek/util-types.h"

namespace zeek::detail {

using AttributesPtr = IntrusivePtr<Attributes>;



using FrameMap = std::vector<IDPtr>;



class FrameSharingInfo {
public:



    std::vector<IDPtr> ids;




    std::vector<const char*> names;



    std::vector<zeek_uint_t> id_start;



    int scope_end = -1;


    bool is_managed = false;
};

using FrameReMap = std::vector<FrameSharingInfo>;

}
