



#pragma once

#include <cstdint>

namespace zeek::detail {

enum AttrExprType : uint8_t {
    AE_NONE,
    AE_CONST,
    AE_NAME,
    AE_RECORD,
    AE_CALL,
};

}
