



#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace zeek::detail {


enum ZOp : uint16_t {
#include "zeek/ZAM-OpsDefs.h"
    OP_NOP,
};










enum ZAMOpType : uint8_t {
    OP_X,
    OP_C,
    OP_V,
    OP_V_I1,
    OP_VC_I1,

    OP_VC,
    OP_VV,
    OP_VV_I2,
    OP_VV_I1_I2,
    OP_VV_FRAME,

    OP_VVC,
    OP_VVC_I2,
    OP_VVV,
    OP_VVV_I3,
    OP_VVV_I2_I3,

    OP_VVVC,
    OP_VVVC_I3,
    OP_VVVC_I2_I3,
    OP_VVVC_I1_I2_I3,
    OP_VVVV,
    OP_VVVV_I4,
    OP_VVVV_I3_I4,
    OP_VVVV_I2_I3_I4,

};


enum ZAMOp1Flavor : uint8_t {
    OP1_READ,
    OP1_WRITE,
    OP1_READ_WRITE,
    OP1_INTERNAL,
};


struct ZAMInstDesc {
    std::string op_class;
    std::string op_types;
    std::string op_eval;
};


extern std::unordered_map<ZOp, ZAMInstDesc> zam_inst_desc;



extern std::vector<std::pair<std::string, std::string>> zam_macro_desc;


extern ZAMOp1Flavor op1_flavor[];


extern bool op_side_effects[];



extern ZOp inverse_ZOP(ZOp op);


extern bool ZOP_has_inverse(ZOp op);

}
