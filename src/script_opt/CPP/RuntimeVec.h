







#pragma once

#include "zeek/Val.h"

namespace zeek::detail {



inline ValPtr vector_append__CPP(VectorValPtr v1, const ValPtr& v2) {
    v1->Assign(v1->Size(), v2);
    return v1;
}


inline ValPtr vector_vec_append__CPP(VectorValPtr v1, const VectorValPtr& v2) {
    if ( ! v2->AddTo(v1.get(), false) )
        reporter->CPPRuntimeError("incompatible vector element assignment");
    return v1;
}


extern VectorValPtr vec_op_pos__CPP(const VectorValPtr& v, const TypePtr& t);
extern VectorValPtr vec_op_neg__CPP(const VectorValPtr& v, const TypePtr& t);
extern VectorValPtr vec_op_not__CPP(const VectorValPtr& v, const TypePtr& t);
extern VectorValPtr vec_op_comp__CPP(const VectorValPtr& v, const TypePtr& t);


extern VectorValPtr vec_op_add__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_sub__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_mul__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_div__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_mod__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_and__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_or__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_xor__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_andand__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_oror__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_lshift__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_rshift__CPP(const VectorValPtr& v1, const VectorValPtr& v2);


extern VectorValPtr vec_op_lt__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_gt__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_eq__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_ne__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_le__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr vec_op_ge__CPP(const VectorValPtr& v1, const VectorValPtr& v2);


extern VectorValPtr vec_op_add__CPP(VectorValPtr v, int incr);
extern VectorValPtr vec_op_sub__CPP(VectorValPtr v, int i);



extern VectorValPtr str_vec_op_add__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_add__CPP(const VectorValPtr& v1, const StringValPtr& v2);
extern VectorValPtr str_vec_op_add__CPP(const StringValPtr& v1, const VectorValPtr& v2);


extern VectorValPtr str_vec_op_lt__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_le__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_eq__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_ne__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_gt__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr str_vec_op_ge__CPP(const VectorValPtr& v1, const VectorValPtr& v2);


extern VectorValPtr pat_vec_op_eq__CPP(const VectorValPtr& v1, const VectorValPtr& v2);
extern VectorValPtr pat_vec_op_ne__CPP(const VectorValPtr& v1, const VectorValPtr& v2);




extern VectorValPtr vector_select__CPP(const VectorValPtr& v1, VectorValPtr v2, VectorValPtr v3);




extern VectorValPtr vector_coerce_to__CPP(const VectorValPtr& v, const TypePtr& targ);


extern VectorValPtr vec_coerce_to_zeek_int_t__CPP(const VectorValPtr& v, TypePtr targ);
extern VectorValPtr vec_coerce_to_zeek_uint_t__CPP(const VectorValPtr& v, TypePtr targ);
extern VectorValPtr vec_coerce_to_double__CPP(const VectorValPtr& v, TypePtr targ);



extern VectorValPtr vec_scalar_mixed_with_vector();

}
