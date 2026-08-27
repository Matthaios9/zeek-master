

#pragma once

#include <memory>

#include "zeek/Func.h"
#include "zeek/Type.h"

namespace zeek {

class ListVal;
using ListValPtr = zeek::IntrusivePtr<ListVal>;

}

namespace zeek::detail {

class HashKey;

class CompositeHash {
public:
    explicit CompositeHash(TypeListPtr composite_type);



    std::unique_ptr<HashKey> MakeHashKey(const Val& v, bool type_check) const;


    ListValPtr RecoverVals(const HashKey& k) const;




    bool SingleValHash(HashKey& hk, const Val* v, Type* bt, bool type_check, bool optional, bool singleton) const;





    bool RecoverOneVal(const HashKey& k, Type* t, ValPtr* pval, bool optional, bool singleton) const;

    bool ReserveSingleTypeKeySize(HashKey& hk, Type*, const Val* v, bool type_check, bool optional,
                                  bool calc_static_size, bool singleton) const;

protected:




    bool ReserveKeySize(HashKey& hk, const Val* v, bool type_check, bool calc_static_size) const;

    bool EnsureTypeReserve(HashKey& hk, const Val* v, Type* bt, bool type_check) const;





    std::unique_ptr<std::unordered_map<const Func*, uint32_t>> func_to_func_id;
    std::unique_ptr<std::vector<FuncPtr>> func_id_to_func;
    void BuildFuncMappings() {
        func_to_func_id = std::make_unique<std::unordered_map<const Func*, uint32_t>>();
        func_id_to_func = std::make_unique<std::vector<FuncPtr>>();
    }

    TypeListPtr type;
    bool is_singleton = false;
};

}
