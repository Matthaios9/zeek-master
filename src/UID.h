

#pragma once

#include <cstring>
#include <string>

#include "zeek/util-types.h"

namespace zeek {

constexpr size_t UID_LEN = 2;

constexpr int UID_POOL_DEFAULT_INTERNAL = 1;
constexpr int UID_POOL_DEFAULT_SCRIPT = 2;
constexpr int UID_POOL_CUSTOM_SCRIPT = 10;





class UID {
public:



    UID() : initialized(false) {}





    explicit UID(zeek_uint_t bits, const uint64_t* v = nullptr, size_t n = 0, size_t pool = UID_POOL_DEFAULT_INTERNAL) {
        Set(bits, v, n, pool);
    }




    UID(const UID& other);













    void Set(zeek_uint_t bits, const uint64_t* v = nullptr, size_t n = 0, size_t pool = UID_POOL_DEFAULT_INTERNAL);






    std::string Base62(std::string prefix = "") const;





    explicit operator bool() const { return initialized; }




    UID& operator=(const UID& other);




    friend bool operator==(const UID& u1, const UID& u2) { return memcmp(u1.uid, u2.uid, sizeof(u1.uid)) == 0; }




    friend bool operator!=(const UID& u1, const UID& u2) { return ! (u1 == u2); }

private:
    uint64_t uid[UID_LEN];
    bool initialized;
};

inline UID::UID(const UID& other) {
    memcpy(uid, other.uid, sizeof(uid));
    initialized = other.initialized;
}

inline UID& UID::operator=(const UID& other) {
    if ( this == &other )
        return *this;

    memmove(uid, other.uid, sizeof(uid));
    initialized = other.initialized;
    return *this;
}

}
