

#pragma once

#include <cstddef>
#include <cstdint>

#include "zeek/Hash.h"

namespace zeek::session::detail {

struct KeyHash;











class Key final {
public:
    const static size_t CONNECTION_KEY_TYPE = 0;














    Key(const void* key_data, size_t size, size_t type, bool copy = false);

    ~Key();



    Key(Key&& rhs) noexcept;
    Key& operator=(Key&& rhs) noexcept;



    Key(const Key& rhs) = delete;
    Key& operator=(const Key& rhs) = delete;






    void CopyData();

    bool operator<(const Key& rhs) const;
    bool operator==(const Key& rhs) const;

    std::size_t Hash() const { return zeek::detail::HashKey::HashBytes(data, size); }

private:
    friend struct KeyHash;

    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t type = CONNECTION_KEY_TYPE;
    bool copied = false;
};

struct KeyHash {
    std::size_t operator()(const Key& k) const { return k.Hash(); }
};

}
