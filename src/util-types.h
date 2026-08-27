

#pragma once

#include <cstdint>
#include <span>
#include <string>

#include "zeek/3rdparty/nonstd/expected.hpp"


using zeek_int_t = int64_t;
using zeek_uint_t = uint64_t;

namespace zeek {



template<typename T, typename E>
using expected = nonstd::expected<T, E>;

template<typename E>
using unexpected = nonstd::unexpected<E>;


using byte_buffer = std::vector<std::byte>;
using byte_buffer_span = std::span<const std::byte>;

namespace util {
namespace detail {





class SafePathOp {
public:
    std::string result;
    bool error = false;

protected:
    void CheckValid(const char* result, const char* path, bool error_aborts);
};

}

class SafeDirname : public detail::SafePathOp {
public:
    explicit SafeDirname(const char* path, bool error_aborts = true);
    explicit SafeDirname(const std::string& path, bool error_aborts = true);

private:
    void DoFunc(const std::string& path, bool error_aborts = true);
};

class SafeBasename : public detail::SafePathOp {
public:
    explicit SafeBasename(const char* path, bool error_aborts = true);
    explicit SafeBasename(const std::string& path, bool error_aborts = true);

private:
    void DoFunc(const std::string& path, bool error_aborts = true);
};




class Deferred {
public:
    Deferred(std::function<void()> deferred) : deferred(std::move(deferred)) {}
    ~Deferred() {
        if ( deferred ) {
            deferred();
        }
    }
    void Cancel() { deferred = nullptr; }

private:
    std::function<void()> deferred;
};

}
}
