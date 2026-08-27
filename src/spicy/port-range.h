

#pragma once

#include <cassert>
#include <tuple>

#include <hilti/rt/types/port.h>

namespace zeek::spicy::rt {


struct PortRange {
    PortRange() = default;
    PortRange(hilti::rt::Port begin_, hilti::rt::Port end_) : begin(begin_), end(end_) {
        assert(begin.port() <= end.port());
        assert(begin.protocol() == end.protocol());
    }

    hilti::rt::Port begin;
    hilti::rt::Port end;

    bool operator<(const PortRange& other) const {

        return std::tie(begin, end) < std::tie(other.begin, other.end);
    }
};

inline bool operator==(const PortRange& a, const PortRange& b) {
    return std::tie(a.begin, a.end) == std::tie(b.begin, b.end);
}

inline bool operator!=(const PortRange& a, const PortRange& b) { return ! (a == b); }

inline PortRange make_port_range(hilti::rt::Port begin, hilti::rt::Port end) { return {begin, end}; }

}
