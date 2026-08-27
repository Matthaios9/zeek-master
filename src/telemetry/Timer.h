


#pragma once

#include <chrono>

#include "zeek/telemetry/Histogram.h"

namespace zeek::telemetry {




class [[nodiscard]] Timer {
public:
    using Clock = std::chrono::steady_clock;

    explicit Timer(std::shared_ptr<Histogram> h) : h_(std::move(h)) { start_ = Clock::now(); }

    Timer(const Timer&) = delete;

    Timer& operator=(const Timer&) = delete;

    ~Timer() { Observe(h_, start_); }


    auto Handle() const noexcept { return h_; }


    auto Started() const noexcept { return start_; }


    static void Observe(const std::shared_ptr<Histogram>& h, Clock::time_point start) {
        using Sec = std::chrono::duration<double>;
        if ( auto end = Clock::now(); end > start )
            h->Observe(std::chrono::duration_cast<Sec>(end - start).count());
    }

private:
    std::shared_ptr<Histogram> h_;
    Clock::time_point start_;
};

}
