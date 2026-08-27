

#pragma once

#include <string>

#include "zeek/Timer.h"

namespace zeek::file_analysis::detail {




class FileTimer final : public zeek::detail::Timer {
public:






    FileTimer(double t, std::string id, double interval);







    void Dispatch(double t, bool is_expire) override;

private:
    std::string file_id;
};

}
