

#pragma once

#include "zeek/Options.h"

namespace zeek::detail {

struct SetupResult {
    int code = 0;
    Options options;
};










SetupResult setup(int argc, char** argv, Options* options = nullptr);





int cleanup(bool did_run_loop);

}
