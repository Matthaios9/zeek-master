





#pragma once

#include <string>

namespace zeek::detail {

static constexpr const char* GLOBAL_MODULE_NAME = "GLOBAL";

extern std::string extract_module_name(const char* name);
extern std::string extract_var_name(const char* name);
extern std::string normalized_module_name(const char* module_name);



extern std::string make_full_var_name(const char* module_name, const char* var_name);

}
