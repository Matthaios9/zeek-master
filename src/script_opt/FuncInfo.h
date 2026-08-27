



#pragma once

#include <string>

namespace zeek::detail {



extern bool is_special_script_func(const std::string& func_name);


extern bool is_ZAM_replaceable_script_func(const std::string& func_name);




extern bool is_idempotent(const std::string& func_name);



extern bool is_foldable(const std::string& func_name);



extern bool has_script_side_effects(const std::string& func_name);

}
