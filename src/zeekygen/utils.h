

#pragma once

#include <ctime>
#include <optional>
#include <string>

namespace zeek::detail {
class ID;
}

namespace zeek::zeekygen::detail {








bool prettify_params(std::string& s);







bool is_public_api(const zeek::detail::ID* id);






time_t get_mtime(const std::string& filename);







std::string make_heading(const std::string& heading, char underline);







size_t end_of_first_sentence(const std::string& s);






bool is_all_whitespace(const std::string& s);





std::string redef_indication(const std::string& from_script);










std::string normalize_script_path(std::string_view path);












std::optional<std::string> source_code_range(const zeek::detail::ID* id);

}
