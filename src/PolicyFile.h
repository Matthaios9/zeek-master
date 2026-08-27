

#pragma once















#include <optional>
#include <string>

namespace zeek::detail {

int how_many_lines_in(const char* policy_filename);

bool LoadPolicyFileText(const char* policy_filename, const std::optional<std::string>& preloaded_content = {});


bool PrintLines(const char* policy_filename, unsigned int start_line, unsigned int how_many_lines, bool show_numbers);

}
