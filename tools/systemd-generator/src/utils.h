

#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace zeek::detail {




void ltrim(std::string& s);




void rtrim(std::string& s);




void trim(std::string& s);




void tolower(std::string& s);




std::optional<int> parse_int(std::string_view sv);




std::vector<std::string_view> split(std::string_view v, char delim);




std::string join(std::span<const std::string> args, const std::string& sep = " ");




std::string join(std::span<const std::filesystem::path> paths, const std::string& sep = " ");




std::optional<std::string> substitute_vars(const std::string& s, const std::map<std::string, std::string>& vars);




bool is_valid_ip(const std::string& s);











class CpuList {
public:





    CpuList(const std::string& list = "");




    std::string CpuAtIndex(int index) const;

    bool IsValid() { return is_valid; }




    const std::vector<int>& Indices() const { return cpus; }




    std::string IndicesSetString(const std::string& sep = ",") const;

private:
    bool is_valid = true;
    std::vector<int> cpus;
};


}
