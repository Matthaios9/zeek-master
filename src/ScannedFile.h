

#pragma once

#include <list>
#include <optional>
#include <string>
#include <vector>

#include "zeek/Obj.h"

namespace zeek::detail {






class ScannedFile {
public:
    ScannedFile(int arg_include_level, std::string arg_name, bool arg_skipped = false,
                bool arg_prefixes_checked = false, bool arg_is_canonical = false);





    bool AlreadyScanned() const;

    int include_level;
    bool skipped;
    bool prefixes_checked;
    std::string name;
    std::string canonical_path;

    static auto constexpr canonical_stdin_path = "<stdin>";
};

extern std::list<ScannedFile> files_scanned;

struct SignatureFile {
    std::string file;
    std::optional<std::string> full_path;
    Location load_location;

    SignatureFile(std::string file);
    SignatureFile(std::string file, std::string full_path, Location load_location);
};

extern std::vector<SignatureFile> sig_files;

}
