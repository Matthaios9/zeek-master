

#pragma once

#include <ctime>
#include <string>
#include <vector>

#include "zeek/zeekygen/Info.h"

namespace zeek::zeekygen::detail {




class PackageInfo : public Info {
public:





    explicit PackageInfo(std::string name);






    std::vector<std::string> GetReadme() const { return readme; }

private:
    time_t DoGetModificationTime() const override;

    std::string DoName() const override { return pkg_name; }

    std::string DoReStructuredText(bool roles_only) const override;

    std::string pkg_name;
    std::vector<std::string> readme;
};

}
