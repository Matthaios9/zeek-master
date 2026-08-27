

#pragma once

#include <ctime>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "zeek/zeekygen/Info.h"

namespace zeek::zeekygen::detail {

class IdentifierInfo;

struct IdInfoComp {
    bool operator()(const IdentifierInfo* lhs, const IdentifierInfo* rhs) const;
};

using id_info_set = std::set<IdentifierInfo*, IdInfoComp>;
using id_info_list = std::list<IdentifierInfo*>;




class ScriptInfo : public Info {
public:





    ScriptInfo(std::string name, std::string path);





    void AddComment(const std::string& comment) { comments.push_back(comment); }






    void AddDependency(const std::string& name) { dependencies.insert(name); }






    void AddModule(const std::string& name) { module_usages.insert(name); }






    void AddIdentifierInfo(IdentifierInfo* info);






    void AddRedef(IdentifierInfo* info) { redefs.insert(info); }




    bool IsPkgLoader() const { return is_pkg_loader; }




    std::vector<std::string> GetComments() const;

private:
    using id_info_map = std::map<std::string, IdentifierInfo*>;
    using string_set = std::set<std::string>;

    time_t DoGetModificationTime() const override;

    std::string DoName() const override { return name; }

    std::string DoReStructuredText(bool roles_only) const override;

    void DoInitPostScript() override ;

    std::string name;
    std::string path;
    bool is_pkg_loader;
    string_set dependencies;
    string_set module_usages;
    std::vector<std::string> comments;
    id_info_map id_info;
    id_info_list redef_options;
    id_info_list options;
    id_info_list constants;
    id_info_list state_vars;
    id_info_list types;
    id_info_list events;
    id_info_list hooks;
    id_info_list functions;
    id_info_set redefs;
};

}
