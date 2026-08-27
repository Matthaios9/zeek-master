

#pragma once

#include "zeek/zeek-config.h"

#include <sys/stat.h>
#include <cerrno>
#include <ctime>
#include <map>
#include <string>
#include <vector>

#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/zeekygen/Configuration.h"
#include "zeek/zeekygen/SpicyModuleInfo.h"

namespace zeek {

class TypeDecl;

namespace zeekygen::detail {

class PackageInfo;
class ScriptInfo;






template<class T>
struct InfoMap {
    using map_type = std::map<std::string, T*>;





    T* GetInfo(const std::string& name) const {
        typename map_type::const_iterator it = map.find(name);
        return it == map.end() ? 0 : it->second;
    }

    map_type map;
};




class Manager {
public:








    Manager(const std::string& config, const std::string& command);




    ~Manager();





    void InitPreScript();





    void InitPostScript();





    void GenerateDocs() const;





    void Script(const std::string& path);







    void ScriptDependency(const std::string& path, const std::string& dep);







    void ModuleUsage(const std::string& path, const std::string& module);





    void StartType(zeek::detail::IDPtr id);







    void Identifier(zeek::detail::IDPtr id, bool from_redef = false);











    void RecordField(const zeek::detail::ID* id, const TypeDecl* field, const std::string& path, bool from_redef);








    void Redef(const zeek::detail::ID* id, const std::string& path, zeek::detail::InitClass ic,
               zeek::detail::ExprPtr init_expr);
    void Redef(const zeek::detail::ID* id, const std::string& path,
               zeek::detail::InitClass ic = zeek::detail::INIT_NONE);





    void AddSpicyModule(std::unique_ptr<SpicyModuleInfo> info) {
        spicy_modules.map[info->Name()] = info.get();
        all_info.push_back(info.release());
    }

    const auto& SpicyModules() const { return spicy_modules.map; }







    void SummaryComment(const std::string& path, const std::string& comment);







    void PreComment(const std::string& comment);







    void PostComment(const std::string& comment, const std::string& identifier_hint = "");





    std::string GetEnumTypeName(const std::string& id) const;






    IdentifierInfo* GetIdentifierInfo(const std::string& name) const { return identifiers.GetInfo(name); }







    ScriptInfo* GetScriptInfo(const std::string& name) const { return scripts.GetInfo(name); }







    PackageInfo* GetPackageInfo(const std::string& name) const { return packages.GetInfo(name); }









    template<class T>
    bool IsUpToDate(const std::string& target_file, const std::vector<T*>& dependencies) const;


    bool IsEnabled() const { return ! disabled; }

private:
    using comment_buffer_t = std::vector<std::string>;
    using comment_buffer_map_t = std::map<std::string, comment_buffer_t>;

    void DbgAndWarn(const char* msg) const;
    void WarnMissingScript(const char* type, const zeek::detail::ID* id, const std::string& script) const;

    IdentifierInfo* CreateIdentifierInfo(zeek::detail::IDPtr id, ScriptInfo* script, bool from_redef = false);

    bool disabled = false;
    bool enable_warnings = false;
    comment_buffer_t comment_buffer;
    comment_buffer_map_t comment_buffer_map;
    InfoMap<PackageInfo> packages;
    InfoMap<ScriptInfo> scripts;
    InfoMap<IdentifierInfo> identifiers;
    InfoMap<SpicyModuleInfo> spicy_modules;
    std::vector<Info*> all_info;
    IdentifierInfo* last_identifier_seen = nullptr;
    IdentifierInfo* incomplete_type = nullptr;
    std::map<std::string, std::string> enum_mappings;
    Config config;
    time_t mtime = 0;
};

template<class T>
bool Manager::IsUpToDate(const std::string& target_file, const std::vector<T*>& dependencies) const {
    struct stat s;

    if ( stat(target_file.c_str(), &s) < 0 ) {
        if ( errno == ENOENT )

            return false;

        reporter->InternalError("Zeekygen failed to stat target file '%s': %s", target_file.c_str(), strerror(errno));
    }

    if ( difftime(mtime, s.st_mtime) > 0 )
        return false;

    if ( difftime(config.GetModificationTime(), s.st_mtime) > 0 )
        return false;

    for ( size_t i = 0; i < dependencies.size(); ++i )
        if ( difftime(dependencies[i]->GetModificationTime(), s.st_mtime) > 0 )
            return false;

    return true;
}

}

namespace detail {

ZEEK_EXTERN_DATA zeekygen::detail::Manager* zeekygen_mgr;

}
}
