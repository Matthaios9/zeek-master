

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>

#include <spicy/rt/driver.h>

#include <hilti/ast/declaration.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/driver.h>

#include <spicy/compiler/driver.h>


static const ::hilti::logging::DebugStream ZeekPlugin("zeek");



#define SPICY_DEBUG(msg) HILTI_DEBUG(ZeekPlugin, std::string(msg));

namespace zeek::spicy {

class GlueCompiler;

struct TypeInfo {
    hilti::ID id;
    hilti::QualifiedType* type = nullptr;
    hilti::declaration::Linkage linkage;
    bool is_resolved = false;
    hilti::ID module_id;
    hilti::rt::filesystem::path module_path;
    hilti::Location location;
};


class Driver : public ::spicy::Driver {
public:







    Driver(std::unique_ptr<GlueCompiler> glue, const char* argv0, hilti::rt::filesystem::path lib_path,
           int zeek_version);


    ~Driver() override;









    hilti::Result<hilti::Nothing> loadFile(hilti::rt::filesystem::path file,
                                           const hilti::rt::filesystem::path& relative_to = {});










    hilti::Result<hilti::Nothing> compile();








    hilti::Result<TypeInfo> lookupType(const hilti::ID& id);










    template<typename T>
    hilti::Result<TypeInfo> lookupType(const hilti::ID& id) {
        auto ti = lookupType(id);
        if ( ! ti )
            return ti.error();

        if ( ! ti->type->type()->isA<T>() )
            return hilti::result::Error(hilti::util::fmt("'%s' is not of expected type", id));

        return ti;
    }








    std::vector<TypeInfo> types() const;









    std::vector<std::pair<TypeInfo, hilti::ID>> exportedTypes() const;


    bool usingBuildDirectory() const { return _using_build_directory; }


    const auto* glueCompiler() const { return _glue.get(); }


    static void usage(std::ostream& out);

protected:









    virtual void hookNewType(const TypeInfo& ) {}


    void hookNewASTPreCompilation(const hilti::Plugin& plugin, hilti::ASTRoot* root) override;


    bool hookNewASTPostCompilation(const hilti::Plugin& plugin, hilti::ASTRoot* root) override;


    hilti::Result<hilti::Nothing> hookCompilationFinished(hilti::ASTRoot* root) override;


    void hookInitRuntime() override;


    void hookFinishRuntime() override;

    std::unique_ptr<GlueCompiler> _glue;
    std::unordered_map<hilti::ID, TypeInfo> _types;
    std::vector<TypeInfo> _public_enums;
    bool _using_build_directory = false;
    hilti::Result<hilti::Nothing> _error = hilti::Nothing();


    enum class GluePhase : uint8_t { Create, ExportTypes, Done };
    GluePhase _glue_phase = GluePhase::Create;
};

}
