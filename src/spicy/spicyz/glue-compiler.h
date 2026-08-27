

#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>
#include <hilti/rt/types/port.h>
#include <hilti/rt/util.h>

#include <spicy/rt/mime.h>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/driver.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/declarations/unit-hook.h>
#include <spicy/ast/types/unit.h>

#include "driver.h"
#include "zeek/spicy/port-range.h"

namespace spicy::rt {
struct Parser;
}

namespace zeek::spicy {

namespace glue {


struct ProtocolAnalyzer {

    hilti::Location location;
    hilti::ID name;
    hilti::rt::Protocol protocol = hilti::rt::Protocol::Undef;
    std::vector<::zeek::spicy::rt::PortRange> ports;
    hilti::ID unit_name_orig;

    hilti::ID unit_name_resp;

    std::string replaces;


    std::optional<TypeInfo> unit_orig;
    std::optional<TypeInfo> unit_resp;
};


struct FileAnalyzer {

    hilti::Location location;
    hilti::ID name;
    std::vector<std::string> mime_types;
    hilti::ID unit_name;
    std::string replaces;


    std::optional<TypeInfo> unit;
};


struct PacketAnalyzer {

    hilti::Location location;
    hilti::ID name;
    hilti::ID unit_name;
    std::string replaces;


    std::optional<TypeInfo> unit;
};





struct ExpressionAccessor {

    int nr;
    std::string expression;
    hilti::Location location;
};


struct SpicyModule {

    hilti::ID id;
    hilti::rt::filesystem::path file;
    std::set<hilti::rt::filesystem::path> evts;


    hilti::node::RetainedPtr<hilti::declaration::Module> spicy_module =
        nullptr;
};


struct Event {

    hilti::rt::filesystem::path file;
    hilti::ID name;
    hilti::ID path;
    std::vector<hilti::node::RetainedPtr<hilti::declaration::Parameter>>
        parameters;
    std::string condition;
    std::vector<std::string> exprs;
    int priority;
    hilti::Location location;


    hilti::ID hook;
    hilti::ID unit;
    hilti::node::RetainedPtr<::spicy::type::Unit> unit_type = nullptr;
    hilti::ID unit_module_id;
    hilti::rt::filesystem::path unit_module_path;
    std::shared_ptr<glue::SpicyModule>
        spicy_module;


    std::vector<ExpressionAccessor> expression_accessors;
};


struct Export {
    hilti::ID spicy_id;
    hilti::ID zeek_id;
    hilti::Location location;


    bool log_all = false;
    std::set<hilti::ID> with;
    std::set<hilti::ID> without;
    std::set<hilti::ID> logs;





    bool validate(const TypeInfo& ti) const;
};

}


class GlueCompiler {
public:

    GlueCompiler() = default;


    virtual ~GlueCompiler();





    auto* context() { return _driver->context()->astContext(); }





    auto* builder() { return static_cast<::spicy::Builder*>(_driver->builder()); }


    bool loadEvtFile(hilti::rt::filesystem::path& path);








    void addSpicyModule(const hilti::ID& id, const hilti::rt::filesystem::path& file);





    bool compile();


    const auto& exportedIDs() const { return _exports; }


    std::optional<glue::Export> exportForZeekID(const hilti::ID& id) const;


    struct ExportedField {
        bool skip = false;
        bool log = false;
    };






    ExportedField exportForField(const hilti::ID& zeek_id, const hilti::ID& field_id) const;

    using ZeekTypeCache = std::map<hilti::ID, hilti::Expression*>;





    hilti::Result<hilti::Nothing> createZeekType(hilti::QualifiedType* t, const hilti::ID& id,
                                                 ::spicy::Builder* builder, ZeekTypeCache* cache) const;








    bool createHILTIExports(hilti::ASTRoot* root);


    struct RecordField {
        hilti::ID id;
        hilti::QualifiedType* type = nullptr;
        bool is_optional;
        bool is_anonymous;
    };








    static std::vector<RecordField> recordFields(const ::spicy::type::Unit* unit);

protected:
    friend class Driver;


    void init(Driver* driver, int zeek_version);

private:



    void preprocessEvtFile(hilti::rt::filesystem::path& path, std::istream& in, std::ostream& out);










    hilti::Result<std::string> getNextEvtBlock(std::istream& in, int* lineno) const;


    glue::ProtocolAnalyzer parseProtocolAnalyzer(const std::string& chunk);
    glue::FileAnalyzer parseFileAnalyzer(const std::string& chunk);
    glue::PacketAnalyzer parsePacketAnalyzer(const std::string& chunk);
    glue::Event parseEvent(const std::string& chunk);
    glue::Export parseExport(const std::string& chunk);


    bool PopulateEvents();





    bool CreateSpicyHook(glue::Event* ev);

    Driver* _driver = nullptr;
    std::optional<int> _zeek_version;

    std::map<hilti::ID, std::shared_ptr<glue::SpicyModule>> _spicy_modules;

    std::vector<std::pair<hilti::ID, hilti::ID>>
        _imports;
    std::map<hilti::ID, glue::Export> _exports;
    std::vector<glue::Event> _events;
    std::vector<glue::ProtocolAnalyzer> _protocol_analyzers;
    std::vector<glue::FileAnalyzer> _file_analyzers;
    std::vector<glue::PacketAnalyzer> _packet_analyzers;
    std::vector<hilti::Location> _locations;

    std::string _doc_id;
    std::string _doc_description;

};
}

namespace std {
template<>
struct hash<zeek::spicy::glue::Event> {
    std::size_t operator()(const zeek::spicy::glue::Event& e) {

        return hilti::rt::hashCombine(std::hash<std::string>()(e.file.generic_string()), std::hash<hilti::ID>()(e.name),
                                      std::hash<hilti::ID>()(e.path), std::hash<hilti::Location>()(e.location));
    }
};
}
