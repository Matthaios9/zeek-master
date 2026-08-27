

#pragma once

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <hilti/rt/library.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/port.h>

#include "zeek/Scope.h"
#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"
#include "zeek/plugin/Plugin.h"
#include "zeek/spicy/port-range.h"
#include "zeek/spicy/spicyz/config.h"
#include "zeek/zeekygen/SpicyModuleInfo.h"




#define SPICY_DEBUG(msg) ::zeek::spicy::log(msg);

namespace hilti::rt {
class Port;
struct Protocol;
}

namespace spicy::rt {
struct Parser;
}

namespace zeek {

namespace analyzer {
class Analyzer;
}

namespace file_analysis {
class Analyzer;
}

namespace packet_analysis {
class Analyzer;
}

namespace spicy {


inline void log(std::string_view msg) {
    DBG_LOG(DBG_SPICY, "%s", std::string(msg).c_str());

    if ( hilti::rt::isInitialized() )
        HILTI_RT_DEBUG("zeek", msg);
}



class Manager : public zeek::plugin::Plugin {
public:
    Manager() = default;












    void registerSpicyModuleBegin(const hilti::rt::String& name, const hilti::rt::String& description);


















    void registerProtocolAnalyzer(const hilti::rt::String& name, hilti::rt::Protocol proto,
                                  const hilti::rt::Vector<::zeek::spicy::rt::PortRange>& ports,
                                  const hilti::rt::String& parser_orig, const hilti::rt::String& parser_resp,
                                  const hilti::rt::String& replaces,
                                  const hilti::rt::integer::safe<uint64_t>& linker_scope);
















    void registerFileAnalyzer(const hilti::rt::String& name, const hilti::rt::Vector<hilti::rt::String>& mime_types,
                              const hilti::rt::String& parser, const hilti::rt::String& replaces,
                              const hilti::rt::integer::safe<uint64_t>& linker_scope);















    void registerPacketAnalyzer(const hilti::rt::String& name, const hilti::rt::String& parser,
                                const hilti::rt::String& replaces,
                                const hilti::rt::integer::safe<uint64_t>& linker_scope);









    hilti::rt::Result<hilti::rt::Nothing> registerType(const hilti::rt::String& id);








    void registerType(const hilti::rt::String& id, const TypePtr& type);





    void registerSpicyModuleEnd();







    TypePtr findType(std::string_view id) const;








    void registerEvent(const hilti::rt::String& name);










    const ::spicy::rt::Parser* parserForProtocolAnalyzer(const Tag& tag, bool is_orig);








    const ::spicy::rt::Parser* parserForFileAnalyzer(const Tag& tag);








    const ::spicy::rt::Parser* parserForPacketAnalyzer(const Tag& tag);










    Tag tagForProtocolAnalyzer(const Tag& tag);










    Tag tagForFileAnalyzer(const Tag& tag);










    Tag tagForPacketAnalyzer(const Tag& tag);









    bool toggleProtocolAnalyzer(const Tag& tag, bool enable);









    bool toggleFileAnalyzer(const Tag& tag, bool enable);









    bool togglePacketAnalyzer(const Tag& tag, bool enable);













    bool toggleAnalyzer(EnumVal* tag, bool enable);


    void analyzerError(analyzer::Analyzer* a, std::string_view msg, std::string_view location);


    void analyzerError(file_analysis::Analyzer* a, std::string_view msg, std::string_view location);


    void analyzerError(packet_analysis::Analyzer* a, std::string_view msg, std::string_view location);


    int numberErrors();

protected:

    zeek::plugin::Configuration Configure() override;


    void InitPreScript() override;


    void InitPostScript() override;


    void Done() override;


    int HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved) override;

private:

    void loadModule(const hilti::rt::filesystem::path& path);


    void autoDiscoverModules();


    void searchModules(std::string_view paths);


    detail::Location makeLocation(const hilti::rt::String& fname);


    void disableReplacedAnalyzers();







    void trackComponent(plugin::Component* c, int32_t tag_type);


    struct ProtocolAnalyzerInfo {

        hilti::rt::String name_analyzer;
        hilti::rt::String name_parser_orig;
        hilti::rt::String name_parser_resp;
        hilti::rt::String name_replaces;
        hilti::rt::Protocol protocol = hilti::rt::Protocol::Undef;
        std::vector<::zeek::spicy::rt::PortRange> ports;
        hilti::rt::integer::safe<uint64_t> linker_scope;


        hilti::rt::String name_zeek;
        hilti::rt::String name_zeekygen;
        Tag tag;
        const ::spicy::rt::Parser* parser_orig;
        const ::spicy::rt::Parser* parser_resp;
        Tag replaces;

        bool operator==(const ProtocolAnalyzerInfo& other) const {
            return name_analyzer == other.name_analyzer && name_parser_orig == other.name_parser_orig &&
                   name_parser_resp == other.name_parser_resp && name_replaces == other.name_replaces &&
                   protocol == other.protocol && ports == other.ports && linker_scope == other.linker_scope;
        }

        bool operator!=(const ProtocolAnalyzerInfo& other) const { return ! (*this == other); }
    };


    struct FileAnalyzerInfo {

        hilti::rt::String name_analyzer;
        hilti::rt::String name_parser;
        hilti::rt::String name_replaces;
        hilti::rt::Vector<hilti::rt::String> mime_types;
        hilti::rt::integer::safe<uint64_t> linker_scope;


        hilti::rt::String name_zeek;
        hilti::rt::String name_zeekygen;
        Tag tag;
        const ::spicy::rt::Parser* parser;
        Tag replaces;

        bool operator==(const FileAnalyzerInfo& other) const {
            return name_analyzer == other.name_analyzer && name_parser == other.name_parser &&
                   name_replaces == other.name_replaces && mime_types == other.mime_types &&
                   linker_scope == other.linker_scope;
        }

        bool operator!=(const FileAnalyzerInfo& other) const { return ! (*this == other); }
    };


    struct PacketAnalyzerInfo {

        hilti::rt::String name_analyzer;
        hilti::rt::String name_parser;
        hilti::rt::String name_replaces;
        hilti::rt::integer::safe<uint64_t> linker_scope;


        hilti::rt::String name_zeek;
        hilti::rt::String name_zeekygen;
        Tag tag;
        const ::spicy::rt::Parser* parser;
        Tag replaces;


        bool operator==(const PacketAnalyzerInfo& other) const {
            return name_analyzer == other.name_analyzer && name_parser == other.name_parser &&
                   name_replaces == other.name_replaces && linker_scope == other.linker_scope;
        }

        bool operator!=(const PacketAnalyzerInfo& other) const { return ! (*this == other); }
    };

    hilti::rt::String _spicy_version;



    std::unique_ptr<zeekygen::detail::SpicyModuleInfo> _module_info;

    std::vector<ProtocolAnalyzerInfo> _protocol_analyzers_by_type;
    std::vector<FileAnalyzerInfo> _file_analyzers_by_type;
    std::vector<PacketAnalyzerInfo> _packet_analyzers_by_type;
    std::unordered_map<std::string, hilti::rt::Library> _libraries;
    std::set<std::string> _locations;
    std::unordered_map<hilti::rt::String, detail::IDPtr> _events;


    std::unordered_map<hilti::rt::String, int32_t> _analyzer_name_to_tag_type;
};

}

extern spicy::Manager* spicy_mgr;

}
