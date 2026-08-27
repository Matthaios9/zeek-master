




#pragma once

#include "zeek/zeek-config.h"

#include <cstdint>
#include <cstdio>
#include <set>
#include <string>

#ifdef _MSC_VER
#include <unistd.h>
#endif

#ifdef DEBUG


#define DBG_LOG(stream, ...)                                                                                           \
    if ( ::zeek::detail::debug_logger.IsEnabled(stream) )                                                              \
    ::zeek::detail::debug_logger.Log(stream, __VA_ARGS__)
#define DBG_LOG_VERBOSE(stream, ...)                                                                                   \
    if ( ::zeek::detail::debug_logger.IsVerbose() && ::zeek::detail::debug_logger.IsEnabled(stream) )                  \
    ::zeek::detail::debug_logger.Log(stream, __VA_ARGS__)
#define DBG_PUSH(stream) ::zeek::detail::debug_logger.PushIndent(stream)
#define DBG_POP(stream) ::zeek::detail::debug_logger.PopIndent(stream)

#define PLUGIN_DBG_LOG(plugin, ...) ::zeek::detail::debug_logger.Log(plugin, __VA_ARGS__)


#else

#define DBG_LOG(...)
#define DBG_LOG_VERBOSE(...)
#define DBG_PUSH(stream)
#define DBG_POP(stream)
#define PLUGIN_DBG_LOG(plugin, ...)


#endif

namespace zeek {

namespace plugin {
class Plugin;
}




enum DebugStream : uint8_t {
    DBG_SERIAL,
    DBG_RULES,
    DBG_STRING,
    DBG_NOTIFIERS,
    DBG_MAINLOOP,
    DBG_ANALYZER,
    DBG_PACKET_ANALYSIS,
    DBG_FILE_ANALYSIS,
    DBG_TM,
    DBG_LOGGING,
    DBG_INPUT,
    DBG_THREADING,
    DBG_PLUGINS,
    DBG_ZEEKYGEN,
    DBG_PKTIO,
    DBG_BROKER,
    DBG_SCRIPTS,
    DBG_SUPERVISOR,
    DBG_HASHKEY,
    DBG_SPICY,
    DBG_CLUSTER,
    DBG_STORAGE,

    NUM_DBGS
};

namespace detail {

class DebugLogger {
public:

    DebugLogger() = default;
    ~DebugLogger();

    void OpenDebugLog(const char* filename = nullptr);

    void Log(DebugStream stream, const char* fmt, ...) __attribute__((format(printf, 3, 4)));
    void Log(const plugin::Plugin& plugin, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

    void PushIndent(DebugStream stream) { ++streams[stream].indent; }
    void PopIndent(DebugStream stream) { --streams[stream].indent; }

    void EnableStream(DebugStream stream) { streams[stream].enabled = true; }
    void DisableStream(DebugStream stream) { streams[stream].enabled = false; }


    void EnableStreams(const char* streams);


    bool CheckStreams(const std::set<std::string>& plugin_names);

    bool IsEnabled(DebugStream stream) const { return streams[stream].enabled; }


    bool HasEnabledStreams() const { return ! enabled_streams.empty(); }

    void SetVerbose(bool arg_verbose) { verbose = arg_verbose; }
    bool IsVerbose() const { return verbose; }

    void ShowStreamsHelp();

private:
    FILE* file = nullptr;
    bool all = false;
    bool verbose = false;

    struct Stream {
        const char* prefix = nullptr;
        int indent = 0;
        bool enabled = false;
    };

    std::set<std::string> enabled_streams;

    static Stream streams[NUM_DBGS];



    std::string PluginStreamName(const std::string& plugin_name) const;
};

ZEEK_EXTERN_DATA DebugLogger debug_logger;

}

}
