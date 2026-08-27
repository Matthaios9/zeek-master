




#pragma once

#include <cstdint>
#include <cstdlib>
#include <deque>
#include <string>
#include <vector>


#include "DebugCmdConstants.h"

namespace zeek::detail {

class DebugCmdInfo {
public:
    DebugCmdInfo(const DebugCmdInfo& info);

    DebugCmdInfo(DebugCmd cmd, const char* const* names, int num_names, bool resume_execution,
                 const char* const helpstring, bool repeatable);

    DebugCmdInfo() : helpstring(nullptr) {}

    int Cmd() const { return cmd; }
    int NumNames() const { return num_names; }
    const std::vector<const char*>& Names() const { return names; }
    bool ResumeExecution() const { return resume_execution; }
    const char* Helpstring() const { return helpstring; }
    bool Repeatable() const { return repeatable; }

protected:
    DebugCmd cmd;

    int32_t num_names;
    std::vector<const char*> names;
    const char* const helpstring;


    bool resume_execution;


    bool repeatable;
};

using DebugCmdInfoQueue = std::deque<DebugCmdInfo*>;
extern DebugCmdInfoQueue g_DebugCmdInfos;

void init_global_dbg_constants();

extern int num_debug_cmds();


const DebugCmdInfo* get_debug_cmd_info(DebugCmd cmd);






int find_all_matching_cmds(const std::string& prefix, const char* array_of_matches[]);







typedef int DbgCmdFn(DebugCmd cmd, const std::vector<std::string>& args);

DbgCmdFn dbg_cmd_backtrace;
DbgCmdFn dbg_cmd_frame;
DbgCmdFn dbg_cmd_help;
DbgCmdFn dbg_cmd_break;
DbgCmdFn dbg_cmd_break_condition;
DbgCmdFn dbg_cmd_break_set_state;
DbgCmdFn dbg_cmd_print;
DbgCmdFn dbg_cmd_info;
DbgCmdFn dbg_cmd_list;
DbgCmdFn dbg_cmd_trace;

}
