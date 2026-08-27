



#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "zeek/Obj.h"
#include "zeek/StmtEnums.h"

#ifdef _MSC_VER
#include <unistd.h>
#endif

namespace zeek {

class Val;
template<class T>
class IntrusivePtr;
using ValPtr = zeek::IntrusivePtr<Val>;

extern std::string current_module;

namespace detail {

class Frame;
class Stmt;
class DbgBreakpoint;
class DbgWatch;
class DbgDisplay;


enum ParseLocationRecType : uint8_t { PLR_UNKNOWN, PLR_FILE_AND_LINE, PLR_FUNCTION };
class ParseLocationRec {
public:
    ParseLocationRecType type;
    int32_t line;
    Stmt* stmt;
    const char* filename;
};

class StmtLocMapping;
using Filemap = std::deque<StmtLocMapping*>;

using BPIDMapType = std::map<int, DbgBreakpoint*>;
using BPMapType = std::multimap<const Stmt*, DbgBreakpoint*>;

class TraceState {
public:
    TraceState() {
        dbgtrace = false;
        trace_file = stderr;
    }


    FILE* SetTraceFile(const char* trace_filename);

    bool DoTrace() const { return dbgtrace; }
    void TraceOn();
    void TraceOff();

    int LogTrace(const char* fmt, ...) __attribute__((format(printf, 2, 3)));

protected:
    bool dbgtrace;
    FILE* trace_file;
};

extern TraceState g_trace_state;

class DebuggerState {
public:
    DebuggerState();
    ~DebuggerState();

    int NextBPID() { return next_bp_id++; }
    int NextWatchID() { return next_watch_id++; }
    int NextDisplayID() { return next_display_id++; }

    bool BreakBeforeNextStmt() { return break_before_next_stmt; }
    void BreakBeforeNextStmt(bool dobrk) { break_before_next_stmt = dobrk; }

    bool BreakFromSignal() { return break_from_signal; }
    void BreakFromSignal(bool dobrk) { break_from_signal = dobrk; }






    int curr_frame_idx;

    bool already_did_list;

    Location last_loc;

    BPIDMapType breakpoints;
    std::vector<DbgWatch*> watches;
    std::vector<DbgDisplay*> displays;
    BPMapType breakpoint_map;

protected:
    bool break_before_next_stmt;
    bool break_from_signal;

    int next_bp_id, next_watch_id, next_display_id;

private:
    Frame* dbg_locals;
};



class StmtLocMapping {
public:
    StmtLocMapping() = default;
    StmtLocMapping(const Location* l, Stmt* s) {
        loc = *l;
        stmt = s;
    }

    bool StartsAfter(const StmtLocMapping* m2);
    const Location& Loc() const { return loc; }
    Stmt* Statement() const { return stmt; }

protected:
    Location loc;
    Stmt* stmt = nullptr;
};

extern bool g_policy_debug;
extern DebuggerState g_debugger_state;














std::vector<ParseLocationRec> parse_location_string(const std::string& s);









bool pre_execute_stmt(Stmt* stmt, Frame* f);
bool post_execute_stmt(Stmt* stmt, Frame* f, Val* result, StmtFlowType* flow);




int dbg_init_debugger(const char* cmdfile = nullptr);
int dbg_shutdown_debugger();


int dbg_handle_debug_input();



int dbg_execute_command(const char* cmd);


ValPtr dbg_eval_expr(const char* expr);


std::string get_context_description(const Stmt* stmt, const Frame* frame);

extern Frame* g_dbg_locals;

extern std::map<std::string, Filemap*> g_dbgfilemaps;


int debug_msg(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

}
}
