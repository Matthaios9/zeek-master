

#pragma once

#include "zeek/zeek-config.h"

#include <cstdarg>
#include <exception>
#include <list>
#include <map>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "zeek/ZeekList.h"
#include "zeek/net_util.h"

namespace zeek {

class Connection;
class EventHandlerPtr;
class RecordVal;
class StringVal;
class IPAddr;
class Reporter;

template<class T>
class IntrusivePtr;
using RecordValPtr = IntrusivePtr<RecordVal>;
using StringValPtr = IntrusivePtr<StringVal>;

namespace detail {

class AssertStmt;
class Expr;
class Frame;
class Location;

}

namespace analyzer {
class Analyzer;
}
namespace file_analysis {
class File;
}




class ReporterException : public std::exception {
protected:
    friend class Reporter;
    ReporterException() = default;
};

class InterpreterException : public ReporterException {
protected:
    friend class Reporter;
    friend class detail::AssertStmt;
    InterpreterException() = default;
};

#define FMT_ATTR __attribute__((format(printf, 2, 3)))

class Reporter {
public:
    using IPPair = std::pair<IPAddr, IPAddr>;
    using ConnTuple = std::tuple<IPAddr, IPAddr, uint32_t, uint32_t, TransportProto>;
    using WeirdCountMap = std::unordered_map<std::string, uint64_t>;
    using WeirdFlowMap = std::map<IPPair, WeirdCountMap>;
    using WeirdConnTupleMap = std::map<ConnTuple, WeirdCountMap>;
    using WeirdSet = std::unordered_set<std::string>;

    Reporter(bool abort_on_scripting_errors);
    ~Reporter();


    void InitOptions();



    void Info(const char* fmt, ...) FMT_ATTR;


    void Warning(const char* fmt, ...) FMT_ATTR;



    void Error(const char* fmt, ...) FMT_ATTR;


    int Errors() { return errors; }



    [[noreturn]] void FatalError(const char* fmt, ...) FMT_ATTR;



    [[noreturn]] void FatalErrorWithCore(const char* fmt, ...) FMT_ATTR;



    [[noreturn]] void ExprRuntimeError(const detail::Expr* expr, const char* fmt, ...)
        __attribute__((format(printf, 3, 4)));



    [[noreturn]] void RuntimeError(const detail::Location* location, const char* fmt, ...)
        __attribute__((format(printf, 3, 4)));


    void ExprRuntimeWarning(const detail::Expr* expr, const char* fmt, ...) __attribute__((format(printf, 3, 4)));



    [[noreturn]] void CPPRuntimeError(const char* fmt, ...) __attribute__((format(printf, 2, 3)));


    void CPPRuntimeWarning(const char* fmt, ...) __attribute__((format(printf, 2, 3)));



    void Weird(const char* name, const char* addl = "",
               const char* source = "");
    void Weird(file_analysis::File* f, const char* name, const char* addl = "",
               const char* source = "");
    void Weird(Connection* conn, const char* name, const char* addl = "",
               const char* source = "");
    void Weird(RecordValPtr conn_id, StringValPtr uid, const char* name, const char* addl = "",
               const char* source = "");
    void Weird(const IPAddr& orig, const IPAddr& resp, const char* name, const char* addl = "",
               const char* source = "");


    void Deprecation(std::string_view msg, const detail::Location* loc1 = nullptr,
                     const detail::Location* loc2 = nullptr);


    void SetIgnoreDeprecations(bool arg) { ignore_deprecations = arg; }



    void Syslog(const char* fmt, ...) FMT_ATTR;



    void InternalWarning(const char* fmt, ...) FMT_ATTR;



    [[noreturn]] void InternalError(const char* fmt, ...) FMT_ATTR;



    void AnalyzerError(analyzer::Analyzer* a, const char* fmt, ...) __attribute__((format(printf, 3, 4)));




    void ReportViaEvents(bool arg_via_events) { via_events = arg_via_events; }





    void PushLocation(const detail::Location* location) { locations.emplace_back(location, nullptr); }

    void PushLocation(const detail::Location* loc1, const detail::Location* loc2) {
        locations.emplace_back(loc1, loc2);
    }


    void PopLocation() { locations.pop_back(); }


    void BeginErrorHandler() { ++in_error_handler; }


    void EndErrorHandler() { --in_error_handler; }




    void ResetNetWeird(const std::string& name);




    void ResetFlowWeird(const IPAddr& orig, const IPAddr& resp);




    void ResetExpiredConnWeird(const ConnTuple& id);





    uint64_t GetWeirdCount() const { return weird_count; }





    const WeirdCountMap& GetWeirdsByType() const { return weird_count_by_type; }




    const WeirdSet& GetWeirdSamplingWhitelist() const { return weird_sampling_whitelist; }






    void SetWeirdSamplingWhitelist(WeirdSet weird_sampling_whitelist) {
        this->weird_sampling_whitelist = std::move(weird_sampling_whitelist);
    }




    const WeirdSet& GetWeirdSamplingGlobalList() const { return weird_sampling_global_list; }






    void SetWeirdSamplingGlobalList(WeirdSet weird_sampling_global_list) {
        this->weird_sampling_global_list = std::move(weird_sampling_global_list);
    }






    uint64_t GetWeirdSamplingThreshold() const { return weird_sampling_threshold; }






    void SetWeirdSamplingThreshold(uint64_t weird_sampling_threshold) {
        this->weird_sampling_threshold = weird_sampling_threshold;
    }






    uint64_t GetWeirdSamplingRate() const { return weird_sampling_rate; }






    void SetWeirdSamplingRate(uint64_t weird_sampling_rate) { this->weird_sampling_rate = weird_sampling_rate; }






    double GetWeirdSamplingDuration() const { return weird_sampling_duration; }







    void SetWeirdSamplingDuration(double weird_sampling_duration) {
        this->weird_sampling_duration = weird_sampling_duration;
    }

private:
    void DoLog(const char* prefix, EventHandlerPtr event, FILE* out, Connection* conn, ValPList* addl, bool location,
               bool time, const char* postfix, const char* fmt, va_list ap) __attribute__((format(printf, 10, 0)));



    void WeirdHelper(EventHandlerPtr event, ValPList vl, const char* fmt_name, ...)
        __attribute__((format(printf, 4, 5)));
    void UpdateWeirdStats(const char* name);
    inline bool WeirdOnSamplingWhiteList(const char* name) { return weird_sampling_whitelist.contains(name); }
    inline bool WeirdOnGlobalList(const char* name) { return weird_sampling_global_list.contains(name); }
    bool PermitNetWeird(const char* name);
    bool PermitFlowWeird(const char* name, const IPAddr& o, const IPAddr& r);
    bool PermitExpiredConnWeird(const char* name, const RecordVal& conn_id);

    enum class PermitWeird : uint8_t { Allow, Deny, Unknown };
    PermitWeird CheckGlobalWeirdLists(const char* name);

    bool EmitToStderr(bool flag);

    int errors;
    int in_error_handler;
    bool via_events;
    bool syslog_open;
    bool info_to_stderr;
    bool warnings_to_stderr;
    bool errors_to_stderr;
    bool abort_on_scripting_errors = false;

    std::list<std::pair<const detail::Location*, const detail::Location*>> locations;

    uint64_t weird_count;
    WeirdCountMap weird_count_by_type;
    WeirdCountMap net_weird_state;
    WeirdFlowMap flow_weird_state;
    WeirdConnTupleMap expired_conn_weird_state;

    WeirdSet weird_sampling_whitelist;
    WeirdSet weird_sampling_global_list;
    uint64_t weird_sampling_threshold;
    uint64_t weird_sampling_rate;
    double weird_sampling_duration;

    bool ignore_deprecations;
};









class ScriptLocationScope {
public:
    ScriptLocationScope(const zeek::detail::Frame* frame);
    ~ScriptLocationScope();
};

ZEEK_EXTERN_DATA Reporter* reporter;

}
