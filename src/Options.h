

#pragma once

#include <optional>
#include <string>
#include <vector>

#include "zeek/DNS_Mgr.h"
#include "zeek/script_opt/ScriptOpt.h"

namespace zeek {





struct Options {





    void filter_supervisor_options();





    void filter_supervised_node_options();

    bool print_version = false;
    bool print_build_info = false;
    bool print_usage = false;
    bool print_execution_time = false;
    bool print_signature_debug_info = false;
    int print_plugins = 0;

    std::optional<std::string> debug_log_streams;
    std::optional<std::string> debug_script_tracing_file;

    std::optional<std::string> identifier_to_print;
    std::optional<std::string> script_code_to_exec;
    std::vector<std::string> script_prefixes = {""};

    int signature_re_level = 4;
    bool ignore_checksums = false;
    bool use_watchdog = false;
    double pseudo_realtime = 0;
    detail::DNS_MgrMode dns_mode = detail::DNS_DEFAULT;

    bool supervisor_mode = false;
    bool parse_only = false;
    bool bare_mode = false;
    bool debug_scripts = false;
    bool perftools_check_leaks = false;
    bool perftools_profile = false;
    bool deterministic_mode = false;
    bool abort_on_scripting_errors = false;
    bool no_unused_warnings = false;

    bool run_unit_tests = false;
    std::vector<std::string> doctest_args;

    std::optional<std::string> pcap_filter;
    std::optional<std::string> interface;
    std::optional<std::string> pcap_file;
    std::vector<std::string> signature_files;

    std::optional<std::string> pcap_output_file;
    std::optional<std::string> random_seed_input_file;
    std::optional<std::string> random_seed_output_file;
    std::optional<std::string> process_status_file;
    std::optional<std::string> zeekygen_config_file;
    std::optional<std::string> unprocessed_output_file;
    std::optional<std::string> event_trace_file;

    std::set<std::string> plugins_to_load;
    std::vector<std::string> scripts_to_load;
    std::vector<std::string> script_options_to_set;

    std::vector<std::string> script_args;


    detail::AnalyOpt analysis_options;
};







Options parse_cmdline(int argc, char** argv);





void usage(const char* prog);




bool fake_dns();

}
