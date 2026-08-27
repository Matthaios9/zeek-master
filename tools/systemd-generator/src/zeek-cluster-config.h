

#pragma once






#include <cassert>
#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "utils.h"

namespace zeek::detail {

class Section;






















std::pair<std::vector<Section>, std::vector<std::string>> parse_ini_like(const std::string& content);

class ZeekClusterConfig;









ZeekClusterConfig parse_config(const std::filesystem::path& default_zeek_base_dir, const std::filesystem::path& file);




class EnvVar {
public:
    EnvVar(std::string key, std::string value) : key(std::move(key)), value(std::move(value)) {}

    const std::string& Key() const { return key; }
    const std::string& Value() const { return value; }

private:
    std::string key;
    std::string value;
};







struct Option {
public:
    Option(std::string key, std::string value) : key(std::move(key)) { values.push_back(std::move(value)); }

    const std::string& Key() const { return key; }
    const std::string& Value() const {
        if ( values.size() > 1 )
            throw std::logic_error("ignoring extra values from " + key);

        return values[0];
    }

    void AddValue(std::string value) { values.push_back(std::move(value)); }

    std::span<const std::string> Values() const { return values; }

    std::string JoinedValues() const { return join(values); };







    std::pair<std::vector<EnvVar>, std::string> AsEnvVars() const {
        std::vector<EnvVar> envs;
        for ( const auto& value : values ) {
            if ( value.empty() )
                continue;

            auto idx = value.find('=');
            if ( idx == std::string::npos )
                return {{}, "invalid env value '" + value + "'"};

            std::string k = value.substr(0, idx);
            std::string v = value.substr(idx + 1);
            envs.emplace_back(EnvVar(std::move(k), std::move(v)));
        }

        return {std::move(envs), ""};
    }




    bool Empty() const { return values.size() == 0 || (values.size() == 1 && values[0].empty()); }

private:
    std::string key;
    std::vector<std::string> values;
};




class Section {
public:
    Section() {}
    explicit Section(std::string name) : name(std::move(name)) {}

    const std::string& Name() const { return name; }
    std::span<const Option> Options() const { return {options.begin(), options.end()}; }
    bool IsUnnamed() const { return name.empty(); }
    bool HasOptions() const { return ! options.empty(); }






    Option* AddOption(Option o) {
        options.push_back(std::move(o));
        return &(*std::prev(options.end()));
    }

private:
    std::string name;
    std::vector<Option> options;
};










class InterfaceWorkerConfig {
public:








    static std::pair<InterfaceWorkerConfig, std::string> from_section(const Section& section,
                                                                      bool allow_unknown_options = false);




    const std::string& Name() const { return section_name; }

    const std::string& Interface() const { return interface; }

    int Workers() const { return workers; }




    std::string FullWorkerName(int index) const {
        if ( index <= 0 || index > Workers() )
            throw std::logic_error("bad index: " + std::to_string(index));

        return FullWorkerName(std::to_string(index));
    }




    std::filesystem::path MakeWorkingDirectory(const std::filesystem::path& spool_dir,
                                               const std::string& suffix) const {
        return spool_dir / FullWorkerName(suffix);
    }

    const std::string& Args() const { return args; }

    const std::optional<std::string>& MemoryMax() const { return memory_max; }

    std::optional<int> Nice() const { return nice; }

    std::string AffinityFor(int index) const { return cpu_list.CpuAtIndex(index); }

    std::optional<const std::string> NumaPolicy() const { return numa_policy; }

    std::span<const EnvVar> Env() const { return std::span{env}; }

private:
    InterfaceWorkerConfig(std::string name = "") : section_name(std::move(name)) {}

    std::string FullWorkerName(const std::string& suffix) const {
        if ( ! Name().empty() )
            return "worker-" + Name() + "-" + suffix;

        return "worker-" + suffix;
    }

    std::string section_name;
    std::string interface;
    int workers = -1;

    std::string args;
    std::vector<EnvVar> env;

    std::optional<int> nice;
    std::optional<std::string> memory_max;
    CpuList cpu_list;
    std::optional<std::string> numa_policy;
};






class ZeekClusterConfig {
public:
    ZeekClusterConfig(std::filesystem::path base_dir, std::filesystem::path source_path)
        : zeek_base_dir(std::move(base_dir)), source_path(std::move(source_path)) {}

    const std::filesystem::path& SourcePath() const { return source_path; }

    void SetExists() { exists = true; }

    bool Exists() const { return exists; }

    bool IsValid() const { return errors.empty(); }




    bool HasFilenameHost() const;




    std::string FilenameHost() const;




    std::filesystem::path Directory() const { return source_path.parent_path(); }




    void Error(std::string msg) { errors.emplace_back(std::move(msg)); }

    std::span<const std::string> Errors() const { return errors; }

    const std::filesystem::path& ZeekBaseDir() const { return zeek_base_dir; }

    std::filesystem::path ZeekExe() const { return zeek_base_dir / "bin" / "zeek"; }

    std::filesystem::path BinDir() const { return ZeekBaseDir() / "bin"; };

    std::filesystem::path SpoolDir() const { return ZeekBaseDir() / "var" / "spool" / "zeek"; }




    std::filesystem::path LogArchiveDir() const { return ZeekBaseDir() / "var" / "logs" / "zeek"; }

    std::filesystem::path GeneratedScriptsDir() const { return SpoolDir() / "generated-scripts"; }

    std::filesystem::path WorkingDirectory(const std::string& wdir) const { return SpoolDir() / wdir; }




    std::string MakeWorkingDirectoryCommand(const std::string& wdir) const {
        return "mkdir -p " + WorkingDirectory(wdir).string();
    }




    std::string ChownWorkingDirectoryCommand(const std::string& wdir) const {
        return "chown " + User() + ":" + Group() + " " + WorkingDirectory(wdir).string();
    }




    std::filesystem::path LogQueueDir() const { return SpoolDir() / "log-queue"; }




    bool Manager() const { return manager; }




    int Loggers() const { return loggers; }




    int Proxies() const { return proxies; }




    int Workers() const {
        int result = 0;
        for ( const auto& iwc : interface_worker_configs )
            result += iwc.Workers();
        return result;
    }

    const std::vector<InterfaceWorkerConfig>& InterfaceWorkerConfigs() const { return interface_worker_configs; }




    std::string ZeekPath() const;




    const std::string& Args() const { return args; }
    const std::string& ManagerArgs() const { return manager_args; }
    const std::string& LoggerArgs() const { return logger_args; }
    const std::string& ProxyArgs() const { return proxy_args; }

    std::span<const EnvVar> Env() const { return std::span{env}; }
    std::span<const EnvVar> ManagerEnv() const { return std::span{manager_env}; }
    std::span<const EnvVar> LoggerEnv() const { return std::span{logger_env}; }
    std::span<const EnvVar> ProxyEnv() const { return std::span{proxy_env}; }
    std::span<const EnvVar> ArchiverEnv() const { return std::span{archiver_env}; }

    std::optional<CpuList> ManagerCpuSet() const { return manager_cpu_set; }
    std::optional<CpuList> LoggerCpuSet() const { return logger_cpu_set; }
    std::optional<CpuList> ProxyCpuSet() const { return proxy_cpu_set; }
    std::optional<CpuList> ArchiverCpuSet() const { return archiver_cpu_set; }

    std::optional<int> ManagerNice() const { return manager_nice; }
    std::optional<int> LoggerNice() const { return logger_nice; }
    std::optional<int> ProxyNice() const { return proxy_nice; }
    std::optional<int> ArchiverNice() const { return archiver_nice; }

    const std::optional<std::string>& ManagerMemoryMax() const { return manager_memory_max; }
    const std::optional<std::string>& LoggerMemoryMax() const { return logger_memory_max; }
    const std::optional<std::string>& ProxyMemoryMax() const { return proxy_memory_max; }
    const std::optional<std::string>& ArchiverMemoryMax() const { return archiver_memory_max; }




    const std::string& ClusterBackendArgs() const { return cluster_backend_args; }





    std::string PrefixedClusterNode(const std::string& s) const {
        if ( cluster_node_prefix && ! cluster_node_prefix->empty() )
            return *cluster_node_prefix + "-" + s;

        return s;
    }






    std::string Path() const;

    const std::string& User() const { return user; }
    const std::string& Group() const { return group; }

    int RestartIntervalSec() const { return restart_interval_sec; }




    bool IsArchiverEnabled() const { return archiver_option.has_value() && *archiver_option != "0"; }




    const std::string& ArchiverArgs() const { return archiver_args; }








    std::string ClusterLayoutCommand() const;

    const std::string& ClusterAddress() const { return cluster_address; }
    int ClusterPort() const { return cluster_port; }

    int MetricsPort() const { return metrics_port; };








    std::string ArchiverCommand() const;

private:
    friend ZeekClusterConfig parse_config(const std::filesystem::path&, const std::filesystem::path&);
    std::filesystem::path zeek_base_dir;
    std::filesystem::path source_path;
    bool exists = false;

    bool manager = false;
    int loggers = -1;
    int proxies = -1;

    std::string args;
    std::string manager_args;
    std::string logger_args;
    std::string proxy_args;

    std::vector<EnvVar> env;
    std::vector<EnvVar> manager_env;
    std::vector<EnvVar> logger_env;
    std::vector<EnvVar> proxy_env;

    std::optional<CpuList> manager_cpu_set;
    std::optional<CpuList> logger_cpu_set;
    std::optional<CpuList> proxy_cpu_set;

    std::string user = "zeek";
    std::string group = "zeek";

    std::string path = "/usr/local/bin:/usr/bin:/bin";
    std::string ext_path = "";

    std::string ext_zeek_path;

    int start_limit_interval_sec = 0;

    std::optional<int> manager_nice;
    std::optional<int> logger_nice;
    std::optional<int> proxy_nice;
    std::optional<int> worker_nice;
    std::optional<int> archiver_nice;

    std::optional<std::string> manager_memory_max;
    std::optional<std::string> logger_memory_max;
    std::optional<std::string> proxy_memory_max;
    std::optional<std::string> worker_memory_max;
    std::optional<std::string> archiver_memory_max;

    std::vector<InterfaceWorkerConfig> interface_worker_configs;

    std::string restart = "always";
    int restart_sec = 1;


    std::string cluster_backend_args;

    int cluster_port = 27760;
    std::string cluster_address;


    int metrics_port = 9991;

    int restart_interval_sec = 1;



    std::optional<std::string> archiver_option;
    std::string archiver_args;
    std::vector<EnvVar> archiver_env;
    std::optional<CpuList> archiver_cpu_set;

    std::filesystem::path cluster_layout_generator;


    std::optional<std::filesystem::path> cluster_layout;


    std::optional<std::string> cluster_node_prefix;

    std::vector<std::string> errors;
};

ZeekClusterConfig parse_config(const std::filesystem::path& zeek_base_dir, const std::filesystem::path& source_path);




std::optional<std::string> gethostname();
}
