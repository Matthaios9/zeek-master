




#include <unistd.h>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <initializer_list>
#include <map>
#include <ranges>
#include <string>
#include <system_error>

#include "systemd-unit.h"
#include "zeek-cluster-config.h"

namespace {

using path = std::filesystem::path;
using Unit = zeek::detail::systemd::Unit;
using ZeekClusterConfig = zeek::detail::ZeekClusterConfig;
using EnvVar = zeek::detail::EnvVar;




std::string systemd_generator_policy_scripts() {

    return "policy/misc/systemd-generator";
}




std::string systemd_unit_name(const std::string& name, int idx = 0) {
    std::string result = "zeek-";
    result += name;
    if ( idx > 0 ) {
        result += "@";
        result += std::to_string(idx);
    }
    return result + ".service";
}







void ensure_symlink(const path& to, const path& new_link) {
    std::error_code ec;
    std::filesystem::create_symlink(to, new_link, ec);
    if ( ec.value() == EEXIST ) {
        std::filesystem::remove(new_link);
        std::filesystem::create_symlink(to, new_link);
    }
}


void systemd_add_environment(Unit& unit, const ZeekClusterConfig& config, std::span<const EnvVar> custom_env,
                             const std::map<std::string, std::string>& vars = {}) {

    for ( const auto& env : std::array{config.Env(), custom_env} | std::views::join ) {
        auto value = zeek::detail::substitute_vars(env.Value(), vars);
        if ( ! value ) {
            std::fprintf(stderr, "worker_env substitution for '%s' failed of '%s'\n", env.Value().c_str(),
                         env.Key().c_str());
            std::exit(1);
        }

        unit.AddEnvironment(env.Key(), std::move(*value));
    }
}

Unit systemd_add_node_unit(const path& file, const std::string& description, const ZeekClusterConfig& config,
                           const std::string& extra_args) {
    auto unit = Unit(file, description, config.SourcePath());
    unit.AddStopPropagatedFrom("zeek.target");
    unit.SetUser(config.User());
    unit.SetGroup(config.Group());
    unit.AddAfter("zeek-setup.service");
    unit.AddEnvironment("PATH", config.Path());
    unit.AddEnvironment("ZEEKPATH", config.ZeekPath());


    unit.AddExecStart(config.ZeekExe().string(),
                      {config.ClusterBackendArgs(), systemd_generator_policy_scripts(), extra_args, config.Args()});

    unit.SetRestart("always");
    unit.SetRestartSec(config.RestartIntervalSec());


    unit.SetStartLimitIntervalSec("0");

    return unit;
}







void systemd_write_units(const path& dir, const ZeekClusterConfig& config) {


    std::error_code ec;

    auto zeek_target_wants = dir / "zeek.target.wants";
    if ( std::filesystem::create_directory(zeek_target_wants, ec); ec ) {
        std::fprintf(stderr, "failed to create directory %s: %s\n", zeek_target_wants.string().c_str(),
                     ec.message().c_str());
        std::exit(1);
    }

    std::string target_desc = "The Zeek Network Security Monitor";
    auto target_unit = Unit(dir / "zeek.target", std::move(target_desc), config.SourcePath());


    auto setup_unit = Unit(dir / "zeek-setup.service", "Zeek Setup", config.SourcePath());
    setup_unit.SetPartOf("zeek.target");
    setup_unit.SetServiceType("oneshot");
    setup_unit.SetStartLimitIntervalSec("0");
    setup_unit.AddExecStart("mkdir -p " + config.GeneratedScriptsDir().string());
    setup_unit.AddExecStart(config.ClusterLayoutCommand());
    setup_unit.AddExecStart("mkdir -p " + (config.LogArchiveDir()).string());
    setup_unit.AddExecStart("chown " + config.User() + ":" + config.Group() + " " + config.LogArchiveDir().string());
    setup_unit.AddExecStart("mkdir -p " + config.LogQueueDir().string());
    setup_unit.AddExecStart("chown " + config.User() + ":" + config.Group() + " " + config.LogQueueDir().string());
    setup_unit.SetRemainAfterExit(true);

    ensure_symlink("../zeek-setup.service", zeek_target_wants / "zeek-setup.service");


    if ( config.Manager() ) {
        auto manager_unit =
            systemd_add_node_unit(dir / "zeek-manager.service", "Zeek Manager", config, config.ManagerArgs());

        manager_unit.AddEnvironment("CLUSTER_NODE", "manager");
        manager_unit.SetSyslogIdentifier("zeek-manager");
        manager_unit.SetWorkingDirectory(config.WorkingDirectory("manager"));






        manager_unit.AddReadWritePath(config.ZeekBaseDir() / "var");
        manager_unit.AddAfter("zeek-logger@.service");
        manager_unit.SetSlice("zeek-manager.slice");
        if ( auto memory_max = config.ManagerMemoryMax(); memory_max )
            manager_unit.SetMemoryMax(*memory_max);
        if ( auto nice = config.ManagerNice(); nice )
            manager_unit.SetNice(*nice);
        if ( auto cpuset = config.ManagerCpuSet(); cpuset )
            manager_unit.SetCpuAffinity(cpuset->IndicesSetString());
        systemd_add_environment(manager_unit, config, config.ManagerEnv());
        manager_unit.Write();

        setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand("manager"));
        setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand("manager"));
        ensure_symlink("../zeek-manager.service", zeek_target_wants / "zeek-manager.service");
    }


    if ( config.Loggers() > 0 ) {

        auto logger_unit =
            systemd_add_node_unit(dir / "zeek-logger@.service", "Zeek Logger %i", config, config.LoggerArgs());
        logger_unit.AddEnvironment("CLUSTER_NODE", config.PrefixedClusterNode("logger-%i"));
        logger_unit.SetSyslogIdentifier("zeek-logger-%i");
        logger_unit.SetWorkingDirectory(config.WorkingDirectory("logger-%i"));
        logger_unit.AddReadWritePath(config.WorkingDirectory("logger-%i"));





        logger_unit.AddReadWritePath(config.ZeekBaseDir() / "var");
        logger_unit.SetSlice("zeek-loggers.slice");
        if ( auto memory_max = config.LoggerMemoryMax(); memory_max )
            logger_unit.SetMemoryMax(*memory_max);
        if ( auto nice = config.LoggerNice(); nice )
            logger_unit.SetNice(*nice);
        if ( auto cpuset = config.LoggerCpuSet(); cpuset )
            logger_unit.SetCpuAffinity(cpuset->IndicesSetString());
        systemd_add_environment(logger_unit, config, config.LoggerEnv());
        logger_unit.Write();


        for ( int idx = 1; idx <= config.Loggers(); idx++ ) {
            auto wdir = "logger-" + std::to_string(idx);
            setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand(wdir));
            setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand(wdir));
            auto name = systemd_unit_name("logger", idx);
            ensure_symlink("../zeek-logger@.service", zeek_target_wants / name);
        }
    }

    if ( config.Proxies() > 0 ) {

        auto proxy_unit =
            systemd_add_node_unit(dir / "zeek-proxy@.service", "Zeek Proxy %i", config, config.ProxyArgs());
        proxy_unit.AddEnvironment("CLUSTER_NODE", config.PrefixedClusterNode("proxy-%i"));
        proxy_unit.SetSyslogIdentifier("zeek-proxy-%i");
        proxy_unit.SetWorkingDirectory(config.WorkingDirectory("proxy-%i"));
        proxy_unit.AddReadWritePath(config.WorkingDirectory("proxy-%i"));
        proxy_unit.AddAfter("zeek-logger@.service");
        proxy_unit.SetSlice("zeek-proxies.slice");
        if ( auto memory_max = config.ProxyMemoryMax(); memory_max )
            proxy_unit.SetMemoryMax(*memory_max);
        if ( auto nice = config.ProxyNice(); nice )
            proxy_unit.SetNice(*nice);
        if ( auto cpuset = config.ProxyCpuSet(); cpuset )
            proxy_unit.SetCpuAffinity(cpuset->IndicesSetString());
        systemd_add_environment(proxy_unit, config, config.ProxyEnv());
        proxy_unit.Write();


        for ( int idx = 1; idx <= config.Proxies(); idx++ ) {
            auto wdir = "proxy-" + std::to_string(idx);
            setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand(wdir));
            setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand(wdir));

            auto name = systemd_unit_name("proxy", idx);
            ensure_symlink("../zeek-proxy@.service", zeek_target_wants / name);
        }
    }

    if ( config.Workers() > 0 ) {

        int host_worker_index = 0;
        for ( const auto& iwc : config.InterfaceWorkerConfigs() ) {




            std::string worker_cluster_node = "worker";
            std::string worker_unit_prefix = "zeek-worker";
            std::string worker_unit_description = "Zeek Worker %i";



            if ( ! iwc.Name().empty() ) {
                worker_cluster_node = worker_cluster_node + "-" + iwc.Name();
                worker_unit_prefix = worker_unit_prefix + "-" + iwc.Name();
                worker_unit_description = worker_unit_description + " (" + iwc.Name() + ")";
            }

            std::string worker_template_unit = worker_unit_prefix + "@.service";


            auto worker_interface_unit =
                systemd_add_node_unit(dir / worker_template_unit, std::move(worker_unit_description), config, {});

            worker_interface_unit.SetExecStart(config.ZeekExe().string(),
                                               {"-i", "${INTERFACE}", config.ClusterBackendArgs(),
                                                systemd_generator_policy_scripts(), iwc.Args(), config.Args()});
            worker_interface_unit.AddEnvironment("CLUSTER_NODE",
                                                 config.PrefixedClusterNode(worker_cluster_node + "-%i"));
            worker_interface_unit.SetSyslogIdentifier(worker_unit_prefix + "-%i");

            if ( config.Manager() )
                worker_interface_unit.AddAfter("zeek-manager.service");
            if ( config.Loggers() > 0 )
                worker_interface_unit.AddAfter("zeek-logger@.service");
            if ( config.Proxies() > 0 )
                worker_interface_unit.AddAfter("zeek-proxy@.service");

            worker_interface_unit.SetAmbientCapabilities("CAP_NET_RAW");
            worker_interface_unit.SetCapabilityBoundingSet("CAP_NET_RAW");
            worker_interface_unit.SetSlice("zeek-workers.slice");
            if ( auto memory_max = iwc.MemoryMax(); memory_max )
                worker_interface_unit.SetMemoryMax(*memory_max);
            if ( auto nice = iwc.Nice(); nice )
                worker_interface_unit.SetNice(*nice);


            worker_interface_unit.SetWorkingDirectory(iwc.MakeWorkingDirectory(config.SpoolDir(), "%i"));
            worker_interface_unit.AddReadWritePath(iwc.MakeWorkingDirectory(config.SpoolDir(), "%i"));

            worker_interface_unit.Write();



            for ( int index = 1; index <= iwc.Workers(); index++ ) {
                ++host_worker_index;

                setup_unit.AddExecStart(config.MakeWorkingDirectoryCommand(iwc.FullWorkerName(index)));
                setup_unit.AddExecStart(config.ChownWorkingDirectoryCommand(iwc.FullWorkerName(index)));

                auto name = worker_unit_prefix + "@" + std::to_string(index) + ".service";
                ensure_symlink("../" + worker_template_unit, zeek_target_wants / name);



                auto d_dir = dir / (name + ".d");
                std::filesystem::create_directories(d_dir);
                auto unit = Unit(d_dir / "10-zeek-systemd-generator.conf", config.SourcePath());


                std::map<std::string, std::string> vars = {
                    {"worker_index", std::to_string(index)},
                    {"worker_index0", std::to_string(index - 1)},
                    {"host_worker_index", std::to_string(host_worker_index)},
                    {"host_worker_index0", std::to_string(host_worker_index - 1)},
                };

                std::string cpu = iwc.AffinityFor(host_worker_index);
                if ( ! cpu.empty() )
                    vars["worker_cpu"] = cpu;

                if ( ! iwc.Name().empty() )
                    vars["interface_section_name"] = iwc.Name();

                auto interface = zeek::detail::substitute_vars(iwc.Interface(), vars);
                if ( ! interface.has_value() ) {
                    std::fprintf(stderr, "interface substitution for '%s' failed\n", iwc.Interface().c_str());
                    std::exit(1);
                }

                unit.AddEnvironment("INTERFACE", *interface);

                if ( ! cpu.empty() )
                    unit.SetCpuAffinity(std::move(cpu));

                if ( auto numa_policy = iwc.NumaPolicy(); numa_policy )
                    unit.SetNumaPolicy(std::move(*numa_policy));

                systemd_add_environment(unit, config, iwc.Env(), vars);

                unit.WriteDropIn();
            }
        }
    }

    target_unit.Write();
    setup_unit.Write();


    if ( config.IsArchiverEnabled() ) {
        auto archiver_unit = Unit(dir / "zeek-archiver.service", "Zeek Archiver", config.SourcePath());
        archiver_unit.SetPartOf("zeek.target");
        archiver_unit.SetSyslogIdentifier("zeek-archiver");
        archiver_unit.SetWorkingDirectory(config.SpoolDir());
        archiver_unit.SetStartLimitIntervalSec("0");
        archiver_unit.SetExecStart(config.ArchiverCommand());
        archiver_unit.SetUser(config.User());
        archiver_unit.SetGroup(config.Group());
        archiver_unit.AddAfter("zeek-setup.service");


        archiver_unit.AddReadWritePath(config.LogQueueDir());
        archiver_unit.AddReadWritePath(config.LogArchiveDir());

        archiver_unit.SetRestart("always");
        archiver_unit.SetRestartSec(config.RestartIntervalSec());

        if ( auto memory_max = config.ArchiverMemoryMax(); memory_max )
            archiver_unit.SetMemoryMax(*memory_max);
        if ( auto nice = config.ArchiverNice(); nice )
            archiver_unit.SetNice(*nice);
        if ( auto cpuset = config.ArchiverCpuSet(); cpuset )
            archiver_unit.SetCpuAffinity(cpuset->IndicesSetString());

        systemd_add_environment(archiver_unit, config, config.ArchiverEnv());

        archiver_unit.SetSlice("zeek-archiver.slice");

        archiver_unit.Write();

        ensure_symlink("../zeek-archiver.service", zeek_target_wants / "zeek-archiver.service");
    }
}


}

int main(int argc, const char* argv[]) {
    const char* program = argv[0];
    bool explicit_config = false;



    std::filesystem::path config_file = std::string(DEFAULT_ETC_DIR) + "/zeek/zeek.conf";



    std::filesystem::path cluster_config_file;
    if ( auto hostname = zeek::detail::gethostname(); hostname.has_value() )
        cluster_config_file = std::string(DEFAULT_ETC_DIR) + "/zeek/cluster/" + *hostname + ".zeek.conf";


    if ( argc >= 3 && std::string_view(argv[1]) == "--config" ) {
        config_file = std::filesystem::weakly_canonical(argv[2]);
        explicit_config = true;

        argc -= 2;
        argv = &argv[2];
    }


    else if ( ! cluster_config_file.empty() && std::filesystem::is_regular_file(cluster_config_file) ) {
        config_file = cluster_config_file;
    }

    std::string_view normal_dir;
    if ( argc == 2 || argc == 4 ) {
        normal_dir = argv[1];
    }
    else {
        std::fprintf(stderr, "Usage: %s [--config test-config] normal-dir [early-dir] [late-dir]\n", program);
        std::exit(1);
    }

    auto config = zeek::detail::parse_config(DEFAULT_BASE_DIR, config_file);
    if ( ! config.Exists() ) {
        if ( explicit_config ) {
            std::fprintf(stderr, "config %s does not exist\n", config_file.c_str());
            return 1;
        }

        return 0;
    }

    if ( ! config.IsValid() ) {
        FILE* out = stderr;
        int stderr_fd = fileno(stderr);
        std::unique_ptr<FILE, int (*)(std::FILE*)> kmsg{nullptr, nullptr};



        if ( ! explicit_config && ! isatty(stderr_fd) ) {
            kmsg = {std::fopen("/dev/kmsg", "a"), &std::fclose};
            if ( kmsg )
                out = kmsg.get();
        }

        std::fprintf(out, "%s: config %s is invalid\n", program, config_file.c_str());
        std::fflush(out);
        for ( const auto& error : config.Errors() ) {
            fprintf(out, "%s: %s\n", program, error.c_str());
            std::fflush(out);
        }

        return 1;
    }

    systemd_write_units(normal_dir, config);

    return 0;
}
