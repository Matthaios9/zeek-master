

#pragma once

#include "zeek/zeek-config.h"

#include <sys/types.h>
#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "zeek/Flare.h"
#include "zeek/Func.h"
#include "zeek/Options.h"
#include "zeek/Pipe.h"
#include "zeek/Timer.h"
#include "zeek/WinHandle.h"
#include "zeek/iosource/IOSource.h"

namespace zeek {
namespace detail {

struct SupervisorStemHandle;
struct SupervisedNode;
struct SupervisorNode;





struct LineBufferedPipe {




    std::unique_ptr<Pipe> pipe;



    std::string prefix;



    FILE* stream = nullptr;




    std::string buffer;





    void Drain();




    size_t Process();






    void Emit(const char* msg) const;




    FuncPtr hook;
};

}
















class Supervisor : public iosource::IOSource {
public:



    struct Config {





        std::string zeek_exe_path;
    };




    struct NodeConfig {
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif



        NodeConfig() = default;
#ifndef _MSC_VER


        NodeConfig(NodeConfig&) = default;
#endif
        NodeConfig(const NodeConfig&) = default;
        NodeConfig(NodeConfig&&) = default;
        ~NodeConfig() = default;
        NodeConfig& operator=(const NodeConfig&) = default;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif





        static NodeConfig FromRecord(const RecordVal* node_val);





        static NodeConfig FromJSON(std::string_view json);





        std::string ToJSON() const;





        RecordValPtr ToRecord() const;





        std::string name;



        std::optional<std::string> interface;



        std::optional<std::string> pcap_file;



        std::optional<std::string> directory;



        std::optional<std::string> stdout_file;



        std::optional<std::string> stderr_file;



        std::optional<int> cpu_affinity;




        std::optional<bool> bare_mode;




        std::vector<std::string> addl_base_scripts;




        std::vector<std::string> addl_user_scripts;



        std::map<std::string, std::string> env;






        std::string cluster;
    };










    static std::optional<detail::SupervisorStemHandle> CreateStem(bool supervisor_mode);






    static const std::optional<detail::SupervisedNode>& ThisNode() { return supervised_node; }

    using NodeMap = std::map<std::string, detail::SupervisorNode, std::less<>>;






    Supervisor(Config cfg, detail::SupervisorStemHandle stem_handle);




    ~Supervisor() override;





    void InitPostScript();




    int StemPID() const { return stem_pid; }





    const NodeMap& Nodes() { return nodes; }








    RecordValPtr Status(std::string_view node_name);







    std::string Create(const RecordVal* node);






    std::string Create(const Supervisor::NodeConfig& node);







    bool Destroy(std::string_view node_name);







    bool Restart(std::string_view node_name);





    void ObserveChildSignal(int signo);

private:

    double GetNextTimeout() override;
    void Process() override;

    size_t ProcessMessages();

    void HandleChildSignal();

    void ReapStem();

    const char* Tag() override { return "zeek::Supervisor"; }

    static std::optional<detail::SupervisedNode> supervised_node;

    Config config;
    int stem_pid;
#ifdef _MSC_VER
    detail::UniqueWinHandle stem_thread_handle;
#endif
    std::atomic<int> last_signal = -1;
    std::unique_ptr<detail::PipePair> stem_pipe;
    detail::LineBufferedPipe stem_stdout;
    detail::LineBufferedPipe stem_stderr;
    detail::Flare signal_flare;
    NodeMap nodes;
    std::string msg_buffer;
    EventHandlerPtr node_status;
};

namespace detail {



struct SupervisorStemHandle {



    std::unique_ptr<detail::PipePair> pipe;




    std::unique_ptr<detail::Pipe> stdout_pipe;




    std::unique_ptr<detail::Pipe> stderr_pipe;



    int pid = 0;
#ifdef _MSC_VER



    UniqueWinHandle thread_handle;
#endif
};




struct SupervisedNode {





    void Init(Options* options) const;




    Supervisor::NodeConfig config;




    int parent_pid;
};




struct SupervisorNode {




    RecordValPtr ToRecord() const;




    const std::string& Name() const { return config.name; }





    SupervisorNode(Supervisor::NodeConfig arg_config) : config(std::move(arg_config)) {}




    Supervisor::NodeConfig config;



    int pid = 0;
#ifdef _MSC_VER




    detail::UniqueWinHandle process_handle;
#endif




    bool killed = false;



    int exit_status = 0;



    int signal_number = 0;




    int revival_attempts = 0;



    int revival_delay = 1;



    std::chrono::time_point<std::chrono::steady_clock> spawn_time;




    detail::LineBufferedPipe stdout_pipe;




    detail::LineBufferedPipe stderr_pipe;
};






class ParentProcessCheckTimer final : public Timer {
public:





    ParentProcessCheckTimer(double t, double interval);

protected:
    void Dispatch(double t, bool is_expire) override;

    double interval;
};
}

ZEEK_EXTERN_DATA Supervisor* supervisor_mgr;

}
