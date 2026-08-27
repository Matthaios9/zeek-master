

#pragma once

#include "zeek/zeek-config.h"

#include <map>
#include <string>
#include <vector>

#include "zeek/Flare.h"
#include "zeek/iosource/IOSource.h"

struct timespec;
struct kevent;

namespace zeek {
namespace iosource {

class PktSrc;
class PktDumper;





class Manager {
public:
    struct ReadySource {
        IOSource* src = nullptr;
        int fd = -1;
        int flags = 0;
    };

    using ReadySources = std::vector<ReadySource>;




    Manager();




    virtual ~Manager();





    void InitPostScript();













    void Register(IOSource* src, bool dont_count = false, bool manage_lifetime = true);





    int Size() const { return sources.size() - dont_counts; }




    int TotalSize() const { return sources.size(); }





    PktSrc* GetPktSrc() const { return pkt_src; }





    void Terminate() { RemoveAll(); }











    PktSrc* OpenPktSrc(const std::string& path, bool is_live);










    PktDumper* OpenPktDumper(const std::string& path, bool append);






    void FindReadySources(ReadySources* ready);












    bool RegisterFd(int fd, IOSource* src, int flags = IOSource::READ);




    bool UnregisterFd(int fd, IOSource* src, int flags = IOSource::READ);






    void Wakeup(std::string_view where);

private:



    struct Source {
        IOSource* src = nullptr;
        bool dont_count = false;
        bool manage_lifetime = false;
    };













    void Poll(ReadySources* ready, double timeout, IOSource* timeout_src);





    void ConvertTimeout(double timeout, struct timespec& spec);




    void Register(PktSrc* src);

    void RemoveAll();












    void ReapSource(Source* src);

    class WakeupHandler final : public IOSource {
    public:
        WakeupHandler();
        ~WakeupHandler() override;







        void Ping(std::string_view where);


        void Process() override;
        const char* Tag() override { return "WakeupHandler"; }
        double GetNextTimeout() override { return -1; }

    private:
        zeek::detail::Flare flare;
    };

    using SourceList = std::vector<Source*>;
    SourceList sources;

    using PktDumperList = std::vector<PktDumper*>;
    PktDumperList pkt_dumpers;

    PktSrc* pkt_src = nullptr;

    int dont_counts = 0;
    int zero_timeout_count = 0;
    WakeupHandler* wakeup = nullptr;
    int poll_counter = 0;
    int poll_interval = 0;

    int event_queue = -1;
    std::map<int, IOSource*> fd_map;
    std::map<int, IOSource*> write_fd_map;



    std::vector<struct kevent> events;
};

}

ZEEK_EXTERN_DATA iosource::Manager* iosource_mgr;

}
