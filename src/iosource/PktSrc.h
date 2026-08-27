

#pragma once

#include <sys/types.h>
#include <optional>
#include <vector>

#include "zeek/iosource/BPF_Program.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/iosource/Packet.h"

struct pcap_pkthdr;

namespace zeek::iosource {




class PktSrc : public IOSource {
public:
    static const uint32_t NETMASK_UNKNOWN = 0xffffffff;




    struct Stats {



        uint64_t received = 0;




        uint64_t dropped = 0;





        uint64_t link = 0;




        uint64_t bytes_received = 0;




        std::optional<uint64_t> filtered;
    };




    PktSrc();




    ~PktSrc() override;





    const std::string& Path() const;




    bool IsLive() const;




    int LinkType() const;





    uint32_t Netmask() const;




    bool IsError() const;

















    virtual bool HasBeenIdleFor(double interval) const;





    const char* ErrorMsg() const;














    virtual bool PrecompileBPFFilter(int index, const std::string& filter);











    detail::BPF_Program* GetBPFFilter(int index);

















    bool ApplyBPFFilter(int index, const struct pcap_pkthdr* hdr, const u_char* pkt);









    bool GetCurrentPacket(const Packet** hdr);


















    virtual bool PrecompileFilter(int index, const std::string& filter) { return PrecompileBPFFilter(index, filter); }













    virtual bool SetFilter(int index) = 0;








    virtual void Statistics(Stats* stats) = 0;










    double GetNextTimeout() override;

protected:
    friend class Manager;







    struct Properties {




        std::string path;





        int selectable_fd;




        int link_type;





        uint32_t netmask;





        bool is_live;

        Properties();
    };







    void Opened(const Properties& props);





    void Closed();







    void Info(const std::string& msg);






    void Error(const std::string& msg);








    void Weird(const std::string& msg, const Packet* pkt);







    void InternalError(const std::string& msg);










    virtual void Open() = 0;








    virtual void Close() = 0;














    virtual bool ExtractNextPacket(Packet* pkt) = 0;





    virtual void DoneWithPacket() = 0;











    virtual detail::BPF_Program* CompileFilter(const std::string& filter);

private:

    bool ExtractNextPacketInternal();


    void InitSource() override;
    void Done() override;
    void Process() override;
    const char* Tag() override;

    Properties props;

    bool have_packet;
    Packet current_packet;

    bool had_packet;

    double idle_at_wallclock = 0.0;


    std::vector<detail::BPF_Program*> filters;

    std::string errbuf;
};

}
