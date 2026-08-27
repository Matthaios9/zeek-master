

#pragma once

extern "C" {
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
}

#include "zeek/iosource/PktSrc.h"
#include "zeek/iosource/af_packet/RX_Ring.h"

namespace zeek::iosource::af_packet {

class AF_PacketSource : public zeek::iosource::PktSrc {
public:









    AF_PacketSource(const std::string& path, bool is_live);




    ~AF_PacketSource() override;

    static PktSrc* InstantiateAF_Packet(const std::string& path, bool is_live);

protected:

    void Open() override;
    void Close() override;
    bool ExtractNextPacket(zeek::Packet* pkt) override;
    void DoneWithPacket() override;
    bool PrecompileFilter(int index, const std::string& filter) override;
    bool SetFilter(int index) override;
    void Statistics(Stats* stats) override;

private:
    Properties props;
    Stats stats;

    int current_filter = 0;
    unsigned int num_discarded = 0;
    int checksum_mode = 0;

    int socket_fd = -1;
    RX_Ring* rx_ring = nullptr;
    struct pcap_pkthdr current_hdr = {};

    struct InterfaceInfo {
        int index = -1;
        int flags = 0;

        bool Valid() { return index >= 0; }
        bool IsUp() { return flags & IFF_UP; }
        bool IsLoopback() { return flags & IFF_LOOPBACK; }
    };

    InterfaceInfo GetInterfaceInfo(const std::string& path);
    bool BindInterface(const InterfaceInfo& info);
    bool EnablePromiscMode(const InterfaceInfo& info);
    bool ConfigureFanoutGroup(bool enabled, bool defrag);
    bool ConfigureHWTimestamping(bool enabled);
    uint32_t GetFanoutMode(bool defrag);
};

}
