

#pragma once

#include <unistd.h>

extern "C" {
#include <pcap.h>
}

#include "zeek/iosource/PktDumper.h"

namespace zeek::iosource::pcap {

class PcapDumper : public PktDumper {
public:
    PcapDumper(const std::string& path, bool append);

    static PktDumper* Instantiate(const std::string& path, bool append);

protected:

    void Open() override;
    void Close() override;
    bool Dump(const Packet* pkt) override;

private:
    Properties props;

    bool append;
    pcap_dumper_t* dumper;
    pcap_t* pd;
};

}
